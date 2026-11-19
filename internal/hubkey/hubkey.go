// Package hubkey is the hub identity key: one ECDSA P-256 key shared by every hub, whose public-key pin is all an agent
// needs to trust a hub. The hub builds a self-signed certificate from it in memory at every start; there are no
// certificate files and nothing to renew.
package hubkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

// NotAfter is the end of every hub certificate: 9999-12-31T23:59:59Z, which RFC 5280 (4.1.2.5) defines as "no
// well-defined expiration".
var NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// Generate returns a new key.
func Generate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Marshal is the PKCS#8 PEM form of the key.
func Marshal(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WriteNew writes the key to path with mode 0600. It refuses to overwrite an existing file.
func WriteNew(path string, key *ecdsa.PrivateKey) error {
	data, err := Marshal(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; refusing to overwrite a key", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// Read reads a PKCS#8 PEM ECDSA P-256 key. The path (after following a symlink) must be a regular file, which is checked
// before it is opened so that a FIFO or device cannot block the hub; the file is then opened without blocking, it must
// be the same file, and its mode is checked on the open handle: no access for others, and group access only as read
// access for the root group (systemd 256+ hands credentials over as root:root 0440 with an ACL for the service user).
func Read(path string) (*ecdsa.PrivateKey, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(before, st) {
		return nil, fmt.Errorf("%s changed while it was being opened", path)
	}
	if err := checkMode(path, st); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// checkMode refuses a key that others can access, or that a group other than root can access, or that any group can write.
func checkMode(path string, st os.FileInfo) error {
	perm := st.Mode().Perm()
	bad := perm&0o007 != 0 || perm&0o020 != 0
	if perm&0o040 != 0 {
		sys, ok := st.Sys().(*syscall.Stat_t)
		bad = bad || !ok || sys.Gid != 0
	}
	if bad {
		return fmt.Errorf("%s is accessible by group or others (mode %v); it must be 0600 or 0400 (0440 only for the root group, as systemd credentials are)", path, perm)
	}
	return nil
}

// Parse reads a PKCS#8 PEM ECDSA P-256 key.
func Parse(data []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PKCS#8 PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New("not a PKCS#8 PEM private key")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the hub identity key must be an ECDSA P-256 key (found %s); run `infra-hub key init` again to make one", keyKind(k))
	}
	return ec, nil
}

func keyKind(k any) string {
	switch k := k.(type) {
	case ed25519.PrivateKey:
		return "Ed25519"
	case *rsa.PrivateKey:
		return "RSA"
	case *ecdsa.PrivateKey:
		return "ECDSA " + k.Curve.Params().Name
	}
	return "an unknown type"
}

// Pin is the pin of the key's public half.
func Pin(key *ecdsa.PrivateKey) (string, error) {
	return hubtrust.PinOfKey(key.Public())
}

// Certificate builds the hub's self-signed certificate in memory: SAN is addresses (IP addresses and DNS names),
// valid from an hour before now until NotAfter. Agents ignore everything but the key; the names and dates exist so
// that ordinary TLS clients and tools can read the certificate.
func Certificate(key *ecdsa.PrivateKey, addresses []string, now time.Time) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "infra-hub"},
		NotBefore:             now.Add(-time.Hour).UTC(),
		NotAfter:              NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, a := range addresses {
		if ip, err := netip.ParseAddr(a); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip.Unmap().AsSlice())
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, a)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
