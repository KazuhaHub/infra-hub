// Package hubkey is the hub identity key: one Ed25519 key shared by every hub, whose public-key pin is all an agent
// needs to trust a hub. The hub builds a self-signed certificate from it in memory at every start; there are no
// certificate files and nothing to renew.
package hubkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
)

// NotAfter is the end of every hub certificate: 9999-12-31T23:59:59Z, which RFC 5280 (4.1.2.5) defines as "no
// well-defined expiration".
var NotAfter = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// Generate returns a new key.
func Generate() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}

// Marshal is the PKCS#8 PEM form of the key.
func Marshal(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WriteNew writes the key to path with mode 0600. It refuses to overwrite an existing file.
func WriteNew(path string, key ed25519.PrivateKey) error {
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
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// Read reads a PKCS#8 PEM Ed25519 key. A regular file that group or others can read is refused.
func Read(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().IsRegular() && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %v); it must be 0600", path, st.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse reads a PKCS#8 PEM Ed25519 key.
func Parse(data []byte) (ed25519.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		return nil, errors.New("not a PKCS#8 PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New("not a PKCS#8 PEM private key")
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return ed, nil
}

// Pin is the pin of the key's public half.
func Pin(key ed25519.PrivateKey) (string, error) {
	return hubtrust.PinOfKey(key.Public())
}

// Certificate builds the hub's self-signed certificate in memory: SAN is addresses (IP addresses and DNS names),
// valid from an hour before now until NotAfter. Agents ignore everything but the key; the names and dates exist so
// that ordinary TLS clients and tools can read the certificate.
func Certificate(key ed25519.PrivateKey, addresses []string, now time.Time) (*tls.Certificate, error) {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}
