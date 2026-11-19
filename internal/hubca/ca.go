// Package hubca is the hub certificate authority: a small ECDSA P-256 CA that the owner runs on a workstation to sign
// the TLS certificates of hubs. Agents trust only this CA (by its public-key pin), never the system roots.
//
// The CA private key must never be on a server. Nothing in the hub's serving path imports the signing functions.
package hubca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
)

const (
	// CAValidity is how long a new CA certificate is valid.
	CAValidity = 20 * 365 * 24 * time.Hour
	// DefaultDays is the default validity of a hub certificate.
	DefaultDays = 825
	// MaxDays caps the validity of a hub certificate.
	MaxDays = 825

	KeyFile  = "ca.key"
	CertFile = "ca.crt"
)

// DNSNameRe is a plain, lower-case DNS name (no wildcard, no trailing dot).
var DNSNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Constraints restrict which names the CA may ever certify. Empty means no restriction.
type Constraints struct {
	IPs   []netip.Prefix // e.g. 192.0.2.0/24
	Names []string       // DNS domains, e.g. example.org (also covers its sub-domains)
}

func (c Constraints) empty() bool { return len(c.IPs) == 0 && len(c.Names) == 0 }

// Init creates a CA key and a self-signed certificate valid for CAValidity in dir. It refuses to overwrite an
// existing CA. The key is written unencrypted with mode 0600: the owner encrypts it (SOPS) and removes the plain file.
func Init(dir string, now time.Time, cons Constraints) (pin string, err error) {
	keyPath, certPath := filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)
	for _, p := range []string{keyPath, certPath} {
		if _, err := os.Lstat(p); err == nil {
			return "", fmt.Errorf("%s already exists; refusing to overwrite a CA", p)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serial, err := newSerial()
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "infra hub CA " + now.UTC().Format("2006-01-02")},
		NotBefore:             now.Add(-5 * time.Minute).UTC(),
		NotAfter:              now.Add(CAValidity).UTC(),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	if !cons.empty() {
		tmpl.PermittedDNSDomainsCritical = true
		// A verifier enforces a name type only if the CA lists a constraint of that type, so the type the owner did
		// not name is excluded altogether.
		if len(cons.IPs) == 0 {
			for _, a := range []string{"0.0.0.0/0", "::/0"} {
				_, n, _ := net.ParseCIDR(a)
				tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, n)
			}
		}
		if len(cons.Names) == 0 {
			tmpl.PermittedDNSDomains = []string{"invalid"} // reserved TLD (RFC 6761): permits no real name
		}
		for _, p := range cons.IPs {
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: p.Masked().Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
		}
		for _, n := range cons.Names {
			if !DNSNameRe.MatchString(n) {
				return "", fmt.Errorf("name constraint %q is not a plain DNS name", n)
			}
			tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	if err := atomicfile.Write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return "", err
	}
	if err := atomicfile.Write(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return "", err
	}
	return Pin(cert), nil
}

// Pin is the curl `--pinnedpubkey` form of the certificate's public key: sha256//<base64 of SHA-256 of the SPKI>.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:])
}

// PinOfKey is the same pin for a public key.
func PinOfKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

// ReadCertificate reads the first certificate of a PEM file.
func ReadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCertificatePEM(data)
}

// ParseCertificatePEM returns the first CERTIFICATE block.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			return nil, errors.New("no certificate in the PEM data")
		}
		if b.Type == "CERTIFICATE" {
			return x509.ParseCertificate(b.Bytes)
		}
	}
}

// ReadPrivateKey reads a PKCS#8 or SEC1 EC private key.
func ReadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%s: no PEM data", path)
	}
	switch b.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		ec, ok := k.(*ecdsa.PrivateKey)
		if !ok || ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s: not an ECDSA P-256 key", path)
		}
		return ec, nil
	case "EC PRIVATE KEY":
		ec, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil || ec.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s: not an ECDSA P-256 key", path)
		}
		return ec, nil
	}
	return nil, fmt.Errorf("%s: unsupported PEM type %q", path, b.Type)
}

// SignOptions are the inputs of Sign.
type SignOptions struct {
	CAKey  *ecdsa.PrivateKey
	CACert *x509.Certificate
	CSRPEM []byte
	Days   int
	Now    time.Time
}

// Sign signs a hub's certificate request. The names come from the request and may be IP and DNS names only; the
// public key is the request's. The result is checked against the CA (name constraints included) before it is
// returned.
func Sign(o SignOptions) (certPEM []byte, cert *x509.Certificate, err error) {
	if o.Days == 0 {
		o.Days = DefaultDays
	}
	if o.Days < 1 || o.Days > MaxDays {
		return nil, nil, fmt.Errorf("days must be between 1 and %d", MaxDays)
	}
	if !o.CACert.IsCA {
		return nil, nil, errors.New("the CA certificate is not a CA")
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&o.CAKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	if string(pubDER) != string(o.CACert.RawSubjectPublicKeyInfo) {
		return nil, nil, errors.New("the CA key does not belong to the CA certificate")
	}
	b, _ := pem.Decode(o.CSRPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("the request is not a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("request signature: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, nil, errors.New("the request's key is not ECDSA P-256")
	}
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return nil, nil, errors.New("the request has e-mail or URI names; only IP and DNS names are allowed")
	}
	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
		return nil, nil, errors.New("the request has no IP or DNS name")
	}
	for _, n := range csr.DNSNames {
		if !DNSNameRe.MatchString(n) {
			return nil, nil, fmt.Errorf("DNS name %q is not a plain lower-case name (no wildcard)", n)
		}
	}
	notAfter := o.Now.Add(time.Duration(o.Days) * 24 * time.Hour).UTC()
	if notAfter.After(o.CACert.NotAfter) {
		return nil, nil, fmt.Errorf("the certificate would outlive the CA (%s)", o.CACert.NotAfter.UTC().Format(time.RFC3339))
	}
	serial, err := newSerial()
	if err != nil {
		return nil, nil, err
	}
	cn := ""
	if len(csr.DNSNames) > 0 {
		cn = csr.DNSNames[0]
	} else {
		cn = csr.IPAddresses[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    o.Now.Add(-5 * time.Minute).UTC(),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, o.CACert, pub, o.CAKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(o.CACert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: o.Now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, nil, fmt.Errorf("the CA would not accept this certificate (name constraints?): %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// NewCSR builds a certificate request for key with the given IP and DNS names.
func NewCSR(key *ecdsa.PrivateKey, names []string) ([]byte, error) {
	var dns []string
	var ips []net.IP
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			ips = append(ips, net.IP(a.Unmap().AsSlice()))
			continue
		}
		if !DNSNameRe.MatchString(n) {
			return nil, fmt.Errorf("%q is neither an IP address nor a plain DNS name", n)
		}
		dns = append(dns, n)
	}
	if len(dns) == 0 && len(ips) == 0 {
		return nil, errors.New("no names for the certificate request")
	}
	cn := "infra-hub"
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns, IPAddresses: ips}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func newSerial() (*big.Int, error) {
	// 127 random bits: positive, unique in practice, and short enough for any parser.
	max := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// ParsePrefix parses a CIDR for a name constraint.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR range", s)
	}
	return p, nil
}
