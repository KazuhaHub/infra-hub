// Package hubtrust is how an agent decides whether to trust a hub's TLS certificate.
//
// The agent is configured with one thing, the pin of the hub CA's public key (AGENT_HUB_CA_PIN, `sha256//<base64>`,
// the output of `infra-hub ca init` and `ca pin`). The hub presents its certificate followed by the CA certificate.
// The presented CA certificate is taken as a root only if the SHA-256 of its SubjectPublicKeyInfo equals the pin; the
// hub certificate must then verify against it by the usual rules (signature, validity, name constraints, key usage)
// and must be valid for the address the agent connected to. The system roots are never consulted.
package hubtrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/hubca"
)

// Verifier checks the chain a hub presents.
type Verifier struct {
	// Pins are the accepted CA pins (more than one only while a CA is being rotated).
	Pins []string
	// Host is the IP address or DNS name the agent connected to; the hub certificate must be valid for it.
	Host string
	// Revoked, if set, refuses a hub certificate whose serial is listed.
	Revoked *hubca.RevocationList
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// VerifyChain checks the DER certificates a hub presented (leaf first).
func (v Verifier) VerifyChain(raw [][]byte) error {
	if len(v.Pins) == 0 {
		return errors.New("no CA pin is configured")
	}
	var pins [][sha256.Size]byte
	for _, p := range v.Pins {
		h, err := hubca.ParsePin(p)
		if err != nil {
			return fmt.Errorf("CA pin: %w", err)
		}
		pins = append(pins, h)
	}
	if v.Host == "" {
		return errors.New("no host to verify the certificate for")
	}
	if len(raw) == 0 {
		return errors.New("the hub presented no certificate")
	}
	if len(raw) > 8 {
		return errors.New("the hub presented too many certificates")
	}
	certs := make([]*x509.Certificate, len(raw))
	for i, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("the hub presented a certificate that does not parse: %w", err)
		}
		certs[i] = c
	}
	leaf := certs[0]
	if leaf.IsCA {
		return errors.New("the hub's certificate is a CA certificate")
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return errors.New("the hub's certificate has no IP or DNS name")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	haveRoot := false
	for _, c := range certs[1:] {
		sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
		if c.IsCA && matches(pins, sum) {
			roots.AddCert(c)
			haveRoot = true
		} else {
			inter.AddCert(c)
		}
	}
	if !haveRoot {
		return errors.New("no certificate in the presented chain has the pinned CA key")
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	// VerifyOptions.DNSName also accepts an IP address.
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: v.Host, CurrentTime: now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("the hub certificate is not valid: %w", err)
	}
	if v.Revoked.Contains(leaf.SerialNumber) {
		return fmt.Errorf("the hub certificate (serial %s) is revoked", leaf.SerialNumber.Text(16))
	}
	return nil
}

func matches(pins [][sha256.Size]byte, sum [sha256.Size]byte) bool {
	for _, p := range pins {
		if bytes.Equal(p[:], sum[:]) {
			return true
		}
	}
	return false
}

// TLSConfig is a client configuration that trusts exactly what VerifyChain accepts. Go's own verification is switched
// off because it would use the system roots; VerifyPeerCertificate does the verification instead, on every
// handshake (resumed sessions repeat it as well, see VerifyConnection).
func (v Verifier) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         v.Host,
		InsecureSkipVerify: true, // replaced by VerifyConnection below; the system roots must not decide
		VerifyConnection: func(cs tls.ConnectionState) error {
			raw := make([][]byte, len(cs.PeerCertificates))
			for i, c := range cs.PeerCertificates {
				raw[i] = c.Raw
			}
			return v.VerifyChain(raw)
		},
	}
}
