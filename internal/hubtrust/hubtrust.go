// Package hubtrust is how an agent decides whether to trust a hub's TLS certificate.
//
// The agent is configured with the pin of the hub identity key (`sha256//<base64>`, printed by `infra-hub key init`
// and `key pin`, carried in the join token). The connection is accepted if and only if the SHA-256 of the
// SubjectPublicKeyInfo of the certificate the hub presents equals one of the pins. Chain, expiry and host name are
// not looked at: the pin is the trust, as with an SSH host key. The hub signs its handshake with the private key, so
// only a holder of that key can present a certificate that matches. The system roots are never consulted.
package hubtrust

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const pinPrefix = "sha256//"

// Pin is the pin of a certificate's public key: sha256//<base64 of SHA-256 of the SPKI>.
func Pin(cert *x509.Certificate) string { return pinOf(cert.RawSubjectPublicKeyInfo) }

// PinOfKey is the same pin for a public key.
func PinOfKey(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return pinOf(der), nil
}

func pinOf(spki []byte) string {
	sum := sha256.Sum256(spki)
	return pinPrefix + base64.StdEncoding.EncodeToString(sum[:])
}

// ParsePin checks the sha256//<base64> form and returns the 32-byte hash.
func ParsePin(pin string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	b64, ok := strings.CutPrefix(pin, pinPrefix)
	if !ok {
		return out, errors.New("a pin looks like sha256//<base64>")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != sha256.Size {
		return out, errors.New("a pin looks like sha256//<base64 of 32 bytes>")
	}
	copy(out[:], raw)
	return out, nil
}

// Verifier checks the certificate a hub presents.
type Verifier struct {
	// Pins are the accepted pins: one, or several while the hub key is being rotated.
	Pins []string
	// Host is the address the agent connects to; it is used only as the TLS server name (SNI), never to decide trust.
	Host string
}

// VerifyChain checks the DER certificates a hub presented (leaf first). Only the leaf's public key matters.
func (v Verifier) VerifyChain(raw [][]byte) error {
	if len(v.Pins) == 0 {
		return errors.New("no hub pin is configured")
	}
	pins := make([][sha256.Size]byte, 0, len(v.Pins))
	for _, p := range v.Pins {
		h, err := ParsePin(p)
		if err != nil {
			return fmt.Errorf("hub pin: %w", err)
		}
		pins = append(pins, h)
	}
	if len(raw) == 0 {
		return errors.New("the hub presented no certificate")
	}
	if len(raw) > 8 {
		return errors.New("the hub presented too many certificates")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return fmt.Errorf("the hub presented a certificate that does not parse: %w", err)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	for _, p := range pins {
		if bytes.Equal(p[:], sum[:]) {
			return nil
		}
	}
	return errors.New("the hub's key does not match any configured pin")
}

// TLSConfig is a client configuration that trusts exactly what VerifyChain accepts. Go's own verification is switched
// off because it would use the system roots and the host name; VerifyConnection does the verification instead, on
// every handshake (resumed sessions repeat it as well).
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
