// Package httpsapi is the hub's HTTPS side: its TLS identity (a key of its own, a certificate signed by the hub CA)
// and the /v1 endpoints that agents use (health, challenge, report).
package httpsapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
	"github.com/KazuhaHub/infra-hub/internal/hubca"
)

// LoadOrCreateKey returns the hub's TLS key, generating an ECDSA P-256 key (file mode 0600) on the first call.
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if st, err := os.Stat(path); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		// Written under a temporary name and linked into place: if another process creates the key first, its key
		// wins and is the one that is read below, so the file is never replaced under a signed request.
		tmp := path + "." + strconv.Itoa(os.Getpid()) + ".tmp"
		if err := atomicfile.Write(tmp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		defer os.Remove(tmp)
		if err := os.Link(tmp, path); err != nil && !os.IsExist(err) {
			return nil, err
		}
	} else if err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by others (mode %v); it must be 0600", path, st.Mode().Perm())
	}
	return hubca.ReadPrivateKey(path)
}

// LoadServingCert reads the hub certificate (leaf first, then any intermediates) and returns it as a TLS certificate
// only if it belongs to key, chains to the CA certificate, is valid now for server authentication and covers every
// name in addresses. Anything else is an error and the hub must not serve HTTPS with it.
func LoadServingCert(key *ecdsa.PrivateKey, certPath, caPath string, addresses []string, now time.Time) (*tls.Certificate, error) {
	ca, err := hubca.ReadCertificate(caPath)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !ca.IsCA {
		return nil, errors.New("CA certificate: not a CA")
	}
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("hub certificate: %w", err)
	}
	var chain [][]byte
	var leaf *x509.Certificate
	inter := x509.NewCertPool()
	for rest := pemData; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("hub certificate: %w", err)
		}
		if leaf == nil {
			leaf = c
		} else {
			inter.AddCert(c)
		}
		chain = append(chain, b.Bytes)
	}
	if leaf == nil {
		return nil, errors.New("hub certificate: no certificate in the file")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("hub certificate does not match the hub's key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, fmt.Errorf("hub certificate does not chain to the CA: %w", err)
	}
	for _, a := range addresses {
		if ip, err := netip.ParseAddr(a); err == nil {
			if err := leaf.VerifyHostname(ip.Unmap().String()); err != nil {
				return nil, fmt.Errorf("hub certificate does not cover %s", a)
			}
		} else if err := leaf.VerifyHostname(a); err != nil {
			return nil, fmt.Errorf("hub certificate does not cover %s", a)
		}
	}
	// The hub presents the whole chain: its certificate, any intermediates, and the CA certificate (public), so that an
	// agent that holds only the CA pin can recognise the CA from what the hub sends (internal/hubtrust).
	if !bytes.Equal(chain[len(chain)-1], ca.Raw) {
		chain = append(chain, ca.Raw)
	}
	return &tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: leaf}, nil
}
