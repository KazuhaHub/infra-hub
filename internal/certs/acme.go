package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KazuhaHub/infra-hub/internal/atomicfile"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// LetsEncryptProduction is the default ACME directory. Tests and staging set acme_directory in the config.
const LetsEncryptProduction = lego.LEDirectoryProduction

// LegoIssuer issues certificates with lego: ECDSA P-256 keys, Cloudflare DNS-01. The account (its key and
// registration) lives in Dir, created on first use; each hub has its own account.
type LegoIssuer struct {
	Directory  string // ACME directory URL
	Email      string // optional contact
	Dir        string // account directory
	CFToken    string // Cloudflare API token (DNS edit on the zones)
	httpConfig func(*lego.Config)
}

type acmeUser struct {
	email string
	reg   *registration.Resource
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func (l *LegoIssuer) account(client func(*acmeUser) (*lego.Client, error)) (*lego.Client, error) {
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return nil, err
	}
	keyPath, regPath := filepath.Join(l.Dir, "account.key"), filepath.Join(l.Dir, "registration.json")
	u := &acmeUser{email: l.Email}
	if pemBytes, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("account.key is not PEM")
		}
		if u.key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("account.key: %w", err)
		}
	} else if os.IsNotExist(err) {
		k, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		der, merr := x509.MarshalECPrivateKey(k)
		if merr != nil {
			return nil, merr
		}
		if werr := atomicfile.Write(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); werr != nil {
			return nil, werr
		}
		u.key = k
	} else {
		return nil, err
	}
	if data, err := os.ReadFile(regPath); err == nil {
		u.reg = &registration.Resource{}
		if err := json.Unmarshal(data, u.reg); err != nil {
			return nil, fmt.Errorf("registration.json: %w", err)
		}
	}
	c, err := client(u)
	if err != nil {
		return nil, err
	}
	if u.reg == nil {
		reg, err := c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		data, _ := json.Marshal(reg)
		if err := atomicfile.Write(regPath, data, 0o600); err != nil {
			return nil, err
		}
		u.reg = reg
	}
	return c, nil
}

// Obtain implements Issuer: a fresh order and a fresh P-256 key for name (for a renewal too).
func (l *LegoIssuer) Obtain(ctx context.Context, name string) (Bundle, error) {
	c, err := l.account(func(u *acmeUser) (*lego.Client, error) {
		cfg := lego.NewConfig(u)
		cfg.CADirURL = l.Directory
		cfg.Certificate.KeyType = certcrypto.EC256
		cfg.UserAgent = "infra-hub"
		if l.httpConfig != nil {
			l.httpConfig(cfg)
		}
		client, err := lego.NewClient(cfg)
		if err != nil {
			return nil, err
		}
		dc := cloudflare.NewDefaultConfig()
		dc.AuthToken = l.CFToken
		p, err := cloudflare.NewDNSProviderConfig(dc)
		if err != nil {
			return nil, err
		}
		// Same resolver as cert-hub used for the propagation check.
		return client, client.Challenge.SetDNS01Provider(p, dns01.AddRecursiveNameservers([]string{"1.1.1.1:53"}))
	})
	if err != nil {
		return Bundle{}, err
	}
	res, err := c.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{name}, Bundle: true})
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Fullchain: res.Certificate, Privkey: res.PrivateKey}, nil
}

// ReadToken reads the Cloudflare token from the systemd credential (or the configured file).
func ReadToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(data))
	if t == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return t, nil
}
