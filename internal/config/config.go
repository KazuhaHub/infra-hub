package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

// repoName is the only repository the hub serves; clients use ssh://infra@<hub>:<port>/infra.git.
const repoName = "infra.git"

// Config is the hub's JSON config file (usually rendered by a configuration tool).
type Config struct {
	// Listen is the address to listen on, e.g. 192.0.2.10:11882. Any reachable address works; the hub does not
	// depend on a particular network.
	Listen string `json:"listen"`
	// Repo is the bare mirror; its last path element must be infra.git.
	Repo string `json:"repo"`
	// Upstream is where the mirror fetches from (a git remote such as GitHub, over the host's deploy key).
	Upstream string `json:"upstream"`
	// State is the JSON file with last-seen times (default: state.json next to the repo).
	State string `json:"state"`
	// HostKey is the hub's own SSH host key (private key file; generated on first start if missing).
	HostKey string `json:"host_key"`
	// MirrorIntervalSeconds is how often the mirror fetches (default 60).
	MirrorIntervalSeconds int `json:"mirror_interval_seconds"`
	// MaxStaleSeconds: the hub refuses to serve when its last successful fetch from upstream is older than this, or
	// when it has had none since it started (default 600). Clients then use their next source.
	MaxStaleSeconds int `json:"max_stale_seconds"`
	// Clients maps a host name to the public key (authorized_keys format) it connects with.
	Clients map[string]string `json:"clients"`
	// Certs is the allow list of certificate names, each mapped to the one host that may fetch it. It is rendered
	// from the inventory; there is no other way to add a name. Empty: the
	// hub issues and serves no certificates.
	Certs map[string]string `json:"certs"`
	// CertDir holds the ACME account and the certificates (default: certs next to the repo, i.e. in StateDirectory).
	CertDir string `json:"cert_dir"`
	// AcmeDirectory is the ACME directory URL (default: Let's Encrypt production). Tests and staging use another.
	AcmeDirectory string `json:"acme_directory"`
	// AcmeEmail is an optional ACME contact.
	AcmeEmail string `json:"acme_email"`
	// CloudflareTokenFile holds the Cloudflare API token; default $CREDENTIALS_DIRECTORY/cf_token (systemd LoadCredential).
	CloudflareTokenFile string `json:"cloudflare_token_file"`
	// IPSources are the providers of IP ranges (name -> where to download and how to read it); IPLists are the named
	// lists built from them plus manual entries, each with the hosts that may fetch it. Both are rendered from the
	// inventory. Empty: the hub collects and serves no lists.
	IPSources map[string]iplists.IPSource `json:"ip_sources"`
	IPLists   map[string]iplists.IPList   `json:"ip_lists"`
	// IPListDir holds one file per provider (default: iplists next to the repo, i.e. in StateDirectory).
	IPListDir string `json:"iplist_dir"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if c.MirrorIntervalSeconds == 0 {
		c.MirrorIntervalSeconds = 60
	}
	if c.MirrorIntervalSeconds < 5 {
		return Config{}, errors.New("config: mirror_interval_seconds must be at least 5")
	}
	if c.MaxStaleSeconds == 0 {
		c.MaxStaleSeconds = 600
	}
	if c.MaxStaleSeconds < 2*c.MirrorIntervalSeconds {
		return Config{}, errors.New("config: max_stale_seconds must be at least twice mirror_interval_seconds")
	}
	if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" || port == "0" {
		return Config{}, fmt.Errorf("config: listen %q must be host:port", c.Listen)
	}
	if !filepath.IsAbs(c.Repo) || filepath.Base(c.Repo) != repoName {
		return Config{}, fmt.Errorf("config: repo must be an absolute path ending in /%s", repoName)
	}
	if c.Upstream == "" || strings.HasPrefix(c.Upstream, "-") {
		return Config{}, errors.New("config: upstream is empty or looks like an option")
	}
	if c.State == "" {
		c.State = filepath.Join(filepath.Dir(c.Repo), "state.json")
	}
	if !filepath.IsAbs(c.HostKey) {
		return Config{}, errors.New("config: host_key must be an absolute path")
	}
	if _, err := c.ClientKeys(); err != nil {
		return Config{}, err
	}
	if c.CertDir == "" {
		c.CertDir = filepath.Join(filepath.Dir(c.Repo), "certs")
	}
	if !filepath.IsAbs(c.CertDir) {
		return Config{}, errors.New("config: cert_dir must be an absolute path")
	}
	if c.AcmeDirectory == "" {
		c.AcmeDirectory = certs.LetsEncryptProduction
	}
	if !strings.HasPrefix(c.AcmeDirectory, "https://") && !strings.HasPrefix(c.AcmeDirectory, "http://") {
		return Config{}, errors.New("config: acme_directory must be an http(s) URL")
	}
	for name, owner := range c.Certs {
		if !certs.NameRe.MatchString(name) {
			return Config{}, fmt.Errorf("config: certificate name %q is not a plain DNS name", name)
		}
		if _, ok := c.Clients[owner]; !ok {
			return Config{}, fmt.Errorf("config: certificate %s is owned by %q, which is not a client", name, owner)
		}
	}
	if c.IPListDir == "" {
		c.IPListDir = filepath.Join(filepath.Dir(c.Repo), "iplists")
	}
	if !filepath.IsAbs(c.IPListDir) {
		return Config{}, errors.New("config: iplist_dir must be an absolute path")
	}
	if err := c.checkIPLists(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// checkIPLists validates the providers and lists, and replaces each list's manual entries by their normalised form.
func (c *Config) checkIPLists() error {
	for name, src := range c.IPSources {
		if !iplists.NameRe.MatchString(name) {
			return fmt.Errorf("config: ip source name %q is not plain", name)
		}
		if err := src.Validate(); err != nil {
			return fmt.Errorf("config: ip source %s: %w", name, err)
		}
	}
	for name, l := range c.IPLists {
		if !iplists.NameRe.MatchString(name) {
			return fmt.Errorf("config: ip list name %q is not plain", name)
		}
		if len(l.Providers) == 0 && len(l.Manual) == 0 {
			return fmt.Errorf("config: ip list %s has no providers and no manual entries", name)
		}
		seen := map[string]bool{}
		for _, p := range l.Providers {
			if seen[p] {
				return fmt.Errorf("config: ip list %s names provider %q twice", name, p)
			}
			seen[p] = true
			if _, ok := c.IPSources[p]; !ok {
				return fmt.Errorf("config: ip list %s uses provider %q, which is not defined", name, p)
			}
		}
		if len(l.Manual) > 0 {
			manual, err := iplists.NormalizeAll(l.Manual)
			if err != nil {
				return fmt.Errorf("config: ip list %s manual entries: %w", name, err)
			}
			l.Manual = manual
		}
		for _, h := range l.Hosts {
			if _, ok := c.Clients[h]; !ok {
				return fmt.Errorf("config: ip list %s is for %q, which is not a client", name, h)
			}
		}
		c.IPLists[name] = l
	}
	return nil
}

// ClientKeys parses the client keys; the same key for two names is an error (identity must be unambiguous).
func (c Config) ClientKeys() (map[string]ssh.PublicKey, error) {
	if len(c.Clients) == 0 {
		return nil, errors.New("config: clients is empty")
	}
	keys := map[string]ssh.PublicKey{}
	seen := map[string]string{}
	for name, line := range c.Clients {
		if name == "" {
			return nil, errors.New("config: a client has an empty name")
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("config: client %s: not a single public key line", name)
		}
		fp := ssh.FingerprintSHA256(key)
		if other, dup := seen[fp]; dup {
			return nil, fmt.Errorf("config: clients %s and %s have the same key", other, name)
		}
		seen[fp] = name
		keys[name] = key
	}
	return keys, nil
}
