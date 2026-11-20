package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/hubtrust"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
)

// repoName is the only repository the hub serves; clients use ssh://infra@<hub>:<port>/infra.git.
const repoName = "infra.git"

// Config is the hub's JSON config file (usually rendered by a configuration tool).
type Config struct {
	// Listen is the address of the SSH server, e.g. 192.0.2.10:11882. Any reachable address works; the hub does not
	// depend on a particular network. Empty: the hub runs no SSH server (HTTPS only); hostKey and the clients' sshKey
	// are then not needed.
	Listen string `json:"listen"`
	// Repo is the bare mirror; its last path element must be infra.git.
	Repo string `json:"repo"`
	// Upstream is where the mirror fetches from (a git remote such as GitHub, over the host's deploy key).
	Upstream string `json:"upstream"`
	// State is the JSON file with last-seen times (default: state.json next to the repo).
	State string `json:"state"`
	// HostKey is the hub's own SSH host key (private key file; generated on first start if missing). Required when
	// Listen is set.
	HostKey string `json:"hostKey"`
	// MirrorIntervalSeconds is how often the mirror fetches (default 60).
	MirrorIntervalSeconds int `json:"mirrorIntervalSeconds"`
	// MaxStaleSeconds: the hub refuses to serve when its last successful fetch from upstream is older than this, or
	// when it has had none since it started (default 600). Clients then use their next source.
	MaxStaleSeconds int `json:"maxStaleSeconds"`
	// Clients maps a host name to how it identifies itself. In the file an entry is either the SSH public key
	// (authorized_keys format) as a string, as before, or an object {"sshKey": "...", "agePublicKey": "age1..."}.
	Clients map[string]Client `json:"clients"`
	// HTTPSAddresses are the IP addresses and DNS names of this hub: the SAN of its self-signed certificate.
	HTTPSAddresses []string `json:"httpsAddresses"`
	// HTTPS configures the HTTPS listener for agents; empty listen means no HTTPS.
	HTTPS HTTPS `json:"https"`
	// Certs is the allow list of certificate names, each mapped to the one host that may fetch it. It is rendered
	// from the inventory; there is no other way to add a name. Empty: the
	// hub issues and serves no certificates.
	Certs map[string]string `json:"certs"`
	// CertDir holds the ACME account and the certificates (default: certs next to the repo, i.e. in StateDirectory).
	CertDir string `json:"certDir"`
	// AcmeDirectory is the ACME directory URL (default: Let's Encrypt production). Tests and staging use another.
	AcmeDirectory string `json:"acmeDirectory"`
	// AcmeEmail is an optional ACME contact.
	AcmeEmail string `json:"acmeEmail"`
	// CloudflareTokenFile holds the Cloudflare API token; default $CREDENTIALS_DIRECTORY/cf_token (systemd LoadCredential).
	CloudflareTokenFile string `json:"cloudflareTokenFile"`
	// IPSources are the providers of IP ranges (name -> where to download and how to read it); IPLists are the named
	// lists built from them plus manual entries, each with the hosts that may fetch it. Both are rendered from the
	// inventory. Empty: the hub collects and serves no lists.
	IPSources map[string]iplists.IPSource `json:"ipSources"`
	IPLists   map[string]iplists.IPList   `json:"ipLists"`
	// IPListDir holds one file per provider (default: iplists next to the repo, i.e. in StateDirectory).
	IPListDir string `json:"ipListDir"`
}

// HTTPS is the HTTPS listener.
type HTTPS struct {
	// Listen is host:port. Empty: HTTPS is off.
	Listen string `json:"listen"`
	// Key is the path of the hub identity key (ECDSA P-256, PKCS#8 PEM, mode 0600), the same on every hub. The hub builds
	// its self-signed certificate from it at every start (docs/hub-key.md).
	Key string `json:"key"`
}

// Client is one host: the SSH key it connects with today and the age public key it answers challenges with.
type Client struct {
	SSHKey       string `json:"sshKey"`
	AgePublicKey string `json:"agePublicKey,omitempty"`
}

// UnmarshalJSON accepts the old form (a string, the SSH key) and the object form.
func (c *Client) UnmarshalJSON(data []byte) error {
	var key string
	if err := json.Unmarshal(data, &key); err == nil {
		*c = Client{SSHKey: key}
		return nil
	}
	type plain Client
	var p plain
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("a client is an SSH key string or an object with sshKey and agePublicKey: %w", err)
	}
	*c = Client(p)
	return nil
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

// deprecatedKeys are the snake_case spellings of earlier releases, accepted for one release. The new spelling is
// camelCase everywhere (docs/conventions.md).
var deprecatedKeys = map[string]string{
	"host_key": "hostKey", "mirror_interval_seconds": "mirrorIntervalSeconds", "max_stale_seconds": "maxStaleSeconds",
	"cert_dir": "certDir", "acme_directory": "acmeDirectory", "acme_email": "acmeEmail",
	"cloudflare_token_file": "cloudflareTokenFile", "ip_sources": "ipSources", "ip_lists": "ipLists", "iplist_dir": "ipListDir",
}

// deprecatedSourceKeys are the same for one entry of ipSources.
var deprecatedSourceKeys = map[string]string{"max_bytes": "maxBytes"}

// renameDeprecated moves each deprecated key of obj to its new name and warns about it. A key set in both spellings
// is an error: which one should win is not for the hub to guess.
func renameDeprecated(obj map[string]json.RawMessage, aliases map[string]string, where string) error {
	for _, old := range sortedAliasKeys(aliases) {
		v, ok := obj[old]
		if !ok {
			continue
		}
		nw := aliases[old]
		if _, both := obj[nw]; both {
			return fmt.Errorf("config: %s%q and %q are both set; use only %q", where, old, nw, nw)
		}
		slog.Warn("deprecated config key, rename it", "key", where+old, "use", where+nw)
		obj[nw] = v
		delete(obj, old)
	}
	return nil
}

func sortedAliasKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// normalizeKeys rewrites the deprecated spellings in data; anything that is not a JSON object is left for the
// decoder to report.
func normalizeKeys(data []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return data, nil
	}
	if err := renameDeprecated(top, deprecatedKeys, ""); err != nil {
		return nil, err
	}
	if raw, ok := top["https"]; ok {
		var h map[string]json.RawMessage
		if json.Unmarshal(raw, &h) == nil {
			removed := false
			for _, old := range []string{"caCert", "cert"} {
				if _, ok := h[old]; ok {
					slog.Warn("removed config key, ignored; delete it and use https.key (the hub identity key)", "key", "https."+old)
					delete(h, old)
					removed = true
				}
			}
			// A v0.3.0 block has a listener and no key: it cannot serve without the identity key, but the hub (and
			// SSH) must still start.
			var key string
			_ = json.Unmarshal(h["key"], &key)
			if _, hasListen := h["listen"]; removed && hasListen && key == "" {
				slog.Warn("https is off until https.key is set to the hub identity key", "key", "https.listen")
				delete(h, "listen")
				delete(h, "key")
			}
			out, err := json.Marshal(h)
			if err != nil {
				return nil, err
			}
			top["https"] = out
		}
	}
	if raw, ok := top["ipSources"]; ok {
		var sources map[string]map[string]json.RawMessage
		if json.Unmarshal(raw, &sources) == nil {
			names := make([]string, 0, len(sources))
			for n := range sources {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if sources[n] == nil {
					continue
				}
				if err := renameDeprecated(sources[n], deprecatedSourceKeys, "ipSources."+n+"."); err != nil {
					return nil, err
				}
			}
			out, err := json.Marshal(sources)
			if err != nil {
				return nil, err
			}
			top["ipSources"] = out
		}
	}
	return json.Marshal(top)
}

func ParseConfig(data []byte) (Config, error) {
	var c Config
	data, err := normalizeKeys(data)
	if err != nil {
		return Config{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	if c.MirrorIntervalSeconds == 0 {
		c.MirrorIntervalSeconds = 60
	}
	if c.MirrorIntervalSeconds < 5 {
		return Config{}, errors.New("config: mirrorIntervalSeconds must be at least 5")
	}
	if c.MaxStaleSeconds == 0 {
		c.MaxStaleSeconds = 600
	}
	if c.MaxStaleSeconds < 2*c.MirrorIntervalSeconds {
		return Config{}, errors.New("config: maxStaleSeconds must be at least twice mirrorIntervalSeconds")
	}
	if c.Listen != "" {
		if _, port, err := net.SplitHostPort(c.Listen); err != nil || port == "" || port == "0" {
			return Config{}, fmt.Errorf("config: listen %q must be host:port", c.Listen)
		}
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
	if (c.Listen != "" || c.HostKey != "") && !filepath.IsAbs(c.HostKey) {
		return Config{}, errors.New("config: hostKey must be an absolute path")
	}
	if _, err := c.ClientKeys(); err != nil {
		return Config{}, err
	}
	if err := c.checkHTTPS(); err != nil {
		return Config{}, err
	}
	if c.Listen == "" && c.HTTPS.Listen == "" {
		return Config{}, errors.New("config: neither listen (SSH) nor https.listen is set; the hub would serve nothing")
	}
	if c.CertDir == "" {
		c.CertDir = filepath.Join(filepath.Dir(c.Repo), "certs")
	}
	if !filepath.IsAbs(c.CertDir) {
		return Config{}, errors.New("config: certDir must be an absolute path")
	}
	if c.AcmeDirectory == "" {
		c.AcmeDirectory = certs.LetsEncryptProduction
	}
	if !strings.HasPrefix(c.AcmeDirectory, "https://") && !strings.HasPrefix(c.AcmeDirectory, "http://") {
		return Config{}, errors.New("config: acmeDirectory must be an http(s) URL")
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
		return Config{}, errors.New("config: ipListDir must be an absolute path")
	}
	if err := c.checkIPLists(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func (c *Config) checkHTTPS() error {
	ageSeen := map[string]string{}
	for name, cl := range c.Clients {
		if cl.AgePublicKey == "" {
			continue
		}
		if other, dup := ageSeen[cl.AgePublicKey]; dup {
			return fmt.Errorf("config: clients %s and %s have the same agePublicKey", other, name)
		}
		ageSeen[cl.AgePublicKey] = name
		if _, err := age.ParseX25519Recipient(cl.AgePublicKey); err != nil {
			return fmt.Errorf("config: client %s: agePublicKey is not an age public key", name)
		}
	}
	seen := map[string]bool{}
	for _, a := range c.HTTPSAddresses {
		if !hubtrust.ValidAddress(a) {
			return fmt.Errorf("config: httpsAddresses: %q is neither an IP address nor a plain lower-case DNS name", a)
		}
		if seen[a] {
			return fmt.Errorf("config: httpsAddresses: %q twice", a)
		}
		seen[a] = true
	}
	h := c.HTTPS
	if h.Listen == "" {
		if h.Key != "" {
			return errors.New("config: https.key is set but https.listen is not")
		}
		return nil
	}
	if _, port, err := net.SplitHostPort(h.Listen); err != nil || port == "" || port == "0" {
		return fmt.Errorf("config: https.listen %q must be host:port", h.Listen)
	}
	if h.Key == "" || !filepath.IsAbs(h.Key) {
		return errors.New("config: https.key must be an absolute path when https.listen is set")
	}
	if len(c.HTTPSAddresses) == 0 {
		return errors.New("config: httpsAddresses is empty but https.listen is set")
	}
	return nil
}

// AgeRecipients are the clients' age public keys, by host name; clients without one are not listed.
func (c Config) AgeRecipients() map[string]age.Recipient {
	out := map[string]age.Recipient{}
	for name, cl := range c.Clients {
		if cl.AgePublicKey == "" {
			continue
		}
		if r, err := age.ParseX25519Recipient(cl.AgePublicKey); err == nil {
			out[name] = r
		}
	}
	return out
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

// SSHEnabled reports whether the hub runs an SSH server.
func (c Config) SSHEnabled() bool { return c.Listen != "" }

// ClientKeys parses the client keys; the same key for two names is an error (identity must be unambiguous). Without an
// SSH server there may be no clients with an SSH key (or no clients at all).
func (c Config) ClientKeys() (map[string]ssh.PublicKey, error) {
	if len(c.Clients) == 0 && c.SSHEnabled() {
		return nil, errors.New("config: clients is empty")
	}
	keys := map[string]ssh.PublicKey{}
	seen := map[string]string{}
	for name, cl := range c.Clients {
		if name == "" {
			return nil, errors.New("config: a client has an empty name")
		}
		line := cl.SSHKey
		if line == "" && (cl.AgePublicKey != "" || !c.SSHEnabled()) {
			continue // an age-only client: it has no SSH identity
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
