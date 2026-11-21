// Package agent is the engine of infra-agent: the configuration, one cycle (fetch, verify, extract, apply, report),
// the state kept between cycles and the lock that keeps two agents apart. The command line is in internal/agentapp.
package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/githubapp"
	"github.com/KazuhaHub/infra-hub/internal/jointoken"
	"github.com/KazuhaHub/infra-hub/internal/sigstorever"
)

// EnvPrefix is the prefix of every setting and of every flag's environment variable.
const EnvPrefix = "INFRA_AGENT_"

// Defaults of the optional settings.
const (
	DefaultEnvFile  = "/etc/infra/agent.env"
	DefaultAgeKey   = "/etc/infra/age.key"
	DefaultStateDir = "/var/lib/infra-agent"
	// DefaultGitHubKey and DefaultGitHubKnownHosts are the deploy key and the known_hosts file a hub host already has;
	// they only matter when INFRA_AGENT_GITHUB_REPO is set.
	DefaultGitHubKey        = "/etc/infra/deploy_key"
	DefaultGitHubKnownHosts = "/etc/infra/github_known_hosts"
	// DefaultGitHubAppKey is the GitHub App private key, used when INFRA_AGENT_GITHUB_APP_ID is set.
	DefaultGitHubAppKey = "/etc/infra/github-app.pem"
	DefaultInterval     = 5 * time.Minute
	// MinInterval keeps a typo from turning the agent into a load generator.
	MinInterval = 10 * time.Second
	// DefaultRepo is the repository the statement must name. Only a hidden flag changes it (tests).
	DefaultRepo = "KazuhaHub/infra"
)

// Modes of the agent.
const (
	ModeVerify = "verify"
	ModeApply  = "apply"
)

// SigSigstore names the Sigstore keyless signature, the only one the agent verifies. SigSSH is what a state written by
// an agent older than v0.15.0 may carry as the signature of its verified bundle (the ssh signature, which is no
// longer verified by anything).
const (
	SigSigstore = "sigstore"
	SigSSH      = "ssh"
)

// legacySignatureModes are the values of INFRA_AGENT_SIGNATURE that older agents knew. They are still accepted so that
// a host that is configured with one keeps updating, but the agent always requires the Sigstore signature.
var legacySignatureModes = []string{"ssh", "either"}

// Settings are the keys that agent.env (and the environment) may carry. Anything else with the prefix is an error.
var settingKeys = []string{"TOKEN", "HOST", "AGE_KEY", "SIGNERS", "MODE", "SIGNATURE", "SIGSTORE_REPO_ID", "SIGSTORE_OWNER_ID", "INTERVAL", "STATE_DIR", "LOG_FORMAT", "LOG_LEVEL", "GITHUB_REPO", "GITHUB_KEY", "GITHUB_KNOWN_HOSTS", "GITHUB_APP_ID", "GITHUB_APP_KEY"}

// ConfigError is a problem with the configuration: the caller exits with the usage code (2).
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

func configErrorf(format string, a ...any) error {
	return &ConfigError{Err: fmt.Errorf(format, a...)}
}

// Config is the validated configuration.
type Config struct {
	Token  jointoken.Token
	Host   string
	AgeKey string
	Mode   string
	// SigstoreRepoID and SigstoreOwnerID are GitHub's numeric IDs of the infra repository and of its owner, which the
	// signing certificate must carry (required).
	SigstoreRepoID, SigstoreOwnerID string
	Interval                        time.Duration
	StateDir                        string
	// Warnings are deprecation notes about the settings (INFRA_AGENT_SIGNATURE other than sigstore, INFRA_AGENT_SIGNERS);
	// the command line logs them once at start.
	Warnings []string
	// Repo is the repository the bundle statement must name.
	Repo string
	// GitHubRepo is the git URL of the repository to fall back to when no hub gives a bundle ("" turns the fallback
	// off); GitHubKey and GitHubKnownHosts are the SSH key and known_hosts file used to reach it.
	GitHubRepo, GitHubKey, GitHubKnownHosts string
	// GitHubAppID (digits, "" = off) and GitHubAppKey: when set, the fallback fetches over https with a read-only
	// GitHub App token instead of ssh, and GitHubKey and GitHubKnownHosts are not used.
	GitHubAppID, GitHubAppKey string

	// LogFormat and LogLevel are read from the file for the command line's logger; the engine ignores them.
	LogFormat, LogLevel string
}

var (
	githubURLRe = regexp.MustCompile(`^(ssh://[A-Za-z0-9@._:\[\]%/~+-]+|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:[A-Za-z0-9._/~+-]+)$`)
	safePathRe  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

var idRe = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ParseEnvFile reads KEY=VALUE lines (blank lines and lines starting with # are skipped; a value may be wrapped in
// one pair of single or double quotes). Every key must be INFRA_AGENT_ plus a known setting; a key twice is an error.
func ParseEnvFile(data []byte) (map[string]string, error) {
	known := map[string]bool{}
	for _, k := range settingKeys {
		known[EnvPrefix+k] = true
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 64<<10)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok || k == "" {
			return nil, configErrorf("line %d: expected KEY=VALUE", n)
		}
		if !known[k] {
			return nil, configErrorf("line %d: unknown setting %s (known: %s)", n, k, knownList())
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		if _, dup := out[k]; dup {
			return nil, configErrorf("line %d: %s is set twice", n, k)
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, configErrorf("%v", err)
	}
	return out, nil
}

func knownList() string {
	names := make([]string, len(settingKeys))
	for i, k := range settingKeys {
		names[i] = EnvPrefix + k
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// LoadConfig reads the env file at path (it must exist) and lets variables of the process environment (environ) override
// the settings, as the convention for every flag says. The result is validated.
func LoadConfig(path string, environ func(string) (string, bool)) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, configErrorf("read %s: %v", path, err)
	}
	vals, err := ParseEnvFile(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return FromValues(vals, environ)
}

// FromValues builds a Config from settings keyed by their full names (INFRA_AGENT_TOKEN ...), with environ overriding.
func FromValues(vals map[string]string, environ func(string) (string, bool)) (Config, error) {
	get := func(key string) string {
		name := EnvPrefix + key
		if environ != nil {
			if v, ok := environ(name); ok && v != "" {
				return v
			}
		}
		return vals[name]
	}
	c := Config{AgeKey: DefaultAgeKey, Mode: ModeVerify, Interval: DefaultInterval, StateDir: DefaultStateDir, Repo: DefaultRepo,
		GitHubKey: DefaultGitHubKey, GitHubKnownHosts: DefaultGitHubKnownHosts, GitHubAppKey: DefaultGitHubAppKey}
	tok := get("TOKEN")
	if tok == "" {
		return c, configErrorf("%sTOKEN is required (the ih1. join token from `infra-hub token`)", EnvPrefix)
	}
	t, err := jointoken.Decode(tok)
	if err != nil {
		return c, configErrorf("%sTOKEN: %v", EnvPrefix, err)
	}
	c.Token = t
	if c.Host = get("HOST"); c.Host == "" {
		return c, configErrorf("%sHOST is required (this host's name in the inventory)", EnvPrefix)
	}
	if !hostRe.MatchString(c.Host) {
		return c, configErrorf("%sHOST %q is not a plain host name", EnvPrefix, c.Host)
	}
	if v := get("AGE_KEY"); v != "" {
		c.AgeKey = v
	}
	if v := get("SIGNERS"); v != "" {
		c.Warnings = append(c.Warnings, EnvPrefix+"SIGNERS is ignored: the agent verifies the Sigstore signature only and needs no allowed_signers file")
	}
	if v := get("STATE_DIR"); v != "" {
		c.StateDir = v
	}
	if v := get("MODE"); v != "" {
		if v != ModeVerify && v != ModeApply {
			return c, configErrorf("%sMODE %q: want verify or apply", EnvPrefix, v)
		}
		c.Mode = v
	}
	if v := get("SIGNATURE"); v != "" {
		if v != SigSigstore && !slices.Contains(legacySignatureModes, v) {
			return c, configErrorf("%sSIGNATURE %q: want sigstore (ssh and either are accepted but deprecated)", EnvPrefix, v)
		}
		if v != SigSigstore {
			c.Warnings = append(c.Warnings, fmt.Sprintf("%sSIGNATURE=%s is deprecated: the agent now always requires the Sigstore signature, as with sigstore", EnvPrefix, v))
		}
	}
	for _, k := range []struct {
		key string
		dst *string
	}{{"SIGSTORE_REPO_ID", &c.SigstoreRepoID}, {"SIGSTORE_OWNER_ID", &c.SigstoreOwnerID}} {
		v := get(k.key)
		if v == "" {
			return c, configErrorf("%s%s is required (GitHub's numeric ID; `gh api repos/<owner>/<repo> -q .id`, `gh api users/<owner> -q .id`)", EnvPrefix, k.key)
		}
		if !idRe.MatchString(v) {
			return c, configErrorf("%s%s %q is not a number", EnvPrefix, k.key, v)
		}
		*k.dst = v
	}
	if v := get("INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, configErrorf("%sINTERVAL %q: %v (for example 5m)", EnvPrefix, v, err)
		}
		if d < MinInterval {
			return c, configErrorf("%sINTERVAL %s is shorter than %s", EnvPrefix, d, MinInterval)
		}
		c.Interval = d
	}
	c.GitHubRepo = get("GITHUB_REPO")
	for _, k := range []string{"GITHUB_KEY", "GITHUB_KNOWN_HOSTS", "GITHUB_APP_ID", "GITHUB_APP_KEY"} {
		if c.GitHubRepo == "" && get(k) != "" {
			return c, configErrorf("%s%s is set without %sGITHUB_REPO", EnvPrefix, k, EnvPrefix)
		}
	}
	if get("GITHUB_APP_KEY") != "" && get("GITHUB_APP_ID") == "" {
		return c, configErrorf("%sGITHUB_APP_KEY is set without %sGITHUB_APP_ID", EnvPrefix, EnvPrefix)
	}
	if id := get("GITHUB_APP_ID"); id != "" {
		var err error
		if c.GitHubAppID, err = githubapp.ParseAppID(id); err != nil {
			return c, configErrorf("%sGITHUB_APP_ID: %v", EnvPrefix, err)
		}
		if v := get("GITHUB_APP_KEY"); v != "" {
			c.GitHubAppKey = v
		}
		// The repository may be an ssh or an https URL; it is fetched over https either way.
		if _, _, err := githubapp.ParseRepo(c.GitHubRepo); err != nil {
			return c, configErrorf("%sGITHUB_REPO: %v", EnvPrefix, err)
		}
	} else if c.GitHubRepo != "" {
		if !githubURLRe.MatchString(c.GitHubRepo) && !(allowFileProtocol && strings.HasPrefix(c.GitHubRepo, "/")) {
			return c, configErrorf("%sGITHUB_REPO %q is not an ssh git URL (git@host:path or ssh://...)", EnvPrefix, c.GitHubRepo)
		}
		if v := get("GITHUB_KEY"); v != "" {
			c.GitHubKey = v
		}
		if v := get("GITHUB_KNOWN_HOSTS"); v != "" {
			c.GitHubKnownHosts = v
		}
	}
	c.LogFormat, c.LogLevel = get("LOG_FORMAT"), get("LOG_LEVEL")
	paths := []string{c.AgeKey, c.StateDir}
	if c.GitHubAppID != "" {
		paths = append(paths, c.GitHubAppKey)
	} else if c.GitHubRepo != "" {
		paths = append(paths, c.GitHubKey, c.GitHubKnownHosts)
		// These two go into GIT_SSH_COMMAND, which git runs through a shell.
		for _, p := range paths[2:] {
			if strings.HasPrefix(p, "/") && !safePathRe.MatchString(p) {
				return c, configErrorf("path %q: only letters, digits, . _ - and / are allowed", p)
			}
		}
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			return c, configErrorf("path %q must be absolute", p)
		}
	}
	return c, nil
}

// SigstoreManager is the TUF-backed trusted root of this configuration: the cache and a small info file in the state
// directory.
func (c Config) SigstoreManager() *sigstorever.Manager {
	return sigstorever.NewManager(filepath.Join(c.StateDir, "sigstore-tuf"), c.SigstoreInfoPath())
}

// SigstoreInfoPath is the file in which the manager records which root it chose and when.
func (c Config) SigstoreInfoPath() string { return filepath.Join(c.StateDir, "sigstore-root.json") }

// CheckFiles verifies that the age key can be read and returns the identity.
func (c Config) CheckFiles() (*Identity, error) {
	id, err := LoadIdentity(c.AgeKey)
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	return id, nil
}

// CheckGitHubFiles verifies that the deploy key and the known_hosts file of the GitHub fallback can be read. It does
// nothing when the fallback is off.
func (c Config) CheckGitHubFiles() error {
	if c.GitHubRepo == "" {
		return nil
	}
	if c.GitHubAppID != "" {
		data, err := os.ReadFile(c.GitHubAppKey)
		if err != nil {
			return configErrorf("GitHub App key: %v", err)
		}
		if _, err := githubapp.ParseKey(data); err != nil {
			return configErrorf("GitHub App key %s: %v", c.GitHubAppKey, err)
		}
		return nil
	}
	for _, p := range []struct{ what, path string }{{"GitHub deploy key", c.GitHubKey}, {"GitHub known_hosts", c.GitHubKnownHosts}} {
		f, err := os.Open(p.path)
		if err != nil {
			return configErrorf("%s: %v", p.what, err)
		}
		st, err := f.Stat()
		f.Close()
		if err != nil {
			return configErrorf("%s: %v", p.what, err)
		}
		if !st.Mode().IsRegular() {
			return configErrorf("%s %s is not a regular file", p.what, p.path)
		}
	}
	return nil
}
