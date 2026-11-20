// Package agent is the engine of infra-agent: the configuration, one cycle (fetch, verify, extract, apply, report),
// the state kept between cycles and the lock that keeps two agents apart. The command line is in internal/agentapp.
package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/KazuhaHub/infra-hub/internal/jointoken"
)

// EnvPrefix is the prefix of every setting and of every flag's environment variable.
const EnvPrefix = "INFRA_AGENT_"

// Defaults of the optional settings.
const (
	DefaultEnvFile  = "/etc/infra-agent/agent.env"
	DefaultAgeKey   = "/etc/infra/age.key"
	DefaultSigners  = "/etc/infra-agent/allowed_signers"
	DefaultStateDir = "/var/lib/infra-agent"
	DefaultInterval = 5 * time.Minute
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

// Settings are the keys that agent.env (and the environment) may carry. Anything else with the prefix is an error.
var settingKeys = []string{"TOKEN", "HOST", "AGE_KEY", "SIGNERS", "MODE", "INTERVAL", "STATE_DIR", "LOG_FORMAT", "LOG_LEVEL"}

// ConfigError is a problem with the configuration: the caller exits with the usage code (2).
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

func configErrorf(format string, a ...any) error {
	return &ConfigError{Err: fmt.Errorf(format, a...)}
}

// Config is the validated configuration.
type Config struct {
	Token    jointoken.Token
	Host     string
	AgeKey   string
	Signers  string
	Mode     string
	Interval time.Duration
	StateDir string
	// Repo is the repository the bundle statement must name.
	Repo string

	// LogFormat and LogLevel are read from the file for the command line's logger; the engine ignores them.
	LogFormat, LogLevel string
}

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
	c := Config{AgeKey: DefaultAgeKey, Signers: DefaultSigners, Mode: ModeVerify, Interval: DefaultInterval, StateDir: DefaultStateDir, Repo: DefaultRepo}
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
		c.Signers = v
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
	c.LogFormat, c.LogLevel = get("LOG_FORMAT"), get("LOG_LEVEL")
	for _, p := range []string{c.AgeKey, c.Signers, c.StateDir} {
		if !strings.HasPrefix(p, "/") {
			return c, configErrorf("path %q must be absolute", p)
		}
	}
	return c, nil
}

// CheckFiles verifies that the age key and the allowed_signers file can be read, and returns the identity.
func (c Config) CheckFiles() (*Identity, error) {
	id, err := LoadIdentity(c.AgeKey)
	if err != nil {
		return nil, &ConfigError{Err: err}
	}
	st, err := os.Stat(c.Signers)
	if err != nil {
		return nil, configErrorf("allowed signers: %v", err)
	}
	if !st.Mode().IsRegular() || st.Size() == 0 {
		return nil, configErrorf("allowed signers %s is not a non-empty regular file", c.Signers)
	}
	return id, nil
}
