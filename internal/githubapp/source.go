package githubapp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultGitBase is where repositories are fetched from.
const DefaultGitBase = "https://github.com"

var (
	scpRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+@github\.com:([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)
	sshRe   = regexp.MustCompile(`^ssh://[A-Za-z0-9._-]+@github\.com(?::22)?/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)
	httpsRe = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$`)
)

// ParseRepo reads owner and repository from a github.com URL in the ssh forms (git@github.com:o/r.git,
// ssh://git@github.com/o/r.git) or the https form. Anything else, including another host, is an error.
func ParseRepo(raw string) (owner, repo string, err error) {
	for _, re := range []*regexp.Regexp{scpRe, sshRe, httpsRe} {
		if m := re.FindStringSubmatch(raw); m != nil {
			if !validName(m[1]) || !validName(m[2]) {
				break
			}
			return m[1], m[2], nil
		}
	}
	return "", "", fmt.Errorf("%q is not a github.com repository URL (git@github.com:owner/repo.git or https://github.com/owner/repo.git)", raw)
}

// ParseAppID checks an App id: digits only.
func ParseAppID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseUint(s, 10, 63); err != nil || n == 0 {
		return "", fmt.Errorf("GitHub App id %q is not a positive number", s)
	}
	return s, nil
}

// Source gives git what it needs to fetch one repository with a GitHub App: the https URL, the transport limits
// and, per call, the environment that carries a current read-only installation token. The key file is read when
// the first token is needed (and again after it changes), never at construction.
type Source struct {
	AppID   string
	KeyFile string
	owner   string // from the upstream URL only
	repo    string

	// API and GitBase are for tests only (no setting reaches them): empty means github.com. Overriding either
	// requires both to be plain http on a loopback address, so the token and the app JWT can only go to
	// api.github.com and github.com or to a local fake.
	API     string
	GitBase string
	HTTP    *http.Client
	Now     func() time.Time

	mu      sync.Mutex
	app     *App
	keyStat string
	recent  []string // the current and the previous token, for Redact
}

// NewSource checks its arguments and makes no request and opens no file.
func NewSource(appID, keyFile, repoURL string) (*Source, error) {
	id, err := ParseAppID(appID)
	if err != nil {
		return nil, err
	}
	if keyFile == "" {
		return nil, errors.New("GitHub App key file is not set")
	}
	owner, repo, err := ParseRepo(repoURL)
	if err != nil {
		return nil, err
	}
	return &Source{AppID: id, KeyFile: keyFile, owner: owner, repo: repo}, nil
}

func (s *Source) base() string {
	if s.GitBase != "" {
		return strings.TrimRight(s.GitBase, "/")
	}
	return DefaultGitBase
}

// Repository is owner/repo as the upstream URL named it.
func (s *Source) Repository() string { return s.owner + "/" + s.repo }

// RemoteURL is the clone URL; it never holds a credential.
func (s *Source) RemoteURL() string {
	return s.base() + "/" + s.owner + "/" + s.repo + ".git"
}

// GitArgs are the -c options that restrict git to the one transport the URL needs and stop it following redirects.
func (s *Source) GitArgs() []string {
	args := []string{"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "http.followRedirects=false", "-c", "credential.helper="}
	if strings.HasPrefix(s.base(), "http://") {
		args = append(args, "-c", "protocol.http.allow=always")
	}
	return args
}

// checkHosts refuses any pairing but github.com with api.github.com, or two loopback fakes.
func (s *Source) checkHosts() error {
	if (s.API == "" || s.API == DefaultAPI) && (s.GitBase == "" || s.GitBase == DefaultGitBase) {
		return nil
	}
	for what, raw := range map[string]string{"API": s.API, "git base": s.GitBase} {
		u, err := url.Parse(raw)
		if raw == "" || err != nil || u.Scheme != "http" || checkBase(raw) != nil {
			return fmt.Errorf("github app: %s override %q: only a loopback http address may replace github.com, and both must be replaced together", what, raw)
		}
	}
	return nil
}

// app returns the App, rebuilt when the key file changed.
func (s *Source) loadApp() (*App, error) {
	if err := s.checkHosts(); err != nil {
		return nil, err
	}
	st, err := os.Stat(s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("GitHub App key: %w", err)
	}
	stamp := fmt.Sprintf("%d/%d", st.Size(), st.ModTime().UnixNano())
	if s.app != nil && s.keyStat == stamp {
		return s.app, nil
	}
	data, err := os.ReadFile(s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("GitHub App key: %w", err)
	}
	key, err := ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("GitHub App key %s: %w", s.KeyFile, err)
	}
	app, err := New(Options{AppID: s.AppID, Key: key, API: s.API, HTTP: s.HTTP, Now: s.Now})
	if err != nil {
		return nil, err
	}
	s.app, s.keyStat = app, stamp
	return app, nil
}

// GitEnv returns environment entries (GIT_CONFIG_COUNT/KEY/VALUE) that make git send the token as Basic
// authentication to this repository's host only. The token is in the environment of the one git process, not in
// its arguments, the URL or any config file.
func (s *Source) GitEnv(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	app, err := s.loadApp()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	tok, err := app.Token(ctx, s.owner, s.repo)
	if err != nil {
		return nil, s.redactErr(err)
	}
	s.mu.Lock()
	if len(s.recent) == 0 || s.recent[len(s.recent)-1] != tok {
		s.recent = append(s.recent, tok)
		if len(s.recent) > 2 {
			s.recent = s.recent[len(s.recent)-2:]
		}
	}
	s.mu.Unlock()
	return []string{
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=http." + s.base() + "/.extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic " + basic(tok),
		"GIT_CONFIG_KEY_1=http.followRedirects",
		"GIT_CONFIG_VALUE_1=false",
	}, nil
}

func basic(tok string) string {
	return base64.StdEncoding.EncodeToString([]byte("x-access-token:" + tok))
}

// Redact removes every token this source handed out from s, for output that may be logged.
func (s *Source) Redact(out string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tok := range s.recent {
		out = strings.ReplaceAll(strings.ReplaceAll(out, tok, "***"), basic(tok), "***")
	}
	return out
}

func (s *Source) redactErr(err error) error {
	if msg := s.Redact(err.Error()); msg != err.Error() {
		return errors.New(msg)
	}
	return err
}
