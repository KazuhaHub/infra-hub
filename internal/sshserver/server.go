package sshserver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/certs"
	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/iplists"
	"github.com/KazuhaHub/infra-hub/internal/state"
)

// RefsFunc reads the refs of the mirror.
type RefsFunc func(ctx context.Context) (map[string]string, error)

// Server is the SSH server. It does exactly one thing: after the Identifier accepts the key, it runs
// `git upload-pack` on the mirror for `git-upload-pack '/infra.git'`. Everything else is refused: the channel
// types, session requests and global requests that are not listed below do not exist here.
type Server struct {
	Ident  Identifier
	State  *state.State
	Signer ssh.Signer
	Repo   string
	Refs   RefsFunc
	// Fresh (optional) returns an error when the mirror is too old to serve; the exec is then answered with a
	// message on stderr and exit status 1, and the client uses its next source.
	Fresh func() error
	// Certs (optional) serves `cert <name>` to the owner of the name. The stale-mirror check does not apply to it.
	Certs certs.CertSource
	// IPLists (optional) serves `iplist <name>` to the hosts the config allows for that list.
	IPLists iplists.IPListSource

	// Limits. NewServer sets the defaults; tests change them before Serve.
	MaxUnauth        int           // connections that have not finished authentication
	PerHostMax       int           // concurrent upload-packs per host identity
	HandshakeTimeout time.Duration // authentication must finish within this
	WaitDelay        time.Duration // after git exits (or is killed), how long to wait for its pipes

	sem     chan struct{} // limits concurrent upload-packs, all hosts together
	mu      sync.Mutex
	perHost map[string]int
	newCmd  func(ctx context.Context, env []string) *exec.Cmd // tests replace the command
}

func NewServer(id Identifier, st *state.State, signer ssh.Signer, repo string, refs RefsFunc) *Server {
	s := &Server{Ident: id, State: st, Signer: signer, Repo: repo, Refs: refs,
		MaxUnauth: 64, PerHostMax: 2, HandshakeTimeout: 20 * time.Second, WaitDelay: 10 * time.Second,
		sem: make(chan struct{}, 8), perHost: map[string]int{}}
	s.newCmd = func(ctx context.Context, env []string) *exec.Cmd {
		git, err := exec.LookPath("git")
		if err != nil {
			git = "git" // Start fails below with a clear error
		}
		cmd := exec.CommandContext(ctx, git, "upload-pack", "--strict", "--timeout=120", repo)
		cmd.Env = env
		return cmd
	}
	return s
}

// acquire takes a global slot and a slot for host, or reports that there is none.
func (s *Server) acquire(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perHost[host] >= s.PerHostMax {
		return false
	}
	select {
	case s.sem <- struct{}{}:
		s.perHost[host]++
		return true
	default:
		return false
	}
}

func (s *Server) release(host string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perHost[host]--
	<-s.sem
}

// uploadPackCommands are the exec requests that are served: what git sends for ssh://host/infra.git (absolute
// path) and for host:infra.git (relative path).
var uploadPackCommands = map[string]bool{
	"git-upload-pack '/infra.git'": true,
	"git-upload-pack 'infra.git'":  true,
	"git-upload-pack /infra.git":   true,
	"git-upload-pack infra.git":    true,
}

// certCommand matches `cert <name>`; the name is validated again against the allow list before anything is served.
var certCommand = regexp.MustCompile(`^cert ([a-z0-9.-]{1,253})$`)

// ipListCommand matches `iplist <name>`; the name is checked against the config before anything is served.
var ipListCommand = regexp.MustCompile(`^iplist ([a-z0-9_-]{1,64})$`)

var gitProtocolValue = regexp.MustCompile(`^version=[0-9]$`)

const hostIdentityKey = "host"

func (s *Server) config(ctx context.Context) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-infra-hub",
		MaxAuthTries:  4,
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			name, err := s.Ident.Identify(ctx, ConnInfo{User: meta.User(), RemoteAddr: meta.RemoteAddr(), Key: key})
			if err != nil {
				log.Printf("deny %s user=%q key=%s: %v", meta.RemoteAddr(), meta.User(), ssh.FingerprintSHA256(key), err)
				return nil, errors.New("not allowed")
			}
			return &ssh.Permissions{Extensions: map[string]string{hostIdentityKey: name}}, nil
		},
	}
	cfg.AddHostKey(s.Signer)
	return cfg
}

// Serve accepts connections until ctx ends. A transient accept error (out of file descriptors, a reset connection)
// is never a reason to stop: back off, capped at one second, and go on, like net/http.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	var wg sync.WaitGroup
	defer wg.Wait()
	cfg := s.config(ctx)
	unauth := make(chan struct{}, s.MaxUnauth) // connections that have not finished authentication
	var delay time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			log.Printf("accept: %v; retrying in %v", err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		delay = 0
		select {
		case unauth <- struct{}{}:
		default:
			nc.Close() // too many connections that have not authenticated: drop this one at once
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, cfg, nc, func() { <-unauth })
		}()
	}
}

// handleConn runs one connection. doneUnauth is called exactly once: when authentication has finished (either way).
func (s *Server) handleConn(ctx context.Context, cfg *ssh.ServerConfig, nc net.Conn, doneUnauth func()) {
	defer nc.Close()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	go func() { <-ctx.Done(); nc.Close() }()
	nc.SetDeadline(time.Now().Add(s.HandshakeTimeout)) // handshake and authentication
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	doneUnauth()
	if err != nil {
		return
	}
	nc.SetDeadline(time.Time{})
	defer conn.Close()
	host := conn.Permissions.Extensions[hostIdentityKey]
	log.Printf("accept %s host=%s", conn.RemoteAddr(), host)
	go ssh.DiscardRequests(reqs) // global requests (tcpip-forward, ...) are all refused
	for nch := range chans {
		if nch.ChannelType() != "session" { // no direct-tcpip, no x11, no forwarded channels
			nch.Reject(ssh.UnknownChannelType, "only session channels")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go s.session(ctx, host, ch, creqs)
	}
}

// session answers the requests of one session channel: env (GIT_PROTOCOL only) and one exec. Every other request
// type (pty-req, shell, subsystem, auth-agent-req@openssh.com, x11-req, signal, ...) is refused.
func (s *Server) session(ctx context.Context, host string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	var gitProtocol string
	started := false
	for req := range reqs {
		switch req.Type {
		case "env":
			var p struct{ Name, Value string }
			if ssh.Unmarshal(req.Payload, &p) == nil && p.Name == "GIT_PROTOCOL" && gitProtocolValue.MatchString(p.Value) {
				gitProtocol = p.Value
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		case "exec":
			var p struct{ Command string }
			if started || ssh.Unmarshal(req.Payload, &p) != nil {
				req.Reply(false, nil)
				return
			}
			var run func()
			if uploadPackCommands[p.Command] {
				run = func() { s.uploadPack(ctx, host, gitProtocol, ch) }
			} else if m := certCommand.FindStringSubmatch(p.Command); m != nil && s.Certs != nil {
				// Anything but the owner, including an unknown name, gets the same refusal: nothing says whether the name exists.
				if owner, ok := s.Certs.Owner(m[1]); !ok || owner != host {
					log.Printf("deny host=%s cert %q: not the owner or not a known name", host, m[1])
					req.Reply(false, nil)
					return
				}
				name := m[1]
				run = func() { s.serveCert(host, name, ch) }
			} else if m := ipListCommand.FindStringSubmatch(p.Command); m != nil && s.IPLists != nil {
				// Not allowed and unknown look the same: nothing says whether the list exists.
				if !s.IPLists.Allowed(m[1], host) {
					log.Printf("deny host=%s iplist %q: not allowed or not a known list", host, m[1])
					req.Reply(false, nil)
					return
				}
				name := m[1]
				run = func() { s.serveIPList(host, name, ch) }
			} else {
				if p.Command != "" {
					log.Printf("deny host=%s command %q", host, p.Command)
				}
				req.Reply(false, nil)
				return
			}
			if !s.acquire(host) {
				log.Printf("deny host=%s: too many concurrent fetches", host)
				req.Reply(false, nil)
				return
			}
			started = true
			req.Reply(true, nil)
			go func() {
				defer s.release(host)
				run()
			}()
		default:
			req.Reply(false, nil)
		}
	}
}

// serveCert writes the certificate as one JSON line on stdout. A missing certificate, or one with less than 7 days
// left, is refused with a message on stderr and exit status 1, so the client keeps what it has and alerts.
func (s *Server) serveCert(host, name string, ch ssh.Channel) {
	defer ch.Close()
	p, err := s.Certs.Fetch(name)
	if err != nil {
		log.Printf("refuse host=%s cert %s: %v", host, name, err)
		fmt.Fprintf(ch.Stderr(), "hub: not serving %s, %v\n", name, err)
		sendExit(ch, 1)
		return
	}
	line, err := json.Marshal(p)
	if err != nil {
		sendExit(ch, 1)
		return
	}
	if _, err := ch.Write(append(line, '\n')); err != nil {
		return
	}
	log.Printf("served host=%s cert %s not_after=%s", host, name, p.NotAfter)
	sendExit(ch, 0)
}

// uploadPack runs git upload-pack on the mirror with the channel as stdin/stdout/stderr and sends its exit status.
// A stale mirror is refused first. The host's last_seen and the refs it was shown are recorded only after a
// successful run (exit status 0), so a failed or refused fetch never looks like a fresh one.
func (s *Server) uploadPack(ctx context.Context, host, gitProtocol string, ch ssh.Channel) {
	defer ch.Close()
	if s.Fresh != nil {
		if err := s.Fresh(); err != nil {
			log.Printf("refuse host=%s: %v", host, err)
			fmt.Fprintf(ch.Stderr(), "hub: not serving, %v\n", err)
			sendExit(ch, 1)
			return
		}
	}
	refs, _ := s.Refs(ctx)
	env := gitmirror.GitEnv()
	if gitProtocol != "" {
		env = append(env, "GIT_PROTOCOL="+gitProtocol)
	}
	cmd := s.newCmd(ctx, env)
	cmd.WaitDelay = s.WaitDelay
	stdin, err := cmd.StdinPipe()
	if err != nil {
		sendExit(ch, 1)
		return
	}
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()
	if err := cmd.Start(); err != nil {
		io.WriteString(ch.Stderr(), "hub: cannot start git\n")
		sendExit(ch, 1)
		return
	}
	go func() { io.Copy(stdin, ch); stdin.Close() }()
	code := 0
	if err := cmd.Wait(); err != nil {
		code = 255
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() >= 0 {
			code = ee.ExitCode()
		}
	}
	if code == 0 {
		s.State.Touch(host, refs)
		log.Printf("served host=%s git-upload-pack main=%.12s", host, refs["refs/heads/main"])
	} else {
		log.Printf("failed host=%s git-upload-pack exit=%d", host, code)
	}
	sendExit(ch, code)
}

func sendExit(ch ssh.Channel, code int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(code))
	ch.SendRequest("exit-status", false, b[:])
}

// serveIPList writes the list as one JSON line on stdout; a list that cannot be built is refused with exit status 1
// and a message on stderr, so the client keeps what it has.
func (s *Server) serveIPList(host, name string, ch ssh.Channel) {
	defer ch.Close()
	p, err := s.IPLists.Serve(name)
	if err != nil {
		log.Printf("refuse host=%s iplist %s: %v", host, name, err)
		fmt.Fprintf(ch.Stderr(), "hub: not serving %s, %v\n", name, err)
		sendExit(ch, 1)
		return
	}
	line, err := json.Marshal(p)
	if err != nil {
		sendExit(ch, 1)
		return
	}
	if _, err := ch.Write(append(line, '\n')); err != nil {
		return
	}
	log.Printf("served host=%s iplist %s version=%.12s entries=%d warnings=%d", host, name, p.Version, len(p.CIDRs), len(p.Warnings))
	sendExit(ch, 0)
}
