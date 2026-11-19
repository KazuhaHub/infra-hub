package sshserver

import (
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/KazuhaHub/infra-hub/internal/gitmirror"
	"github.com/KazuhaHub/infra-hub/internal/state"
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

type testHub struct {
	addr    string
	hostPub ssh.PublicKey
	repo    string
	state   *state.State
	clients map[string]ssh.Signer
	privs   map[string]ed25519.PrivateKey
	srv     *Server
	mirror  *gitmirror.Mirror
	skew    atomic.Int64 // added to the mirror's clock, to make it look older
	wrapLn  func(net.Listener) net.Listener
	done    chan struct{}
}

// startHub serves a mirror of a fresh upstream (repo is named infra.git) to two clients, host-a and host-b. The
// mirror has just fetched, so it is fresh. tweak (optional) may change the hub before it starts serving.
func startHub(t *testing.T, tweak ...func(*testHub)) *testHub {
	t.Helper()
	upstream, _ := testutil.MakeUpstream(t)
	repo := filepath.Join(t.TempDir(), "infra.git")
	h := &testHub{repo: repo, clients: map[string]ssh.Signer{}, privs: map[string]ed25519.PrivateKey{}}
	m := &gitmirror.Mirror{Repo: repo, Upstream: upstream, Now: func() time.Time { return time.Now().Add(time.Duration(h.skew.Load())) }}
	h.mirror = m
	if err := m.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ssh.PublicKey{}
	for _, n := range []string{"host-a", "host-b"} {
		s, _, priv := testutil.NewKeyPriv(t)
		h.clients[n] = s
		h.privs[n] = priv
		keys[n] = s.PublicKey()
	}
	hostSigner, err := LoadOrCreateHostKey(filepath.Join(t.TempDir(), "host_key"))
	if err != nil {
		t.Fatal(err)
	}
	h.hostPub = hostSigner.PublicKey()
	h.state, _ = state.LoadState(filepath.Join(t.TempDir(), "state.json"))
	h.srv = NewServer(NewSSHKeyIdentifier(keys), h.state, hostSigner, repo, func(ctx context.Context) (map[string]string, error) {
		return gitmirror.ReadRefs(ctx, repo)
	})
	h.srv.Fresh = func() error { return m.Fresh(10 * time.Minute) }
	for _, f := range tweak {
		f(h)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	if h.wrapLn != nil {
		ln = h.wrapLn(ln)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.done = make(chan struct{})
	go func() { h.srv.Serve(ctx, ln); close(h.done) }()
	t.Cleanup(func() { cancel(); <-h.done })
	return h
}

// blockingCommand replaces git with a command that runs until its stdin is closed (a fetch that stays busy).
func blockingCommand(h *testHub) {
	h.srv.newCmd = func(ctx context.Context, env []string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "cat > /dev/null")
	}
}

func (h *testHub) dial(signer ssh.Signer, user string) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.hostPub),
	})
}

// gitEnv writes host's private key and a pinned known_hosts file into dir and returns an environment in which git
// reaches the hub over ssh as that host, and the repo URL.
func (h *testHub) gitEnv(t *testing.T, dir, host string) ([]string, string) {
	t.Helper()
	ip, port, _ := strings.Cut(h.addr, ":")
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, []byte("["+ip+"]:"+port+" "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(h.hostPub)))+"\n"), 0o644)
	key := filepath.Join(dir, "id_"+host)
	testutil.WritePrivateKey(t, key, h.privs[host])
	env := append(gitmirror.GitEnv(), "GIT_SSH_COMMAND=ssh -F /dev/null -i "+key+" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+kh)
	return env, "ssh://infra@" + h.addr + "/infra.git"
}
