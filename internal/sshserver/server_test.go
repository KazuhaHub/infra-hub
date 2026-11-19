package sshserver

import (
	"context"
	"errors"
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
	"github.com/KazuhaHub/infra-hub/internal/testutil"
)

func TestOnlyListedKeysAndTheRightUserGetIn(t *testing.T) {
	h := startHub(t)
	stranger, _ := testutil.NewKey(t)
	if c, err := h.dial(stranger, "infra"); err == nil {
		c.Close()
		t.Fatal("unknown key accepted")
	}
	if c, err := h.dial(h.clients["host-a"], "root"); err == nil {
		c.Close()
		t.Fatal("wrong user accepted")
	}
	c, err := h.dial(h.clients["host-a"], "infra")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestEverythingExceptUploadPackIsRefused(t *testing.T) {
	h := startHub(t)
	c, err := h.dial(h.clients["host-a"], "infra")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	session := func() *ssh.Session {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	refused := func(what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s was accepted", what)
		}
	}
	for _, cmd := range []string{
		"git-receive-pack '/infra.git'", "git-receive-pack 'infra.git'",
		"git-upload-pack '/other.git'", "git-upload-pack '/../infra.git'", "git-upload-pack '/infra.git/../x'",
		"git-upload-pack '/infra.git' extra", "git-upload-pack '/infra.git'; id", "git-upload-archive '/infra.git'",
		"sh", "id", "", "git-upload-pack /etc",
	} {
		refused("exec "+cmd, session().Start(cmd))
	}
	refused("shell", session().Shell())
	refused("pty", session().RequestPty("xterm", 24, 80, ssh.TerminalModes{}))
	refused("subsystem", session().RequestSubsystem("sftp"))
	refused("env FOO", session().Setenv("FOO", "bar"))
	refused("env GIT_PROTOCOL with junk", session().Setenv("GIT_PROTOCOL", "version=2; id"))
	if err := session().Setenv("GIT_PROTOCOL", "version=2"); err != nil {
		t.Errorf("GIT_PROTOCOL=version=2 refused: %v", err)
	}
	ok, _ := session().SendRequest("auth-agent-req@openssh.com", true, nil)
	refused("agent forwarding", boolErr(ok))
	ok, _ = session().SendRequest("x11-req", true, nil)
	refused("x11", boolErr(ok))
	_, err = c.Dial("tcp", "127.0.0.1:22")
	refused("direct-tcpip", err)
	l, err := c.Listen("tcp", "127.0.0.1:0")
	if l != nil {
		l.Close()
	}
	refused("remote port forwarding", err)
}

func boolErr(ok bool) error {
	if ok {
		return nil
	}
	return os.ErrInvalid
}

// A real git client over ssh: clone works for both protocol versions, a push cannot happen, an unknown key cannot clone.
func TestEndToEndCloneAndPushAttempt(t *testing.T) {
	testutil.NeedTool(t, "git", "ssh")
	h := startHub(t)
	dir := t.TempDir()
	_, _, strangerPriv := testutil.NewKeyPriv(t)
	privStranger := filepath.Join(dir, "id_x")
	testutil.WritePrivateKey(t, privStranger, strangerPriv)
	envA, url := h.gitEnv(t, dir, "host-a")
	privA := ""
	env := func(key string) []string {
		if key == privA {
			return envA
		}
		return append(append([]string{}, envA...), "GIT_SSH_COMMAND=ssh -F /dev/null -i "+key+" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+filepath.Join(dir, "known_hosts"))
	}
	want := testutil.RunGit(t, h.repo, "rev-parse", "refs/heads/main")
	for _, v := range []string{"0", "2"} {
		dest := filepath.Join(dir, "clone"+v)
		cmd := exec.Command("git", "-c", "protocol.version="+v, "clone", "-q", "--branch", "main", url, dest)
		cmd.Env = append(env(privA), "GIT_TRACE_PACKET=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("clone (protocol %s): %v\n%s", v, err, out)
		}
		// GIT_PROTOCOL reached upload-pack: "version 2" appears only when v2 was really negotiated
		if got := strings.Contains(string(out), "version 2"); got != (v == "2") {
			t.Fatalf("protocol %s: trace mentions \"version 2\" = %v\n%s", v, got, out)
		}
		if got := testutil.RunGit(t, dest, "rev-parse", "HEAD"); got != want {
			t.Fatalf("cloned %s, want %s", got, want)
		}
	}
	if r := h.state.Snapshot()["host-a"]; r.Main != want || r.LastSeen.IsZero() {
		t.Fatalf("state for host-a = %+v", r)
	}
	// push attempt: fails, and the mirror has no new ref
	dest := filepath.Join(dir, "clone2")
	push := exec.Command("git", "push", url, "HEAD:refs/heads/evil")
	push.Dir, push.Env = dest, env(privA)
	if out, err := push.CombinedOutput(); err == nil {
		t.Fatalf("push succeeded: %s", out)
	}
	if refs, _ := gitmirror.ReadRefs(t.Context(), h.repo); len(refs) != 2 {
		t.Fatalf("refs after push attempt: %v", refs)
	}
	// unknown key
	bad := exec.Command("git", "clone", "-q", url, filepath.Join(dir, "bad"))
	bad.Env = env(privStranger)
	if out, err := bad.CombinedOutput(); err == nil {
		t.Fatalf("clone with an unknown key succeeded: %s", out)
	}
}

func execRaw(t *testing.T, s *ssh.Session, cmd string) bool {
	t.Helper()
	ok, err := s.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{cmd}))
	if err != nil {
		return false
	}
	return ok
}

const goodCmd = "git-upload-pack '/infra.git'"

func TestSecondExecOnTheSameSessionIsRefused(t *testing.T) {
	h := startHub(t, blockingCommand)
	c, err := h.dial(h.clients["host-a"], "infra")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, _ := c.NewSession()
	if !execRaw(t, s, goodCmd) {
		t.Fatal("first exec refused")
	}
	if execRaw(t, s, goodCmd) {
		t.Fatal("second exec on the same session accepted")
	}
}

func openExec(t *testing.T, c *ssh.Client) (*ssh.Session, bool) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	return s, execRaw(t, s, goodCmd)
}

func TestPerHostAndGlobalSlotLimits(t *testing.T) {
	h := startHub(t, blockingCommand, func(h *testHub) { h.srv.sem = make(chan struct{}, 3) })
	a, _ := h.dial(h.clients["host-a"], "infra")
	b, _ := h.dial(h.clients["host-b"], "infra")
	defer a.Close()
	defer b.Close()
	a1, ok := openExec(t, a)
	if !ok {
		t.Fatal("host-a first fetch refused")
	}
	if _, ok := openExec(t, a); !ok {
		t.Fatal("host-a second fetch refused")
	}
	if _, ok := openExec(t, a); ok {
		t.Fatal("host-a third concurrent fetch accepted: per-host limit is 2")
	}
	if _, ok := openExec(t, b); !ok {
		t.Fatal("host-b blocked by host-a's slots")
	}
	if _, ok := openExec(t, b); ok {
		t.Fatal("fourth fetch accepted: global limit is 3 in this test")
	}
	a1.Close() // frees a slot for everyone
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := openExec(t, b); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot was not released after the fetch ended")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStaleMirrorIsRefusedAndNothingIsRecorded(t *testing.T) {
	testutil.NeedTool(t, "git", "ssh")
	h := startHub(t)
	dir := t.TempDir()
	env, url := h.gitEnv(t, dir, "host-a")
	ls := func() (string, error) {
		cmd := exec.Command("git", "ls-remote", url)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := ls(); err != nil {
		t.Fatalf("fresh mirror refused: %v\n%s", err, out)
	}
	if h.state.Snapshot()["host-a"].LastSeen.IsZero() {
		t.Fatal("successful fetch not recorded")
	}
	h2 := startHub(t)
	env2, url2 := h2.gitEnv(t, t.TempDir(), "host-a")
	h2.skew.Store(int64(11 * time.Minute)) // the last fetch now looks 11 minutes old
	cmd := exec.Command("git", "ls-remote", url2)
	cmd.Env = env2
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "not serving") {
		t.Fatalf("stale mirror served (err=%v):\n%s", err, out)
	}
	if _, seen := h2.state.Snapshot()["host-a"]; seen {
		t.Fatal("a refused fetch was recorded as seen")
	}
}

func TestMirrorFreshness(t *testing.T) {
	upstream, _ := testutil.MakeUpstream(t)
	now := time.Now()
	m := &gitmirror.Mirror{Repo: filepath.Join(t.TempDir(), "infra.git"), Upstream: upstream, Now: func() time.Time { return now }}
	if err := m.Fresh(10 * time.Minute); err == nil {
		t.Fatal("never fetched: must refuse")
	}
	if err := m.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Fresh(10 * time.Minute); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	now = now.Add(9 * time.Minute)
	if err := m.Fresh(10 * time.Minute); err != nil {
		t.Fatalf("9 minutes: %v", err)
	}
	now = now.Add(2 * time.Minute)
	if err := m.Fresh(10 * time.Minute); err == nil {
		t.Fatal("11 minutes old: must refuse")
	}
	m.Upstream = filepath.Join(t.TempDir(), "gone") // a failing fetch does not make it fresh again
	if err := m.Fetch(context.Background()); err == nil {
		t.Fatal("fetch from nowhere succeeded")
	}
	if err := m.Fresh(10 * time.Minute); err == nil {
		t.Fatal("a failed fetch refreshed the mirror")
	}
}

func TestFailedUploadPackIsNotRecorded(t *testing.T) {
	h := startHub(t, func(h *testHub) {
		h.srv.newCmd = func(ctx context.Context, env []string) *exec.Cmd {
			return exec.CommandContext(ctx, "sh", "-c", "exit 3")
		}
	})
	c, _ := h.dial(h.clients["host-a"], "infra")
	defer c.Close()
	s, _ := c.NewSession()
	err := s.Run(goodCmd)
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 3 {
		t.Fatalf("err = %v, want exit status 3", err)
	}
	if _, seen := h.state.Snapshot()["host-a"]; seen {
		t.Fatal("a failed upload-pack was recorded")
	}
}

func TestHandshakeDeadlineAndUnauthenticatedLimit(t *testing.T) {
	h := startHub(t, func(h *testHub) {
		h.srv.HandshakeTimeout = 300 * time.Millisecond
		h.srv.MaxUnauth = 2
	})
	closed := func(c net.Conn, within time.Duration) bool {
		c.SetReadDeadline(time.Now().Add(within))
		buf := make([]byte, 256)
		for { // the server sends its version banner first; drain until the connection ends
			if _, err := c.Read(buf); err != nil {
				ne, isNet := err.(net.Error)
				return !(isNet && ne.Timeout()) // closed by the server, not just silent
			}
		}
	}
	// the third connection while two idle ones hold the slots is closed at once
	c1, _ := net.Dial("tcp", h.addr)
	c2, _ := net.Dial("tcp", h.addr)
	time.Sleep(100 * time.Millisecond)
	c3, _ := net.Dial("tcp", h.addr)
	if !closed(c3, 200*time.Millisecond) {
		t.Fatal("connection over the unauthenticated limit was kept open")
	}
	// the idle ones are cut off at the handshake deadline, which frees the slots
	if !closed(c1, 2*time.Second) || !closed(c2, 2*time.Second) {
		t.Fatal("idle connection survived the handshake deadline")
	}
	c, err := h.dial(h.clients["host-a"], "infra")
	if err != nil {
		t.Fatalf("slots not freed: %v", err)
	}
	c.Close()
}

type flakyListener struct {
	net.Listener
	fail atomic.Int32
}

func (l *flakyListener) Accept() (net.Conn, error) {
	if l.fail.Add(-1) >= 0 {
		return nil, errors.New("accept: too many open files (simulated)")
	}
	return l.Listener.Accept()
}

func TestTransientAcceptErrorsDoNotStopServe(t *testing.T) {
	h := startHub(t, func(h *testHub) {
		h.wrapLn = func(ln net.Listener) net.Listener {
			f := &flakyListener{Listener: ln}
			f.fail.Store(4)
			return f
		}
	})
	c, err := h.dial(h.clients["host-a"], "infra")
	if err != nil {
		t.Fatalf("dial after transient accept errors: %v", err)
	}
	c.Close()
	select {
	case <-h.done:
		t.Fatal("Serve returned because of a transient accept error")
	default:
	}
}
