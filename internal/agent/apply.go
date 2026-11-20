package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ApplyTimeout bounds one ansible run. It stays inside infra-pull's LOCK_MAX (1800 s, its unit's TimeoutStartSec): the
// agent holds infra-pull's lock for the length of a run, and infra-pull calls a lock held longer than LOCK_MAX stuck.
const ApplyTimeout = 25 * time.Minute

// killGrace is how long ansible gets to stop after SIGTERM before its whole process group is killed (a variable for
// tests).
var killGrace = 30 * time.Second

// RestartFileEnv names the file, in ansible's environment, that a configuration run creates to ask the agent for a
// restart (a new binary, settings or unit). A run that restarted the service itself would kill its own ansible halfway,
// so it only creates this file; the agent sees it after the cycle, once the result is saved and reported, and exits so
// that systemd starts it again (Restart=always).
const RestartFileEnv = EnvPrefix + "RESTART_FILE"

// RestartFile is the restart request file of a state directory.
func RestartFile(stateDir string) string { return filepath.Join(stateDir, "restart-requested") }

// ApplyError is an ansible run that ended badly; Message is short and safe to report (no ansible output).
type ApplyError struct{ Message string }

func (e *ApplyError) Error() string { return e.Message }

// Apply runs ansible for host in <release>/infra, in its own process group. The output goes to out (the journal under
// systemd); it is never copied into a report, because a task could print something sensitive. When ctx ends or
// ApplyTimeout passes, the group gets SIGTERM, and SIGKILL after killGrace: ansible's own children die with it.
// restartFile is passed to ansible as RestartFileEnv.
func Apply(ctx context.Context, ansible, release, host, ageKey, restartFile string, out io.Writer) error {
	dir := filepath.Join(release, "infra")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return &ApplyError{Message: "the release has no infra/ directory"}
	}
	ctx, cancel := context.WithTimeout(ctx, ApplyTimeout)
	defer cancel()
	cmd := exec.Command(ansible, "-i", "inventory/hosts.yml", "--limit", host, "site.yml")
	cmd.Dir = dir
	cmd.Env = applyEnv(os.Environ(), ageKey, restartFile)
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return &ApplyError{Message: "cannot run ansible-playbook: " + err.Error()}
	}
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	stopped := false
	select {
	case err = <-done:
	case <-ctx.Done():
		stopped = true
		killGroup(pgid, syscall.SIGTERM)
		select {
		case err = <-done:
		case <-time.After(killGrace):
		}
		killGroup(pgid, syscall.SIGKILL) // whatever is left of the group, ansible's children included
		if err == nil {
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
			}
		}
	}
	if stopped {
		return &ApplyError{Message: "ansible-playbook was stopped: " + ctx.Err().Error()}
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return &ApplyError{Message: fmt.Sprintf("ansible-playbook exited with status %d", ee.ExitCode())}
		}
		return &ApplyError{Message: "ansible-playbook: " + err.Error()}
	}
	return nil
}

// killGroup sends sig to the process group, unless the group no longer exists (then the id may belong to something
// new, and there is nothing to signal). It reports whether it sent the signal.
func killGroup(pgid int, sig syscall.Signal) bool {
	if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
		return false
	}
	return syscall.Kill(-pgid, sig) == nil
}

// applyEnv is the environment of ansible: the agent's own, without its settings, plus the age key for SOPS and the
// restart request file.
func applyEnv(env []string, ageKey, restartFile string) []string {
	out := make([]string, 0, len(env)+2)
	for _, e := range env {
		if strings.HasPrefix(e, EnvPrefix) || strings.HasPrefix(e, "SOPS_AGE_KEY_FILE=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "SOPS_AGE_KEY_FILE="+ageKey, RestartFileEnv+"="+restartFile)
}
