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

// ApplyTimeout bounds one ansible run.
const ApplyTimeout = time.Hour

// ApplyError is an ansible run that ended badly; Message is short and safe to report (no ansible output).
type ApplyError struct{ Message string }

func (e *ApplyError) Error() string { return e.Message }

// Apply runs ansible for host in <release>/infra. The output goes to the process's stderr (the journal under
// systemd); it is never copied into a report, because a task could print something sensitive.
func Apply(ctx context.Context, ansible, release, host, ageKey string, stdout, stderr io.Writer) error {
	dir := filepath.Join(release, "infra")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return &ApplyError{Message: "the release has no infra/ directory"}
	}
	ctx, cancel := context.WithTimeout(ctx, ApplyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, ansible, "-i", "inventory/hosts.yml", "--limit", host, "site.yml")
	cmd.Dir = dir
	cmd.Env = applyEnv(os.Environ(), ageKey)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) } // ansible and its children
	cmd.WaitDelay = 30 * time.Second
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		switch {
		case ctx.Err() != nil:
			return &ApplyError{Message: "ansible-playbook was stopped: " + ctx.Err().Error()}
		case errors.As(err, &ee):
			return &ApplyError{Message: fmt.Sprintf("ansible-playbook exited with status %d", ee.ExitCode())}
		default:
			return &ApplyError{Message: "cannot run ansible-playbook: " + err.Error()}
		}
	}
	return nil
}

// applyEnv is the environment of ansible: the agent's own, without its settings, plus the age key for SOPS.
func applyEnv(env []string, ageKey string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, EnvPrefix) || strings.HasPrefix(e, "SOPS_AGE_KEY_FILE=") {
			continue
		}
		out = append(out, e)
	}
	return append(out, "SOPS_AGE_KEY_FILE="+ageKey)
}
