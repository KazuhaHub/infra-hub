// Package bundle is the config bundle contract (docs/bundle.md): the strict parser of the signed statement, the
// reader that takes the three files from the mirror's main-attestation branch, and the archive the hub encrypts to
// a host. The agent reuses ParseStatement and the member names.
package bundle

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Limits of the three files, as the contract fixes them.
const (
	MaxTarball   = 64 << 20
	MaxStatement = 4 << 10
	MaxSignature = 4 << 10
)

// Member names, in the order they appear in the archive.
const (
	StatementName = "bundle"
	SignatureName = "bundle.sig"
	TarballName   = "bundle.tar.gz"
)

// Statement is the content of the `bundle` file.
type Statement struct {
	Repo   string // owner/name
	Ref    string // refs/heads/main
	Commit string // 40 lower-case hex
	Time   int64  // unix seconds
	SHA256 string // of bundle.tar.gz, 64 lower-case hex
	Size   int64  // bytes of bundle.tar.gz
}

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	numberRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)
)

// maxTime is the largest mtime a ustar header holds (11 octal digits); the statement time becomes the members' mtime.
const maxTime = 8589934591

// String renders the statement in the exact form ParseStatement accepts.
func (s Statement) String() string {
	return fmt.Sprintf("infra-bundle v1\nrepo %s\nref %s\ncommit %s\ntime %d\nsha256 %s\nsize %d\n", s.Repo, s.Ref, s.Commit, s.Time, s.SHA256, s.Size)
}

// ParseStatement parses the statement strictly: ASCII only, LF line endings, exactly seven lines in the fixed order,
// one space between key and value, a final newline, and every value in its exact form. Anything else is an error.
func ParseStatement(data []byte) (Statement, error) {
	var s Statement
	if len(data) > MaxStatement {
		return s, errors.New("statement is too large")
	}
	for _, b := range data {
		if b == '\n' {
			continue
		}
		if b < 0x20 || b > 0x7e {
			return s, errors.New("statement has a byte outside printable ASCII or LF")
		}
	}
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		return s, errors.New("statement does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 7 {
		return s, fmt.Errorf("statement has %d lines, want 7", len(lines))
	}
	if lines[0] != "infra-bundle v1" {
		return s, errors.New(`statement does not start with "infra-bundle v1"`)
	}
	keys := []string{"repo", "ref", "commit", "time", "sha256", "size"}
	vals := make([]string, len(keys))
	for i, key := range keys {
		v, ok := strings.CutPrefix(lines[i+1], key+" ")
		if !ok || v == "" || strings.HasPrefix(v, " ") || strings.HasSuffix(v, " ") {
			return s, fmt.Errorf("statement line %d is not %q and a value", i+2, key)
		}
		vals[i] = v
	}
	s.Repo, s.Ref, s.Commit, s.SHA256 = vals[0], vals[1], vals[2], vals[4]
	if !repoRe.MatchString(s.Repo) {
		return s, errors.New("statement repo is not owner/name")
	}
	if s.Ref != "refs/heads/main" {
		return s, errors.New("statement ref is not refs/heads/main")
	}
	if !commitRe.MatchString(s.Commit) {
		return s, errors.New("statement commit is not 40 lower-case hex digits")
	}
	if !sha256Re.MatchString(s.SHA256) {
		return s, errors.New("statement sha256 is not 64 lower-case hex digits")
	}
	if !numberRe.MatchString(vals[3]) {
		return s, errors.New("statement time is not a decimal number")
	}
	if !numberRe.MatchString(vals[5]) {
		return s, errors.New("statement size is not a decimal number")
	}
	s.Time, _ = strconv.ParseInt(vals[3], 10, 64)
	s.Size, _ = strconv.ParseInt(vals[5], 10, 64)
	if s.Time < 1 || s.Time > maxTime {
		return s, errors.New("statement time is out of range (1 to 8589934591)")
	}
	return s, nil
}
