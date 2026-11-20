# Conventions

`infra-hub`, `infra-agent` and Rackbook (KazuhaHub/rackbook) follow the same conventions so that they read as one
family. Where Rackbook already decided something, this follows Rackbook.

## Logging

- Go's `log/slog`, written to **stderr**. Under systemd stderr goes to the journal; nothing writes its own log files.
- Default handler: `slog.NewTextHandler` (`key=value`), as in Rackbook. `--log-format json` switches to
  `slog.NewJSONHandler` for machines.
- Levels: `debug` (off by default, `--log-level debug`), `info` (normal events), `warn` (something degraded but handled:
  a fallback, a retry, a held change), `error` (an operation failed and needs attention). `error` is never used for an
  expected condition such as "nothing changed".
- The message is a short lower-case phrase without a trailing period; details go into attributes:
  `slog.Info("bundle applied", "version", v, "took", d)`.
- Attribute names are the same everywhere (lower camelCase, like the JSON below): `host`, `feature`, `version`,
  `from`, `to`, `list`, `provider`, `cert`, `path`, `took`, `err`, `commit`, `hub`, `mode`, `result`, `statementTime`, `newest`, `message`.
- Never log a secret, a private key, a token, a nonce, or a file's content that may hold one. Values that could be
  secret are logged as `[redacted]`.

## Command line

- `github.com/spf13/cobra`, as Rackbook's main command. One binary per program, subcommands for actions:
  `infra-hub serve`, `infra-hub status`, `infra-hub iplist accept`, `infra-agent run`, `infra-agent status`,
  `infra-agent check-config`.
- Flags are `--long-name` (single-letter short forms only for `-h`, `-v`, `-o`). Every flag can also come from the
  environment as `INFRA_HUB_<NAME>` / `INFRA_AGENT_<NAME>`; the environment file is the normal way to configure a
  service.
- Every command that shows state accepts `-o json` (`--output json`) and prints stable, documented JSON; the default
  is a short human table.
- `--version` prints `infra-hub 0.2.0 (commit abcdef0, built 2026-11-19)`.
- Exit codes: `0` success; `1` the operation failed; `2` usage error (bad flag or argument); `3` "not ready / try
  again" (e.g. the hub is unreachable and nothing changed locally). No other codes.
- Errors go to stderr as one line, `infra-agent: <what failed>: <why>`, and the process exits with the code above.

## JSON (status, API, reports)

- Field names are **lower camelCase**, as in Rackbook's API (`historyKept`, `tokenStatus`): `lastSeen`,
  `mirrorAge`, `notAfter`.
- Times are RFC 3339 in UTC (`2026-11-19T08:20:33Z`); durations are integer seconds with the unit in the name
  (`mirrorAgeSeconds`).
- Missing values are omitted (`omitempty`), not `null`, unless the absence itself carries meaning.
- Every top-level object carries `"apiVersion": "v1"` so readers can refuse what they do not understand.
- Lists are arrays sorted by a stable key (name), never maps keyed by user data, so diffs stay readable.

## HTTP API (hub)

- Paths are `/v1/<noun>` (`/v1/bundle`, `/v1/challenge`, `/v1/report`, `/v1/certs/<name>`, `/v1/iplists/<name>`).
- Errors are JSON `{"apiVersion":"v1","error":{"code":"not_found","message":"..."}}` with a matching HTTP status;
  `code` is a stable snake_case token, `message` is for people.
- Conditional GET with `ETag` / `If-None-Match`; unchanged resources answer `304`.

## Files on a machine

- Configuration in `/etc/infra/` (root, 0700 directory, 0600 files with secrets).
- State in `/var/lib/infra-agent/` (root, 0700), written atomically (temporary file + rename).
- Binaries in `/usr/local/bin/` (root, 0755), with versions under `/usr/local/lib/infra-agent/<version>/`.

## Changes

- Commit messages: imperative, plain English, no prefixes beyond an optional `area: ` (`hub: refuse stale mirrors`).
- Every behaviour change comes with a test; security-relevant code with a test that the bad case is refused.
- No AI or tool attribution in commits, code, docs or release notes.
