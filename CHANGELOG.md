# Changelog

## Unreleased

### Added

- The hub identity key: one Ed25519 key shared by every hub, whose pin (`sha256//...`) is all an agent needs.
  `infra-hub key init --out <path>` generates it (refuses to overwrite) and prints the pin, `key pin --key <path>`
  prints it again, and `token --key <path> --hub <url>...` prints the one-line `ih1.` token for an agent install (public
  pins and hub URLs only, no secret). `-o json` is supported. See docs/hub-key.md.
- An HTTPS listener (`https.listen`, TLS 1.3 only) that serves a self-signed certificate built in memory at start from
  the key at `https.key` (SAN from `httpsAddresses`, valid until 9999-12-31): no certificate files, nothing to renew.
  `internal/hubtrust` accepts a hub if and only if its leaf's public-key hash matches a configured pin (several pins
  allow a rotation); chain, expiry and host name are ignored. `internal/jointoken` encodes and decodes the token.
- HTTPS endpoints: `GET /v1/healthz`, `POST /v1/challenge` (an age-encrypted single-use nonce for a registered host,
  rate limited) and `POST /v1/report` (the answer to the challenge plus a small, validated report). The latest report
  of each host is stored in the state and shown by `status -o json` as `hosts[].report`.
- A client in the config can be an object with `sshKey` and `agePublicKey`; the old string form still works.

### Changed

- Config keys are camelCase: `hostKey`, `mirrorIntervalSeconds`, `maxStaleSeconds`, `certDir`, `acmeDirectory`,
  `acmeEmail`, `cloudflareTokenFile`, `ipSources` (`maxBytes` in a source), `ipLists`, `ipListDir`. The snake_case
  spellings are accepted for one release with a warning naming the new key; setting both spellings of a key is an error.
- The command line is built with cobra: `infra-hub serve`, `status`, `iplist accept <provider>`,
  `iplist history <list> [--limit N]` and `version`, plus `--version`. Flags are `--long-name` and can come from
  `INFRA_HUB_<NAME>` environment variables. Exit codes are 0, 1, 2 (usage) and 3 (not ready).
- Logging uses `log/slog` on stderr: text by default, `--log-format json`, `--log-level`. Messages are short
  lower-case phrases with attributes. Registered secrets, private key blocks and URL credentials are redacted from
  every record.
- `status -o json` is a new document: `"apiVersion": "v1"`, lower camelCase keys, `...Seconds` units, RFC 3339 UTC
  times, hosts, certificates, providers and lists as arrays sorted by name, missing values omitted. `status` prints a
  short table by default. `iplist history` prints the same style of document.
- Releases embed the version, commit and build date: `infra-hub --version` prints
  `infra-hub 0.2.0 (commit abcdef0, built 2026-11-19)`.

### Deprecated

- The old spellings `-config`, `-no-refs`, `-limit`, `iplist-accept` and `iplist-history` still work for this release
  and print a warning on stderr. They will be removed in the next release.
- The previous snake_case `status` JSON is kept as the hidden `status --format legacy`. It stays the default only when
  the old `-config` spelling is used and neither `-o` nor `--format` is given, so a monitor that has not been updated
  keeps working. `iplist-history` keeps printing the previous JSON as well.
