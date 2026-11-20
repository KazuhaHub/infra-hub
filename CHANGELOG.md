# Changelog

## v0.5.0

### Added

- `GET /v1/bundle/<host>` on the HTTPS listener: the config bundle, read from the tip of `main-attestation` in the mirror
  (`bundle`, `bundle.sig`, `bundle.tar.gz`) and returned age-encrypted (binary) to the host's `agePublicKey` as an
  uncompressed ustar with those three members in that order. `ETag` is the commit, `If-None-Match` gives `304`,
  responses are `Cache-Control: no-store`, requests are rate limited per address, only GET and HEAD are allowed. Errors:
  `404 unknown_host`, `503 no_bundle` (a file missing or over its limit, or a malformed statement), `503 stale_mirror`.
  The hub parses the statement strictly but does not verify the signature or the hash; the agent does. The format is in
  docs/bundle.md.
- `internal/bundle`: `ParseStatement` (strict), the reader of the three files with size caps, and the archive writer.
- The hub builds the archive once per tip and shares it between hosts, answers `If-None-Match` for the current tip from the cached
  statement (no tarball read), and refuses a statement time outside 1..8589934591 with `no_bundle`. `status` reads only the
  statement file.
- `infra-hub status` shows the bundle the hub serves (`bundle` in `-o json`): its commit and time, or why none is served.

## v0.4.1

### Fixed

- The hub identity key is accepted as a systemd credential: systemd 256+ hands credentials over as root:root 0440 with an ACL
  for the service user, which v0.4.0 refused as group-readable (HTTPS stayed off). Group read access is now allowed for the
  root group only; others, other groups and group write are still refused.

## v0.4.0

### Added

- The hub identity key: one ECDSA P-256 key shared by every hub, whose pin (`sha256//...`) is all an agent needs.
  `infra-hub key init --out <path>` generates it (refuses to overwrite) and prints the pin, and `key pin --key <path>`
  prints it again. `infra-hub token --pin <pin>... [--key <path>] --hub <url>...` prints the one-line `ih1.` token for an
  agent install (public pins and hub URLs only, no secret; several pins during a rotation). `-o json` is supported.
  See docs/hub-key.md.
- `https.key`: the path of the hub identity key. With `https.listen` set the hub serves a self-signed certificate built
  in memory at start from this key (SAN from `httpsAddresses`, valid until 9999-12-31, TLS 1.3 only): no certificate
  files, nothing to renew.
- `internal/hubtrust` accepts a hub if and only if its leaf's public-key hash matches one of the configured pins
  (chain, expiry and host name are ignored); `internal/jointoken` encodes and strictly decodes the token.

### Changed

- The agent-side trust is now a list of key pins instead of a CA pin. A hub whose identity key cannot be read logs an
  error, serves no HTTPS and keeps serving SSH.
- `https.cert` and `https.caCert` are ignored for one release, with a warning that names `https.key`; delete them from
  the config. A v0.3.0 `https` block (`listen`, `cert`, `caCert`, no `key`) still loads: the hub warns that the old
  fields are ignored and that HTTPS is off until `https.key` is set, and keeps serving SSH.

### Removed

- `infra-hub ca init`, `ca sign`, `ca pin` and `ca revoke`, `infra-hub https csr`, `internal/hubca` and docs/ca.md. The
  hub CA and its certificate chain are gone.
- Leftover files from the CA model: `hub-https.key` and `hub.csr` in the hub's state directory (the directory of the
  state file, by default next to `infra.git`). The hub no longer reads or writes them; delete them.

## v0.3.0

### Added

- Hub CA tooling for the owner's workstation: `infra-hub ca init --out <dir>` (ECDSA P-256 key, 20-year CA
  certificate, optional `--permit-ip` / `--permit-dns` name constraints, prints the `sha256//...` pin),
  `ca sign` (signs a hub's request; only IP and DNS names) and `ca pin`. The revocation list file format is defined
  and parsed (`internal/hubca`); nothing enforces it yet. See docs/ca.md.
- The hub's HTTPS identity: its own ECDSA P-256 key in the state directory, a certificate request (`hub.csr`,
  `infra-hub https csr`) with the names of `httpsAddresses`, and an HTTPS listener (`https.listen`, TLS 1.3 only) that
  starts only with a certificate that matches the key, covers the configured names and chains to `https.caCert`.
- HTTPS endpoints: `GET /v1/healthz`, `POST /v1/challenge` (an age-encrypted single-use nonce for a registered host,
  rate limited) and `POST /v1/report` (the answer to the challenge plus a small, validated report). The latest report
  of each host is stored in the state and shown by `status -o json` as `hosts[].report`.
- A client in the config can be an object with `sshKey` and `agePublicKey`; the old string form still works.

### Changed

- Config keys are camelCase: `hostKey`, `mirrorIntervalSeconds`, `maxStaleSeconds`, `certDir`, `acmeDirectory`,
  `acmeEmail`, `cloudflareTokenFile`, `ipSources` (`maxBytes` in a source), `ipLists`, `ipListDir`. The snake_case
  spellings are accepted for one release with a warning naming the new key; setting both spellings of a key is an error.
- The hub presents its certificate and the CA certificate; `internal/hubtrust` verifies such a chain against a CA pin
  (for the agent).
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
