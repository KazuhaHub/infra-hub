# Changelog

## v0.10.0

The SSH server is removed. The hub is its HTTPS server: bundle, certificates, IP lists, challenge and report.

### Removed

- The SSH server (`internal/sshserver`): git upload-pack serving of the mirror, the `cert` and `iplist` commands over SSH,
  the SSH host key (generated and kept at `hostKey` until now) and the SSH client identity by public key. The git
  mirror and its fetch from upstream stay: `GET /v1/bundle/<host>` is built from it.
- `status`: the per-host `lastSeen`, `main` and `mainAttestation` (they were only fed by SSH fetches) and the per-list
  `hosts`. `apiVersion` stays `v1`: consumers that ignore missing fields keep working. The time the hub last heard from a
  host is the report's `receivedAt` (`hosts[].report`); the table shows the report and its time. The legacy snake_case
  document (`--format legacy`) keeps its shape: a host's `last_seen` is now its latest report's `receivedAt` (zero if it
  never reported), and its per-host `main` and `main_attestation` and the lists' `hosts` are gone.
- The `hosts` records of the state file (last-seen times of SSH fetches) are no longer read or written; an old state file
  still loads.
- The `golang.org/x/crypto` direct dependency (it remains only as a dependency of age and lego).

### Changed

- Config compatibility: a release must accept the previous release's config, because hubs follow the latest release. The
  keys of the removed server are still accepted and ignored, with one warning at startup that names them: `listen`,
  `hostKey` (and `host_key`), `clients.*.sshKey` (also a client written as an SSH key string) and `ipLists.*.hosts`.
  They are never an error, and they can be deleted at leisure. Everything else is validated as before; a client may now
  be `{}`.
- A config without `https.listen` is refused: there is no other listener. An unusable hub identity key (or an HTTPS
  server that stops) makes `serve` exit with an error instead of idling; the check now happens before the mirror
  starts.
- IP lists are public data on HTTPS and no longer have an allow list; the list's hosts are not checked against the
  clients.

## v0.9.0

### Added

- `GET /v1/iplist/<name>` (and `HEAD`) on the HTTPS listener: the same JSON object `iplist <name>` sends over SSH (`name`,
  `version`, `generated`, `cidrs`, `warnings`), as one line. The lists are public data: no host in the path, no
  encryption, no allow list, and `ipLists.*.hosts` is ignored here. `ETag` is a hash of the list's `version` and its sorted
  `warnings`, so `If-None-Match` answers `304` until an entry or a warning changes (`generated` alone does not). Errors: `404 not_found` (unknown list or a name that is not `[a-z0-9_-]{1,64}`), `503 not_serving`
  (the list cannot be built: a provider never delivered or its state is unreadable), `429 rate_limited` (per peer
  address, 60 a minute, burst 20), `405` for other methods.
- `GET /v1/cert/<host>/<name>`: the JSON line `cert <name>` sends over SSH (`name`, `fullchain`, `privkey`, `not_after`),
  age-encrypted (binary) to the host's `agePublicKey`, `Cache-Control: no-store`. Served only when the config says the
  host owns the name and the host has an age key; every other case (unknown host, unknown name, not the owner, no age
  key) is the same `404 not_found`. `503 not_serving` with a generic message when the certificate is missing or has
  less than 7 days left (the reason is in the hub log). `429` per peer address, 30 a minute, burst 10. The hub logs
  `cert served` and `iplist served`.
- `GET /v1/healthz` also reports the hub's `version`.
- `infra-agent cert <name> [--hub URL] [--out-dir DIR]`: fetches the certificate from the hubs of the token over the
  pinned connection, decrypts it with the host's age key and checks it. Without `--out-dir` it prints the first
  decrypted answer; with it, `<i>.json` or `<i>.err` per hub is written safely into the directory (0600, owned by the
  directory's owner, nothing followed through a symlink). See docs/agent.md.

### Changed

- A config with neither `listen` (SSH) nor `https.listen` is refused. Without SSH, a hub whose HTTPS server cannot start
  (unusable identity key) or stops exits with an error instead of idling.
- The SSH server is optional. Without `listen` in the config no SSH listener starts, and `hostKey` and the clients'
  `sshKey` are not needed (a client may have only an `agePublicKey`; `clients` may even be empty). Certificates and IP
  lists are managed either way. A config with `listen` loads exactly as before (it still needs `hostKey` and at least
  one client). With SSH on, `ipLists.*.hosts` keeps its meaning for the SSH path; a list without `hosts` is served to no
  host over SSH.
## v0.8.0

### Added

- infra-agent: GitHub fallback for hub hosts. With `INFRA_AGENT_GITHUB_REPO` (and optionally `INFRA_AGENT_GITHUB_KEY`,
  default `/etc/infra/deploy_key`, and `INFRA_AGENT_GITHUB_KNOWN_HOSTS`, default `/etc/infra/github_known_hosts`) the
  agent fetches `main-attestation` from GitHub when no hub gave a usable bundle, and runs the same signature, statement,
  forward-only and extraction checks as for a hub's bundle. Hubs that answer "nothing new" do not trigger it. The result
  names GitHub as the source and a warning is logged each time. `check-config` shows the settings and checks the files.
  Existing agent.env files stay valid. See docs/agent.md, "GitHub fallback (hub hosts)".

## v0.7.0

### Added

- infra-agent: restart request. ansible runs with `INFRA_AGENT_RESTART_FILE=<state dir>/restart-requested`; a playbook
  that changes the agent (binary, settings, unit) creates that file instead of restarting the service from inside its
  own run. After the cycle (result saved and reported) the agent removes the file and exits 0 so that systemd starts it
  again; the unit must keep `Restart=always`. A stale request is removed at startup; one that cannot be removed is
  ignored. Needed before a host runs the agent in apply mode. See docs/agent.md, "Restarting from a configuration run".

## v0.6.0

### Added

- `infra-agent` v1 (`cmd/infra-agent`): fetches the host's bundle from the hubs over pinned TLS 1.3, decrypts it with the
  host's age key, verifies it (`ssh-keygen -Y verify`, namespace `infra-bundle`, statement checks, forward-only by
  statement time), extracts it safely into `<state>/releases/<commit>`, applies it with ansible (apply mode) and
  reports. Commands `run [--once]`, `status [-o json]`, `check-config` and `version`; configuration in
  `/etc/infra/agent.env`; a lock keeps two agents apart. Released with infra-hub from the same tag
  (`infra-agent-linux-amd64`, `infra-agent-linux-arm64`). See docs/agent.md and the example unit docs/infra-agent.service.

### Changed

- `POST /v1/report` accepts the results `verified`, `rejected`, `unreachable` and `unchanged` besides `ok` and `failed`, and
  `appliedCommit` may be empty (nothing applied yet). A report with another result is still refused with `400 bad_report`,
  and a non-empty `appliedCommit` must still be a full lower-case commit id. A report may carry `rejectedHubs`, at most 8
  hub URLs (the hubs that served the agent a bundle it rejected); `infra-hub status` shows them in the table and in JSON. `status -o json` leaves `appliedCommit` out
  when it is empty.

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
