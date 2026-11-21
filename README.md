# infra-hub

A small hub and agent for managing a fleet of machines without SSH: signed configuration bundles, age-encrypted
secrets and certificates, and a plain IP-plus-HTTPS network.

One repository holds both programs and they are released together under one version:

| Program | What it is | Status |
| --- | --- | --- |
| `cmd/infra-hub` | The server. Mirrors the configuration repository, issues certificates, collects IP lists, receives reports. | Works. Serves its agents over HTTPS only: bundle, certificates, IP lists, challenge and report. The SSH server was removed in v0.10.0. |
| `cmd/infra-agent` | The per-machine agent. Fetches the signed config bundle, verifies it, applies it with ansible, reports back. | v1 works ([docs/agent.md](docs/agent.md)), with the install script (`GET /install`) and the kick; no self-update yet. Run it in verify mode beside infra-pull first. |

The design (no SSH, age keys, challenge-response, signed bundles) is written down in
[docs/design.md](docs/design.md). Logging, CLI and JSON conventions shared with Rackbook are in [docs/conventions.md](docs/conventions.md). The hub side (phase 1, 3a) and the agent's bundle path (phase 2) are done.

This is the code only. Your data (inventory, templates, roles, secrets) stays in your own private repository.

## The agent

`infra-agent` runs as root under systemd on each managed host. It fetches the host's config bundle from the hubs over
HTTPS (trusting only the pinned hub key), decrypts it with the host's age key, verifies the CI's Sigstore keyless signature, extracts it safely, applies it with `ansible-playbook` and reports the result. It opens no port.

```
infra-agent run [--once]          run the cycle every INFRA_AGENT_INTERVAL (default 5m), or once
infra-agent status [-o json]      what is applied and verified, and the last result
infra-agent check-config          validate agent.env and the token, ask each hub for /v1/healthz
infra-agent cert <name> [--hub URL] [--out-dir DIR]   fetch a certificate from the hubs, decrypted with the age key
infra-agent version
```

Configuration is one env file (`/etc/infra/agent.env`): `INFRA_AGENT_TOKEN` and `INFRA_AGENT_HOST` are required;
`INFRA_AGENT_MODE` is `verify` (default: never runs ansible) or `apply`. Everything is in [docs/agent.md](docs/agent.md),
with an example systemd unit in [docs/infra-agent.service](docs/infra-agent.service).

## What the hub does today

- **Git mirror.** Keeps a bare, read-only mirror of `main` and `main-attestation` of your configuration repository,
  fetched from its upstream, and serves the signed config bundle built from it to each host over HTTPS
  (`GET /v1/bundle/<host>`). The mirror itself is not served: there is no git protocol and no SSH server.
- **Certificates.** Obtains and renews certificates through ACME (DNS-01 with Cloudflare, via
  [lego](https://github.com/go-acme/lego)) for the names in its config, and serves each one to the single host that owns
  it.
- **IP lists.** Downloads published IP ranges (Cloudflare, Fastly, AWS CloudFront, GitHub, Google, ...), validates them,
  holds suspicious changes until a person accepts them, and serves the named lists (public data) over HTTPS.

Commands:

```
infra-hub serve                                   run the hub
infra-hub check-config                            validate the config and the existing state file, start nothing
infra-hub status [-o json] [--no-refs]            mirror, hosts, certificates, IP lists
infra-hub iplist accept <provider>                apply a held IP list update
infra-hub iplist history <list> [--limit N]       change history of a list (JSON)
infra-hub key init --out <path>                   generate the hub identity key (once); prints its pin
infra-hub key pin --key <path>                    print the sha256// pin of a key
infra-hub token (--pin <pin>... | --key <path>) --hub <url> [--hub <url>...]
                                                  print the one-line token for an agent install (no secret in it)
infra-hub version                                 also: infra-hub --version
```

`check-config` loads the config exactly as `serve` does (old keys accepted, removed keys warned about on stderr, all
validation) and reads the state file if it exists (it never writes it). It does not open the identity key, the Cloudflare
token or any certificate, and uses no network, so it works outside the service. It prints `config ok: https <listen>, N
clients, M certs, K ip lists` and exits `0`, or prints the error on stderr and exits `1`. Run it with a newly installed
binary before switching to it.

Every flag can also come from the environment as `INFRA_HUB_<NAME>` (`--config` is `INFRA_HUB_CONFIG`, `--log-level`
is `INFRA_HUB_LOG_LEVEL`); the config file defaults to `/etc/infra-hub/config.json`. Logs go to stderr through
`log/slog`, as `key=value` text by default or JSON with `--log-format json`; `--log-level` is `debug`, `info` (default),
`warn` or `error`. Exit codes: `0` success, `1` the operation failed, `2` usage error, `3` not ready (`status`: the
mirror has not fetched yet).

`status` also shows the config bundle the hub serves (commit and time, or why none).

`status -o json` prints the document described in [docs/conventions.md](docs/conventions.md): `"apiVersion": "v1"`,
lower camelCase keys, RFC 3339 UTC times, durations as `...Seconds`, hosts, certificates, providers and lists as arrays
sorted by name.

- **HTTPS for agents.** `https.listen` is required (it is the hub's only listener). The hub serves `GET /v1/healthz`, `POST /v1/challenge`,
  `POST /v1/report`, `GET /v1/wait/<host>` (long poll: answers when the bundle changed), `GET /install` (the agent install script), `GET /v1/bundle/<host>` (the age-encrypted config bundle, format in
  [docs/bundle.md](docs/bundle.md)), `GET /v1/cert/<host>/<name>` (the owner's certificate and key, age-encrypted to the
  host) and `GET /v1/iplist/<name>` (public JSON, `ETag`/`304`; `HEAD` works) over TLS 1.3, using a self-signed certificate built from the hub identity key, which agents pin
  (see [docs/hub-key.md](docs/hub-key.md)). A host proves it holds its age key by decrypting a single-use nonce; its
  latest report shows up in `status -o json` under `hosts[].report`, whose `receivedAt` is the time the hub last heard
  from the host. If the identity key cannot be used the hub exits with an error rather than idle.

The config is one JSON file; see `internal/config/config.go` for every field. The HTTPS part (all values are
examples):

```json
{
  "clients": {
    "web1": {"agePublicKey": "age1qqq...example"}
  },
  "httpsAddresses": ["192.0.2.10", "hub.example.org"],
  "https": {
    "listen": "192.0.2.10:8443",
    "key": "/etc/infra-hub/hub.key"
  }
}
```

A client is an object with an optional `agePublicKey` (a host without one gets no challenge). Only age X25519 keys (`age1...`) are supported. `https.key` is
the hub identity key (ECDSA P-256, PKCS#8 PEM, mode 0600), the same file on every hub. At start the hub builds a
self-signed certificate from it in memory (names from `httpsAddresses`, valid until 9999-12-31); there are no
certificate files and nothing to renew. An agent trusts a hub if and only if the key matches its pin
(`internal/hubtrust`). The earlier `https.cert` and `https.caCert` are gone; for one release they are ignored with a
warning that names `https.key`.

### Config of the removed SSH server

Hubs follow the latest release, so a release accepts the config written for the one before it. The keys of the SSH
server removed in v0.10.0 (`listen`, `hostKey` / `host_key`, `clients.*.sshKey` or a client written as an SSH key string,
`ipLists.*.hosts`) are still accepted: they are ignored and the hub logs one warning that names them. Delete them when
convenient. A config without `https.listen` is refused: there is no other listener.

### GitHub App (optional): `githubApp`

```json
"upstream": "git@github.com:KazuhaHub/infra.git",
"githubApp": {"appId": 123456, "keyFile": "/run/credentials/infra-hub.service/github_app_key"}
```

Without `githubApp` the mirror fetches `upstream` over ssh with the deploy key from `CREDENTIALS_DIRECTORY`, as before.
With it, the mirror fetches `https://github.com/<owner>/<repo>.git`, derived from `upstream` (the ssh forms
`git@github.com:o/r.git` and `ssh://git@github.com/o/r.git` and the https form are all accepted; the host must be
`github.com`), with a short-lived read-only installation token of a GitHub App:

- The hub signs an RS256 JWT (issued 60 s in the past, valid 9 minutes, `iss` = `appId`), looks up the installation of
  the repository (`GET /repos/{owner}/{repo}/installation`) and asks for a token narrowed to that one repository and
  `{"contents": "read"}` (`POST /app/installations/{id}/access_tokens`). The token is kept in memory and replaced 5
  minutes before it expires; concurrent requests share one request to GitHub.
- git receives the token as `http.https://github.com/.extraheader` (Basic `x-access-token`) through
  `GIT_CONFIG_COUNT/KEY/VALUE` in its environment, with `http.followRedirects=false`, `protocol.allow=never` and only
  https allowed. The token is never in a command line, the remote URL, `.git/config` or a log line (git output is scrubbed
  of it before it is logged), and git runs with a clean environment (no inherited `GIT_TRACE*`, `GIT_CURL_VERBOSE`,
  `GIT_ASKPASS` and so on). The repository the token is for comes from `upstream` only.
- The key file is read when a token is needed (and again after it changes), not at start and not by `check-config`,
  which validates `appId` (positive), `keyFile` (absolute) and that `upstream` is a github.com repository, and never
  opens the key. A config without `githubApp` loads unchanged.
- The key is a PEM RSA key (PKCS#1 or PKCS#8) of the App.

#### Creating the read-only App (owner steps)

1. GitHub, organisation KazuhaHub, Settings, Developer settings, GitHub Apps, New GitHub App. Name `infra-hub`, any
   homepage URL, Webhook off. Repository permissions: Contents: Read-only, nothing else (Metadata: Read is added
   automatically). Where can this App be installed: Only on this account.
2. Create the App, note its App ID, and Generate a private key (a `.pem` file downloads).
3. Install App, choose KazuhaHub, Only select repositories, `infra` only.
4. Store the `.pem` with SOPS in the infra repository; deploy it to both hubs as the systemd credential `github_app_key`
   (replace the `deploy_key` and `known_hosts` credentials), and to the hub hosts' agents as `/etc/infra/github-app.pem`
   (mode 0600).
5. Add `githubApp` to each hub's config, and `INFRA_AGENT_GITHUB_APP_ID=<App ID>` (key path default
   `/etc/infra/github-app.pem`) to the hub hosts' `agent.env`. Restart or let the service reload; check the mirror
   fetches (`infra-hub status`), then remove the old read-only deploy key from the repository's settings.

### Config keys are camelCase (migration)

Every config key is lower camelCase, like the rest of the JSON this project writes (`mirrorIntervalSeconds`, `maxStaleSeconds`, `waitTimeoutSeconds`, `certDir`, `acmeDirectory`, `acmeEmail`, `cloudflareTokenFile`,
`ipSources` (with `maxBytes` inside a source), `ipLists`, `ipListDir`). The earlier snake_case spellings (`mirror_interval_seconds`, `max_stale_seconds`, `cert_dir`, `acme_directory`, `acme_email`, `cloudflare_token_file`,
`ip_sources` with `max_bytes`, `ip_lists`, `iplist_dir`) still work for one release: the hub logs a warning that names
the new key and starts. A config that sets both spellings of one key is rejected. To migrate, rename the keys; nothing
else changes.

## Build and test

Requires Go 1.26 or newer. The git tests also need `git` on the PATH (they are skipped otherwise).

```
go build ./...
go vet ./...
go test -race ./...
go mod verify
```

Layout:

```
cmd/infra-hub/       the server's main package
cmd/infra-agent/     the agent's main package
internal/agent/      the agent's engine: config, cycle, verification, extraction, apply, state, lock
internal/agentapp/   the agent's command line
internal/agenttest/  test bench: signed bundles, git mirror, real hub servers, ansible stub
internal/app/        command line and wiring
internal/gitmirror/  the read-only git mirror
internal/certs/      certificate store, renewal, ACME issuer
internal/iplists/    IP list collection, validation, history
internal/hubkey/     the hub identity key: generate, read, pin, the in-memory self-signed certificate
internal/hubtrust/   how an agent decides to trust a hub: the leaf's key hash must match a pin
internal/jointoken/  the one-line join token (`ih1.` + pins and hub URLs)
internal/bundle/     the config bundle: statement parser, reader of the mirror, archive
internal/httpsapi/   the hub's TLS identity and the /v1 HTTPS endpoints
internal/config/     the config file
internal/state/      the mirror time and the latest report of each host
testdata/            public IP-range fixtures used by the tests
```

## Security model

- The hub is read-only towards its clients. A client can fetch only what the config allows it to fetch: the config
  bundle (encrypted to it), the certificates it owns (encrypted to it) and the public IP lists. Nothing a client sends
  can add a name, a list or an entry.
- Configuration is trusted because of a signature, not because of where it came from. The configuration repository's CI
  signs "this commit is on main" (a Sigstore keyless signature); machines verify it themselves and only move
  forward. A stale or compromised mirror can delay an update but cannot forge one.
- Certificate names, owners and IP sources come only from the hub's config, which you render from your own inventory.
- IP-list updates are validated (reserved ranges, size and address-space limits) and a large change is held until a
  person accepts it; the last good list keeps being served meanwhile.
- There is no SSH server: every machine holds only its age key, authenticates to the hub with an age-based
  challenge-response and receives age-encrypted, signed bundles. A future step lets a machine generate its own
  certificate private key so the hub never holds one. See [docs/design.md](docs/design.md).

Report vulnerabilities privately through GitHub's "Report a vulnerability" on this repository.

## Releases and verification

Pushing a `v*` tag builds static binaries (`CGO_ENABLED=0`) for linux/amd64 and linux/arm64 for every program under
`cmd/`, writes `SHA256SUMS`, records a GitHub build provenance attestation for every file, and publishes them as a
release. To verify a download:

```
gh attestation verify infra-hub-linux-amd64 --repo KazuhaHub/infra-hub
sha256sum --check --ignore-missing SHA256SUMS
```

## License

Apache-2.0. See [LICENSE](LICENSE).
