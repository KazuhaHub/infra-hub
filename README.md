# infra-hub

A small hub and agent for managing a fleet of machines without SSH: signed configuration bundles, age-encrypted
secrets and certificates, and a plain IP-plus-HTTPS network.

One repository holds both programs and they are released together under one version:

| Program | What it is | Status |
| --- | --- | --- |
| `cmd/infra-hub` | The server. Mirrors the configuration repository, issues certificates, collects IP lists. | Works. Today it serves its clients over SSH (read-only git, `cert`, `iplist`). |
| `cmd/infra-agent` | The per-machine agent. Pulls config, reports back, updates itself. | In progress. Not in the tree yet. |

The target design (no SSH, age keys, challenge-response, signed bundles) is written down in
[docs/design.md](docs/design.md). Logging, CLI and JSON conventions shared with Rackbook are in [docs/conventions.md](docs/conventions.md). The hub starts from its current SSH transport; the new transport arrives in later
changes.

This is the code only. Your data (inventory, templates, roles, secrets) stays in your own private repository.

## What the hub does today

- **Git mirror.** Keeps a bare, read-only mirror of `main` and `main-attestation` of your configuration repository and
  serves it over SSH to the hosts listed in its config. Each host is identified by its public key; nothing else is
  served (no push, no shell, no other repository).
- **Certificates.** Obtains and renews certificates through ACME (DNS-01 with Cloudflare, via
  [lego](https://github.com/go-acme/lego)) for the names in its config, and serves each one to the single host that owns
  it.
- **IP lists.** Downloads published IP ranges (Cloudflare, Fastly, AWS CloudFront, GitHub, Google, ...), validates them,
  holds suspicious changes until a person accepts them, and serves named lists to the hosts allowed to fetch them.

Commands:

```
infra-hub serve                                   run the hub
infra-hub status [-o json] [--no-refs]            mirror, hosts, certificates, IP lists
infra-hub iplist accept <provider>                apply a held IP list update
infra-hub iplist history <list> [--limit N]       change history of a list (JSON)
infra-hub version                                 also: infra-hub --version
```

Every flag can also come from the environment as `INFRA_HUB_<NAME>` (`--config` is `INFRA_HUB_CONFIG`, `--log-level`
is `INFRA_HUB_LOG_LEVEL`); the config file defaults to `/etc/infra-hub/config.json`. Logs go to stderr through
`log/slog`, as `key=value` text by default or JSON with `--log-format json`; `--log-level` is `debug`, `info` (default),
`warn` or `error`. Exit codes: `0` success, `1` the operation failed, `2` usage error, `3` not ready (`status`: the
mirror has not fetched yet).

`status -o json` prints the document described in [docs/conventions.md](docs/conventions.md): `"apiVersion": "v1"`,
lower camelCase keys, RFC 3339 UTC times, durations as `...Seconds`, hosts, certificates, providers and lists as arrays
sorted by name.

Deprecated, removed in the next release: the old spellings `-config`, `-no-refs`, `-limit`, `iplist-accept` and
`iplist-history` still work and print a warning on stderr. With `-config`, `status` keeps printing the previous
snake_case JSON (also available as the hidden `--format legacy`) unless `-o` is given.

The config is one JSON file; see `internal/config/config.go` for every field.

## Build and test

Requires Go 1.26 or newer. The git tests also need `git` and `ssh` on the PATH (they are skipped otherwise).

```
go build ./...
go vet ./...
go test -race ./...
go mod verify
```

Layout:

```
cmd/infra-hub/       the server's main package
internal/app/        command line and wiring
internal/sshserver/  the SSH server: identity, host key, git upload-pack, cert and iplist commands
internal/gitmirror/  the read-only git mirror
internal/certs/      certificate store, renewal, ACME issuer
internal/iplists/    IP list collection, validation, history
internal/config/     the config file
internal/state/      per-host last-seen state
testdata/            public IP-range fixtures used by the tests
```

## Security model

- The hub is read-only towards its clients. A client can fetch only what the config allows it to fetch: the mirror
  of one repository, the certificates it owns, and the IP lists assigned to it. Nothing a client sends can add a
  name, a list or an entry.
- Configuration is trusted because of a signature, not because of where it came from. The configuration repository's CI
  signs "this commit is on main" (an `ssh-keygen -Y sign` attestation); machines verify it themselves and only move
  forward. A stale or compromised mirror can delay an update but cannot forge one.
- Certificate names, owners and IP sources come only from the hub's config, which you render from your own inventory.
- IP-list updates are validated (reserved ranges, size and address-space limits) and a large change is held until a
  person accepts it; the last good list keeps being served meanwhile.
- The target design removes SSH completely: every machine holds only its age key, authenticates to the hub with an
  age-based challenge-response, receives age-encrypted, signed bundles, and generates its own certificate private key so
  the hub never holds one. See [docs/design.md](docs/design.md).

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
