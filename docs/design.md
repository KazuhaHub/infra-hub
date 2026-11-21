# Target design

Status: the hub speaks HTTPS only; the SSH server was removed in v0.10.0 (phase 4a). The agent exists since phase 2 (it fetches, verifies,
applies and reports the config bundle, see [agent.md](agent.md)); this document is what the remaining phases build towards.

| Phase | Content | State |
| --- | --- | --- |
| 1 | Hub side: hub identity key and token, HTTPS, `/v1/healthz`, `/v1/challenge`, `/v1/report`, reports in `status` | done |
| 2 | `infra-agent` v1: challenge-response client, report sender, polling, bundle fetch, verify and apply (see [agent.md](agent.md)) | done, to be run beside infra-pull first |
| 3a | Hub side of `GET /v1/bundle/<host>` (format in [bundle.md](bundle.md)) | done |
| 3b | Certificates and IP lists over HTTPS: `GET /v1/cert/<host>/<name>`, `GET /v1/iplist/<name>`, `infra-agent cert`; the SSH server is optional | done (the hub side and `infra-agent cert`; an agent-side IP list fetcher and the CSR model below are open) |
| 3c | Kick: the agent long-polls `GET /v1/wait/<host>`, so a merge is applied within about a mirror interval (outward connections only) | done (v0.12.0) |
| 3e | GitHub App for the mirror and the agent fallback: a read-only installation token instead of a deploy key | done (v0.13.0) |
| 3d | Install script: `GET /install` | done (v0.12.0) |
| 3 | Self-update, the CSR model for certificates, the IP list fetcher in the agent | open |
| 4a | SSH removed from the hub: `internal/sshserver`, the git upload-pack serving, `listen`, `hostKey`, `clients.*.sshKey` and `ipLists.*.hosts` are gone from the code and still accepted (ignored, one warning) in the config | done (v0.10.0) |
| 4 | Hub key rotation across agents: tokens list several pins, `docs/hub-key.md` is the runbook, `TestHubKeyRotation` covers it | done |

## Goals

- No SSH at all, and no dependency on any Tailscale-specific feature. The network is plain IP plus HTTPS; any private
  or public network works.
- Each machine holds only an **age key** (`/etc/infra/age.key`). It already has one for SOPS secrets.
- One protocol, one release, one version for both programs (`infra-hub`, `infra-agent`), so there is no compatibility
  matrix between them.

## Components

- **infra** (private repository, not in this repo): inventory, feature templates, Ansible roles and SOPS secrets.
  Its CI produces the signed bundle.
- **infra-hub** (this repo): the server. Serves bundles, issues certificates, collects IP lists, receives reports.
- **infra-agent** (this repo, v1 in [agent.md](agent.md)): runs on every machine, applies config and reports.

## infra to machine

- **Config bundle.** A tarball of the attested commit of the infra repository, signed by infra's CI (a Sigstore keyless
  signature, below) and encrypted with age to the machine that fetches it. A machine verifies the signature before it
  applies anything and only moves forward. The format is in [bundle.md](bundle.md). `GET /v1/bundle/<host>` reads
  `bundle`, `bundle.tar.gz` and `bundle.sigstore.json` from the tip of `main-attestation` in the mirror, takes the commit
  from the strictly parsed statement (it verifies neither signature nor hash: the hub is not trusted for integrity), and
  answers an age-encrypted ustar with `ETag` and `304`, or `503 no_bundle` / `503 stale_mirror`.
- **Sigstore keyless signature of the bundle (v0.14.0; the only signature since v0.15.0).** CI signs the statement
  `bundle` with cosign keyless (GitHub Actions OIDC, the public-good Fulcio and Rekor) and publishes `bundle.sigstore.json`.
  The agent verifies it with sigstore-go against the public-good trusted root (embedded, refreshed through TUF), pinned to the
  identity of the `attest-main.yml` workflow of the infra repository on `main` and to the numeric repository and owner IDs.
  There are no signing keys to keep or distribute. The earlier ssh signature (`bundle.sig`) is no longer verified by anything; the hub
  still serves it to agents of v0.14.0 and older (archive formats 1 and 2) for as long as CI publishes it, and a new
  archive format 3 (no ssh signature) is what v0.15.0 agents ask for, so the key can be retired without a flag day
  (rollout order in [bundle.md](bundle.md)). The
  reasoning: a signing key in CI secrets can be exfiltrated and used elsewhere, while a keyless signature is only
  issued to a run of that workflow on `main` and is recorded in a public log. The agent binary grows by about 14 MB for
  the verification library; the hub does not link it (it never verifies). See [agent.md](agent.md) and
  [bundle.md](bundle.md).
- **Certificates.** Implemented in phase 3b: the hub obtains the certificate and holds its private key, and
  `GET /v1/cert/<host>/<name>` returns a JSON line (name, fullchain, privkey, not_after), age-encrypted to the owner's `agePublicKey`. Unknown host, unknown name, a name owned by another host and a
  host without an age key all answer the same `404 not_found`; a missing certificate or one with less than 7 days left
  is a `503 not_serving` with no reason in the body. Future work, the CSR model: the machine generates its own private
  key and sends a CSR, the hub obtains the certificate with lego `ObtainForCSR` and returns only the public chain, so
  the hub never holds a machine's private key. It needs an authenticated request (the challenge nonce) and changes the
  payload, so it is a new endpoint, not a change of this one.
- **IP lists.** Implemented in phase 3b: `GET /v1/iplist/<name>` is public data (provider ranges and manual entries),
  so it has no host in the path, no encryption and no allow list. Its
  `ETag` is a hash of the list's `version` (itself a hash of the entries) and its sorted warnings, so `If-None-Match`
  gives a `304` although `generated` changes at every request, and a new warning (a held update, say) gives a `200`. Signing the lists with a hub signing key whose public half is part of the signed bundle
  remains an option.
- **GitHub App, not a deploy key (v0.13.0).** Both the hub mirror (`githubApp` in the config) and the agent's GitHub
  fallback (`INFRA_AGENT_GITHUB_APP_ID`) can authenticate to GitHub as one read-only App installed only on the
  infrastructure repository. Tokens last an hour, are narrowed to that repository and `contents: read`, live in memory and
  in the environment of one git process, and the key can be rotated in one place. The ssh deploy key keeps working when
  the App is not configured, so every older config loads unchanged. The package is `internal/githubapp`; its fake
  GitHub (REST API plus smart-HTTP git that accepts only valid tokens) is `internal/githubapp/githubapptest`.
- **No SSH server.** Phase 4a removed it (v0.10.0). The config keys it used (`listen`, `hostKey`, `clients.*.sshKey`,
  `ipLists.*.hosts`) are accepted and ignored with one warning, because hubs follow the latest release and a release
  must read the previous one's config. A config without `https.listen` is refused. The git mirror stays: it is where
  the bundle comes from. `status` no longer has a per-host `lastSeen`, `main` or `mainAttestation`; the host's report
  carries `receivedAt`.

## Hub identity (a pinned key, no CA)

The link between agents and hubs must not depend on any outside service, so it does not use Let's Encrypt, and there is
no CA of our own either. It works like an SSH host key:

- There is one **hub identity key** (ECDSA P-256, PKCS#8 PEM), the same on every hub (primary and standbys), so all hubs
  have one fingerprint. It is generated once (`infra-hub key init`, see [hub-key.md](hub-key.md)), kept in SOPS for the
  hubs and the admin, and deployed to the path `https.key` in each hub's config (mode 0600).
- At start the hub builds a **self-signed certificate** from the key in memory: SAN = `httpsAddresses`, NotBefore =
  now minus one hour, NotAfter = 9999-12-31T23:59:59Z (RFC 5280: "no well-defined expiration"), TLS 1.3 only. There
  are no certificate files, no renewal, and nothing that expires and interrupts agents.
- An agent holds a list of **pins**, `sha256//<base64 of the SHA-256 of the SPKI>` (the curl `--pinnedpubkey` format).
  It accepts a connection if and only if the leaf certificate's SubjectPublicKeyInfo hash equals one of the pins. It
  ignores the chain, the dates and the host name: the pin is the trust. System roots are never used, so Let's Encrypt,
  DNS or Cloudflare being down does not affect the agents. The verifier is `internal/hubtrust`.
- `infra-hub token --pin PIN --hub URL...` prints one line for the agent install, `ih1.` plus base64url of
  `{"v":1,"pins":["sha256//..."],"hubs":["https://host:port",...]}` (`internal/jointoken`). It holds no secret, and
  it takes the public pin from the inventory, so no private key is decrypted to make a token. During a rotation it
  carries both pins (`--pin OLD --pin NEW`).
- Rotating: give the agents the new pin first (the list holds both), then switch the hubs to the new key, then drop the
  old pin. No machine is touched by hand.

Why this is acceptable: the config bundle is signed by infra's CI and age-encrypted to each host, so hub TLS is a second
layer on top of end-to-end protection, not the only one. A stolen hub key lets someone impersonate a hub (to read what
agents send it, or to withhold and delay updates) but not inject configuration: a bundle they forge fails the
signature check, and they cannot read secrets that are not encrypted to them.

Certificates that the hub obtains **for the machines' own services** (DERP and so on) still come from Let's Encrypt,
because those are used by the public.

## Installing an agent (one command)

Rackbook (or the owner) shows one command, in the same spirit as Beszel's agent install, with the token from
`infra-hub token`:

```
curl -fsSL -k --pinnedpubkey 'sha256//<hub pin>' https://<hub address>:<port>/install | sudo sh -s -- <token> <host> [--hub]
```

1. curl only talks to a hub whose key matches the pin (the one in the token; `-k` only switches off the certificate
   chain check that cannot succeed for a self-signed certificate, the pin check stays), so the install script is
   authentic. There is no CA pin any more.
2. The script downloads `infra-agent` from the hub (the hub serves the release it verified with Sigstore), writes
   `agent.env` (hub URLs and pins from the token, `AGENT_HUB_PINS`), and creates the age key.
   (Implemented in v0.12.0 differently from this sketch: the hub serves the script, the script downloads the binary from
   the GitHub release and checks it against `SHA256SUMS`; see [agent.md](agent.md).)
3. It prints the age public key. Registering the machine is a reviewed change in the private infra repository (Rackbook
   opens it); once merged, the agent starts receiving bundles.

## machine to infra

Reports go over HTTPS, authenticated by **challenge-response with the machine's age key**:

1. The agent asks for a challenge.
2. The hub sends a random nonce encrypted (age) to the machine's registered age public key.
3. The agent decrypts it and sends the plaintext nonce back together with its report.

The nonce is single-use with a short TTL, so a captured report cannot be replayed. Only the holder of the age private
key can read the nonce, so no password or token is stored on the machine.

Only age X25519 recipients (`age1...`) are supported as a host's `agePublicKey`; plugin and post-quantum recipient
types are rejected when the config is read.

Implemented in phase 1: `POST /v1/challenge` (body `{"host":"<name>"}`) returns the age-armored ciphertext of a random
32-byte nonce, encrypted to the host's `agePublicKey` from the hub config. `POST /v1/report` carries
`{"apiVersion":"v1","host":...,"nonce":"<hex of the decrypted nonce>","report":{...}}`. A nonce is single use, valid
5 minutes, held in memory (bounded). Challenges are rate limited per host and per peer address. The report is
validated (`appliedCommit` or empty, `result` one of ok, failed, verified, rejected, unreachable, unchanged, `message`, `time`, `features[]`; at most 64 KiB), the latest one per
host is stored in the hub's state and appears in `infra-hub status -o json` as `hosts[].report`. Errors are
`401 bad_nonce`, `400 bad_report`, `413 too_large`, `429 rate_limited`, `404 unknown_host`.

The hub serves HTTPS (TLS 1.3 only) when `https.listen` is set, with the self-signed certificate it builds from
`https.key`; if the key cannot be read the hub logs an error and exits with a failure (it has no other listener).

## Polling and kicking

- The agent polls every 5 minutes by default (configurable). The hub answers `304 Not Modified` when nothing changed,
  so an idle poll costs about 1 KB with TLS session resumption.
- The hub does not push anything to an agent (an agent opens no port). Instead, between cycles the agent holds a long
  request, `GET /v1/wait/<host>?etag=<last verified commit>`, to the first hub that supports it. The hub answers at once
  when the bundle it would serve differs, otherwise when its mirror sees a new `main-attestation` tip that changes it, or
  after about 4 minutes with "no change". The answer carries only whether and which commit; the bundle is still fetched,
  verified and applied as always. The poll interval stays the upper bound, and a hub without the endpoint (404) is just
  not asked for an hour. Details in [agent.md](agent.md).

## Alert mail

The agent sends alert mail directly through SMTP AUTH, with credentials from SOPS. Mail is never relayed through other
servers.

## Updates

The agent updates itself from releases of this repository. It verifies each release with Sigstore (GitHub
attestations): the signer identity must be this repository's release workflow on `refs/tags/*`. It keeps the previous
version and falls back to it if the new one cannot report within N minutes.

## Layout on a machine

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/infra-agent` | the binary (previous version kept next to it) |
| `/etc/infra/agent.env` | agent settings |
| `/etc/infra/age.key` | the machine's age private key |
| `infra-agent.service` | the one systemd unit |
| `/var/lib/infra-agent/` | state directory |

## Threat notes

- A compromised hub can withhold or delay updates and can see report contents it is sent, but it cannot forge a config
  bundle (signature) or read secrets not encrypted to it, and it never holds machine certificate keys.
- A compromised network path sees only TLS traffic to a hub that holds the pinned key; replay of reports fails on the
  nonce.
- The hub identity key is shared by all hubs, so a leak of it from one hub is a leak for all: rotate it (agents first).
  The holder can impersonate a hub but cannot inject configuration (see above).
- `/v1/challenge` needs no credential (the nonce is useless without the host's age key), so someone who knows a host
  name and can send requests from many addresses can still crowd that host's real challenges out of the hub's limits
  and delay its reports; the per-address and per-host limits make this expensive, not impossible.
- A compromised machine can read only what is encrypted to its own age key.
- The kick port carries no authority, so exposing it to the private network does not widen what an attacker can do.
