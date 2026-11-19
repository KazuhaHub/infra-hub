# Target design

Status: the hub speaks SSH (unchanged) and, since phase 1, HTTPS. The agent is not written yet; this document is what
the next changes build towards.

| Phase | Content | State |
| --- | --- | --- |
| 1 | Hub side: CA tooling, hub HTTPS identity, `/v1/healthz`, `/v1/challenge`, `/v1/report`, reports in `status` | done |
| 2 | `infra-agent`: challenge-response client, report sender, polling | open |
| 3 | `/v1/bundle`, certificates and IP lists over HTTPS, install script, kick, self-update | open |
| 4 | Revocation list enforced (agent side), CA rotation, SSH removed | open |

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
- **infra-agent** (this repo, to be written): runs on every machine, applies config and reports.

## infra to machine

- **Config bundle.** A tarball of the attested commit of the infra repository, signed by infra's CI
  (`ssh-keygen -Y sign` attestation, namespace `infra-main`, as today) and encrypted with age to the machines that may
  read it. A machine verifies the signature before it applies anything and only moves forward.
- **Certificates.** The machine generates its own private key and sends a CSR. The hub obtains the certificate with
  lego `ObtainForCSR` and returns only the public certificate chain. The hub never holds a machine's private key.
- **IP lists.** Signed by a hub signing key whose public half is part of the signed bundle.

## Hub identity (no public CA needed)

The link between agents and hubs must not depend on any outside service, so it does not use Let's Encrypt:

- A small **hub CA** (an ECDSA P-256 key: it is the curve every TLS client and curl build supports) is the only thing agents trust. Its private key never lives on a server: it is kept
  encrypted for the owner only and is used on the owner's workstation to sign hub certificates (`infra-hub ca`, see [ca.md](ca.md)). The CA can carry a
  critical name constraint, so that even a stolen CA key can only certify the fleet's own addresses.
- Every hub (primary, standbys) has its **own** key and a certificate for it signed by the hub CA. Adding a hub is one
  signature; no agent changes. A compromised hub is revoked alone (the revocation list, a JSON list of serials defined in `internal/hubca`, is part of
  the signed bundle; enforcing it is phase 4).
- `agent.env` holds only the **CA pin**: `AGENT_HUB_CA_PIN=sha256//<base64 of the SHA-256 of the CA's SPKI>` (the
  curl `--pinnedpubkey` format; one or, during a rotation, several comma-separated pins). The CA certificate itself is
  public and is not stored on the machine.
- The hub presents its **full chain**: its own certificate followed by the CA certificate. An agent builds its root pool
  from the presented CA certificate only if the SPKI hash of that certificate equals a pin; the hub certificate must
  then verify against it in the normal way (signature, validity, name constraints, server-authentication usage) and
  must be valid for the address the agent connected to. System roots are never used, so Let's Encrypt, DNS or
  Cloudflare being down does not affect the agents. A different CA certificate with the same subject does not match
  the pin and is refused. The verifier is `internal/hubtrust`, written once for the agent.
- Rotating the CA: the old CA signs the new CA's public key; agents learn the new pin over the verified channel and
  add it to `AGENT_HUB_CA_PIN`, then the old one is retired. No machine is touched by hand.

Certificates that the hub obtains **for the machines' own services** (DERP and so on) still come from Let's Encrypt,
because those are used by the public.

## Installing an agent (one command)

Rackbook (or the owner) shows one command, in the same spirit as Beszel's agent install:

```
curl -fsSL --pinnedpubkey 'sha256//<hub key pin>' -k https://<hub address>:<port>/install \
  | sudo sh -s -- --hub <address>[,<address>...] --hub-ca-pin 'sha256//<CA pin>'
```

(`--pinnedpubkey` takes the **hub's** key pin, which `infra-hub ca sign` prints for each hub certificate; the CA pin
after `--hub-ca-pin` is the one `infra-hub ca init` printed.)

```
```

1. curl only talks to the hub whose key matches the pin, so the install script is authentic.
2. The script downloads `infra-agent` from the hub (the hub serves the release it verified with Sigstore), writes
   `agent.env` (hub addresses and `AGENT_HUB_CA_PIN`), and creates the age key.
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
validated (`appliedCommit`, `result` ok or failed, `message`, `time`, `features[]`; at most 64 KiB), the latest one per
host is stored in the hub's state and appears in `infra-hub status -o json` as `hosts[].report`. Errors are
`401 bad_nonce`, `400 bad_report`, `413 too_large`, `429 rate_limited`, `404 unknown_host`.

The hub serves HTTPS (TLS 1.3 only) only with a certificate that matches its own key, covers the names in
`httpsAddresses` and chains to the configured CA certificate; otherwise it logs an error, keeps writing nothing but the
certificate request `hub.csr`, and serves SSH as before.

## Polling and kicking

- The agent polls every 5 minutes by default (configurable). The hub answers `304 Not Modified` when nothing changed,
  so an idle poll costs about 1 KB with TLS session resumption.
- The hub can "kick" an agent to make it check now. The agent listens on a small port bound to a configured private
  address and accepts only a no-authority "check now" request with rate limiting. The request carries no data and
  grants no capability: at worst it causes an early poll.

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
- A compromised network path sees only TLS traffic to a hub certified by the hub CA; replay of reports fails on the
  nonce.
- A compromised hub certificate is revoked through the signed bundle; the other hubs keep working.
- `/v1/challenge` needs no credential (the nonce is useless without the host's age key), so someone who knows a host
  name and can send requests from many addresses can still crowd that host's real challenges out of the hub's limits
  and delay its reports; the per-address and per-host limits make this expensive, not impossible.
- A compromised machine can read only what is encrypted to its own age key.
- The kick port carries no authority, so exposing it to the private network does not widen what an attacker can do.
