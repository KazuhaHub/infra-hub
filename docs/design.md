# Target design

Status: the hub exists and speaks SSH today. The agent and the transport below are not implemented yet; this document
is what the next changes build towards.

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

## machine to infra

Reports go over HTTPS, authenticated by **challenge-response with the machine's age key**:

1. The agent asks for a challenge.
2. The hub sends a random nonce encrypted (age) to the machine's registered age public key.
3. The agent decrypts it and sends the plaintext nonce back together with its report.

The nonce is single-use with a short TTL, so a captured report cannot be replayed. Only the holder of the age private
key can read the nonce, so no password or token is stored on the machine.

## Polling and kicking

- The agent polls every minute. The hub answers `304 Not Modified` when nothing changed.
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
- A compromised network path sees only TLS traffic; replay of reports fails on the nonce.
- A compromised machine can read only what is encrypted to its own age key.
- The kick port carries no authority, so exposing it to the private network does not widen what an attacker can do.
