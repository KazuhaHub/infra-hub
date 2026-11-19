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

## Hub identity (no public CA needed)

The link between agents and hubs must not depend on any outside service, so it does not use Let's Encrypt:

- A small **hub CA** (an ed25519 key) is the only thing agents trust. Its private key never lives on a server: it is kept
  encrypted for the owner only and is used on the owner's workstation to sign hub certificates.
- Every hub (primary, standbys) has its **own** key and a certificate for it signed by the hub CA. Adding a hub is one
  signature; no agent changes. A compromised hub is revoked alone (the revocation list is part of the signed bundle).
- Agents verify the hub's TLS certificate against the pinned CA public key (`AGENT_HUB_CA` in `agent.env`), not against
  the system roots and not by expiry of a public CA. Let's Encrypt, DNS or Cloudflare being down does not affect them.
- Rotating the CA: the old CA signs the new CA's public key; agents learn it over the verified channel and add it, then
  the old one is retired. No machine is touched by hand.

Certificates that the hub obtains **for the machines' own services** (DERP and so on) still come from Let's Encrypt,
because those are used by the public.

## Installing an agent (one command)

Rackbook (or the owner) shows one command, in the same spirit as Beszel's agent install:

```
curl -fsSL --pinnedpubkey 'sha256//<hub key pin>' -k https://<hub address>:<port>/install \
  | sudo sh -s -- --hub <address>[,<address>...] --hub-ca <CA public key>
```

1. curl only talks to the hub whose key matches the pin, so the install script is authentic.
2. The script downloads `infra-agent` from the hub (the hub serves the release it verified with Sigstore), writes
   `agent.env`, and creates the age key.
3. It prints the age public key. Registering the machine is a reviewed change in the private infra repository (Rackbook
   opens it); once merged, the agent starts receiving bundles.

## machine to infra

Reports go over HTTPS, authenticated by **challenge-response with the machine's age key**:

1. The agent asks for a challenge.
2. The hub sends a random nonce encrypted (age) to the machine's registered age public key.
3. The agent decrypts it and sends the plaintext nonce back together with its report.

The nonce is single-use with a short TTL, so a captured report cannot be replayed. Only the holder of the age private
key can read the nonce, so no password or token is stored on the machine.

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
- A compromised machine can read only what is encrypted to its own age key.
- The kick port carries no authority, so exposing it to the private network does not widen what an attacker can do.
