# The hub identity key (for the owner)

Agents trust one thing: the pin of the hub identity key, in the same way that an SSH client trusts a host key it has
seen before. There is one key for all hubs (the primary and every standby), so there is one pin. Nothing expires,
there is no certificate to renew and no file that depends on your laptop.

All example values below are placeholders.

## How it works

- The key is an ECDSA P-256 key in a PKCS#8 PEM file (`PRIVATE KEY`). P-256 is the curve that every TLS client
  supports; the system curl of macOS (LibreSSL) cannot handshake with an Ed25519 certificate. A key of any other type
  is refused: run `key init` again.
- At every start the hub builds a self-signed certificate from the key in memory: the names are `httpsAddresses`, it
  is valid from one hour before the start until 9999-12-31T23:59:59Z (the RFC 5280 value for "no well-defined
  expiration"), and it is served over TLS 1.3 only. Nothing is written to disk.
- An agent accepts a connection if and only if the SHA-256 of the SubjectPublicKeyInfo of the presented certificate
  equals one of its pins (`sha256//<base64>`, the format of curl's `--pinnedpubkey`). It ignores the chain, the dates
  and the host name. The hub proves it holds the key by signing the TLS handshake with it.

## Generate it once

On a trusted machine:

```
infra-hub key init --out ./hub.key
```

This writes `hub.key` (mode 0600; it refuses to overwrite an existing file) and prints the pin:

```
sha256//AbCdEf...=
```

`infra-hub key pin --key ./hub.key` prints the pin again. The pin is public.

## Keep it

`hub.key` is created unencrypted because it has to be readable once. Encrypt it at once and delete the plain file:

1. In the private infra repository, store it as a SOPS file for the **hubs and the admin** (age recipients: the age key
   of every hub and the admin key; no other machine, and no agent):
   ```
   sops --encrypt --age <hub age keys>,<admin age key> hub.key > secrets/hub.key.sops
   ```
2. Commit the SOPS file. Delete `hub.key` (`shred -u` where it works; on an encrypted disk a plain `rm` is fine).
3. Deployment decrypts it on each hub to the path of `https.key` in the hub's config (for example
   `/etc/infra-hub/hub.key`, owner = the user that runs the hub, mode 0600). The hub refuses a key that others can read.

## Give it to the agents

The pin is public and is kept in the inventory, so a token needs no private key:

```
infra-hub token --pin 'sha256//AbCdEf...=' --hub https://192.0.2.10:8443 --hub https://hub.example.org:8443
```

prints one line, `ih1.` followed by base64url of `{"v":1,"pins":["sha256//..."],"hubs":["https://...",...]}`. The agent
install takes it as its argument (`curl ... | sh -s -- <token>`). The token holds no secret: only the public pins and
the hubs' URLs. `--pin` can be repeated, and `--key <path>` can be given as well (its pin is computed, and listed
first); a pin that is given twice is listed once. Do not decrypt the key just to make a token.

## Rotating the key

Rotate when the key may have leaked, or whenever you like. A token holds a list of pins and an agent accepts a hub that
presents any of them, so a rotation never cuts an agent off, as long as the order below is kept. `internal/agent`'s
`TestHubKeyRotation` runs exactly these steps (old hub with a token of both pins, the same address with the new key,
then a token of the new pin only; a token of the new pin refuses the old hub, a token of the old pin refuses the new
hub).

Where the pins live in the private infra repository: the agents' pins are in the token `infra_agent_token` in
`inventory/group_vars/all.yml` (the public pin is also `hub_identity_pin` there; the IP list client reads that one).
The private key of the hubs is `hub_identity_key` in each hub's SOPS file.

1. **New key.** On a trusted machine: `infra-hub key init --out ./hub-new.key` (prints the new pin). Do not touch the
   hubs yet.
2. **Agents first.** In `inventory/group_vars/all.yml` make the agents accept both pins: set the token to
   `infra-hub token --pin <old pin> --pin <new pin> --hub <url> --hub <url>` (same `--hub` URLs and order as now) and
   list both pins wherever `hub_identity_pin` is used. Merge it and wait until every agent has applied it (every
   host's report in `infra-hub status` shows the new commit). The hubs still use the old key.
3. **Hubs.** Put the new key into each hub's SOPS file as `hub_identity_key` (replace the old value; every hub gets the
   same key), delete `./hub-new.key`, deploy, and restart the hubs (the deploy does it). Agents accept the new pin. Check
   with `infra-hub status` that hosts keep reporting.
4. **Drop the old pin.** Set the token to `infra-hub token --pin <new pin> --hub ...`, remove the old pin from
   `hub_identity_pin` and merge. New installs use this token as well.

If the hubs are switched before every agent has the new pin, those agents cannot reach any hub until they are given the
pin by hand. To undo step 3 put the old key back into SOPS and restart the hubs; the agents still accept it until step 4.

## If the key leaks

Someone with the key can pretend to be a hub: an agent would talk to them. They cannot give agents a configuration (a
bundle is signed by CI and encrypted to each host's age key, see [design.md](design.md)). Rotate as above; because a
leaked key is still accepted until the agents drop its pin, do steps 2 to 4 without delay.
