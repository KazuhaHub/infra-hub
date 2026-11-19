# The hub CA (for the owner)

Agents trust one thing: the public key of the hub CA. Every hub has its own key and a certificate for it that this CA
signed. The CA key is used only on your workstation, a few times a year. It never goes on a server.

All example values below are placeholders.

## Create the CA

On the workstation:

```
infra-hub ca init --out ./hub-ca \
  --permit-ip 192.0.2.0/24 --permit-dns example.org
```

This writes `ca.crt` (public, valid 20 years) and `ca.key` (ECDSA P-256, mode 0600) and prints the pin:

```
sha256//AbCdEf...=
```

The pin identifies the CA's public key; it is public, and `infra-hub ca pin --cert hub-ca/ca.crt` prints it again. It
is the only thing an agent is given (`AGENT_HUB_CA_PIN`): a hub presents its certificate followed by the CA
certificate, and the agent accepts the presented CA certificate only if its key matches the pin. Note that
`curl --pinnedpubkey` compares the key of the server's own certificate, not the CA's: for the install one-liner use the
**hub pin** that `ca sign` prints for each hub certificate (`infra-hub ca pin --cert hub.crt` prints it too).

`--permit-ip` and `--permit-dns` (repeatable) put a critical name constraint into the CA certificate: whatever happens
to the CA key, certificates for other names are rejected by every verifier. A name type you do not list is excluded
altogether (only `--permit-ip` means no DNS names at all). Use the address ranges and domains your
hubs will ever have. They cannot be changed later (it would be a new CA, see Rotating).

## Keep the key

`ca.key` is created unencrypted because it has to be readable once. Encrypt it at once and delete the plain file:

1. In the private infra repository, store it as a SOPS file encrypted to the admin age key only (no machine key, no
   CI key): for example `secrets/hub-ca.key.sops`.
   ```
   sops --encrypt --age <admin age public key> hub-ca/ca.key > secrets/hub-ca.key.sops
   ```
2. Commit the SOPS file and `ca.crt` (public) to that repository. Delete `hub-ca/ca.key` (`shred -u` where it works; on
   an encrypted disk a plain `rm` is acceptable).
3. To sign, decrypt into a temporary location, sign, and remove it again:
   ```
   sops --decrypt secrets/hub-ca.key.sops > "$TMPDIR/ca.key"; chmod 600 "$TMPDIR/ca.key"
   ```

Never put the CA key in the hub's configuration, in CI, or on any server.

## Sign a hub's certificate

1. On the hub, as the user that runs it, print the request (this also creates the hub's own key on first use):
   ```
   infra-hub https csr --config /etc/infra-hub/config.json > hub.csr
   ```
   The names in it come from `httpsAddresses` in the hub's config (IP addresses and/or lower-case DNS names).
   While there is no usable certificate the hub also writes the same request to `hub.csr` next to its state file (once per start).
2. On the workstation:
   ```
   infra-hub ca sign --ca-key "$TMPDIR/ca.key" --ca-cert hub-ca/ca.crt --csr hub.csr --out hub.crt [--days 825]
   ```
   The names are taken from the request. Only IP and DNS names are accepted (no wildcards, no e-mail or URI names);
   the CA's name constraints are checked before the certificate is written. It prints the serial, the expiry and the hub pin. Write
   them down; the serial is what a revocation entry names.
3. Commit `hub.crt` to the infra repository; infra places it at the hub's `https.cert` path. The running hub notices
   within about 30 seconds, checks that the certificate matches its key, covers `httpsAddresses` and chains to
   `https.caCert`, and starts serving HTTPS, presenting its certificate followed by the CA certificate. A certificate that fails the check is logged as an error and not used;
   the hub keeps serving SSH. A renewed file is picked up within 5 minutes.

Adding a standby hub is the same steps on that hub: one new signature, no change on the agents.

Renew a hub certificate before it expires (825 days by default) by signing a new request, which can be the same
request: the key stays.

## Revocation

A revoked hub is one whose certificate must no longer be trusted (its server was compromised). The format is a plain
JSON file, to be distributed later inside the signed bundle (so it needs no signature of its own):

```json
{
  "apiVersion": "v1",
  "revoked": [
    {"serial": "1a2b3c", "time": "2026-11-19T08:00:00Z", "reason": "server compromised"}
  ]
}
```

`serial` is the certificate serial in lower-case hex without leading zeros (as `ca sign` prints it); entries are sorted
ascending by serial as a number (`ff` comes before `100`), without duplicates. The type and the parser exist in `internal/hubca`; no command writes the file and
nothing enforces it yet. The agent will enforce it in a later phase.

## Rotating the CA

Rotate when the CA key may have leaked or in good time before the CA certificate expires (20 years).

1. Create the new CA (`ca init` into a new directory) and store its key as above.
2. The old CA signs the new CA's public key; agents learn the new pin over the verified channel and add it to
   `AGENT_HUB_CA_PIN`. This transition is part of the agent phase; until it exists, rotation means giving every agent
   the new pin by a reviewed change in the infra repository.
3. Sign every hub's request with the new CA and place the new certificates.
4. When no agent trusts only the old CA any more, retire it: remove the old pin from the agents' settings and delete
   the old SOPS file.
