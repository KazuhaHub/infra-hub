# infra-agent

The per-machine agent. It runs as root under systemd on every managed Linux host, fetches this host's config bundle from
the hubs over HTTPS, verifies it, applies it with ansible and reports the result. It only connects outward and opens no
port. The design follows Beszel: one env file, one token line. The bundle format is in [bundle.md](bundle.md), the hub
identity key and the pin in [hub-key.md](hub-key.md), the overall design in [design.md](design.md).

This is v1: it covers the bundle path (fetch, verify, extract, apply, report). There is no install script and no
self-update yet (see "Next steps"); certificates, IP lists and the kick port are not part of it.

## Configuration

`/etc/infra-agent/agent.env` (`--env-file` or `INFRA_AGENT_ENV_FILE` changes the path): one `KEY=VALUE` per line, `#`
comments, an optional pair of quotes around a value, no `export`. The same keys can be set in the process environment,
which wins over the file (so a systemd `EnvironmentFile=` or `Environment=` works as well). A key that is not in the
table, or a key set twice, is an error: the agent exits with code 2 and names the line.

| Key | Default | Meaning |
| --- | --- | --- |
| `INFRA_AGENT_TOKEN` | required | The `ih1.` join token from `infra-hub token`: the hubs, tried in the order given, and the pins of the hub identity key. It holds no secret. |
| `INFRA_AGENT_HOST` | required | This host's name in the inventory (letters, digits, `.`, `_`, `-`). It is the name in `/v1/bundle/<host>` and in `ansible-playbook --limit`. |
| `INFRA_AGENT_AGE_KEY` | `/etc/infra/age.key` | The host's age private key. It decrypts the bundle and the challenge, and is passed to ansible as `SOPS_AGE_KEY_FILE`. |
| `INFRA_AGENT_SIGNERS` | `/etc/infra-agent/allowed_signers` | The `ssh-keygen` allowed_signers file with the CI key: `infra-main namespaces="infra-main,infra-bundle" ssh-ed25519 AAAA...`. |
| `INFRA_AGENT_MODE` | `verify` | `verify` or `apply` (below). |
| `INFRA_AGENT_INTERVAL` | `5m` | Time between cycles, at least 10 s. Every wait gets a random difference of up to 10 %. |
| `INFRA_AGENT_STATE_DIR` | `/var/lib/infra-agent` | State directory (below). |
| `INFRA_AGENT_LOG_FORMAT`, `INFRA_AGENT_LOG_LEVEL` | `text`, `info` | The `--log-format` and `--log-level` flags, which can be set in the file too. |

All paths must be absolute. An example:

```
# /etc/infra-agent/agent.env  (0600, root)
INFRA_AGENT_TOKEN=ih1.<the line printed by `infra-hub token`>
INFRA_AGENT_HOST=web1
INFRA_AGENT_MODE=verify
INFRA_AGENT_INTERVAL=5m
```

Commands:

```
infra-agent run [--once]          run the cycle every interval (or once)
infra-agent status [-o json]      applied and verified bundle, last result, last hub, last cycle
infra-agent check-config          validate agent.env, the token and the key files; ask each hub for /v1/healthz
infra-agent version
```

`run --once` exits 0 for `ok`, `verified` and `unchanged`; 1 for `failed`, `rejected` and `unreachable`; 2 for a
configuration error; 3 when another infra-agent holds the lock (below). `status -o json` has `"apiVersion": "v1"`, camelCase
keys and RFC 3339 UTC times.

## One cycle

1. **Fetch.** `GET /v1/bundle/<host>` from each hub in order until one answers, over TLS 1.3 with the pinned key as the only
   trust (`internal/hubtrust`), a 60 s timeout, no redirects, no proxy, and the response capped at 70 MiB. `If-None-Match`
   carries the last verified commit. A `304` means there is nothing new. A `503` (`stale_mirror`, `no_bundle`), another
   error status, a network error or a TLS error is logged and the next hub is tried. A bundle that fails verification
   (below) is also logged and the next hub is tried. If no hub gives a usable bundle the result is `rejected` (some hub
   served one that failed a check) or `unreachable`.
2. **Decrypt and check the archive.** age decryption with the host's key. The plain archive must hold exactly `bundle`,
   `bundle.sig` and `bundle.tar.gz`, in that order, each a regular file within its size limit (4 KiB, 4 KiB, 64 MiB), and
   nothing else. The age stream is read to its end, so a truncated or altered ciphertext is refused.
3. **Verify the signature.** `ssh-keygen -Y verify -f <signers> -I infra-main -n infra-bundle -s <sig>` with the statement
   on stdin: the tool `infra-pull` already uses, run without a shell, with a 30 s timeout.
4. **Check the statement.** Strict parse (`internal/bundle`), then: `repo` is `KazuhaHub/infra`, `ref` is `refs/heads/main`,
   and `sha256` and `size` match `bundle.tar.gz`. Any failure here or in 2 and 3 is result `rejected`: nothing is
   extracted and nothing is applied.
5. **Forward only** (below).
6. **Extract** `bundle.tar.gz` into `<state>/releases/<commit>/`, safely and atomically (below). The newest three
   releases are kept.
7. **Apply** (apply mode only): in `<release>/infra`, `ansible-playbook -i inventory/hosts.yml --limit <host> site.yml`
   with `SOPS_AGE_KEY_FILE=<age key>`. The output goes to stderr, which is the journal. A non-zero exit is `failed`, and
   the applied state does not change, so the next cycle tries again (also when the hub answers `304`: the extracted
   release is applied again). On success the applied commit, statement time and time of the apply are written atomically.
   Like infra-pull, the same commit is applied again when the last success is more than 24 h old, which repairs drift.
   One run is stopped after an hour.
8. **Report.** `POST /v1/challenge`, decrypt the nonce with the age key, `POST /v1/report` with `appliedCommit`,
   `result`, a short `message` (at most 500 bytes, never ansible output) and `time`. It goes to the hub that served the
   bundle, then to the others until one accepts it. A report that cannot be delivered is logged and does not change the
   result. Nonces are never logged.

Results: `ok` (applied), `verified` (verify mode: fetched and verified, nothing applied), `unchanged` (nothing new, or an
older bundle was ignored), `failed` (ansible failed), `rejected` (signature, hash or format), `unreachable` (no hub gave
a bundle). `appliedCommit` in a report is the last commit ansible applied successfully, empty if there is none yet.

### Forward only

The bundle carries no git history, so the agent cannot ask "is the new commit a descendant of the applied one". It
compares the statement `time` instead. CI signs only the current `main`, and signs it when it becomes `main`, so a later
signed time means a later `main`; a replay of an old bundle carries an older time, and the signature does not allow
changing it. The rule:

- `time` is strictly greater than the newest statement time the agent has applied or verified: new, it is extracted
  (and applied in apply mode).
- Same commit and same time: nothing new; only the 24 h re-apply rule applies.
- Anything else, an older time or an equal time with another commit: ignored with a warning in the journal, not an error;
  the result is `unchanged` and the agent keeps working on what it already has (including retrying a failed apply).

The line is the newer of the applied and the verified time, not only the applied one. In verify mode nothing is applied,
and after a failed apply the newer bundle was still genuinely signed, so a hub that then serves an older one must not move
the agent back. A bundle from a wrong clock in CI, with a time in the past, would be ignored until a bundle with a later
time is signed; CI's clock is part of what is trusted.

### Extraction

`bundle.tar.gz` is extracted into a temporary directory under `releases/` and then renamed to `releases/<commit>`, so a
release directory is always complete. The extractor refuses: absolute paths, `..`, backslashes, a path that passes
through a symlink made by the archive, symlinks whose target is absolute or leaves the tree (a target may start with
`../` as often as the link's depth allows, and has no `..` after that), hard links to anything but an earlier regular
file of the archive, devices, FIFOs and every other type, a file that appears twice, and an archive without `infra/`. It stops at 512 MiB unpacked, and at 200000 entries. Files
keep their permission bits without setuid, setgid and sticky, and belong to the user that runs the agent. Go's
`os.Root` is a second guard: no file operation can leave the directory. A refused tarball is result `rejected`.

## Verify and apply mode

`verify` (the default) does everything up to and including extraction and reports `verified`, but never runs ansible. It is
for the first phase of a rollout: the agent proves on the real host that it reaches the hubs, decrypts, verifies and
extracts what CI signed, with no effect on the host. `apply` also runs ansible. Switching the mode needs a restart of the
service; the first cycle in apply mode applies the bundle that was already verified.

## State

```
/var/lib/infra-agent/            0700, root
  state.json                     0600, written atomically (apiVersion v1)
  lock                           flock; held by `run` for its whole life, so `run --once` and the daemon never overlap
  releases/<commit>/infra/...    the newest three extracted releases
```

`state.json` holds `applied` and `verified` (`commit`, `time` the statement time, `at`), `lastResult`, `lastMessage`,
`lastHub` and `lastCycle`. A state file that does not parse stops the agent with an error and is never replaced
silently, because it carries the forward-only line; after looking at it, remove it, and the agent starts from nothing.
A second `infra-agent run` exits with code 3 and the message `another infra-agent is running`.

## Running it beside infra-pull

Do not replace infra-pull in one step. On one host first:

1. Install the binary, the age key (already there for SOPS), `allowed_signers` and `agent.env` with `INFRA_AGENT_MODE=verify`.
   Register the host in the hub's config with its `agePublicKey`.
2. `infra-agent check-config`, then `infra-agent run --once`. Watch `status` and the hub's `status -o json` (`hosts[].report`
   shows `verified`).
3. Run the service in verify mode for a while next to infra-pull, which keeps applying.
4. Compare: the commit the agent verified is the one infra-pull applied. Then stop infra-pull's timer on that host and
   set `INFRA_AGENT_MODE=apply`. The two must never apply at once; ansible is not safe to run twice in parallel.
5. When that host has been quiet for some days, repeat for the next hosts.

The example unit is [infra-agent.service](infra-agent.service).

## Next steps

- An install script (`curl ... | sudo sh -s -- <token>`, see design.md) that writes `agent.env` and creates the age key.
  There is none yet: the files are placed by hand.
- Self-update from the signed releases, with fallback to the previous version.
- Certificates and IP lists over HTTPS, the kick port, alert mail (design.md, phase 3).
