# infra-agent

The per-machine agent. It runs as root under systemd on every managed Linux host, fetches this host's config bundle from
the hubs over HTTPS, verifies it, applies it with ansible and reports the result. It only connects outward and opens no
port. The design follows Beszel: one env file, one token line. The bundle format is in [bundle.md](bundle.md), the hub
identity key and the pin in [hub-key.md](hub-key.md), the overall design in [design.md](design.md).

This is v1: it covers the bundle path (fetch, verify, extract, apply, report), the install script and the kick (below).
There is no self-update yet (see "Next steps"); IP lists are not part of it.

## Configuration

`/etc/infra/agent.env` (`--env-file` or `INFRA_AGENT_ENV_FILE` changes the path): one `KEY=VALUE` per line, `#`
comments, an optional pair of quotes around a value, no `export`. The same keys can be set in the process environment,
which wins over the file (so a systemd `EnvironmentFile=` or `Environment=` works as well). A key that is not in the
table, or a key set twice, is an error: the agent exits with code 2 and names the line.

| Key | Default | Meaning |
| --- | --- | --- |
| `INFRA_AGENT_TOKEN` | required | The `ih1.` join token from `infra-hub token`: the hubs, tried in the order given, and the pins of the hub identity key. It holds no secret. |
| `INFRA_AGENT_HOST` | required | This host's name in the inventory (letters, digits, `.`, `_`, `-`). It is the name in `/v1/bundle/<host>` and in `ansible-playbook --limit`. |
| `INFRA_AGENT_AGE_KEY` | `/etc/infra/age.key` | The host's age private key. It decrypts the bundle and the challenge, and is passed to ansible as `SOPS_AGE_KEY_FILE`. |
| `INFRA_AGENT_SIGNERS` | `/etc/infra/allowed_signers` | The `ssh-keygen` allowed_signers file with the CI key: `infra-main namespaces="infra-main,infra-bundle" ssh-ed25519 AAAA...`. It is the file infra-pull installs on the hosts. |
| `INFRA_AGENT_MODE` | `verify` | `verify` or `apply` (below). |
| `INFRA_AGENT_INTERVAL` | `5m` | Time between cycles, at least 10 s. Every wait gets a random difference of up to 10 %. |
| `INFRA_AGENT_STATE_DIR` | `/var/lib/infra-agent` | State directory (below). |
| `INFRA_AGENT_GITHUB_REPO` | empty (off) | Git URL of the infra repository, for the GitHub fallback (below), for example `git@github.com:KazuhaHub/infra.git`. |
| `INFRA_AGENT_GITHUB_KEY` | `/etc/infra/deploy_key` | The deploy key for that repository. Setting it without `INFRA_AGENT_GITHUB_REPO` is an error. |
| `INFRA_AGENT_GITHUB_APP_ID` | empty (off) | Numeric ID of the read-only GitHub App; when set, the fallback fetches over https with an installation token instead of ssh. Setting it without `INFRA_AGENT_GITHUB_REPO` is an error. |
| `INFRA_AGENT_GITHUB_APP_KEY` | `/etc/infra/github-app.pem` | The App's private key (PEM). Setting it without `INFRA_AGENT_GITHUB_APP_ID` is an error. |
| `INFRA_AGENT_GITHUB_KNOWN_HOSTS` | `/etc/infra/github_known_hosts` | The known_hosts file that pins GitHub's host key. Setting it without `INFRA_AGENT_GITHUB_REPO` is an error. |
| `INFRA_AGENT_LOG_FORMAT`, `INFRA_AGENT_LOG_LEVEL` | `text`, `info` | The `--log-format` and `--log-level` flags, which can be set in the file too. |

All paths must be absolute. An example:

```
# /etc/infra/agent.env  (0600, root)
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
infra-agent cert <name> [--hub URL] [--out-dir DIR]
                                  fetch a certificate from the hubs, decrypt it with the age key
infra-agent version
```

`run --once` exits 0 for `ok`, `verified` and `unchanged`; 1 for `failed` and `rejected`; 3 for `unreachable`, when
another infra-agent holds the lock (below), and when the run was interrupted by a signal (SIGINT, SIGTERM); 2 for a
configuration error (including a state directory or `releases/` with the wrong mode or owner). `status -o json` has `"apiVersion": "v1"`, camelCase
keys and RFC 3339 UTC times.

## One cycle

Between cycles `run` waits for the interval or for a kick (next section). Before the first cycle, `run` (not `--once`) waits a random delay of up to the interval or 60 s, whichever is shorter, so
that a fleet that starts together does not call the hubs together.

1. **Fetch.** `GET /v1/bundle/<host>` from each hub in order until one gives a usable answer, over TLS 1.3 with the pinned
   key as the only trust (`internal/hubtrust`), a 60 s timeout, no redirects, no proxy. `If-None-Match` carries the last
   verified commit. The ciphertext is decrypted as it arrives, through a reader that fails above 70 MiB; it is never held
   whole in memory. A `304` means there is nothing new, but only when an `If-None-Match` was sent and the hub's `ETag` is
   the commit sent; any other `304` is a hub error. A `503` (`stale_mirror`, `no_bundle`), another error status, a
   network error, a connection that breaks in the middle of a body, or a TLS error is logged and the next hub is tried.
   A bundle that fails verification (below) is also logged and the next hub is tried. So is every answer that says
   nothing new (a `304`, the same bundle, an older one): the other hubs may be ahead of a mirror that lags, so the agent
   asks them all, stops at the first newer bundle, and falls back to what it has verified (the answer of the first hub that
   had nothing new) only when every hub has answered. If no hub gives a usable bundle the result is `rejected` (some hub served one that failed a
   check) or `unreachable`.
2. **Decrypt and check the archive.** age decryption with the host's key. The plain archive must hold exactly `bundle`,
   `bundle.sig` and `bundle.tar.gz`, in that order, each a regular file within its size limit (4 KiB, 4 KiB, 64 MiB), and
   nothing else. The age stream is read to its end, so a truncated or altered ciphertext is refused.
3. **Verify the signature.** `ssh-keygen -Y verify -f <signers> -I infra-main -n infra-bundle -s <sig>` with the statement
   on stdin: the tool `infra-pull` already uses, run without a shell, with a 30 s timeout. A verification failure is a
   rejection; an `ssh-keygen` that cannot run or does not finish in 30 s is a fault of the host (result `failed`), not of
   the bundle.
4. **Check the statement.** Strict parse (`internal/bundle`), then: `repo` is `KazuhaHub/infra`, `ref` is `refs/heads/main`,
   and `sha256` and `size` match `bundle.tar.gz`. Any failure here or in 2 and 3 is result `rejected`: nothing is
   extracted and nothing is applied.
5. **Forward only** (below).
6. **Extract** `bundle.tar.gz` into `<state>/releases/<commit>/`, safely and atomically (below). The newest three
   releases are kept.
7. **Apply** (apply mode only): the agent first takes `flock` on `/var/lib/infra/lock`, the lock infra-pull and the
   bootstrap hold while they apply, and waits up to 30 minutes for it, so that two runs of ansible on one host can never
   overlap. It then writes `/var/lib/infra/lock.since` as infra-pull does (the epoch in seconds and a newline, through
   `lock.since.new` and a rename) and removes it when it lets go; infra-pull reads that file's age to tell a stuck holder
   from a working one, and calls a lock held for more than its `LOCK_MAX` (1800 s, the `TimeoutStartSec` of its unit)
   stuck. For that reason one ansible run is limited to 25 minutes here, inside `LOCK_MAX`; keep it so if either
   side changes. If it is still held after that the result is `failed` with the message `another run holds
   /var/lib/infra/lock`. Then, in `<release>/infra`, `ansible-playbook -i inventory/hosts.yml --limit <host> site.yml`
   with `SOPS_AGE_KEY_FILE=<age key>` and `INFRA_AGENT_RESTART_FILE=<state dir>/restart-requested` (see "Restarting
   from a configuration run"), in its own process group. The output goes to stderr, which is the journal. A
   non-zero exit is `failed`, and the applied state does not change, so the next cycle tries again (also when the hub
   answers `304`: the extracted release is applied again). On success the applied commit, the statement time of that
   bundle and the time of the apply are written atomically. Like infra-pull, the same commit is applied again when the
   last success is more than 24 h old, which repairs drift. One run is stopped after 25 minutes, and when the agent is
   stopped: SIGTERM to the process group, SIGKILL to the whole group after 30 s (skipped when the group is already gone).
8. **Report.** `POST /v1/challenge`, decrypt the nonce with the age key, `POST /v1/report` with `appliedCommit`,
   `result`, a short `message` (at most 500 bytes, never ansible output) and `time`. It goes to the hub that served the
   bundle, then to the others until one accepts it. When the serving hub is not the first one in the token, when no hub
   served, or when some hub served a rejected bundle, it goes to every hub, so that the first and the rejecting hub also
   learn what happened. A hub that served a rejected bundle is named in the message: `hub X served a rejected bundle:
   <reason>`, even when another hub then gave a good one. A report that cannot be delivered is logged and does not
   change the result. The report also lists those hubs in `rejectedHubs` (at most 8 hub URLs; `infra-hub status` shows
   them under the host's report). Nonces are never logged.

If the agent is stopped in the middle of a cycle it logs `interrupted` and leaves `lastResult` and the other last-cycle
fields of the state as they were.

Results: `ok` (applied), `verified` (verify mode: fetched and verified, nothing applied), `unchanged` (nothing new, or an
older bundle was ignored), `failed` (ansible failed, or a fault of the host), `rejected` (signature, hash or format),
`unreachable` (no hub gave a bundle). `appliedCommit` in a report is the last commit ansible applied successfully, empty if
there is none yet.

### Forward only

The bundle carries no git history, so the agent cannot ask "is the new commit a descendant of the applied one". It
compares the statement `time` instead. CI signs only the current `main`, and signs it when it becomes `main`, so a later
signed time means a later `main`; a replay of an old bundle carries an older time, and the signature does not allow
changing it. The line is the statement time of the newest **verified** bundle. The rule:

- `time` is strictly greater than that: new, it is extracted (and applied in apply mode).
- The same commit and the same time: nothing new; only the 24 h re-apply rule applies, to the verified bundle.
- Anything else, an older time or an equal time with another commit: ignored with a warning in the journal, not an error;
  the result is `unchanged` and the agent keeps working on the verified bundle (including retrying a failed apply). The
  applied bundle is never re-applied because it was replayed: after a newer bundle was verified but failed to apply, a
  replay of the applied (older) one is ignored, 24 h rule included, and the retry applies the newer one. The record of
  what was applied always takes its time from the bundle that was applied.

The line is the verified time, not the applied one: in verify mode nothing is applied, and after a failed apply the newer
bundle was still genuinely signed, so a hub that then serves an older one must not move the agent back. A bundle from a
wrong clock in CI, with a time in the past, would be ignored until a bundle with a later time is signed; CI's clock is
part of what is trusted.

**First floor.** A fresh agent has no mark, and would accept any validly signed old bundle, however old. So in a cycle (and
only there, never at startup) where the state has neither a verified nor an applied bundle, the agent reads infra-pull's
record `/var/lib/infra/applied`, one line `<commit> <unix applied_at>`, and takes `applied_at` as the minimum statement
time. That works because infra-pull applied an attested commit of `main` at `applied_at`, so any bundle signed at or
after that moment is that `main` or a newer one, and anything signed before it is older than what the host already runs.
Cases:

- no file: no floor; the cycle goes on.
- `applied_at` is 0: infra-pull writes `<commit> 0` when it seeds its floor and has not applied anything yet. The floor
  is unknown, so the cycle verifies nothing: result `unchanged`, message `waiting for infra-pull to record an applied
  time`. It is not an error, and the agent tries again next cycle.
- a file that is not in that form: result `failed` with a message that names the file. It is not an exit, so a daemon
  does not crash-loop on it; it repairs itself when the file does.

Once the state has a mark the file is not read. Consequence: the bundle of the `main` that infra-pull applied was signed
before `applied_at`, so on a host that is already current the agent reports `unchanged` until the next `main` is
signed; its first `verified` is that next bundle.

**What the time rule relies on.** Forward-only by statement time is only as good as the signing side's ordering: infra's
`attest-main.yml` must serialize its signing jobs (`concurrency` with `cancel-in-progress: false`), so that two runs
cannot sign out of order, and must keep its "main moved on" check, so that it never signs a commit that is no longer the
tip of `main`. Without those a newer `main` could be signed with an older time, and the agent would ignore it.

### Extraction

`bundle.tar.gz` is extracted into a temporary directory under `releases/` and then renamed to `releases/<commit>`, so a
release directory is always complete. The extractor refuses: absolute paths, `..`, backslashes, a path that passes
through a symlink made by the archive, symlinks whose target is absolute or leaves the tree (a target may start with
`../` as often as the link's depth allows, and has no `..` after that), hard links to anything but an earlier regular
file of the archive, devices, FIFOs and every other type, a file that appears twice or conflicts with another entry (a
file where a directory is needed, and the reverse), and an archive without `infra/`. It stops at 512 MiB unpacked, and
at 200000 entries. Files keep their permission bits without setuid, setgid and sticky, and belong to the user that runs
the agent. Go's `os.Root` is a second guard: no file operation can leave the directory. A refused tarball is result
`rejected`; a failure of the disk (no space, I/O error, permissions) is a fault of the host and result `failed`.

## Kick: applying a merge within about a mirror interval

The agent opens no port, so the hub cannot push. Instead the agent asks, and the hub answers late. Between two cycles
`run` sends `GET /v1/wait/<host>?etag=<commit>` to the first hub of the token that supports it, with the last verified
commit (empty when there is none). The hub:

- answers at once `200 {"apiVersion":"v1","changed":true,"commit":"<commit>"}` when the bundle it would serve now is not
  `etag`;
- otherwise holds the request until its mirror brings a `main-attestation` tip that changes the bundle (the mirror
  fetches every `mirrorIntervalSeconds`, 60 by default), then answers as above; or, after `waitTimeoutSeconds` (240 by
  default, 10 to 300), `200 {"apiVersion":"v1","changed":false}`.

The answer holds no secret: the commit is what the `ETag` of `/v1/bundle/<host>` shows anyway. On `changed` the agent
starts a cycle at once (at least 10 s after the previous cycle ended; when the kick names the commit whose apply just failed, the retry waits for the normal interval instead), which fetches, verifies and applies as always: a
kick decides only *when*, never *what*. So a wrong or hostile answer can cause at most an early poll.

- **The interval stays the upper bound.** The wait never extends the time between cycles: when the interval (plus or
  minus 10 %) is over, the cycle runs whether or not a hub answered.
- **Older hubs.** A hub that answers 404 (no `/v1/wait`) is not asked again for an hour; if no hub supports it the agent
  just sleeps, as before.
- **Errors** (a refused connection, 429, 5xx, a malformed answer) are logged and followed by a jittered back-off (15 s,
  doubling up to 5 minutes) inside the interval. An answer of "no change" is followed by a pause of at least 10 s. The
  agent never repeats a request without a pause.
- **No loop on a bundle that cannot be verified.** After a kick that named commit X, the next wait asks "anything newer
  than X" even if the cycle could not verify X (rejected, failed), so one bad bundle is one early cycle, not a series.
- **Limits on the hub.** At most 2 held requests per host and 256 in all (429 `too_many_waiters`), 12 requests a minute
  per peer address (burst 10), a 503 like `/v1/bundle` when the mirror is stale, 404 `unknown_host` for a host that is
  not registered. A held request ends when the client disconnects or the hub stops. A hold is shorter than the 5 minute
  idle timeout of common proxies and NAT tables; the agent gives up on a request after 5.5 minutes.

## Installing an agent (`GET /install`)

A host that is already on the tailnet is installed with one command (the pin and the address are those of the hub; the
token is the `ih1.` line of `infra-hub token`):

```
curl -fsSk --pinnedpubkey 'sha256//<pin>' https://<hub>:11883/install | sudo sh -s -- <ih1 token> <inventory-host-name> [--hub] [--force]
```

The hub serves a POSIX `sh` script (`text/plain`, built into the binary, no secret in it; the pin is what makes it
authentic, `-k` only drops the chain check that a self-signed certificate cannot pass). The script, as root, on Debian or
Ubuntu (apt) with x86_64 or aarch64:

1. installs only what is missing: `ansible-core`, `git`, `openssh-client`, `age`, `curl`, `openssl`, `ca-certificates` by
   apt (the same set as the infra repository's `infra_agent` role), and `sops` from its GitHub release (version 3.13.3,
   keep it in step with infra's `sops_version`), checked against the `sops-v3.13.3.checksums.txt` of that release;
2. creates `/etc/infra` (0700) and, if missing, `/etc/infra/age.key` (`age-keygen`), and prints the age **public** key;
3. writes `/etc/infra/agent.env` (0600) with the token, the host name and `INFRA_AGENT_MODE=apply`;
4. resolves the latest `infra-hub` release (the redirect of `releases/latest`, the tag must be `vX.Y.Z`), downloads
   `infra-agent-linux-<arch>`, checks it against the release's `SHA256SUMS`, runs `version` on it, installs it as
   `/usr/local/lib/infra-agent/<tag>/infra-agent` and moves the stable symlink `/usr/local/lib/infra-agent/infra-agent`;
5. writes `/etc/systemd/system/infra-agent.service` (the text of [infra-agent.service](infra-agent.service), with
   `ExecStart` at the stable symlink) and does **not** start it;
6. prints the next steps: register the host in the infra repository with the printed age public key and merge; copy
   `allowed_signers` from the infra repository to `/etc/infra/allowed_signers`; then `infra-agent check-config` and
   `systemctl enable --now infra-agent`.

`allowed_signers` is not fetched from the hub: the bundle is verified with it, so it has to come from the administrator,
not from the thing whose bundle it checks. A fresh host has no applied record, so the first bundle it accepts is any
validly signed one, however old (the guard that infra's `bootstrap-host.sh` offers, `INFRA_FLOOR`, is not part of this
script).

`--hub` is for hub hosts: it also creates `/etc/infra/deploy_key` (ed25519, no passphrase), prints its public key (add it
as a read-only deploy key of the infra repository on GitHub), writes `/etc/infra/github_known_hosts` with GitHub's
published ed25519 host key (the same constant as `bootstrap-host.sh`), and adds `INFRA_AGENT_GITHUB_REPO` to
`agent.env`.

It can be run again. An existing `age.key` is kept; an existing `agent.env` that differs from what the run would write
stops the run, and an existing unit that differs is left alone, unless `--force` is given, which keeps the old file as
`<file>.bak-<time>` and writes the new one (`--force` also replaces the age key, which then needs a new registration).
Everything that could refuse is checked before anything is changed. The script is one function called on its last line,
and every command that might read standard input gets `/dev/null`, so nothing can swallow the rest of a script that is
piped in.

## GitHub fallback (hub hosts)

If a commit breaks the HTTPS of every hub, no agent can fetch the fix from a hub. A host that sets
`INFRA_AGENT_GITHUB_REPO` can then take the bundle from GitHub itself. The fallback is turned on only on the hub hosts, which already use their key to mirror the repository from GitHub.

`INFRA_AGENT_GITHUB_REPO` must be an ssh URL (`git@host:path` or `ssh://...`); the key and known_hosts paths may use only
letters, digits, `.`, `_`, `-` and `/`, because they are passed to ssh through a shell. The fetch allows no transport but
ssh, uses `ConnectTimeout=15` and trusts only the given known_hosts file. If a fetch fails (a killed git can leave a lock
file behind, the repository may be damaged), the agent deletes `<state dir>/github.git` and fetches and reads once more in the same
cycle (this also covers a damaged object at an unchanged tip). A GitHub tree that holds no usable bundle (a missing file, a file over its limit, a malformed statement) is
`rejected`, but only when the second attempt finds the same.

The fallback runs only when no hub gave a usable bundle: every hub was unreachable or failed, or every answer was
rejected. A hub that answers "nothing new" (a `304`, the same bundle, an older one) is an answer, and GitHub is not asked.
The agent then fetches `refs/heads/main-attestation` (depth 1, forced, no tags) into the bare repository
`<state dir>/github.git` with the deploy key (`ssh -i`, `IdentitiesOnly`, `BatchMode`, `StrictHostKeyChecking=yes`, the
known_hosts file above; 3 minutes at most) and reads the same three files the hubs read. Nothing else differs: the
signature, the statement and hash, the forward-only rule, the extraction and the state are the same checks as for a
bundle from a hub, minus the decryption (the files are plain in git).

- A bundle that passes is verified, and applied in apply mode, as usual. The result's hub is `github`, the message says
  that the bundle came from GitHub because no hub gave one, and the agent logs a warning every time it uses the fallback.
  `status` shows it as the last hub.
- A bundle that fails a check is `rejected`. One that is not newer than what was verified is ignored, as for a hub.
- If the fetch fails, the result stays `unreachable` or `rejected` as the hubs left it, and the message gets
  `; GitHub fallback: <error>` appended.
- The report still goes to every hub, since none served the bundle.

### With a GitHub App

With `INFRA_AGENT_GITHUB_APP_ID` set, the fallback does not use ssh, the deploy key or known_hosts (those two settings are
ignored). `INFRA_AGENT_GITHUB_REPO` may then be the ssh form (`git@github.com:KazuhaHub/infra.git`) or the https form; the
host must be `github.com`, and the fetch uses `https://github.com/<owner>/<repo>.git`. The agent signs an app JWT with the
key, asks GitHub for an installation token narrowed to that repository and `contents: read`, keeps it in memory until 5
minutes before it expires, and gives it to git through `GIT_CONFIG_*` in the environment (an `http.extraheader` for
github.com, `http.followRedirects=false`; only https is allowed). It never appears in a command line, the URL, the
repository config or the log, and git runs with a clean environment. The retry (delete `github.git` and fetch again) and
every check after the fetch are the same. Without the App settings nothing changes: ssh with the deploy key. How to create
the App: [README](../README.md#github-app-optional-githubapp).

`check-config` prints the fallback settings (or `github fallback: off`) and checks that the key and the known_hosts file
can be read (with the App: that the App key can be read and parsed).

## Fetching a certificate

```
infra-agent cert <name> [--hub URL] [--out-dir DIR]
```

Reads `agent.env` like the other commands (the token with its hubs and pins, `INFRA_AGENT_HOST`, the age key; the
signers file and the state directory are not needed and the command takes no lock). For each hub of the token, in
order (or only `--hub`, which must be one of them: exit 2 otherwise), it calls `GET /v1/cert/<host>/<name>` over the
pinned TLS 1.3 connection, accepts at most 1 MiB plus the age overhead, decrypts the answer with the age key and checks
that it is a JSON object with the string fields `name` (the name asked for), `fullchain`, `privkey` and `not_after`.
The hub answers `404 not_found` for a name this host does not own and `503 not_serving` when the certificate is
missing or too close to expiry.

- **Without `--out-dir`** the first successful decrypted answer is printed on stdout (the JSON line, as `cert <name>`
  printed over SSH) and the command exits 0. Reasons for hubs that failed go to stderr.
- **With `--out-dir DIR`** every hub is asked, and for the hub at position `i` of the token (0-based) the command writes
  `DIR/<i>.json` (the decrypted answer) or `DIR/<i>.err` (a one-line reason). The directory is opened with
  `openat2` and `RESOLVE_NO_SYMLINKS` (a symlink anywhere in the path is refused), the stale `<i>.json` and `<i>.err`
  of every hub of the token are removed first, also with `--hub` (a symlink
  in their place is unlinked, never followed), and each file is created with `O_EXCL` under a temporary name in the
  directory, set to mode 0600 and to the directory's owner and group, synced and renamed into place. A file
  that cannot be written is reported on stderr and the other hubs are still handled.

Exit codes: 0 when at least one `.json` was written (or, without `--out-dir`, a hub answered), 1 when none was, 2 for a configuration or usage error (a name that is
not a DNS name, `--hub` not in the token, an unusable `--out-dir`).

## Verify and apply mode

`verify` (the default) does everything up to and including extraction and reports `verified`, but never runs ansible. It is
for the first phase of a rollout: the agent proves on the real host that it reaches the hubs, decrypts, verifies and
extracts what CI signed, with no effect on the host. `apply` also runs ansible. Before any host is switched to `apply`, the infra repository must stop and disable
`infra-pull.timer` on that host (that gate is landed separately in infra); the lock only keeps two runs that overlap
apart, it does not make two owners of one host safe. Switching the mode needs a restart of the service; the first cycle in apply mode applies the bundle that was already verified.

## Restarting from a configuration run

A run that changes the agent itself (a new binary, `agent.env` or the unit) must not restart `infra-agent.service`
from inside the run: systemd would stop the agent and kill its ansible halfway. Instead the playbook creates the file
named by `INFRA_AGENT_RESTART_FILE` (only set when the agent runs ansible; under infra-pull or by hand the variable is
absent and the playbook restarts the service as usual). A playbook that changes the unit still runs
`systemctl daemon-reload` in the same run, or the restart uses the old unit. After the cycle (its result saved and
reported, unless that failed) the agent removes the file and exits with status 0, and the unit's `Restart=always` starts
it again with the new binary, settings and unit. The unit must keep `Restart=always`: with `Restart=on-failure` an exit 0
is final and the agent stays down. `run --once` does not restart: it logs that a restart was asked for and leaves the
file, which the service removes when it starts. A request that is still there when the agent starts is removed (the new process already runs what was asked
for). A request that cannot be removed is ignored with an error in the journal, so the agent does not exit after
every cycle.

## State

```
/var/lib/infra-agent/            0700, owned by the user that runs the agent (root)
  state.json                     0600, written atomically (apiVersion v1)
  lock                           flock; held by `run` for its whole life, so `run --once` and the daemon never overlap
  restart-requested              created by a configuration run to ask for a restart; removed by the agent
  releases/<commit>/infra/...    the newest three extracted releases
```

`state.json` holds `applied` and `verified` (`commit`, `time` the statement time, `at`), `lastResult`, `lastMessage`,
`lastHub` and `lastCycle`. A state file that does not parse stops the agent with an error and is never replaced
silently, because it carries the forward-only line; after looking at it, remove it, and the agent starts from nothing.
A second `infra-agent run` exits with code 3 and the message `another infra-agent is running`. The agent creates a
missing state directory (0700) and never changes an existing one: if it exists and is not a real directory, is not owned
by the user running the agent, or does not have mode 0700, it refuses to run (exit 2) and says what is wrong. `releases/` gets the same check. A missing
`/var/lib/infra` (for infra-pull's lock) is created with mode 0700.

## Running it beside infra-pull

Do not replace infra-pull in one step. On one host first:

1. Install the binary, the age key (already there for SOPS), `allowed_signers` and `agent.env` with `INFRA_AGENT_MODE=verify`.
   Register the host in the hub's config with its `agePublicKey`.
2. `infra-agent check-config`, then `infra-agent run --once`. Watch `status` and the hub's `status -o json` (`hosts[].report`
   shows `verified`).
3. Run the service in verify mode for a while next to infra-pull, which keeps applying.
4. Compare: the commit the agent verified is the one infra-pull applied. Then stop infra-pull's timer on that host and
   set `INFRA_AGENT_MODE=apply`. The two must never apply at once; ansible is not safe to run twice in parallel. The
   agent already waits for infra-pull's lock `/var/lib/infra/lock` while it applies (step 7), which keeps a run that is in
   progress apart from it. Gating `infra-pull.timer` itself (so that it does not start while the agent owns the host)
   is done later, in the infra repository, as part of the cut-over; until then rely on the lock.
5. When that host has been quiet for some days, repeat for the next hosts.

The example unit is [infra-agent.service](infra-agent.service).

## Next steps

- Self-update from the signed releases, with fallback to the previous version.
- IP lists in the agent (the hub serves them at `GET /v1/iplist/<name>`), the CSR model for certificates, alert mail (design.md, phase 3).
