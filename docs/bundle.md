# Config bundle format v1

The shared contract between the CI of KazuhaHub/infra, infra-hub and infra-agent. The hub implements the delivery side
(`internal/httpsapi/bundle.go`); the statement parser, the archive writer and the reader of the mirror are in
`internal/bundle`, which the agent reuses.

Produced by infra's CI workflow attest-main.yml in the same run that signs the attestation, and published on the
orphan branch `main-attestation` next to `attestation` and `attestation.sig` (those two stay exactly as they are; infra-pull
reads only them). Three new files:

- `bundle.tar.gz`: `git archive --format=tar.gz --prefix=infra/ <COMMIT>` of the attested commit (the tree only, no .git).
- `bundle`: the statement, ASCII, LF line endings, exactly these 7 lines in this order, ending with a newline:
    infra-bundle v1
    repo <owner/name>            e.g. KazuhaHub/infra
    ref refs/heads/main
    commit <40 lower-case hex>   the same commit as the attestation of this run
    time <unix seconds>
    sha256 <64 lower-case hex>   of bundle.tar.gz
    size <decimal bytes>         of bundle.tar.gz
- `bundle.sig`: `ssh-keygen -Y sign -n infra-bundle -f <INFRA_ATTEST_KEY> bundle` (same key as the attestation,
  namespace `infra-bundle`, principal `infra-main`). allowed_signers lines carry namespaces="infra-main,infra-bundle".

Limits: bundle.tar.gz at most 64 MiB; statement at most 4 KiB; signature at most 4 KiB.

## Hub delivery

`GET /v1/bundle/<host>` on the hub's HTTPS listener (TLS 1.3, pinned identity key).
- <host> must be a configured client; otherwise 404 `unknown_host` (same JSON error shape as other endpoints).
- The hub reads the three files from the tip of `main-attestation` in its mirror. Missing or over-limit: 503 `no_bundle`.
  It parses the statement only to get the commit (strict format as above, else 503 `no_bundle`); it does NOT verify the
  signature or the hash (the agent does; the hub is not trusted for integrity).
- Mirror older than maxStaleSeconds: 503 `stale_mirror` (same rule as the SSH side).
- Response 200: `Content-Type: application/octet-stream`, `ETag: "<commit>"`, `Cache-Control: no-store`, body = age
  (binary, not armored) encryption to the host's agePublicKey of an uncompressed POSIX ustar archive with exactly three
  regular-file members in this order: `bundle`, `bundle.sig`, `bundle.tar.gz` (mode 0644, uid/gid 0, mtime = statement
  time, no other entries).
- `If-None-Match: "<commit>"` matching the current commit: 304 with the ETag, no body.
- Only GET and HEAD are allowed (405 `method_not_allowed` otherwise). Errors use the JSON error shape of
  [conventions.md](conventions.md).
- Rate limited per client IP, with the same limiter and the same address rule as /v1/challenge (IPv6 counted per /64),
  429 `rate_limited`: 30 requests a minute, burst 20. This is looser than /v1/challenge (12 a minute, burst 10) on
  purpose. The challenge limit exists because each challenge occupies a slot in a bounded nonce store, so one address
  must not be able to crowd a host's real nonce out; a bundle request holds no such state, an unchanged poll is a 304
  answered from memory, and many machines can legitimately share one address (NAT, a site gateway). The expensive part,
  building and encrypting a bundle, happens once per tip and host and is serialized, so the limit only has to stop
  abuse, not protect the build.
- The time in the statement must be 1 to 8589934591 (the largest mtime of a ustar header); anything else is `no_bundle`.

### Caching and memory

The hub keeps state for the current tip of `main-attestation` only; a new tip drops all of it. The tip is read under the
same lock that guards the cache, so a request can never work from an older tip than one already seen.

- The parsed statement of the tip (read once; the signature and the tarball are only checked to exist and to be within
  their limits). An `If-None-Match` for the current commit is answered from it with a 304, without reading or building
  anything else.
- The plain ustar archive, built once per tip and shared by every host (about the size of `bundle.tar.gz`, up to 64 MiB).
- The age ciphertext per host, kept while the archive plus all ciphertexts fit in 256 MiB; beyond that older hosts'
  ciphertext is dropped and rebuilt on demand.

Peak memory while a bundle is built is the tarball read from git (<= 64 MiB), the archive (<= 64 MiB) and one
ciphertext (<= 64 MiB) at the same time, about 192 MiB, on top of the cache of up to 256 MiB: budget roughly 450 MiB for
a hub that serves a maximal bundle. The files read from git are released as soon as the archive is built. Builds are
serialized, so concurrent requests do not multiply this. `infra-hub status` reads only the statement file.
- `infra-hub status` shows the commit and statement time the hub serves, or the reason it serves none
  (`bundle` in `-o json`: `served`, `commit`, `time`, or `reason` and `message`).

## Agent checks (for the later infra-agent)

Decrypt with /etc/infra/age.key; tar must have exactly those three members; verify bundle.sig over bundle with
principal infra-main, namespace infra-bundle, against the pinned allowed_signers; parse the statement strictly; repo/ref
match; sha256 and size of bundle.tar.gz match; commit is the applied commit or a descendant (forward only); then extract.
