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
- Rate limited per client IP like /v1/challenge (429 `rate_limited`). Encrypted results are cached in memory, one per
  host, for the current tip of `main-attestation` only: when the branch moves, every older entry is dropped.
- `infra-hub status` shows the commit and statement time the hub serves, or the reason it serves none
  (`bundle` in `-o json`: `served`, `commit`, `time`, or `reason` and `message`).

## Agent checks (for the later infra-agent)

Decrypt with /etc/infra/age.key; tar must have exactly those three members; verify bundle.sig over bundle with
principal infra-main, namespace infra-bundle, against the pinned allowed_signers; parse the statement strictly; repo/ref
match; sha256 and size of bundle.tar.gz match; commit is the applied commit or a descendant (forward only); then extract.
