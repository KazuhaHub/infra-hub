# Config bundle format v1 (archive format 2 adds the Sigstore signature)

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

- `bundle.sigstore.json` (optional, new in v0.14.0): a Sigstore bundle (protobuf JSON, media type
  `application/vnd.dev.sigstore.bundle.v0.3+json`) made by `cosign sign-blob --bundle bundle.sigstore.json bundle` in the same
  workflow run, keyless: the GitHub Actions OIDC token, the public-good Fulcio and Rekor. It signs the statement file
  `bundle` (the artifact digest is the sha256 of its bytes) and carries the Fulcio certificate and the Rekor entry. The
  signing identity the agent requires is the certificate's subject alternative name
  `https://github.com/<owner/name>/.github/workflows/attest-main.yml@refs/heads/main` with OIDC issuer
  `https://token.actions.githubusercontent.com`; the same name is in the certificate whatever event started the run
  (push, schedule, workflow_dispatch), because the name is the workflow reference, and the event is a separate extension.
  The agent also pins the certificate's GitHub extensions (source repository and owner URIs and numeric IDs, ref, build
  signer, runner, source digest = the statement's commit); see agent.md.
  Later the ssh signature is dropped and this becomes the only signature; the file is optional until then.

Limits: bundle.tar.gz at most 64 MiB; statement at most 4 KiB; signature at most 4 KiB; bundle.sigstore.json at most
64 KiB (a real one is about 6 KiB).

## Hub delivery

`GET /v1/bundle/<host>` on the hub's HTTPS listener (TLS 1.3, pinned identity key).
- <host> must be a configured client; otherwise 404 `unknown_host` (same JSON error shape as other endpoints).
- The hub reads the files from the tip of `main-attestation` in its mirror. A missing or over-limit `bundle`, `bundle.sig`
  or `bundle.tar.gz`: 503 `no_bundle`. `bundle.sigstore.json` is optional: if it is missing or over its limit, the hub
  serves as if it did not exist.
  It parses the statement only to get the commit (strict format as above, else 503 `no_bundle`); it does NOT verify the
  signature or the hash (the agent does; the hub is not trusted for integrity).
- Mirror older than maxStaleSeconds: 503 `stale_mirror` (same rule as the SSH side).
- Response 200: `Content-Type: application/octet-stream`, `ETag: "<commit>"`, `Cache-Control: no-store`, body = age
  (binary, not armored) encryption to the host's agePublicKey of an uncompressed POSIX ustar archive (mode 0644, uid/gid 0,
  mtime = statement time, no other entries) in one of two formats, chosen by the request (below).
- **Archive format.** By default (no `X-Infra-Bundle-Format` request header, or the value `1`) the archive holds exactly
  three regular-file members in this order: `bundle`, `bundle.sig`, `bundle.tar.gz`. Agents before v0.14.0 reject any other
  member count, so a request without the header gets these three even when the branch has `bundle.sigstore.json`.
  With `X-Infra-Bundle-Format: 2` the archive holds four members in this fixed order: `bundle`, `bundle.sig`,
  `bundle.tar.gz`, `bundle.sigstore.json`; when the hub has no `bundle.sigstore.json` it answers with the three files (the
  agent then falls back according to its signature mode, [agent.md](agent.md)). A number above 2 is answered as 2; a value
  that is not a positive number is 400 `bad_format`. A hub older than v0.14.0 ignores the header and sends the three files.
  The `ETag` is the commit in both formats and every answer to this endpoint carries `Vary: X-Infra-Bundle-Format`, so a
  cache keeps the formats apart. (An agent that holds a bundle verified with the ssh signature and now requires Sigstore
  sends no `If-None-Match`, so it receives the files again instead of a 304.) A header was chosen over a query parameter
  so that the path, the logs and the 304 logic stay as they were.
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
- The plain ustar archive, built once per tip and format and shared by every host (about the size of `bundle.tar.gz`, up
  to 64 MiB; when there is no `bundle.sigstore.json` the two formats are the same archive and held once).
- The age ciphertext per host and format, kept while the archive plus all ciphertexts fit in 256 MiB; beyond that older hosts'
  ciphertext is dropped and rebuilt on demand.

Peak memory while a bundle is built is the tarball read from git (<= 64 MiB), the archive (<= 64 MiB) and one
ciphertext (<= 64 MiB) at the same time, about 192 MiB, on top of the cache of up to 256 MiB: budget roughly 450 MiB for
a hub that serves a maximal bundle. The files read from git are released as soon as the archive is built. Builds are
serialized, so concurrent requests do not multiply this. `infra-hub status` reads only the statement file.
- `infra-hub status` shows the commit and statement time the hub serves, or the reason it serves none
  (`bundle` in `-o json`: `served`, `commit`, `time`, or `reason` and `message`).

## Agent checks (for the later infra-agent)

Decrypt with /etc/infra/age.key; tar must have exactly those three members, or those three and `bundle.sigstore.json` as the
fourth; verify the signature (by the agent's signature mode: bundle.sig over bundle with
principal infra-main, namespace infra-bundle, against the pinned allowed_signers, and/or bundle.sigstore.json over bundle
against the embedded Sigstore trusted root and the workflow identity above, with a Rekor entry and a verified time); parse the statement strictly; repo/ref
match; sha256 and size of bundle.tar.gz match; forward only: the statement time is strictly greater than the newest applied
or verified one (the bundle has no git history, so a descendant check is not possible; the reasoning is in
[agent.md](agent.md)); then extract. Implemented by `infra-agent` ([agent.md](agent.md)).
