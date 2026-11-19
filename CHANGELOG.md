# Changelog

## Unreleased

### Changed

- The command line is built with cobra: `infra-hub serve`, `status`, `iplist accept <provider>`,
  `iplist history <list> [--limit N]` and `version`, plus `--version`. Flags are `--long-name` and can come from
  `INFRA_HUB_<NAME>` environment variables. Exit codes are 0, 1, 2 (usage) and 3 (not ready).
- Logging uses `log/slog` on stderr: text by default, `--log-format json`, `--log-level`. Messages are short
  lower-case phrases with attributes. Registered secrets, private key blocks and URL credentials are redacted from
  every record.
- `status -o json` is a new document: `"apiVersion": "v1"`, lower camelCase keys, `...Seconds` units, RFC 3339 UTC
  times, hosts, certificates, providers and lists as arrays sorted by name, missing values omitted. `status` prints a
  short table by default. `iplist history` prints the same style of document.
- Releases embed the version, commit and build date: `infra-hub --version` prints
  `infra-hub 0.2.0 (commit abcdef0, built 2026-11-19)`.

### Deprecated

- The old spellings `-config`, `-no-refs`, `-limit`, `iplist-accept` and `iplist-history` still work for this release
  and print a warning on stderr. They will be removed in the next release.
- The previous snake_case `status` JSON is kept as the hidden `status --format legacy`. It stays the default only when
  the old `-config` spelling is used and neither `-o` nor `--format` is given, so a monitor that has not been updated
  keeps working. `iplist-history` keeps printing the previous JSON as well.
