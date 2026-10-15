# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Leveled, dependency-free logger (`@p2p-trust-stack/core/util/logger`) — every log
  line the stack emits now routes through one gate, controlled by the `P2PTS_LOG_LEVEL`
  environment variable (`silent` | `error` | `warn` | `info` | `debug`) or programmatically
  with `setLogLevel()` / `setLogSink()`. The default is `warn`, so the packages are quiet
  unless a host asks for more.
- Initial public monorepo scaffold: two published packages
  (`@p2p-trust-stack/core` and `@p2p-trust-stack/app-api`), dual-license
  (GPL-3.0 + commercial), `exports` maps, build config, and governance docs.

## [0.1.0] - TBD

### Added
- `@p2p-trust-stack/core` — initial public release of the protocol stack
  (`crypto`, `did`, `keystore`, `tsp`, `transport`, `relationship`, `vtc`, `tx`,
  plus the shared `db`, `services`, `platform`, `exchange` and `tsp-handlers`
  modules).
- `@p2p-trust-stack/app-api` — initial public release of the agent application
  API (`createAgentStack`, the `TrustStack` domains, the closed event
  catalogue, the `Host` seam, the durable stores and the DTOs).

[Unreleased]: https://github.com/TrustStackers/p2p-trust-stack/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/TrustStackers/p2p-trust-stack/releases/tag/v0.1.0
