# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-30

### Added
- Leveled, dependency-free logger (`@p2p-trust-stack/core/util/logger`) — every log
  line the stack emits now routes through one gate, controlled by the `P2PTS_LOG_LEVEL`
  environment variable (`silent` | `error` | `warn` | `info` | `debug`) or programmatically
  with `setLogLevel()` / `setLogSink()`. The default is `warn`, so the packages are quiet
  unless a host asks for more.
- Logging from a config file (`@p2p-trust-stack/core/config/logging-env`) — an app can
  keep its verbosity in a `.env` (`P2PTS_LOG_LEVEL`, `CEREMONY_TRACE`) instead of an
  environment variable, because `P2PTS_LOG_LEVEL=info node …` is POSIX-shell syntax that
  cannot live in a `package.json` script on Windows and does not exist where a native host
  launches Node (Capacitor). Resolution order is `setLogLevel()` > config file >
  `P2PTS_LOG_LEVEL` > `warn`, and a missing or malformed file is never fatal.
  Entry points: `applyLoggingEnv()` / `getEffectiveLogging()`.
- `setCeremonyTrace()` / `isCeremonyTraceEnabled()` (`core/relationship/ceremony-trace`) —
  the `[CEREMONY]` OOBI→RFI→RFA trace is now switchable programmatically and from a config
  file, not only via the `CEREMONY_TRACE` environment variable.
- `createLoggingConfigApi()` (`@p2p-trust-stack/app-api`) — the `logging-config` domain, so
  every front end reads and applies the same `.env` logging block identically.
- Bootstrap/relay configuration domain (`@p2p-trust-stack/app-api`
  `domains/bootstrap-config`) — typed access to the bootstrap/relay `.env` for front ends,
  including the selectable-VTN role-split `.env`.
- Ordered dial-candidate ladder (`@p2p-trust-stack/core/transport/dial-candidates`) and a
  hardened relay-health check (`core/transport/relay-health`), so connections survive
  relay-only and NAT'd paths.

### Changed
- `explainFailure()` now distinguishes a `connection` failure (a join or connect — nothing
  was kept locally, and a retry may be running) from a `mutation` (accepted locally and
  queued for the server), so it no longer tells a user their "change has been kept locally"
  after a failed connection.

### Fixed
- Agents on separate routers behind NAT that share a `192.168.1.x` subnet are no longer
  treated as if they were on the same LAN.
- Transport: `bootstrap-client` and `libp2p-transport` no longer stall or crash on slow or
  interrupted server responses.

## [0.1.0] - TBD

### Added
- `@p2p-trust-stack/core` — initial public release of the protocol stack
  (`crypto`, `did`, `keystore`, `tsp`, `transport`, `relationship`, `vtc`, `tx`,
  plus the shared `db`, `services`, `platform`, `exchange` and `tsp-handlers`
  modules).
- `@p2p-trust-stack/app-api` — initial public release of the agent application
  API (`createAgentStack`, the `TrustStack` domains, the closed event
  catalogue, the `Host` seam, the durable stores and the DTOs).
- Initial public monorepo scaffold: two published packages
  (`@p2p-trust-stack/core` and `@p2p-trust-stack/app-api`), dual-license
  (GPL-3.0 + commercial), `exports` maps, build config, and governance docs.

[Unreleased]: https://github.com/TrustStackers/p2p-trust-stack/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/TrustStackers/p2p-trust-stack/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TrustStackers/p2p-trust-stack/releases/tag/v0.1.0
