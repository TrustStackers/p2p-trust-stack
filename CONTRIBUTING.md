# Contributing to the P2P Trust Stack

Thank you for your interest in contributing! This document covers local
development, the contribution workflow, and the project's hard rules.

The repository is a monorepo of two published packages —
[`@p2p-trust-stack/core`](./packages/core) (the protocol engine) and
[`@p2p-trust-stack/app-api`](./packages/app-api) (the application-facing agent
API, which depends on `core`).

## Before you start: sign the CLA

All contributions are accepted only under the [Contributor License
Agreement](./CLA.md). This lets the project stay dual-licensed (GPL-3.0-only +
commercial). Opening a pull request constitutes your acceptance of the CLA. The
requirement is enforced on every PR (currently by maintainer review; an
automated CLA check will be added).

## Dependency policy (hard rule)

This project is **dual-licensed**, and its commercial license can only cover
the project's own code. Therefore:

- **All runtime dependencies MUST be permissively licensed** (MIT, Apache-2.0,
  BSD, or ISC).
- **No copyleft dependencies** (GPL, AGPL, LGPL, SSPL, EUPL) may be added to
  `dependencies`. If a feature needs one, raise it in an issue first.
- CI will fail on new copyleft runtime dependencies.

## Local development

```bash
# Prereqs: Node.js >= 22.5, npm
npm install          # installs both workspaces
npm run build        # tsc -> dist/ for both packages
npm test             # both test suites
npm run verify       # typecheck + test + packed-tarball smoke test
```

## Workflow

1. Open an issue describing the change (bug, feature, doc).
2. Fork and create a branch.
3. Make your change; add or update tests.
4. Run `npm run typecheck` and `npm test`.
5. Open a pull request. Keep it focused and describe the motivation.

## Code style

- TypeScript strict mode is on; keep `tsc --noEmit` clean.
- Match existing naming and module structure.
- Prefer small, typed, exported functions; avoid new global state.

## License of contributions

By contributing, you agree your contribution is licensed under the same
dual-license terms as the rest of the project (see [CLA.md](./CLA.md) and
[LICENSE](./LICENSE)).
