# @p2p-trust-stack/core

The **protocol engine** of the P2P Trust Stack: a libp2p-based implementation of the
Trust Spanning Protocol (TSP), decentralized DID creation and rotation, an encrypted
SQLite keystore, relationships/OOBI, Verified Trust Communities (VTCs), verifiable
credentials, and the transaction coordination layer.

`core` is the lower half of the stack. The application-facing API,
[`@p2p-trust-stack/app-api`](../app-api), depends on it — **not the other way round.**

## Install

```bash
npm install @p2p-trust-stack/core
```

> Requires **Node.js >= 22.5** (uses the built-in `node:sqlite`). Node-only — there is
> no browser build.

### Peer dependencies

`core` does **not** create its own libp2p node. You construct one (with your own
transports, encryption and muxers) and pass it to `Libp2pTransport`. Declare libp2p
yourself:

```bash
npm install libp2p @libp2p/interface
```

```ts
import { createLibp2p } from 'libp2p';
import { Libp2pTransport } from '@p2p-trust-stack/core/transport';

const node = await createLibp2p({ /* your transports, noise, yamux, … */ });
const transport = new Libp2pTransport(node);
```

## Module map

| Subpath | Contents |
|---|---|
| `@p2p-trust-stack/core/crypto` | Ed25519/X25519, SHA-256, Blake2b, HKDF, HPKE-Auth, CESR codec, post-quantum (ML-KEM / ML-DSA) |
| `@p2p-trust-stack/core/did` | `did:peer:4` and `did:scid:vh` create/resolve, rotation, witness attestation, name resolution |
| `@p2p-trust-stack/core/keystore` | SQLite + AES-256-GCM + Argon2id encrypted keystore |
| `@p2p-trust-stack/core/tsp` | TSP v3 message seal/open (GEN, RFI, RFA, RFD, CONFIDENTIAL) |
| `@p2p-trust-stack/core/transport` | `TspTransport` interface + libp2p adapter, bootstrap client, relay health |
| `@p2p-trust-stack/core/relationship` | Relationship manager/store, OOBI, RFI/RFA ceremony, VRC minting |
| `@p2p-trust-stack/core/vtc` | VTC/VRC types, codec, store |
| `@p2p-trust-stack/core/tx` | Transaction coordination layer (coordinator, ceremonies, participants, operation proofs) |
| `@p2p-trust-stack/core/exchange` | Computed Record Exchange (CRE) — recordset catalog, engine, watermarks |
| `@p2p-trust-stack/core/db` | DataSource abstraction, migrations (20 shipped `.sql` files), typed repositories |
| `@p2p-trust-stack/core/services` | Shared business logic (VTA/VTC creation, profiles, recovery, policy engine, credential factory) |
| `@p2p-trust-stack/core/platform` | `P2PTS_HOME` resolution and network detection |
| `@p2p-trust-stack/core/config` | Config loaders (typed `.env` → `BootstrapEnv`, `buildBootstrapUrls`; logging block → `applyLoggingEnv`) |
| `@p2p-trust-stack/core/tsp-handlers` | TSP protocol envelope types |
| `@p2p-trust-stack/core/util` | Small shared utilities (leveled `logger`, dedup log) |

The package ships `migrations/` (20 SQL files) and `SCHEMA_VERSION` alongside `dist/`.

## Examples

```ts
// did:peer:4 identity
import { createDidPeer4, resolveDidPeer4 } from '@p2p-trust-stack/core/did';
const { did, didDocument } = createDidPeer4();

// Encrypted keystore
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore';
const store = new SqliteKeyStore('/path/p2pts-keystore.db');

// TSP message seal/open
import { tspSeal, tspOpen } from '@p2p-trust-stack/core/tsp/v3';
```

## Logging

Every log line the stack emits goes through one dependency-free gate,
`@p2p-trust-stack/core/util/logger`. Verbosity is controlled by the `P2PTS_LOG_LEVEL`
environment variable — or programmatically with `setLogLevel()` — and defaults to
**`warn`**, so the package stays quiet unless you ask for more.

| Level | Emits |
|---|---|
| `silent` | nothing |
| `error` | errors only |
| `warn` | errors + warnings **(default)** |
| `info` | + lifecycle / state changes |
| `debug` | + per-message wire traces |

```bash
P2PTS_LOG_LEVEL=info node my-app.js
```

```ts
import { setLogLevel, setLogSink } from '@p2p-trust-stack/core/util/logger';

setLogLevel('debug');                                    // or 'silent'
setLogSink((level, args) => myLogger[level](...args));   // route instead of suppress
```

### Setting it from a config file instead

`P2PTS_LOG_LEVEL=info node …` is POSIX-shell syntax, so it cannot live in a
`package.json` script that has to run on Windows, and it does not exist at all where a
native host launches Node (Capacitor). `config/logging-env.ts` reads the same two keys
out of a `.env`, so an app can keep its verbosity in a file:

```ts
import { applyLoggingEnv } from '@p2p-trust-stack/core/config/logging-env';

applyLoggingEnv({ path: '/etc/my-app/.env' });   // cannot throw
```

```
# .env
P2PTS_LOG_LEVEL=info
CEREMONY_TRACE=1
```

The resolved order is **`setLogLevel()` > the config file > `P2PTS_LOG_LEVEL` > the
default**, so an embedder's explicit call always wins, and the environment variable
still works exactly as documented above. A missing, unreadable or malformed file is
never fatal — it just leaves logging at the next rung. `getEffectiveLogging()` reports
what is actually in force.

`CEREMONY_TRACE=1` is separate from the level on purpose: it emits the `[CEREMONY]`
OOBI→RFI→RFA trace lines and is **not** silenced by `P2PTS_LOG_LEVEL=silent`, nor
switched on by `debug`. `setCeremonyTrace()` overrides it programmatically.

## License

Dual-licensed under **GPL-3.0-only** or a commercial license — see the repository's
`LICENSE` and `NOTICE`, and `COMMERCIAL-LICENSE.md` for the commercial terms.
