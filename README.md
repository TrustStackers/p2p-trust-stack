# P2P Trust Stack

A libp2p-based implementation of the **Trust Spanning Protocol (TSP)**, decentralized
DID creation and rotation, an encrypted SQLite keystore, relationships/OOBI, Verified
Trust Communities (VTCs), and verifiable credentials — published as **two npm packages**.

The stack is a monorepo of two packages:

| Package | Role | Depends on |
|---|---|---|
| [`@p2p-trust-stack/core`](./packages/core) | The protocol engine: crypto primitives, DIDs, the encrypted keystore, TSP, transport, relationships, VTCs/VRCs, the transaction coordination layer, and the shared data layer. | — |
| [`@p2p-trust-stack/app-api`](./packages/app-api) | The application-facing agent API: `createAgentStack()`, the typed `TrustStack` surface (identity, connectivity, relationships, messaging, credentials, communities, names, profiles, contexts, delegations), the event bus, and the `Host` seam. | `@p2p-trust-stack/core` |

**The dependency direction is one-way:**

```
@p2p-trust-stack/app-api  ──depends on──▶  @p2p-trust-stack/core
```

`app-api` builds on `core`; `core` never depends on `app-api`. Install the whole stack
(`app-api`) to build an application, or embed just the protocol layer (`core`) to speak
TSP directly.

## Requirements

- **Node.js >= 22.5** — the stack uses the built-in `node:sqlite`.
- **Node-only.** There is no browser build.
- **libp2p is a peer dependency of `core`** (`libp2p` + `@libp2p/interface`). The
  transport does not create a libp2p node for you — you construct one and hand it in.

## Install

Application developers — install the app API; `core` comes with it:

```bash
npm install @p2p-trust-stack/app-api
```

Protocol-only embedders — install just the core:

```bash
npm install @p2p-trust-stack/core
```

If you use the core transport, declare libp2p yourself:

```bash
npm install libp2p @libp2p/interface
```

## Quick start — the app API

`createAgentStack()` is the single entry point. It creates (or unlocks) an agent but does
**not** start it — call `start()` after subscribing, so no event is missed.

```ts
import { createAgentStack } from '@p2p-trust-stack/app-api';

const stack = await createAgentStack({ agent: { name: 'alice', passphrase: '…' } });

stack.on('message.received', (e) => console.log('message from', e.peerDid));
stack.on('connection.open', (e) => console.log('peer up', e.peerId));

await stack.start();

// Domains
const me = await stack.identity.current();
const oobi = await stack.relationships.oobi();
await stack.relationships.connect(peerOobi);
await stack.messaging.send(peerDid, 'hello', { confidential: true });
```

`TrustStack` exposes these domains: `identity`, `connectivity`, `relationships`,
`messaging`, `credentials`, `communities`, `names`, `profiles`, `contexts`, `delegations`,
plus the event bus (`on` / `once` / `off` / `replay` / `replayDurable` / `cursor`) and
`asContext()` capability scoping. See the [app-api README](./packages/app-api).

## Quick start — the core

```ts
import { createLibp2p } from 'libp2p';
import { Libp2pTransport } from '@p2p-trust-stack/core/transport';
import { createDidPeer4 } from '@p2p-trust-stack/core/did';

const node = await createLibp2p({ /* your transports, noise, yamux, … */ });
const transport = new Libp2pTransport(node);

const { did, didDocument } = createDidPeer4();
```

## Package contents

### `@p2p-trust-stack/core`

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
| `@p2p-trust-stack/core/tsp-handlers` | TSP protocol envelope types |
| `@p2p-trust-stack/core/util` | Small shared utilities (dedup log) |

The package ships `migrations/` and `SCHEMA_VERSION` alongside `dist/`.

### `@p2p-trust-stack/app-api`

| Domain | Methods |
|---|---|
| `identity` | `current`, `sign`, `list`, `create`, `import`, `activate`, `deactivate`, `recoveryState`, `lookup` |
| `connectivity` | `health`, `ready`, `status`, `refresh`, `connectUtility`, `utilityStatus`, `pushIdentity`, `networkProfile`, `networkChanged`, `explainFailure` |
| `relationships` | `oobi`, `connect`, `connectDiscovered`, `reconnect`, `duplicateNotice`, `list`, `get`, `disconnect`, `acknowledge`, `ceremonyStatus`, `resetCeremony`, `verify`, `vrc`, `dtgVrc`, `graph`, `debug` |
| `messaging` | `send`, `transcript`, `latest`, `unread`, `clear` |
| `credentials` | `list`, `issue`, `verify`, `signatures`, `revoke`, `invitations`, `declineInvitation`, `acceptInvitation`, `viewModels` |
| `communities` | `list`, `governanceDocs`, `detail`, `checkName`, `parents`, `adminCandidates`, `invite`, `create`, `governanceProposals`, `propose`, `approve`, `ceremonyLog`, `ceremonyLogThread`, `pendingCeremonies`, `approveCeremony`, `ceremony`, `resetCeremony` |
| `names` | `register`, `resolve`, `revoke`, `list` |
| `profiles` | `list`, `create`, `update`, `remove`, `claims`, `addClaim`, `updateClaim`, `removeClaim`, `card`, `syncStatus` |
| `contexts` | `provision`, `list`, `revoke`, `get`, `isExpired` |
| `delegations` | `list`, `create`, `revoke` |

Plus the **closed event catalogue** (30 events), the **`Host` seam** (`createNodeHost`),
the durable stores (`createAgentEventsStore`, `createAgentMessagesStore`), and the typed
errors (`StackError`, `NoActiveAgentError`, `CapabilityError`, `NotImplementedError`,
`UtilityServerUnavailableError`).

## Repository layout

```
packages/
  core/      @p2p-trust-stack/core
  app-api/   @p2p-trust-stack/app-api
scripts/     smoke-pack.mjs — packed-tarball smoke test
```

## Development

```bash
npm install          # installs both workspaces
npm run build        # build both packages (tsc)
npm run typecheck    # build, then tsc --noEmit for both
npm test             # both test suites
npm run smoke:pack   # pack both tarballs and verify the shipped assets
npm run verify       # typecheck + test + smoke:pack
```

## License

**Dual-licensed.** Use the stack under **GPL-3.0-only** — see [LICENSE](./LICENSE) —
or under a commercial license — see [COMMERCIAL-LICENSE.md](./COMMERCIAL-LICENSE.md).
See [NOTICE](./NOTICE) for the license-reference declaration, third-party
attribution, and trademark terms.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). All contributors must sign the
[Contributor License Agreement](./CLA.md).

## Security

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.
