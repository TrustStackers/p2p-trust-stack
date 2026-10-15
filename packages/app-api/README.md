# @p2p-trust-stack/app-api

The **application-facing API** of the P2P Trust Stack. This is the single module an
application imports: `createAgentStack()` returns a typed `TrustStack` whose domains
cover identity, connectivity, relationships, messaging, credentials, communities, names,
profiles, contexts and delegations — plus a closed event catalogue and the `Host` seam.

`app-api` depends on [`@p2p-trust-stack/core`](../core); `core` never depends on
`app-api`.

## Install

```bash
npm install @p2p-trust-stack/app-api
```

`@p2p-trust-stack/core` is installed with it.

> Requires **Node.js >= 22.5** (uses the built-in `node:sqlite`). Node-only — there is
> no browser build.

## Quick start

```ts
import { createAgentStack } from '@p2p-trust-stack/app-api';

const stack = await createAgentStack({ agent: { name: 'alice', passphrase: '…' } });

stack.on('message.received', (e) => console.log('message from', e.peerDid));
stack.on('connection.open', (e) => console.log('peer up', e.peerId));

await stack.start();

const me = await stack.identity.current();
const oobi = await stack.relationships.oobi();
await stack.relationships.connect(peerOobi);
await stack.messaging.send(peerDid, 'hello', { confidential: true });

await stack.stop();
```

`createAgentStack()` creates (or unlocks) the agent but does **not** start it — subscribe
first, then call `start()`, so no event is missed.

## The `TrustStack` surface

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

## Events

The event catalogue is **closed** (`STACK_EVENTS`): 30 names covering identity,
connectivity, messaging, relationships, credentials & invitations, communities &
governance, names & profiles, sync, and errors. Subscribe with `stack.on(name, handler)`;
replay retained events with `stack.replay(...)` / `stack.replayDurable(...)`, and take a
resumable cursor with `stack.cursor()`.

## The `Host` seam

`createNodeHost()` is the Node binding: it owns `P2PTS_HOME` and the per-agent layout
(directory, database, keystore) and provides `createAgent` / `unlockAgent`. Pass your own
`Host` to `createAgentStack({ host })` for a non-Node embedding.

## Capability scoping

`stack.asContext(contextId, { allow })` returns a **deny-by-default** view of the stack
for one provisioned app context. Anything not explicitly allowed — including every
unclassified method — is refused.

## License

Dual-licensed under **GPL-3.0-only** or a commercial license — see the repository's
`LICENSE` and `NOTICE`, and `COMMERCIAL-LICENSE.md` for the commercial terms.
