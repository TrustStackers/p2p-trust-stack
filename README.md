# @p2p-trust-stack/core — P2P Trust Stack

The core protocol-stack library for the **P2P Trust Stack**: a libp2p-based
implementation of the Trust Spanning Protocol (TSP), decentralized DID
creation and rotation, an encrypted SQLite keystore, relationships/OOBI,
Verified Trust Communities (VTCs), and verifiable credentials.

This package is the **open-source core**. It is the protocol layer that any
Node.js application can embed to participate in the network.

## Install

```bash
npm install @p2p-trust-stack/core
```

> Requires **Node.js >= 22.5** (uses the built-in `node:sqlite`). This is a
> **Node-only** library — there is no browser support.

## Peer dependency: libp2p

This library does **not** create its own libp2p node. You construct a
`libp2p` node (with your own transports/encryption/muxers) and pass it to
`Libp2pTransport`. Declare `libp2p` as your own dependency:

```bash
npm install libp2p
```

```ts
import { createLibp2p } from 'libp2p'
import { Libp2pTransport } from '@p2p-trust-stack/core/transport'

const node = await createLibp2p({ /* your transports, noise, yamux, ... */ })
const transport = new Libp2pTransport(node)
```

## Module map

| Subpath | Contents |
|---|---|
| `@p2p-trust-stack/core/crypto` | Ed25519/X25519, SHA-256, Blake2b, HKDF, HPKE-Auth, CESR codec |
| `@p2p-trust-stack/core/did` | `did:peer:4` create/resolve, VID method, rotation, name resolution |
| `@p2p-trust-stack/core/keystore` | SQLite + AES-256-GCM + Argon2id encrypted keystore |
| `@p2p-trust-stack/core/tsp` | TSP message seal/open (GEN, RFI, RFA, CONFIDENTIAL) |
| `@p2p-trust-stack/core/transport` | `TspTransport` interface + libp2p adapter |
| `@p2p-trust-stack/core/relationship` | Relationship manager, store, OOBI, ceremony |
| `@p2p-trust-stack/core/vtc` | VTC/VRC types, codec, store |
| `@p2p-trust-stack/core/tx` | Transaction coordinator, ceremonies, participants |

## License

**Dual-licensed.** See [LICENSE](./LICENSE) (GPL-3.0) or
[COMMERCIAL-LICENSE-OUTLINE.md](./COMMERCIAL-LICENSE-OUTLINE.md) for the
commercial alternative. See [NOTICE](./NOTICE) for third-party attribution.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). All contributors must sign the
[Contributor License Agreement](./CLA.md).

## Security

See [SECURITY.md](./SECURITY.md) for reporting vulnerabilities.
