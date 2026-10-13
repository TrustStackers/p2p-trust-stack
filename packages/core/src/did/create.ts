/**
 * did:peer:4 VID creation — Step 2.
 *
 * Generates Ed25519 + X25519 key pairs, constructs a DID document, and
 * encodes it as a did:peer:4 long-form DID string.
 */

import { base58btc } from 'multiformats/bases/base58';
import {
  generateEd25519KeyPair,
  ed25519ToX25519,
} from '../crypto/primitives.js';
import {
  generateMlDsa65KeyPair,
  generateMlKem768X25519KeyPair,
} from '../crypto/pqc.js';
import { encodePeer4 } from './numalgo4.js';
import type { DidDocument, DidPeer4Result, ServiceEndpoint, VerificationMethod } from './types.js';

// ---------------------------------------------------------------------------
// Multikey encoding helpers
// ---------------------------------------------------------------------------

/**
 * Encode a raw 32-byte Ed25519 public key as a Multikey publicKeyMultibase string.
 * Prefix: 0xed 0x01 (varint for multicodec code 0xed = ed25519-pub)
 */
function encodeEd25519Multikey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return base58btc.encode(prefixed);
}

/**
 * Encode a raw 32-byte X25519 public key as a Multikey publicKeyMultibase string.
 * Prefix: 0xec 0x01 (varint for multicodec code 0xec = x25519-pub)
 */
function encodeX25519Multikey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0xec;
  prefixed[1] = 0x01;
  prefixed.set(publicKey, 2);
  return base58btc.encode(prefixed);
}

/**
 * Encode a raw ML-DSA-65 public key (1952 bytes) as a Multikey
 * publicKeyMultibase string, using the REGISTERED `ml-dsa-65-pub` multicodec
 * (0x1211 → varint bytes 0x91 0x24).
 */
function encodeMlDsa65Multikey(publicKey: Uint8Array): string {
  const prefixed = new Uint8Array(2 + publicKey.length);
  prefixed[0] = 0x91;
  prefixed[1] = 0x24;
  prefixed.set(publicKey, 2);
  return base58btc.encode(prefixed);
}

/**
 * Encode an MLKEM768-X25519 public key (1216 bytes) for a DID document.
 *
 * Deliberately NOT a Multikey: no multicodec is registered for ML-KEM public
 * keys, so there is no honest self-describing prefix to use (see
 * `ML_DSA_65_PUB_MULTICODEC` in crypto/pqc.ts). The multibase `u` prefix marks
 * plain base64url, and the algorithm is stated in the verification method's
 * `type` instead — a local convention pending standardization, not a claim of
 * interoperability.
 */
function encodeHybridKemPublicKey(publicKey: Uint8Array): string {
  return 'u' + Buffer.from(publicKey).toString('base64url');
}

// ---------------------------------------------------------------------------
// DID document construction
// ---------------------------------------------------------------------------

/** Optional post-quantum keys to publish in the DID document. */
export interface PqcDocumentKeys {
  /** ML-DSA-65 public key (1952 bytes) — root-of-trust signing key. */
  mlDsa65PublicKey?: Uint8Array;
  /** MLKEM768-X25519 public key (1216 bytes) — PQ key agreement. */
  hybridKemPublicKey?: Uint8Array;
}

/**
 * Build a DID document for did:peer:4 encoding.
 *
 * The document does NOT include an `id` field — the DID is derived from the
 * document, so including it would create a circular dependency.
 *
 * @param signingPublicKey   Raw 32-byte Ed25519 public key
 * @param agreementPublicKey Raw 32-byte X25519 public key
 * @param transport          Optional libp2p transport info for the TSP service entry
 */
export function buildDidPeer4Document(
  signingPublicKey: Uint8Array,
  agreementPublicKey: Uint8Array,
  transport?: ServiceEndpoint,
  identityKey?: Uint8Array,
  pqc?: PqcDocumentKeys,
): DidDocument {
  const verificationMethod: VerificationMethod[] = [
    {
      id: '#key-1',
      type: 'Multikey',
      controller: '',
      publicKeyMultibase: encodeEd25519Multikey(signingPublicKey),
    },
    {
      id: '#key-2',
      type: 'Multikey',
      controller: '',
      publicKeyMultibase: encodeX25519Multikey(agreementPublicKey),
    },
  ];

  // Slot-A: when a distinct did:scid:vh identity key is provided (utility server),
  // carry it in #key-scid so the did:scid:vh log/rotation follows that key while
  // #key-1 (verificationMethod[0]) stays the PERMANENT TSP VID key. TSP handshake
  // verification reads [0]; the did:scid:vh chain/validateChain reads #key-scid.
  if (identityKey) {
    verificationMethod.push({
      id: '#key-scid',
      type: 'Multikey',
      controller: '',
      publicKeyMultibase: encodeEd25519Multikey(identityKey),
    });
  }

  // Post-quantum roots of trust. APPENDED deliberately: `extractEd25519PublicKey`
  // reads verificationMethod[0] and `extractX25519PublicKey` reads [1] BY INDEX
  // (and #key-scid is conditional), so inserting here would reassign their
  // meanings and silently break peer key resolution. Both are found by `id`.
  if (pqc?.mlDsa65PublicKey) {
    verificationMethod.push({
      id: '#key-mldsa',
      type: 'Multikey',
      controller: '',
      publicKeyMultibase: encodeMlDsa65Multikey(pqc.mlDsa65PublicKey),
    });
  }
  if (pqc?.hybridKemPublicKey) {
    verificationMethod.push({
      id: '#key-kem',
      type: 'MLKEM768X25519PublicKey',
      controller: '',
      publicKeyMultibase: encodeHybridKemPublicKey(pqc.hybridKemPublicKey),
    });
  }

  const doc: DidDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/multikey/v1',
    ],
    verificationMethod,
    // Verification relationships (W3C DID Core §5.3):
    //   - assertionMethod: the key authorized to sign credentials/claims.
    //     For Slot-A (did:scid:vh with a distinct identity key) this is the
    //     rotatable #key-scid; otherwise the single #key-1 doubles as asserter.
    //   - authentication: keys authorized for authentication. #key-1 (the
    //     stable TSP/transport key) always authenticates; #key-scid is added
    //     for Slot-A so the identity key can also authenticate.
    assertionMethod: identityKey ? ['#key-scid'] : ['#key-1'],
    authentication: identityKey
      ? ['#key-1', '#key-scid']
      : ['#key-1'],
    keyAgreement: ['#key-2'],
  };

  // PQ roots of trust also participate in the relationships they belong to: the
  // ML-DSA-65 key asserts (it signs rotations / introductions), and the hybrid KEM
  // key agrees. Both are additive — the classical entries stay first.
  if (pqc?.mlDsa65PublicKey) {
    doc.assertionMethod = [...(doc.assertionMethod ?? []), '#key-mldsa'];
  }
  if (pqc?.hybridKemPublicKey) {
    doc.keyAgreement = [...(doc.keyAgreement ?? []), '#key-kem'];
  }

  if (transport) {
    doc.service = [
      {
        id: '#tsp',
        type: 'TSPTransport',
        serviceEndpoint: transport,
      },
    ];
  }

  return doc;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Create a new did:peer:4 VID.
 *
 * Generates fresh Ed25519 + X25519 key pairs, constructs the DID document,
 * and encodes it as a did:peer:4 long-form DID string.
 *
 * @param transport  Optional libp2p transport info (peerId + multiaddrs) to
 *                   include in the DID document's TSP service entry.
 * @returns DidPeer4Result containing the DID string, document, and key pairs.
 */
export async function createDidPeer4(transport?: ServiceEndpoint): Promise<DidPeer4Result> {
  // 2.1 — Generate key pairs
  const signingKeyPair = generateEd25519KeyPair();
  const agreementKeyPair = ed25519ToX25519(signingKeyPair.secretKey);

  // 2.1b — Post-quantum roots of trust (see DidMethodCreateResult): ML-DSA-65 for
  // high-value async statements, MLKEM768-X25519 for PQ key agreement.
  const mlDsa65KeyPair = generateMlDsa65KeyPair();
  const hybridKemKeyPair = generateMlKem768X25519KeyPair();

  // 2.2 — Construct the DID document
  const document = buildDidPeer4Document(
    signingKeyPair.publicKey,
    agreementKeyPair.publicKey,
    transport,
    undefined,
    {
      mlDsa65PublicKey: mlDsa65KeyPair.publicKey,
      hybridKemPublicKey: hybridKemKeyPair.publicKey,
    },
  );

  // 2.3 — Encode as did:peer:4
  const { did, shortFormDid } = await encodePeer4(document);

  return {
    did,
    shortFormDid,
    document,
    signingKeyPair,
    agreementKeyPair,
    mlDsa65KeyPair,
    hybridKemKeyPair,
  };
}
