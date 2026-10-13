/**
 * Tests for the shared VTC invitation artifacts.
 *
 * Two defects are pinned here:
 *  1. **Not dialable** — the old producers packed `"<communityDid>|<peerId>"` into
 *     the OOBI's peerId slot. A libp2p peerId cannot contain `|`, so anything that
 *     dialled it failed; `connectionOobi` must carry the plain peerId.
 *  2. **Mis-addressed** — the old artifact's `did` was the community DID, but the
 *     node the peerId reaches is the utility SERVER (a community is an identities
 *     row, not a libp2p node). An invite-derived RFI is therefore refused by the
 *     rev-3 addressee check — the last test below proves that with the same
 *     verifier the handshake uses.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/relationship/vtc-invite.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { buildVtcInvite, parseVtcInvite, packInvitePeerField } from '../../src/relationship/vtc-invite.js';
import { verifyRfiDigest } from '../../src/relationship/handshake-verify.js';
import { computeSaidDigest } from '../../src/tsp/v3/message.js';

const COMMUNITY_DID = 'did:peer:4zCommunityDidPlaceholder';
const SERVER_DID = 'did:scid:vh:1:zUtilityServer';
const AGENT_DID = 'did:scid:vh:1:zAlice';
const PEER_ID = '12D3KooWBcfvnqH5dWwgMiDbJkQStErz9yhhrHMfEtnL6E1affzB';
const MULTIADDRS = ['/ip4/127.0.0.1/tcp/4003/p2p/' + PEER_ID];
const NONCE = new Uint8Array(16).fill(0x5a);

/** A CESR-encoded Ed25519 VID — what the OOBI codec requires for its `vid` slot. */
function newVid(): string {
  return cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, generateEd25519KeyPair().publicKey);
}

function build() {
  return buildVtcInvite({
    communityDid: COMMUNITY_DID,
    serverDid: SERVER_DID,
    vid: newVid(),
    peerId: PEER_ID,
    multiaddrs: MULTIADDRS,
  });
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

test('buildVtcInvite: the legacy token still round-trips (backward compatible)', () => {
  const artifact = build();
  const parsed = parseVtcInvite(artifact.invite);

  assert.equal(parsed.communityDid, COMMUNITY_DID, 'the legacy token names its community');
  assert.equal(parsed.peerId, PEER_ID, 'the packed peerId unpacks back to the plain peerId');
  assert.deepEqual(parsed.multiaddrs, MULTIADDRS);
  assert.equal(parsed.did, COMMUNITY_DID, 'legacy token keeps the community in the did slot');
});

test('buildVtcInvite: connectionOobi is dialable and addressed to the SERVER', () => {
  const artifact = build();
  const parsed = parseVtcInvite(artifact.connectionOobi);

  assert.equal(artifact.connectionDid, SERVER_DID);
  assert.equal(parsed.did, SERVER_DID, 'the connection artifact addresses the node that answers');
  assert.equal(parsed.peerId, PEER_ID, 'the peerId must stay a plain, dialable libp2p peerId');
  assert.ok(!parsed.peerId.includes('|'), 'a packed peerId can never be dialled');
  assert.deepEqual(parsed.multiaddrs, MULTIADDRS);
  assert.equal(parsed.communityDid, null, 'the connection artifact carries no community reference');
});

test('buildVtcInvite: falls back to the community DID when the server DID is unknown', () => {
  const artifact = buildVtcInvite({
    communityDid: COMMUNITY_DID,
    serverDid: null,
    vid: newVid(),
    peerId: PEER_ID,
    multiaddrs: MULTIADDRS,
  });
  assert.equal(artifact.connectionDid, null);
  assert.equal(parseVtcInvite(artifact.connectionOobi).did, COMMUNITY_DID);
  assert.equal(parseVtcInvite(artifact.connectionOobi).peerId, PEER_ID, 'still dialable');
});

test('buildVtcInvite: refuses a packed or empty peerId', () => {
  assert.throws(
    () => buildVtcInvite({
      communityDid: COMMUNITY_DID, serverDid: SERVER_DID, vid: newVid(),
      peerId: packInvitePeerField(COMMUNITY_DID, PEER_ID), multiaddrs: MULTIADDRS,
    }),
    /plain libp2p peerId/,
  );
  assert.throws(
    () => buildVtcInvite({
      communityDid: COMMUNITY_DID, serverDid: SERVER_DID, vid: newVid(),
      peerId: '', multiaddrs: MULTIADDRS,
    }),
    /peerId is required/,
  );
});

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

test('parseVtcInvite: accepts a plain (modern) OOBI', () => {
  const artifact = build();
  const parsed = parseVtcInvite(artifact.connectionOobi);
  assert.equal(parsed.communityDid, null);
  assert.equal(parsed.peerId, PEER_ID);
});

test('parseVtcInvite: throws on a malformed token', () => {
  assert.throws(() => parseVtcInvite('not-an-oobi'), SyntaxError);
});

// ---------------------------------------------------------------------------
// Why the two artifacts exist: the addressee check from the rev-3 handshake
// ---------------------------------------------------------------------------

test('an invite RFI built from the legacy token is REFUSED; one from connectionOobi is accepted', () => {
  const artifact = build();
  const legacyDid = parseVtcInvite(artifact.invite).did;
  const modernDid = parseVtcInvite(artifact.connectionOobi).did;

  // The server evaluates an inbound invite addressed to the community DID.
  const viaLegacy = verifyRfiDigest({
    vidSender: AGENT_DID,
    localDid: SERVER_DID,
    nonce: NONCE,
    digest: computeSaidDigest('RFI', AGENT_DID, legacyDid, { nonce: NONCE }),
    receiverVid: legacyDid,
  });
  assert.equal(viaLegacy.ok, false, 'a community-addressed invite cannot be answered by the server');
  assert.equal((viaLegacy as unknown as { reason: string }).reason, 'rfi_addressed_elsewhere');

  // Addressed via the connection OOBI, the same invite verifies.
  const viaConnection = verifyRfiDigest({
    vidSender: AGENT_DID,
    localDid: SERVER_DID,
    nonce: NONCE,
    digest: computeSaidDigest('RFI', AGENT_DID, modernDid, { nonce: NONCE }),
    receiverVid: modernDid,
  });
  assert.deepEqual(viaConnection, { ok: true });
});

// ---------------------------------------------------------------------------
// OOBI signing (H2 prerequisite): the DIALABLE artifact is signed, the legacy
// token's bytes are untouched
// ---------------------------------------------------------------------------

test('buildVtcInvite: connectionOobi is UNSIGNED when no signer is installed', async () => {
  const { setOobiSigner } = await import('../../src/relationship/oobi-signer.js');
  setOobiSigner(null);
  try {
    const artifact = build();
    assert.equal(
      parseVtcInvite(artifact.connectionOobi).mlDsa65Signature,
      undefined,
      'with no ML-DSA-65 key in the process the OOBI must stay unsigned (today\'s behaviour)',
    );
  } finally {
    setOobiSigner(null);
  }
});

test('buildVtcInvite: a signer is used ONLY for the DID it is authoritative for', async () => {
  const { setOobiSigner, getOobiSignerFor } = await import('../../src/relationship/oobi-signer.js');
  const { verifyOobiSignature, decodeOobi } = await import('../../src/relationship/oobi.js');
  const { generateMlDsa65KeyPair } = await import('../../src/crypto/pqc.js');
  const { signOobi } = await import('../../src/relationship/oobi.js');

  const kp = generateMlDsa65KeyPair();
  // Authoritative for somebody ELSE's DID — the mistake the route used to make by
  // signing every OOBI it built (community, or an agent's did:scid:vh) with the
  // server's own key.
  setOobiSigner((oobi) => signOobi(oobi, kp.secretKey), 'did:scid:vh:1:zSomebodyElse');

  try {
    const vid = newVid();
    const artifact = buildVtcInvite({
      communityDid: COMMUNITY_DID,
      serverDid: SERVER_DID,
      vid,
      peerId: PEER_ID,
      multiaddrs: MULTIADDRS,
    });

    // getOobiSignerFor is the guard; the artifact must come out UNSIGNED.
    assert.equal(getOobiSignerFor(SERVER_DID), null, 'not the authority for the connection DID');
    assert.equal(getOobiSignerFor('did:scid:vh:1:zSomebodyElse') !== null, true, 'authority honoured');
    assert.equal(
      decodeOobi(artifact.connectionOobi).mlDsa65Signature,
      undefined,
      'a signature under the wrong identity\'s key can never verify, so it must not be emitted',
    );
    assert.equal(verifyOobiSignature(decodeOobi(artifact.connectionOobi), kp.publicKey), false);
  } finally {
    setOobiSigner(null);
  }
});

test('buildVtcInvite: connectionOobi is SIGNED and verifies; the legacy token is byte-identical', async () => {
  const { setOobiSigner } = await import('../../src/relationship/oobi-signer.js');
  const { verifyOobiSignature } = await import('../../src/relationship/oobi.js');
  const { generateMlDsa65KeyPair } = await import('../../src/crypto/pqc.js');

  const kp = generateMlDsa65KeyPair();
  // Build both artifacts from the SAME vid: `build()` mints a fresh random VID
  // per call, so comparing two `build()` outputs would compare randomness rather
  // than the signing behaviour under test.
  const vid = newVid();
  const buildWithFixedVid = () => buildVtcInvite({
    communityDid: COMMUNITY_DID,
    serverDid: SERVER_DID,
    vid,
    peerId: PEER_ID,
    multiaddrs: MULTIADDRS,
  });

  setOobiSigner(null);
  const unsignedArtifact = buildWithFixedVid();

  const { signOobi, decodeOobi } = await import('../../src/relationship/oobi.js');
  setOobiSigner((oobi) => signOobi(oobi, kp.secretKey));

  try {
    const signedArtifact = buildWithFixedVid();

    // The dialable artifact carries a signature that verifies against the key.
    // (Asserted on the OOBI payload itself: `parseVtcInvite` intentionally
    // exposes only the addressing fields a caller needs.)
    const oobi = decodeOobi(signedArtifact.connectionOobi);
    assert.ok(oobi.mlDsa65Signature, 'connectionOobi must carry an ML-DSA-65 signature');
    assert.equal(
      verifyOobiSignature(oobi, kp.publicKey),
      true,
      "the signature must verify against the signer's public key",
    );
    // The signature covers the 4-item body, so the addressing fields are intact.
    assert.equal(oobi.did, SERVER_DID, 'signing must not change the addressed DID');
    assert.equal(oobi.peerId, PEER_ID, 'signing must not change the dialable peerId');

    // The legacy token is a compatibility contract: signing must NOT touch it,
    // or already-issued tokens would stop matching byte-for-byte.
    assert.equal(
      signedArtifact.invite,
      unsignedArtifact.invite,
      'the legacy invite token must stay byte-identical whether or not a signer is installed',
    );
  } finally {
    setOobiSigner(null);
  }
});

