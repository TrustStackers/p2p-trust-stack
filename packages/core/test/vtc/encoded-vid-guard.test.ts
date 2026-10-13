/**
 * Tests for CESR-VID vs DID/UUID separation in the VTC/VRC codec (G7).
 *
 * One field name carried three kinds of identifier across the codebase:
 *
 *  - `src/vtc/vtc.ts`      `createVtc`/`issueVrc` → CESR-encoded Ed25519 keys
 *  - `src/did/name-vrc.ts` `issueNameClaim`     → `did:key:…` DIDs
 *  - `src/vtc/store.ts`    DB read-back         → DIDs, and UUIDs for signerVid
 *  - `src/services/vtc.ts` adminVids            → UUIDs
 *
 * The binary codec encodes every VID as a CESR key primitive, so any of the
 * latter three reaching `encodeVrc`/`encodeGovernanceDoc` threw a bare
 * `expected ED25519_PUBLIC_KEY` from deep inside `cesrDecode` — with no hint of
 * which field was wrong. `CesrVid` + `asCesrVrc`/`asEncodedGovernanceDoc`
 * make that a compile error plus a named runtime error.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/encoded-vid-guard.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import {
  isCesrVid,
  asCesrVid,
  asCesrVrc,
  asEncodedGovernanceDoc,
  encodeVrc,
  decodeVrc,
  encodeVidList,
  decodeVidList,
} from '../../src/vtc/codec.js';
import type { Vrc, VtcGovernanceDoc } from '../../src/vtc/types.js';
import { issueNameClaim, verifyNameClaim } from '../../src/did/name-vrc.js';
import { buildDidPeer4Document } from '../../src/did/create.js';

/** A DID — `issueNameClaim` puts one of these in `subjectVid`. */
const DID = 'did:peer:4zQmUL61Nc1F7ioiKxHNqwnJXX4srh';
/** A UUID — `store.ts`/`services/vtc.ts` put these in vid fields. */
const UUID = 'b6c9c1c2-0f3e-4a7b-8c9d-0e1f2a3b4c5d';

function makeVid(): { vid: string; secretKey: Uint8Array; publicKey: Uint8Array } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), ...kp };
}

/** A VRC in the shape `issueVrc` produces (CESR-key VIDs). */
function makeVrc(): Vrc {
  const subject = makeVid();
  const issuer = makeVid();
  const signer = makeVid();
  return {
    subjectVid: subject.vid,
    issuerVid: issuer.vid,
    claim: { type: 'membership' },
    issuedAt: 1_700_000_000,
    digest: new Uint8Array(32).fill(7),
    signatures: [{ signerVid: signer.vid, signature: new Uint8Array(64).fill(9) }],
  };
}

test('isCesrVid: accepts a CESR key, rejects DID/UUID/empty/non-string', () => {
  const v = makeVid();
  assert.equal(isCesrVid(v.vid), true);
  assert.equal(isCesrVid(DID), false, 'a DID is not a CESR key');
  assert.equal(isCesrVid(UUID), false, 'a UUID is not a CESR key');
  assert.equal(isCesrVid(''), false);
  assert.equal(isCesrVid('not-base64url-!!'), false);
  assert.equal(isCesrVid(undefined), false);
  assert.equal(isCesrVid(42), false);
});

test('the name-claim VRC from issueNameClaim: DID-flavoured VIDs the codec refuses BY NAME', () => {
  const kp = generateEd25519KeyPair();
  const agreement = generateEd25519KeyPair();
  const doc = buildDidPeer4Document(kp.publicKey, agreement.publicKey);
  const nameUri = 'vta:p2pts.mainnet:alice';

  // The REAL producer (src/did/name-vrc.ts) — not a hand-made approximation, so
  // this test cannot drift from what the name service actually issues (H16).
  const vrc = issueNameClaim({ nameUri, did: 'did:peer:4:z8NameClaimSubject', signingKeyPair: kp });

  // 1. The shape the design question is about: every VID is a DID, and all three
  //    are the same self-claiming value derived from the signing key.
  assert.match(vrc.subjectVid, /^did:key:/, 'subjectVid is a DID');
  assert.equal(vrc.issuerVid, vrc.subjectVid, 'self-issued');
  assert.equal(vrc.signatures[0].signerVid, vrc.subjectVid, 'self-signed');
  assert.equal(isCesrVid(vrc.subjectVid), false, 'a did:key value is NOT a CESR key');
  assert.equal(vrc.claim.type, 'AgentName');
  assert.equal(vrc.claim.nameUri, nameUri);

  // 2. The name service itself works today: issue → verify round-trips against the
  //    DID document that carries the same Ed25519 key.
  assert.equal(verifyNameClaim(vrc, doc), true, 'the name claim verifies against its own key');

  // 3. The codec refuses that shape, naming the field — the property G7 added. This
  //    is why H16 is a documented hazard rather than a live defect.
  assert.throws(
    () => asCesrVrc(vrc),
    (err: Error) => {
      assert.ok(err instanceof TypeError);
      assert.match(err.message, /asCesrVrc: subjectVid/);
      assert.match(err.message, /looks like a DID/);
      return true;
    },
  );

  // 4. …and the refusal stays legible even for a caller that bypassed the brand and
  //    reached the binary encoder directly, which is the path a future feature would
  //    take by accident.
  assert.throws(
    () => encodeVrc(vrc as never),
    (err: Error) => {
      assert.ok(err instanceof TypeError, 'still a type error, not a parse error');
      assert.match(err.message, /encodeVrc: subjectVid is not CESR-encodable/);
      assert.match(err.message, /looks like a DID/);
      return true;
    },
  );

  // 5. A tampered claim no longer verifies (the digest covers the claim body).
  const tampered = { ...vrc, claim: { ...vrc.claim, nameUri: 'vta:p2pts.mainnet:mallory' } };
  assert.equal(verifyNameClaim(tampered, doc), false, 'a rewritten name invalidates the signature');
});

test('asCesrVid: brands a valid key, and names a DID or UUID for the rest', () => {
  const v = makeVid();
  assert.equal(asCesrVid(v.vid), v.vid, 'returns the same string, branded');

  assert.throws(
    () => asCesrVid(DID, 'subjectVid', 'asCesrVrc'),
    (err: Error) => {
      assert.ok(err instanceof TypeError, 'a type error, not a parse error');
      assert.match(err.message, /asCesrVrc: subjectVid/);
      assert.match(err.message, /looks like a DID/);
      return true;
    },
  );

  assert.throws(
    () => asCesrVid(UUID, 'signerVid', 'asCesrVrc'),
    (err: Error) => {
      assert.match(err.message, /looks like a UUID/);
      return true;
    },
  );

  assert.throws(() => asCesrVid(null), /must be a CESR-encoded Ed25519 public key string \(got null\)/);
});


test('asCesrVrc: rejects the name-claim shape (DID subjectVid) naming the field', () => {
  // Exactly what `issueNameClaim` builds: subjectVid is `did:key:…`.
  const nameClaimVrc: Vrc = {
    ...makeVrc(),
    subjectVid: `did:key:${Buffer.from(new Uint8Array(32)).toString('base64url')}`,
  };

  assert.throws(
    () => asCesrVrc(nameClaimVrc),
    (err: Error) => {
      assert.match(err.message, /asCesrVrc: subjectVid/);
      assert.match(err.message, /looks like a DID/);
      assert.match(err.message, /CESR Ed25519 keys/, 'explains the required form');
      return true;
    },
  );

  // And the DID cannot be smuggled in through the signature list either.
  const signerDid: Vrc = {
    ...makeVrc(),
    signatures: [{ signerVid: DID, signature: new Uint8Array(64) }],
  };
  assert.throws(() => asCesrVrc(signerDid), /asCesrVrc: signatures\[0\]\.signerVid/);
});

test('asEncodedGovernanceDoc: rejects a UUID admin (the services/vtc.ts shape)', () => {
  const good = makeVid();
  const doc: VtcGovernanceDoc = {
    vtcVid: good.vid,
    vtcDid: DID,
    name: 'Acme',
    adminVids: [good.vid, UUID],
    threshold: 2,
    allowedClaimTypes: ['membership'],
    createdAt: 1_700_000_000,
    digest: new Uint8Array(32).fill(3),
    signatures: [{ signerVid: good.vid, signature: new Uint8Array(64) }],
  };

  assert.throws(
    () => asEncodedGovernanceDoc(doc),
    (err: Error) => {
      assert.match(err.message, /asEncodedGovernanceDoc: adminVids\[1\]/);
      assert.match(err.message, /looks like a UUID/);
      return true;
    },
  );

  // A DID-form vtcVid (what `governanceRowToDoc` produces) is rejected too.
  assert.throws(
    () => asEncodedGovernanceDoc({ ...doc, vtcVid: DID, adminVids: [good.vid] }),
    /asEncodedGovernanceDoc: vtcVid.*looks like a DID/s,
  );
});

test('the legitimate path is unobstructed: CESR VIDs round-trip through the guard', () => {
  const vrc = makeVrc();
  const encoded = encodeVrc(asCesrVrc(vrc));
  const decoded = decodeVrc(encoded);

  assert.deepEqual(decoded.subjectVid, vrc.subjectVid);
  assert.deepEqual(decoded.issuerVid, vrc.issuerVid);
  assert.deepEqual(decoded.signatures, vrc.signatures);
  // decodeVrc's output is branded, so it feeds straight back into encodeVrc.
  assert.deepEqual(decodeVrc(encodeVrc(decoded)).digest, vrc.digest);
});

test('a DB-shaped VRC (DID issuerVid from the store) cannot be encoded', () => {
  // Mirrors `credentialRowToVrc(row, issuerDid, subjectDid, sigRows)` — the shape
  // VtcStore returns. It is legitimate for storage/verification and must NOT be
  // accepted by the binary codec.
  const storedVrc: Vrc = {
    ...makeVrc(),
    subjectVid: DID,
    issuerVid: DID,
    signatures: [{ signerVid: UUID, signature: new Uint8Array(64) }],
  };

  assert.throws(() => encodeVrc(asCesrVrc(storedVrc)), /asCesrVrc: subjectVid/);
  // Sanity: the same guard accepts the VID-list form used by the codec.
  const v = makeVid();
  assert.deepEqual(decodeVidList(encodeVidList([asCesrVid(v.vid)])), [v.vid]);
});
