/**
 * Tests for core VTC/VRC API — Step 10, Task 10.7.
 *
 * Covers:
 *   - createVtc: happy path, insufficient founders
 *   - issueVrc: happy path, disallowed claim type, non-admin signer, insufficient signatures
 *   - verifyVrc: happy path, insufficient-signatures, wrong-signer/tampered rejection
 *   - verifyGovernanceDoc: happy path, tampered rejection
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/vtc.test.ts
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';
import { cesrEncode, CESR_CODES } from '../../src/crypto/cesr.js';
import { createVtc, issueVrc, verifyVrc, verifyGovernanceDoc } from '../../src/vtc/vtc.js';
import type { VtcGovernanceDoc } from '../../src/vtc/types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeFounder(): { vid: string; signingKeyPair: { secretKey: Uint8Array; publicKey: Uint8Array } } {
  const kp = generateEd25519KeyPair();
  return { vid: cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey), signingKeyPair: kp };
}

// ---------------------------------------------------------------------------
// createVtc
// ---------------------------------------------------------------------------

test('createVtc: happy path — produces a VtcIdentity with a valid self-signed governance doc', async () => {
  const admin1 = makeFounder();
  const admin2 = makeFounder();

  const identity = await createVtc({
    name: 'Genesis Witness VTC',
    founders: [admin1, admin2],
    threshold: 2,
    allowedClaimTypes: ['witness-member'],
  });

  assert.ok(identity.governanceDoc.vtcVid.length > 0);
  assert.equal(identity.governanceDoc.name, 'Genesis Witness VTC');
  assert.deepEqual(identity.governanceDoc.adminVids, [admin1.vid, admin2.vid]);
  assert.equal(identity.governanceDoc.threshold, 2);
  assert.equal(identity.governanceDoc.signatures.length, 2);

  const result = verifyGovernanceDoc(identity.governanceDoc);
  assert.equal(result.valid, true, `expected valid governance doc, got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 2);
});

test('createVtc: throws when threshold exceeds founder count', async () => {
  const admin1 = makeFounder();

  // Option A semantics: a single signer may found a VTC (genesis mint is not
  // gated on signer count == threshold). The impossible case — threshold
  // greater than the number of admins (M > N) — is still rejected.
  await assert.rejects(
    () => createVtc({
      name: 'Bad VTC',
      founders: [admin1],
      threshold: 2,
      allowedClaimTypes: ['witness-member'],
    }),
    /cannot exceed the number of founding admins \(1\)/,
  );
});

test('createVtc: single originator signer with listed co-admins founds a VTC (bootstrapping)', async () => {
  const originator = makeFounder();
  const coadmin1 = makeFounder();
  const coadmin2 = makeFounder();

  // Option A: genesis mint is not gated on signer count == threshold. The
  // originator signs alone; co-admins are listed and become founding admins by
  // selection (no pre-existing founding-admin credential required).
  const identity = await createVtc({
    name: 'Bootstrap VTC',
    founders: [originator],
    threshold: 2,
    allowedClaimTypes: ['witness-member'],
    listedAdmins: [coadmin1.vid, coadmin2.vid],
  });

  assert.equal(identity.governanceDoc.threshold, 2);
  assert.equal(identity.governanceDoc.signatures.length, 1);
  // adminVids = originator + both listed co-admins (deduped)
  assert.deepEqual(
    [...identity.governanceDoc.adminVids],
    [originator.vid, coadmin1.vid, coadmin2.vid],
  );
  assert.deepEqual(
    [...identity.governanceDoc.signatures.map((s) => s.signerVid)],
    [originator.vid],
  );

  // The genesis doc is a validly-minted but partially-formed doc: threshold 2
  // with only the originator's signature. verifyGovernanceDoc reports
  // insufficient signatures until the co-admins co-sign — this is NOT an
  // error, and Option A explicitly allows it.
  const result = verifyGovernanceDoc(identity.governanceDoc);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'insufficient-signatures');
  assert.equal(result.validSignatureCount, 1);
});

// ---------------------------------------------------------------------------
// issueVrc / verifyVrc
// ---------------------------------------------------------------------------

async function makeGovernanceDoc(threshold = 2): Promise<{
  doc: VtcGovernanceDoc;
  admin1: ReturnType<typeof makeFounder>;
  admin2: ReturnType<typeof makeFounder>;
}> {
  const admin1 = makeFounder();
  const admin2 = makeFounder();
  const identity = await createVtc({
    name: 'Witness VTC',
    founders: [admin1, admin2],
    threshold,
    allowedClaimTypes: ['witness-member'],
  });
  return { doc: identity.governanceDoc, admin1, admin2 };
}

test('issueVrc / verifyVrc: happy path — 2-of-2 co-signed VRC verifies', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDoc(2);
  const subject = makeFounder();

  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  const result = verifyVrc(vrc, doc);
  assert.equal(result.valid, true, `expected valid VRC, got: ${result.reason}`);
  assert.equal(result.validSignatureCount, 2);
});

test('issueVrc: throws for a claim type not in allowedClaimTypes', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDoc(2);
  const subject = makeFounder();

  assert.throws(
    () => issueVrc({
      governanceDoc: doc,
      subjectVid: subject.vid,
      claim: { type: 'not-allowed' },
      signers: [admin1, admin2],
    }),
    /is not in the VTC's allowedClaimTypes/,
  );
});

test('issueVrc: throws when a signer is not on the admin list', async () => {
  const { doc, admin1 } = await makeGovernanceDoc(2);
  const outsider = makeFounder();
  const subject = makeFounder();

  assert.throws(
    () => issueVrc({
      governanceDoc: doc,
      subjectVid: subject.vid,
      claim: { type: 'witness-member' },
      signers: [admin1, outsider],
    }),
    /is not on the VTC's admin list/,
  );
});

test('issueVrc: throws when fewer signers than threshold are supplied', async () => {
  const { doc, admin1 } = await makeGovernanceDoc(2);
  const subject = makeFounder();

  assert.throws(
    () => issueVrc({
      governanceDoc: doc,
      subjectVid: subject.vid,
      claim: { type: 'witness-member' },
      signers: [admin1],
    }),
    /governance doc requires 2 signatures, only 1 signer/,
  );
});

test('verifyVrc: rejects insufficient-signatures when governance doc threshold raised after issuance', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDoc(1);
  const subject = makeFounder();

  // Issue with only 1-of-2 (meets original threshold=1).
  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1],
  });

  // Simulate a stricter governance doc requiring 2 signatures.
  const stricterDoc: VtcGovernanceDoc = { ...doc, threshold: 2 };

  const result = verifyVrc(vrc, stricterDoc);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'insufficient-signatures');
  assert.equal(result.validSignatureCount, 1);
});

test('verifyVrc: rejects a tampered VRC (digest mismatch)', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDoc(2);
  const subject = makeFounder();

  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  // Tamper with the claim after issuance without recomputing the digest/signatures.
  const tampered = { ...vrc, claim: { type: 'witness-member', extra: 'injected' } };

  const result = verifyVrc(tampered, doc);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'digest-mismatch');
});

test('verifyVrc: rejects signatures from admins no longer on the governance doc', async () => {
  const { doc, admin1, admin2 } = await makeGovernanceDoc(2);
  const subject = makeFounder();

  const vrc = issueVrc({
    governanceDoc: doc,
    subjectVid: subject.vid,
    claim: { type: 'witness-member' },
    signers: [admin1, admin2],
  });

  // Simulate admin2 being removed from the governance doc (admin rotation).
  const rotatedDoc: VtcGovernanceDoc = { ...doc, adminVids: [admin1.vid] };

  const result = verifyVrc(vrc, rotatedDoc);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'insufficient-signatures');
  assert.equal(result.validSignatureCount, 1);
});

// ---------------------------------------------------------------------------
// verifyGovernanceDoc
// ---------------------------------------------------------------------------

test('verifyGovernanceDoc: rejects a tampered governance doc', async () => {
  const { doc } = await makeGovernanceDoc(2);

  const tampered: VtcGovernanceDoc = { ...doc, name: 'Renamed VTC' };

  const result = verifyGovernanceDoc(tampered);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'digest-mismatch');
});
