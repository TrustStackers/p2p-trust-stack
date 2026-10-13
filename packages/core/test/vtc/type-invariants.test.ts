/**
 * D-5b — the compile-time tripwire on the CESR-key/DID distinction.
 *
 * `src/vtc/type-invariants.ts` holds the assertions; **`tsc --noEmit` is what enforces
 * them** (see that file's header for why they cannot live in `test/` — this package's
 * tsconfig does not type-check tests, so a `@ts-expect-error` here would pass without
 * testing anything).
 *
 * This test has a different job: it proves the assertion file is still present, still
 * exported, and still reporting `true` — i.e. that nobody deleted the tripwire instead
 * of fixing the invariant.
 *
 * Run with:
 *   node --experimental-strip-types --loader ./test-loader.mjs --test test/vtc/type-invariants.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { D5B_TYPE_INVARIANTS, generalModelAcceptsDidFormVids } from '../../src/vtc/type-invariants.js';
import { asCesrVid, asCesrVrc } from '../../src/vtc/codec.js';
import { CESR_CODES, cesrEncode } from '../../src/crypto/cesr.js';
import { generateEd25519KeyPair } from '../../src/crypto/primitives.js';

test('D-5b: every compile-time invariant still holds', () => {
  assert.deepEqual(
    D5B_TYPE_INVARIANTS,
    {
      encodedSubjectIsBranded: true,
      encodedIssuerIsBranded: true,
      encodedSignerIsBranded: true,
      plainStringIsNotCesrVid: true,
      cesrVidFlowsIntoGeneralModel: true,
      generalModelStillAcceptsDids: true,
    },
    'if this fails, an invariant broke — fix src/vtc/types.ts or the brand, not this test',
  );
});

test('D-5b: the runtime guard and the compile-time claim agree', () => {
  const kp = generateEd25519KeyPair();
  const keyVid = cesrEncode(CESR_CODES.ED25519_PUBLIC_KEY, kp.publicKey);
  const did = 'did:scid:vh:1:z6MkExampleDidFormIdentifier';

  // The brand's runtime enforcement: a key passes, a DID is refused BY NAME.
  assert.equal(asCesrVid(keyVid), keyVid);
  assert.throws(() => asCesrVid(did, 'subjectVid', 'asCesrVrc'), /subjectVid/);
  assert.throws(() => asCesrVid(did), /looks like/);

  // And the general model keeps accepting the DID form — the asymmetry is intentional
  // (the store persists DIDs there; only the encoded model is CESR-only).
  const didForm = {
    subjectVid: did, issuerVid: did, claim: { type: 'witness-member' },
    issuedAt: 1, digest: new Uint8Array(32), signatures: [],
  };
  assert.equal(generalModelAcceptsDidFormVids(did, didForm).subjectVid, did,
    'a DID-form Vrc is a legitimate general-model value (and is NOT encodable)');
  assert.throws(() => asCesrVrc(didForm), /subjectVid/, 'the encoded model refuses it by field name');
});
