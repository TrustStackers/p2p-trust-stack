import { test } from 'node:test';
import assert from 'node:assert/strict';

import { guardAuthorizer } from '../../src/services/trust-tasks/authorizer.js';
import type { PolicyQuery } from '../../src/services/policy-engine.js';

test('guardAuthorizer maps the ceremony context onto a GovernanceGuard query', async () => {
  const seen: PolicyQuery[] = [];
  const guard = {
    authorize: async (q: PolicyQuery) => {
      seen.push(q);
      return { allowed: true, reason: 'ok' };
    },
  };

  const res = await guardAuthorizer(guard).authorize('issue_credential', {
    communityDid: 'did:example:vtc',
    actorDid: 'did:example:vtc',
    params: { kind: 'MembershipCredential', subjectDid: 'did:example:alice' },
  });

  assert.equal(res.allowed, true);
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0], {
    action: 'issue_credential',
    communityDid: 'did:example:vtc',
    actorDid: 'did:example:vtc',
    params: { kind: 'MembershipCredential', subjectDid: 'did:example:alice' },
  });
});

test('guardAuthorizer fails CLOSED with a named reason when a DID is missing', async () => {
  let called = false;
  const guard = {
    authorize: async () => {
      called = true;
      return { allowed: true };
    },
  };
  const auth = guardAuthorizer(guard);

  const noCommunity = await auth.authorize('issue_credential', { actorDid: 'did:x' });
  assert.equal(noCommunity.allowed, false);
  assert.match(noCommunity.reason ?? '', /communityDid/);

  const noActor = await auth.authorize('issue_credential', { communityDid: 'did:x' });
  assert.equal(noActor.allowed, false);
  assert.match(noActor.reason ?? '', /actorDid/);

  assert.equal(called, false, 'the guard must not be consulted without both DIDs');
});

test('guardAuthorizer forwards caller-known facts as extraFacts (they win over derived)', async () => {
  let facts: Record<string, unknown> | undefined;
  const guard = {
    authorize: async (_q: PolicyQuery, f?: Record<string, unknown>) => {
      facts = f;
      return { allowed: true };
    },
  };

  await guardAuthorizer(guard).authorize('issue_credential', {
    communityDid: 'did:c',
    actorDid: 'did:a',
    facts: { approval_count: 2 },
  });

  assert.deepEqual(facts, { approval_count: 2 });
});
