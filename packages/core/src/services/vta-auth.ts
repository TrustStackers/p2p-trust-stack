/**
 * VTA challenge/response authentication service.
 */
import type { DataSource } from '../db/data-source.js';
import { randomBytes } from 'node:crypto';
import { verifyEd25519 } from '../crypto/primitives.js';
import * as noncesRepo from '../db/repositories/nonces-repo.js';
import * as identitiesRepo from '../db/repositories/identities-repo.js';
import * as didDocumentsRepo from '../db/repositories/did-documents-repo.js';
import * as keysRepo from '../db/repositories/keys-repo.js';

const DEFAULT_EXPIRY_SECONDS = 5 * 60;
const AUTH_PURPOSE = 'auth';

export class VtaAuthValidationError extends Error {}
export class VtaAuthNotFoundError extends Error {}

export interface IssueChallengeInput { identityUuid: string; appName?: string; expiresInSeconds?: number; }
export interface IssueChallengeResult { identityUuid: string; nonce: string; purpose: string; expiresAt: number | null; }

export async function issueChallenge(db: DataSource, input: IssueChallengeInput): Promise<IssueChallengeResult> {
  if (!input.identityUuid) throw new VtaAuthValidationError('identityUuid is required');
  const identity = await identitiesRepo.findByUuid(db, input.identityUuid);
  if (!identity) throw new VtaAuthNotFoundError(`identity ${input.identityUuid} not found`);
  if (identity.role !== 'vta') throw new VtaAuthValidationError(`identity ${input.identityUuid} is not a VTA`);

  const nonce = randomBytes(32).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + (input.expiresInSeconds ?? DEFAULT_EXPIRY_SECONDS);
  const purpose = input.appName ? `${AUTH_PURPOSE}:${input.appName}` : AUTH_PURPOSE;

  await noncesRepo.create(db, { identityUuid: input.identityUuid, nonce, purpose, expiresAt });
  return { identityUuid: input.identityUuid, nonce, purpose, expiresAt };
}

export interface VerifyChallengeInput { identityUuid: string; nonce: string; signature: string; }
export interface VerifyChallengeResult { valid: boolean; reason?: string; did?: string; }

export async function verifyChallenge(db: DataSource, input: VerifyChallengeInput): Promise<VerifyChallengeResult> {
  if (!input.identityUuid || !input.nonce || !input.signature) throw new VtaAuthValidationError('identityUuid, nonce, and signature are required');
  const identity = await identitiesRepo.findByUuid(db, input.identityUuid);
  if (!identity) throw new VtaAuthNotFoundError(`identity ${input.identityUuid} not found`);

  const nonceRow = await noncesRepo.findByIdentityAndNonce(db, input.identityUuid, input.nonce);
  if (!nonceRow) return { valid: false, reason: 'nonce not found or already consumed' };
  await noncesRepo.consume(db, nonceRow.uuid);

  const now = Math.floor(Date.now() / 1000);
  if (nonceRow.expiresAt !== null && nonceRow.expiresAt < now) return { valid: false, reason: 'nonce expired' };
  if (!nonceRow.purpose || !nonceRow.purpose.startsWith(AUTH_PURPOSE)) return { valid: false, reason: 'nonce was not issued for authentication' };

  const primaryDidDocument = await didDocumentsRepo.findPrimaryForIdentity(db, input.identityUuid);
  if (!primaryDidDocument) return { valid: false, reason: 'identity has no primary did_document on record' };

  const ed25519Key = await keysRepo.findCurrentForDidDocument(db, primaryDidDocument.uuid, 'ed25519');
  if (!ed25519Key) return { valid: false, reason: 'identity has no published ed25519 key on record' };

  let signatureBytes: Uint8Array;
  try { signatureBytes = new Uint8Array(Buffer.from(input.signature, 'base64')); }
  catch { return { valid: false, reason: 'signature is not valid base64' }; }

  const message = new TextEncoder().encode(input.nonce);
  const valid = verifyEd25519(signatureBytes, message, ed25519Key.publicKey);
  return valid ? { valid: true, did: primaryDidDocument.did } : { valid: false, reason: 'signature verification failed' };
}