/**
 * RCard (RelationshipCard) — JCard (RFC 7095) + W3C VC conversion.
 *
 * Converts the flat profile claims model (ProfileCard from profiles.ts)
 * into a JCard-formatted vCard 4.0 array, and wraps it in a DTG
 * RelationshipCard W3C Verifiable Credential.
 *
 * ## JCard Format (RFC 7095)
 *
 *   ["vcard", [
 *     ["version", {}, "text", "4.0"],
 *     ["fn", {}, "text", "Alice Smith"],
 *     ["email", {}, "text", "alice@example.com"],
 *     ...
 *   ]]
 *
 * ## Claim Key → vCard Property Mapping
 *
 * | Claim Key              | vCard Property |
 * |------------------------|----------------|
 * | name, displayName, fn  | fn             |
 * | email                  | email          |
 * | phone, tel             | tel            |
 * | organization, org      | org            |
 * | title                  | title          |
 * | url, website           | url            |
 * | bio, about, note       | note           |
 * | anything else          | x-<key>        |
 */
import type { ProfileCard } from '../profiles.js';
import type { DtgCredentialVc } from '../dtg-credential.js';
import { buildDtgCredential } from '../dtg-credential.js';
import type { Ed25519KeyPair } from '../../crypto/primitives.js';

// ── JCard Types ────────────────────────────────────────────────────────────

type JCardProperty = [string, Record<string, string>, string, string | string[]];
type JCard = ['vcard', JCardProperty[]];

// ── Claim → vCard Property Mapping ─────────────────────────────────────────

const CLAIM_TO_VCARD: Record<string, string> = {
  name: 'fn', displayName: 'fn', fn: 'fn',
  email: 'email', phone: 'tel', tel: 'tel',
  organization: 'org', org: 'org', title: 'title',
  url: 'url', website: 'url',
  bio: 'note', about: 'note', note: 'note',
};

function claimKeyToVCard(key: string): string {
  return CLAIM_TO_VCARD[key.toLowerCase()] ?? `x-${key.toLowerCase()}`;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Convert a ProfileCard to a JCard (RFC 7095) array.
 * Excludes claims with disclosure='never' or 'zkp_only'.
 * Includes 'discretionary' claims only when key is in requestedKeys.
 */
export function profileToJCard(
  profile: ProfileCard,
  requestedKeys: string[] = [],
): JCard {
  const requested = new Set(requestedKeys);
  const properties: JCardProperty[] = [];

  for (const claim of profile.claims) {
    if (claim.disclosure === 'never') continue;
    if (claim.disclosure === 'zkp_only') continue;
    if (claim.disclosure === 'discretionary' && !requested.has(claim.key)) continue;
    if (claim.value === null || claim.value === undefined) continue;
    const vcardName = claimKeyToVCard(claim.key);
    const type = claim.valueType === 'url' ? 'uri' : 'text';
    properties.push([vcardName, {}, type, claim.value]);
  }
  properties.unshift(['version', {}, 'text', '4.0']);
  return ['vcard', properties];
}

/**
 * Build a signed DTG RelationshipCard W3C VC wrapping a JCard.
 * type = ["VerifiableCredential", "RelationshipCard"] — NO "DTGCredential".
 */
export function buildRCard(params: {
  profile: ProfileCard;
  issuerDid: string;
  subjectDid: string;
  signerKey: Ed25519KeyPair;
  verificationMethod: string;
  requestedKeys?: string[];
}): DtgCredentialVc {
  const { profile, issuerDid, subjectDid, signerKey, verificationMethod, requestedKeys } = params;
  const jcard = profileToJCard(profile, requestedKeys);
  return buildDtgCredential({
    subtype: 'RelationshipCard',
    id: `urn:uuid:profile-${profile.profileUuid}`,
    issuerDid,
    subjectDid,
    claim: { card: jcard },
    validFrom: Math.floor(Date.now() / 1000),
    verificationMethod,
    signerSecretKey: signerKey.secretKey,
  });
}
