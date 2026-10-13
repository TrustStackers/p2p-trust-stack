/**
 * Identity Service — shared-core API for identity lookups routed through the
 * Computed Record Exchange (CRE) catalog.
 *
 * The coordinator `identity_lookup` participant was retired in Phase G — the
 * general-DID public read is now the `exchange:identity-lookup` pull recordset,
 * served by ExchangeQueryParticipant through the same materializer/ACL/N6
 * machinery as registry/recovery/rcard.
 */

import { exchangePull } from '../../exchange/index.js';
import type { ParticipantTransport } from '../participant.js';
import { didToUuid } from '../../db/uuid-helpers.js';

export interface IdentityLookupResultPayload {
  found: boolean;
  did?: string;
  didDocument?: object;
  publicKeys?: {
    ed25519: string;
    x25519: string;
  };
  recoveryState?: unknown;
}

/**
 * Look up public identity data for a DID through the `exchange:identity-lookup`
 * pull recordset (standard-lookup mode — the target DID may be any DID).
 *
 * @param requesterDid  The calling agent's own DID (ACL-role principal)
 * @param transport     TSP participant transport for reaching the utility server
 * @param serverPid     The utility server's participant pid (e.g. 'server:us-1')
 * @param did           The DID to look up
 */
export async function lookupIdentityViaExchange(
  requesterDid: string,
  transport: ParticipantTransport,
  serverPid: string,
  did: string,
): Promise<IdentityLookupResultPayload> {
  const rows = (await exchangePull({
    name: 'identity-lookup',
    req: {
      requester: { realDid: requesterDid, uuid: didToUuid(requesterDid), role: 'vta' },
      filters: { did },
    },
    peer: serverPid,
    transport,
  })) as IdentityLookupResultPayload[];
  return rows[0] ?? { found: false };
}