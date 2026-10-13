/**
 * `names` domain — register, resolve, revoke, list.
 *
 * Thin wrapper over the runtime's name service (`src/did/name-service.ts`, `src/did/name-resolver.ts`). The
 * only addition is that a successful register/revoke announces itself, so a UI can stop re-fetching the name
 * list to confirm its own action (design §4.2's agent-name use case).
 */
import { requireAgent, type DomainContext } from './context.js';
import type { NameEntryDto, RegisterResultDto, ResolvedNameDto } from '../dto/names.js';

export interface NamesApi {
  /** Register a name for the active identity. Emits `name.registered` on success. */
  register(params: { name: string; namespace: string; profileUuid?: string }): Promise<RegisterResultDto>;
  /** Resolve a name URI, or null when nothing is bound. */
  resolve(nameUri: string): Promise<ResolvedNameDto | null>;
  /** Revoke a previously registered name. Emits `name.revoked` on success. */
  revoke(params: { name: string; namespace: string }): Promise<RegisterResultDto>;
  /** Every name registered by the active identity. */
  list(): Promise<NameEntryDto[]>;
}

/** Build the `names` domain. */
export function createNamesApi(ctx: DomainContext): NamesApi {
  return {
    async register(params): Promise<RegisterResultDto> {
      const agent = requireAgent(ctx, 'register a name');
      if (!params.name || !params.namespace) throw new Error('name and namespace are required');
      const result = await agent.registerName(params);
      if (result.success) {
        ctx.bus.emit('name.registered', {
          name: params.name,
          namespace: params.namespace,
          did: agent.getDid(),
          at: Date.now(),
        });
      }
      return result;
    },

    async resolve(nameUri: string): Promise<ResolvedNameDto | null> {
      const agent = requireAgent(ctx, 'resolve a name');
      if (!nameUri) throw new Error('nameUri is required');
      const result = await agent.resolveName(nameUri);
      if (!result) return null;
      const rCard = (result as { rCard?: unknown }).rCard;
      return {
        peerId: result.peerId,
        did: result.did,
        multiaddrs: result.multiaddrs,
        ...(rCard !== undefined ? { rCard } : {}),
      };
    },

    async revoke(params): Promise<RegisterResultDto> {
      const agent = requireAgent(ctx, 'revoke a name');
      if (!params.name || !params.namespace) throw new Error('name and namespace are required');
      const result = await agent.revokeName(params);
      if (result.success) {
        ctx.bus.emit('name.revoked', {
          name: params.name,
          namespace: params.namespace,
          did: agent.getDid(),
          at: Date.now(),
        });
      }
      return result;
    },

    async list(): Promise<NameEntryDto[]> {
      const agent = requireAgent(ctx, 'list names');
      const entries = await agent.listNames();
      // Explicit projection: only the contract fields cross the boundary.
      return entries.map((e) => ({
        nameUri: e.nameUri,
        namespace: e.namespace,
        name: e.name,
        did: e.did,
        bindingType: e.bindingType,
      }));
    },
  };
}
