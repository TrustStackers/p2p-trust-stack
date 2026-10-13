/**
 * CredentialReceiveParticipant — agent-side participant that receives minted
 * community-governed credentials (VMC/VEC/VWC/DGT) pushed from the utility
 * server and persists them to the agent's local SQLite `credentials` table.
 *
 * Split out of VtcReceiveParticipant in Phase F to restore type clarity as the
 * CredentialFactory grows more kinds (VRC/VMC/VEC/DGT) — community state and
 * credential state are now handled by distinct participants.
 *
 * Handles:
 *   - 'exchange:credential' — persist a minted credential for THIS agent
 *     (idempotent by uuid). Delivered by the server's queue-row fan-out over the
 *     CRE `credential` recordset.
 *
 * pid: 'peer:{agentDid}' — identifies this agent as a participant.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type {
  Operation,
  Outcome,
  Participant,
  Vote,
} from '@p2p-trust-stack/core/tx/types.js';
import {
  classifyCredentialVerdict,
  classifyCredentialBinding,
  resolveCredentialVerifyPolicy,
  resolveCredentialBindingPolicy,
  type CredentialVerifyPolicy,
  type CredentialBindingPolicy,
} from '@p2p-trust-stack/core/services/credential-factory/verify-policy.js';

/**
 * Phase 6 — a minted community-governed credential delivered to the subject
 * agent via the durable queue (op_type='exchange:credential'). Mirrors the
 * server-side CredentialPushData shape (vtc-push-data.ts).
 */
export interface CredentialPushData {
  credentialUuid: string;
  vcType: string;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  w3cVcJson: string | null;
  claim: string | null;
  status: string;
  validFrom: number;
  validUntil: number | null;
  credentialDigest: string | null;
  createdAt: number | null;
  issuerDid: string | null;
  subjectDid: string | null;
}

/**
 * What the participant reports after a credential is persisted locally.
 *
 * Deliberately a small projection, not the whole push payload: a consumer announcing the arrival needs to know
 * *what* landed and *whose* it is, not the credential's full contents.
 */
export interface PersistedCredentialEvent {
  uuid: string;
  vcType: string;
  issuerIdentityUuid: string;
  subjectIdentityUuid: string;
  status: string;
}

export class CredentialReceiveParticipant implements Participant {
  readonly pid: string;
  private readonly appDb: DataSource;   // Agent's local SQLite (agent-database.db)
  private readonly txDb: DataSource;    // SQLite (tx-coordinator.db)
  private readonly verifyPolicy: CredentialVerifyPolicy;
  private readonly bindingPolicy: CredentialBindingPolicy;
  /**
   * Called after a credential is actually written to the local table.
   *
   * This participant is the ONLY thing that knows a credential was delivered — nothing else watches the table —
   * so without this hook an observer can only discover an arrival by polling. Not called on the idempotent
   * "already present" path: a re-delivery is not a new arrival.
   */
  private readonly onPersisted?: (credential: PersistedCredentialEvent) => void;
  /**
   * Verification seam. Defaults to the real `CredentialFactoryImpl.verify()`;
   * injectable so the refusal branch is directly testable — reaching a *judged*
   * invalid verdict with the real verifier needs a resolvable issuer key plus a
   * real eddsa-jcs-2022 proof, which is not something a unit test should build.
   */
  private readonly verifyCredential?: (raw: string) => Promise<{
    valid: boolean; reason?: string; detectedKind?: string;
  }>;

  constructor(
    pid: string,
    appDb: DataSource,
    txDb: DataSource,
    verifyPolicy?: CredentialVerifyPolicy,
    verifyCredential?: (raw: string) => Promise<{ valid: boolean; reason?: string; detectedKind?: string }>,
    bindingPolicy?: CredentialBindingPolicy,
    onPersisted?: (credential: PersistedCredentialEvent) => void,
  ) {
    this.pid = pid;
    this.appDb = appDb;
    this.txDb = txDb;
    // Explicit option → env → 'warn' for each policy independently.
    this.verifyPolicy = resolveCredentialVerifyPolicy(verifyPolicy);
    this.bindingPolicy = resolveCredentialBindingPolicy(bindingPolicy);
    this.verifyCredential = verifyCredential;
    this.onPersisted = onPersisted;
  }

  /**
   * This agent's own DID, taken from the participant id the coordinator
   * registered (`peer:{did}`). Used to bind an incoming credential to its
   * recipient — the thing F-001/F-026 found missing.
   */
  private get selfDid(): string | undefined {
    const prefix = 'peer:';
    return this.pid.startsWith(prefix) ? this.pid.slice(prefix.length) : undefined;
  }

  handlesOperation(op: Operation): boolean {
    return op.op === 'exchange:credential';
  }

  async prepare(txId: string, operations: Operation[]): Promise<Vote> {
    for (const op of operations) {
      try {
        if (op.op !== 'exchange:credential') continue;
        const data = op.params as unknown as CredentialPushData;
        if (!data?.credentialUuid) return 'no';
        // F-003: the verdict decides whether this credential is worth persisting.
        // A refusal is a clean 'no' vote, never an exception — the coordinator
        // aborts the tx, which is the correct 2PC outcome for a rejected input.
        const { store, message, level } = await this.verifyIncoming(data);
        this.logVerdict(data, level, message);
        if (!store) return 'no';

        // F-001/F-026: and the credential must be FOR this agent, FROM the issuer
        // the delivery names. Proof-valid-but-addressed-elsewhere was accepted
        // silently before, because `verify()` only ever saw bytes.
        const binding = this.checkBinding(data);
        this.logVerdict(data, binding.level, binding.message);
        if (!binding.store) return 'no';

        await this.upsertCredential(data);
      } catch (err) {
        console.error(`[credential-receive] prepare failed for tx ${txId}:`, (err as Error)?.message);
        return 'no';
      }
    }

    // Durably record 'prepared' BEFORE voting yes.
    await this.txDb.run(
      `INSERT OR REPLACE INTO tx_participant_state (tx_id, pid, outcome)
       VALUES (?, ?, 'prepared')`,
      txId,
      this.pid,
    );

    return 'yes';
  }

  async commit(txId: string): Promise<void> {
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'committed'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async abort(txId: string): Promise<void> {
    // upsertCredential is idempotent (uuid-keyed), so a precise rollback is
    // unnecessary — the credential stays or is re-upserted on the next delivery.
    await this.txDb.run(
      `UPDATE tx_participant_state SET outcome = 'aborted'
       WHERE tx_id = ? AND pid = ?`,
      txId,
      this.pid,
    );
  }

  async compensate(txId: string): Promise<void> {
    await this.abort(txId);
  }

  async inquiry(txId: string): Promise<Outcome> {
    const row = await this.txDb.get<{ outcome: string }>(
      'SELECT outcome FROM tx_participant_state WHERE tx_id = ? AND pid = ?',
      txId,
      this.pid,
    );
    return (row?.outcome as Outcome) ?? 'unknown';
  }

  /**
   * F-003 — call the credential verifier on the RECEIVE path.
   *
   * Before this, `CredentialFactoryImpl.verify()` had no caller anywhere in the
   * tree: every credential delivered to this agent was persisted unchecked. The
   * verifier is now consulted on every `exchange:credential` delivery, with the
   * verdict classified by `classifyCredentialVerdict` (which keeps
   * "could not verify" distinct from "invalid" — audit F-031).
   *
   * The factory is imported lazily, as `verified-channel.ts` does, so this
   * participant keeps no hard dependency on the credential-factory graph at
   * module load.
   */
  private async verifyIncoming(data: CredentialPushData): Promise<{
    store: boolean;
    message: string;
    level: 'info' | 'warn' | 'error';
  }> {
    if (this.verifyPolicy === 'off') return { store: true, message: '', level: 'info' };

    const hasPayload = typeof data.w3cVcJson === 'string' && data.w3cVcJson.length > 0;
    if (!hasPayload) {
      return {
        ...classifyCredentialVerdict({ hasPayload: false }, this.verifyPolicy),
        store: true,
      };
    }

    let result: { valid: boolean; reason?: string; detectedKind?: string } | undefined;
    let error: unknown;
    try {
      if (this.verifyCredential) {
        result = await this.verifyCredential(data.w3cVcJson as string);
      } else {
        const { CredentialFactoryImpl } = await import(
          '@p2p-trust-stack/core/services/credential-factory/credential-factory-impl.js'
        );
        const factory = new CredentialFactoryImpl(this.appDb);
        result = await factory.verify(data.w3cVcJson as string) as {
          valid: boolean; reason?: string; detectedKind?: string;
        };
      }
    } catch (err) {
      // `verify()` catches internally and returns valid:false, so reaching here
      // means construction or an import failed. Never let that abort the tx by
      // itself — the classifier treats it as INDETERMINATE, not invalid.
      error = err;
    }

    return classifyCredentialVerdict({ result, error, hasPayload: true }, this.verifyPolicy);
  }

  /**
   * Read the three binding fields out of the delivered VC and classify them.
   *
   * Parsing is inside the guard: a malformed payload must degrade to
   * INDETERMINATE (stored), never throw into the prepare loop or be mistaken for
   * a definite mismatch.
   */
  private checkBinding(data: CredentialPushData): {
    store: boolean;
    message: string;
    level: 'info' | 'warn' | 'error';
  } {
    if (this.bindingPolicy === 'off') return { store: true, message: '', level: 'info' };

    const raw = typeof data.w3cVcJson === 'string' && data.w3cVcJson.length > 0 ? data.w3cVcJson : undefined;
    if (!raw) {
      return classifyCredentialBinding({ hasPayload: false }, this.bindingPolicy);
    }

    let vcIssuer: string | undefined;
    let vcSubjectId: string | undefined;
    let vcMemberOf: string | undefined;
    try {
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      if (typeof parsed.issuer === 'string') vcIssuer = parsed.issuer;
      const subject = parsed.credentialSubject;
      if (typeof subject === 'object' && subject !== null) {
        const s = subject as Record<string, unknown>;
        if (typeof s.id === 'string') vcSubjectId = s.id;
        // A VMC names the community it claims membership of; a mismatch with the
        // signing issuer is exactly the "community asserting membership alone"
        // shape F-001 describes.
        if (typeof s.memberOf === 'string') vcMemberOf = s.memberOf;
      }
    } catch {
      return classifyCredentialBinding({ hasPayload: false }, this.bindingPolicy);
    }

    return classifyCredentialBinding({
      hasPayload: true,
      selfDid: this.selfDid,
      payloadIssuerDid: data.issuerDid,
      vcIssuer,
      vcSubjectId,
      vcMemberOf,
    }, this.bindingPolicy);
  }

  /** Log a verdict at the severity the classifier chose. */
  private logVerdict(data: CredentialPushData, level: 'info' | 'warn' | 'error', message: string): void {
    if (!message) return; // policy=off
    const line = `[credential-receive] ${data.credentialUuid.slice(0, 8)} (${data.vcType}): ${message}`;
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
  }

  /**
   * Persist a minted community-governed credential to the local `credentials`
   * table (custody='remote', subject is this agent). Idempotent by credential
   * uuid: the same VMC/VEC/WVC is never double-written.
   */
  private async upsertCredential(data: CredentialPushData): Promise<void> {
    // The `credentials.vc_type` CHECK is lowercase in BOTH migration sets
    // ('vmc','vec','vrc','vic','custom_endorsement','delegation'), and every
    // push-payload producer today reads the value straight from the server's own
    // column — so a correct delivery is already lowercase. Normalise anyway: a
    // payload carrying 'VMC' would otherwise fail the INSERT, and because
    // `prepare()` votes 'no' on a throw, the credential would be silently lost in
    // a 2PC abort. Logged, not silent, so a producer that drifts is still visible.
    const vcType = data.vcType?.toLowerCase() ?? data.vcType;
    if (vcType !== data.vcType) {
      console.warn(
        `[credential-receive] ${data.credentialUuid.slice(0, 8)}: vcType "${data.vcType}" normalised to ` +
        `"${vcType}" for the vc_type CHECK — a producer is emitting non-canonical case`,
      );
    }

    const existing = await this.appDb.get<{ uuid: string }>(
      'SELECT uuid FROM credentials WHERE uuid = ?', data.credentialUuid,
    );
    if (existing) {
      console.log(`[credential-receive] credential ${data.credentialUuid.slice(0, 8)} already present locally — skipping`);
      return;
    }

    // Ensure issuer + subject identity rows exist (remote custody) so FKs hold.
    for (const id of [data.issuerIdentityUuid, data.subjectIdentityUuid]) {
      if (!id) continue;
      await this.appDb.run(
        `INSERT OR IGNORE INTO identities (uuid, name, role, custody, created_at)
         VALUES (?, NULL, 'vta', 'remote', unixepoch())`,
        id,
      );
    }

    const now = Math.floor(Date.now() / 1000);
    await this.appDb.run(
      `INSERT INTO credentials
         (uuid, vc_type, issuer_identity_uuid, subject_identity_uuid,
          w3c_vc_json, claim, status, valid_from, valid_until,
          credential_digest, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(uuid) DO UPDATE SET status = excluded.status`,
      data.credentialUuid,
      vcType,
      data.issuerIdentityUuid,
      data.subjectIdentityUuid,
      data.w3cVcJson,
      data.claim,
      data.status ?? 'issued',
      data.validFrom ?? now,
      data.validUntil ?? null,
      data.credentialDigest,
      data.createdAt ?? now,
    );

    console.log(`[credential-receive] persisted credential ${data.credentialUuid.slice(0, 8)} (${data.vcType}) for subject ${data.subjectIdentityUuid.slice(0, 8)}`);

    // Announce the arrival. Placed after the write and NOT on the "already present" early return above: a
    // re-delivery of a credential we already hold is not a new arrival, and re-announcing it would make a UI
    // re-read for nothing.
    //
    // Guarded on purpose. `prepare()` votes 'no' on any throw, so an observer that threw would ABORT a
    // transaction whose credential has already been written — turning a successful delivery into a refusal. The
    // announcement is a side effect and must never decide the 2PC outcome.
    try {
      this.onPersisted?.({
        uuid: data.credentialUuid,
        vcType: vcType ?? '',
        issuerIdentityUuid: data.issuerIdentityUuid,
        subjectIdentityUuid: data.subjectIdentityUuid,
        status: data.status ?? 'issued',
      });
    } catch (err) {
      console.warn(`[credential-receive] arrival observer failed: ${(err as Error)?.message ?? err}`);
    }
  }
}