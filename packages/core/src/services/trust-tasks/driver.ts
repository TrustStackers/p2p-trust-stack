/**
 * The ceremony DRIVER — walks a cataloged ceremony, one trust-task step at a time.
 *
 * Definitions come from the DB (`ceremony_templates` / `trust_task_templates`); the
 * *work* of a step comes from code: a `policy` step is gated by the injected
 * authorizer (a thin wrapper over `GovernanceGuard.authorize`), and an `effect`
 * step is performed by its registered executor (see `catalog.ts`). Every step is
 * logged to `trust_tasks` as a request + response under the shared `threadId`.
 *
 * A `repeat` directive may name a collection passed in `options.collections`, or —
 * with a `$`-prefix — a path into the accumulated OUTPUT of an earlier step (e.g.
 * `$task:p2pts:vtc:establish:0.1#foundingAdmins`), so a later step can fan out over
 * what an earlier step produced.
 *
 * The driver is orchestration only — it does NOT re-implement the 2PC coordinator.
 */

import { generateUuid } from '../../db/uuid-helpers.js';
import type { DataSource } from '../../db/data-source.js';
import * as catalogRepo from '../../db/repositories/trust-task-catalog-repo.js';
import * as trustTasksRepo from '../../db/repositories/trust-tasks-repo.js';
import { parseStepTemplate, parseCeremonyDefinition, resolveExecutor } from './catalog.js';
import { resultToPolicyDecision } from './project.js';
import type { PolicyResult } from '../policy-engine.js';

/** The policy-gate dependency: decide whether a step's action is allowed. */
export interface CeremonyAuthorizer {
  authorize(action: string, context: Record<string, unknown>): Promise<PolicyResult>;
}

export interface DriveCeremonyOptions {
  /** Required only when the ceremony contains a `policy` step. */
  authorizer?: CeremonyAuthorizer;
  /** Context handed to the authorizer and each effect executor. */
  context?: Record<string, unknown>;
  /** Named static collections backing a plain `repeat` directive. */
  collections?: Record<string, unknown[]>;
}

export interface DriveCeremonyResult {
  threadId: string;
  completed: boolean;
  /** The step `type` that denied (present when `completed === false`). */
  haltedAt?: string;
  stepsRun: number;
  /** Step `type` → the effect step's result (for `$`-fed repeats + callers). */
  outputs: Record<string, unknown>;
}

/** Run a ceremony to completion (or until a gate denies). */
export async function driveCeremony(
  db: DataSource,
  ceremonyName: string,
  threadId: string,
  opts: DriveCeremonyOptions,
): Promise<DriveCeremonyResult> {
  const ceremony = await catalogRepo.findCeremonyByName(db, ceremonyName);
  if (!ceremony) throw new Error(`ceremony '${ceremonyName}' is not defined in the catalog`);
  const def = parseCeremonyDefinition(ceremony.template);

  const outputs: Record<string, unknown> = {};
  let stepsRun = 0;

  for (const ref of def.steps) {
    if (ref.ceremony) {
      const nested = await driveCeremony(db, ref.ceremony, threadId, opts);
      stepsRun += nested.stepsRun;
      Object.assign(outputs, nested.outputs);
      if (!nested.completed) {
        return { threadId, completed: false, haltedAt: nested.haltedAt, stepsRun, outputs };
      }
      continue;
    }

    const stepType = ref.step;
    if (!stepType) throw new Error('a ceremony step must name `step` or `ceremony`');

    for (const item of resolveIterations(ref.repeat, opts.collections, outputs)) {
      const outcome = await driveStep(db, stepType, threadId, opts, item);
      stepsRun += 1;
      if (outcome.result !== undefined) outputs[stepType] = outcome.result;
      if (!outcome.allowed) {
        return { threadId, completed: false, haltedAt: stepType, stepsRun, outputs };
      }
    }
  }

  return { threadId, completed: true, stepsRun, outputs };
}

function resolveIterations(
  repeat: string | undefined,
  collections: Record<string, unknown[]> | undefined,
  outputs: Record<string, unknown>,
): Array<unknown | undefined> {
  if (!repeat || repeat === 'once') return [undefined];
  if (repeat.startsWith('$')) {
    // `$<stepType>[#<dot.separated.path>]` — the output of an earlier effect step.
    // `#` delimits (the type's version `0.1` legally contains dots), matching the
    // fragment convention in type-uris.ts (#request / #response). Without `#`, the
    // step's whole output must itself be an array.
    const rest = repeat.slice(1);
    const hash = rest.indexOf('#');
    const stepType = hash === -1 ? rest : rest.slice(0, hash);
    let value: unknown = outputs[stepType];
    if (value === undefined) {
      throw new Error(`repeat '${repeat}' does not resolve (no output for '${stepType}')`);
    }
    if (hash !== -1) {
      for (const part of rest.slice(hash + 1).split('.')) {
        if (value && typeof value === 'object' && part in (value as object)) {
          value = (value as Record<string, unknown>)[part];
        } else {
          throw new Error(`repeat '${repeat}' does not resolve (missing '${part}')`);
        }
      }
    }
    if (!Array.isArray(value)) throw new Error(`repeat '${repeat}' does not resolve to an array`);
    return value;
  }
  const col = collections?.[repeat];
  if (!col) throw new Error(`repeat '${repeat}' references an unknown collection`);
  return col;
}

interface StepOutcome {
  allowed: boolean;
  result?: unknown;
}

async function driveStep(
  db: DataSource,
  stepType: string,
  threadId: string,
  opts: DriveCeremonyOptions,
  item?: unknown,
): Promise<StepOutcome> {
  const row = await catalogRepo.findStepByType(db, stepType);
  if (!row) throw new Error(`step '${stepType}' is not defined in the catalog`);
  const tpl = parseStepTemplate(row.template);

  const context: Record<string, unknown> = { ...(opts.context ?? {}) };
  if (item !== undefined) context.item = item;

  await trustTasksRepo.record(db, {
    uuid: generateUuid(),
    threadId,
    type: stepType,
    direction: 'request',
    payload: { kind: tpl.kind, action: tpl.action, ...(item !== undefined ? { item } : {}) },
  });

  if (tpl.kind === 'policy') {
    if (!opts.authorizer) throw new Error(`no authorizer provided for policy step '${stepType}'`);
    const decision: PolicyResult = await opts.authorizer.authorize(tpl.action, context);
    await trustTasksRepo.record(db, {
      uuid: generateUuid(),
      threadId,
      type: stepType,
      direction: 'response',
      payload: resultToPolicyDecision(decision),
      status: decision.allowed ? 'allowed' : 'denied',
    });
    return { allowed: decision.allowed };
  }

  const executor = resolveExecutor(stepType);
  if (!executor) {
    // NB: `coordination` steps are RECORDED by the ceremony coordinator (its begin /
    // approve handlers), never driven — so a ceremony listing one is a catalog mistake
    // and must fail loudly here rather than as a mysterious missing executor.
    if (tpl.kind !== 'effect') {
      throw new Error(
        `step '${stepType}' has kind '${tpl.kind}', which the driver cannot execute`,
      );
    }
    throw new Error(`no executor registered for effect step '${stepType}'`);
  }
  const result = await executor(context);
  // An effect executor may signal the RECIPIENT of its response via a reserved
  // `recipientDid` field on its returned object; the driver surfaces it as the
  // structured `recipient_did` column (still present in the payload body too).
  let recipientDid: string | undefined;
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>).recipientDid === 'string') {
    recipientDid = (result as Record<string, unknown>).recipientDid as string;
  }
  await trustTasksRepo.record(db, {
    uuid: generateUuid(),
    threadId,
    type: stepType,
    direction: 'response',
    recipientDid,
    payload: { result },
    status: 'completed',
  });
  return { allowed: true, result };
}
