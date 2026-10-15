// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The ceremony TASK LOG — reading `trust_tasks` back as ceremonies.
 *
 * A thread is one ceremony RUN. Its id names the ceremony only by CONVENTION
 * (`vtc-establish` uses the ceremony id, member onboarding a fresh uuid,
 * governance-change the proposal id), so a ceremony is identified from the task TYPES
 * the thread contains: a step→ceremony index built from `ceremony_templates`, plus the
 * founding ceremony's coordination events (which are deliberately not catalog steps —
 * see `type-uris.ts`).
 *
 * ## Everything a reader sees comes from the DATABASE
 *
 * A ceremony's title + description live in its `ceremony_templates.display` column, and
 * each step's label + request/response sentences live in `trust_task_templates.display` —
 * JSON columns kept SEPARATE from `template`, which is the trust-task definition and stays
 * aligned with the trust-task structure. A developer who adds a ceremony therefore writes
 * its wording in the catalog — no UI change and no parallel label map to keep in step. The
 * UI fills `{placeholder}` slots from each step's recorded payload.
 *
 * There is exactly ONE implementation of this, shared by both readers: the
 * `GET /trust-tasks/*` HTTP routes, and the TSP `ceremony_log_*` queries the agent app
 * reads through. Two copies could disagree about what a thread is; this cannot.
 */

import type { DataSource } from '../../db/data-source.js';
import * as trustTasksRepo from '../../db/repositories/trust-tasks-repo.js';
import type { TrustTaskDirection } from '../../db/repositories/trust-tasks-repo.js';
import * as catalogRepo from '../../db/repositories/trust-task-catalog-repo.js';
import { parseCeremonyDefinition, parseStepDisplay, parseCeremonyDisplay } from './catalog.js';
import {
  CEREMONY_PROPOSE_TYPE,
  CEREMONY_CO_SIGN_TYPE,
  CEREMONY_VTC_ESTABLISH,
} from './type-uris.js';

/** A step's reader-facing wording, as stored on its catalog row. */
export interface CeremonyLogDisplay {
  label?: string;
  request?: string;
  response?: string;
}

/** One ceremony run, as the task log presents it. */
export interface CeremonyLogThread {
  threadId: string;
  /** The ceremony's catalog `name`, or null when nothing identifies it. */
  ceremony: string | null;
  /** The ceremony's reader-facing title, from its catalog row. */
  ceremonyLabel: string | null;
  /** The ceremony's one-line description, from its catalog row. */
  ceremonyDescription: string | null;
  documentCount: number;
  types: string[];
  statuses: string[];
  startedAt: number | null;
  lastAt: number | null;
}

/** One recorded step within a ceremony run. */
export interface CeremonyLogStep {
  id: string;
  type: string;
  /** The step's catalog wording; null when the type has no catalog row. */
  display: CeremonyLogDisplay | null;
  direction: TrustTaskDirection;
  issuerDid: string | null;
  recipientDid: string | null;
  payload: unknown;
  proof: unknown;
  status: string;
  createdAt: number | null;
}

/** The catalog lookups the log needs, built in one pass. */
interface CatalogIndex {
  /** step type → the ceremony that runs it */
  stepCeremony: Map<string, string>;
  /** step type → its reader-facing wording */
  stepDisplay: Map<string, CeremonyLogDisplay>;
  /** ceremony name → its reader-facing title + description */
  ceremonyDisplay: Map<string, { label?: string; description?: string }>;
}

async function buildCatalogIndex(db: DataSource): Promise<CatalogIndex> {
  const index: CatalogIndex = {
    stepCeremony: new Map(), stepDisplay: new Map(), ceremonyDisplay: new Map(),
  };

  // Steps and coordination events both carry wording in their `display` COLUMN; `template`
  // is the trust-task definition and is deliberately NOT read for presentation. Rule rows
  // are rule BODIES, never displayed as steps, and have no `display`.
  for (const row of await catalogRepo.listSteps(db)) {
    if (row.family === 'rule') continue;
    const display = parseStepDisplay(row.display);
    index.stepDisplay.set(row.type, display ?? {});
  }

  for (const ceremony of await catalogRepo.listCeremonies(db)) {
    const def = parseCeremonyDefinition(ceremony.template);
    const display = parseCeremonyDisplay(ceremony.display);
    index.ceremonyDisplay.set(ceremony.name, display ?? {});
    for (const ref of def.steps) {
      // A step may appear in more than one ceremony; the first name wins (the catalog is
      // read in name order), which is enough to label a thread.
      if (ref.step && !index.stepCeremony.has(ref.step)) {
        index.stepCeremony.set(ref.step, ceremony.name);
      }
    }
  }

  return index;
}

/**
 * Name the ceremony a thread belongs to, from the task types it contains.
 *
 * The founding ceremony's proposal / co-signature documents are not catalog steps —
 * they are coordination events — so they are recognised explicitly rather than looked
 * up.
 */
export function resolveCeremonyName(types: string[], stepCeremony: Map<string, string>): string | null {
  if (types.includes(CEREMONY_PROPOSE_TYPE) || types.includes(CEREMONY_CO_SIGN_TYPE)) {
    return CEREMONY_VTC_ESTABLISH;
  }
  for (const type of types) {
    const ceremony = stepCeremony.get(type);
    if (ceremony) return ceremony;
  }
  return null;
}

/** Every ceremony run the node has recorded, newest first, with its catalog wording. */
export async function listCeremonyThreads(db: DataSource): Promise<CeremonyLogThread[]> {
  const threads = await trustTasksRepo.listThreads(db);
  const index = await buildCatalogIndex(db);
  return threads.map((thread) => {
    const ceremony = resolveCeremonyName(thread.types, index.stepCeremony);
    const wording = ceremony ? index.ceremonyDisplay.get(ceremony) : undefined;
    return {
      threadId: thread.threadId,
      ceremony,
      ceremonyLabel: wording?.label ?? null,
      ceremonyDescription: wording?.description ?? null,
      documentCount: thread.documentCount,
      types: thread.types,
      statuses: thread.statuses,
      startedAt: thread.firstAt,
      lastAt: thread.lastAt,
    };
  });
}

/**
 * One ceremony run's steps, in RECORD ORDER.
 *
 * `trust_tasks` rows carry time-ordered (UUIDv7) ids precisely so that several steps
 * committed within the same second still come back in the order they happened — see
 * `trust-tasks-repo.listByThread`.
 */
export async function getCeremonyThread(db: DataSource, threadId: string): Promise<CeremonyLogStep[]> {
  const rows = await trustTasksRepo.listByThread(db, threadId);
  const index = await buildCatalogIndex(db);
  return rows.map((row) => ({
    id: row.uuid,
    type: row.type,
    display: index.stepDisplay.get(row.type) ?? null,
    direction: row.direction,
    issuerDid: row.issuerDid,
    recipientDid: row.recipientDid,
    payload: row.payload === null ? null : JSON.parse(row.payload),
    proof: row.proof === null ? null : JSON.parse(row.proof),
    status: row.status,
    createdAt: row.createdAt,
  }));
}
