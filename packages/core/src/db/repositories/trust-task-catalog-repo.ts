// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Repository: `trust_task_templates` + `ceremony_templates` (migration 0019).
 *
 * The authoritative catalog of trust-task STEP and CEREMONY definitions. The
 * `template` column is the JSON definition (see
 * `src/services/trust-tasks/catalog.ts` for the parsed shapes); `type`/`family`/
 * `version` (and `name` for ceremonies) are indexed columns for lookup. Executors
 * are registered in CODE, never stored here.
 */

import type { DataSource } from '../data-source.js';

export interface TrustTaskStepRow {
  uuid: string;
  type: string;
  family: string;
  version: string;
  template: string; // JSON (TrustTaskStepTemplate) — the trust-task definition
  /**
   * JSON (StepDisplay) — the READER-FACING wording for the UI, kept in its own column so
   * `template` stays a pure trust-task document. NULL for rows with no wording (rules).
   */
  display: string | null;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

export interface CeremonyTemplateRow {
  uuid: string;
  name: string;
  version: string;
  template: string; // JSON (CeremonyDefinition) — {steps:[…]}
  /** JSON (CeremonyDisplay) — the ceremony's {label, description}. */
  display: string | null;
  recordedByNode: string | null;
  replicatedAt: number | null;
  createdAt: number | null;
  updatedAt: number | null;
}

interface RawStepRow {
  uuid: string;
  type: string;
  family: string;
  version: string;
  template: string;
  display: string | null;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

interface RawCeremonyRow {
  uuid: string;
  name: string;
  version: string;
  template: string;
  display: string | null;
  recorded_by_node: string | null;
  replicated_at: number | null;
  created_at: number | null;
  updated_at: number | null;
}

function stepRow(raw: RawStepRow): TrustTaskStepRow {
  return {
    uuid: raw.uuid,
    type: raw.type,
    family: raw.family,
    version: raw.version,
    template: raw.template,
    display: raw.display,
    recordedByNode: raw.recorded_by_node,
    replicatedAt: raw.replicated_at,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

function ceremonyRow(raw: RawCeremonyRow): CeremonyTemplateRow {
  return {
    uuid: raw.uuid,
    name: raw.name,
    version: raw.version,
    template: raw.template,
    display: raw.display,
    recordedByNode: raw.recorded_by_node,
    replicatedAt: raw.replicated_at,
    createdAt: raw.created_at,
    updatedAt: raw.updated_at,
  };
}

export async function listSteps(db: DataSource): Promise<TrustTaskStepRow[]> {
  const rows = await db.all<RawStepRow>('SELECT * FROM trust_task_templates ORDER BY family, type');
  return rows.map(stepRow);
}

export async function findStepByType(db: DataSource, type: string): Promise<TrustTaskStepRow | null> {
  const row = await db.get<RawStepRow>('SELECT * FROM trust_task_templates WHERE type = ?', type);
  return row ? stepRow(row) : null;
}

export async function listCeremonies(db: DataSource): Promise<CeremonyTemplateRow[]> {
  const rows = await db.all<RawCeremonyRow>('SELECT * FROM ceremony_templates ORDER BY name');
  return rows.map(ceremonyRow);
}

export async function findCeremonyByName(db: DataSource, name: string): Promise<CeremonyTemplateRow | null> {
  const row = await db.get<RawCeremonyRow>('SELECT * FROM ceremony_templates WHERE name = ?', name);
  return row ? ceremonyRow(row) : null;
}
