-- 0004_rotation_log_and_witness_attestations.sql
-- Hash-chained, append-only rotation log per DID document, plus normalized
-- witness attestations backing a rotation (M-of-N witness quorum support).

CREATE TABLE IF NOT EXISTS rotation_log (
  uuid                TEXT PRIMARY KEY,            -- UUIDv7 for cross-node dedup
  did_document_uuid   TEXT NOT NULL,               -- did_documents.uuid FK target
  version             INTEGER NOT NULL,
  previous_hash       BLOB,
  new_public_key      BLOB NOT NULL,
  signed_entry        BLOB NOT NULL,
  recorded_by_node    TEXT,
  replicated_at       INTEGER,
  created_at          INTEGER,
  UNIQUE(did_document_uuid, version)
);

CREATE INDEX IF NOT EXISTS idx_rotation_log_did_document_uuid ON rotation_log(did_document_uuid);

CREATE TABLE IF NOT EXISTS witness_attestations (
  uuid                      TEXT PRIMARY KEY,      -- UUIDv7 for cross-node dedup
  rotation_log_uuid         TEXT NOT NULL,         -- rotation_log.uuid FK target
  witness_did_document_uuid TEXT NOT NULL,         -- did_documents.uuid FK target
  signature                 BLOB NOT NULL,
  recorded_by_node          TEXT,
  replicated_at             INTEGER,
  attested_at               INTEGER,
  UNIQUE(rotation_log_uuid, witness_did_document_uuid)
);

CREATE INDEX IF NOT EXISTS idx_witness_attestations_rotation_uuid ON witness_attestations(rotation_log_uuid);