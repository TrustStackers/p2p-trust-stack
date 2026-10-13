-- 0005_relationships.sql
-- Direct Layer-2 peer links (libp2p), independent of any VTC/VTN context.
--
-- direction uses a CRDT lattice merge: pending < {outbound,inbound} < bidirectional.
-- When two nodes report different directions for the same peer pair, the
-- merged result is the join in the lattice.

CREATE TABLE IF NOT EXISTS relationships (
  uuid                     TEXT PRIMARY KEY,          -- UUIDv7 for cross-node dedup
  local_identity_uuid      TEXT NOT NULL,             -- identities.uuid FK target
  remote_identity_uuid     TEXT NOT NULL,             -- identities.uuid FK target
  local_did_document_uuid  TEXT,                      -- did_documents.uuid FK target
  remote_did_document_uuid TEXT,                      -- did_documents.uuid FK target
  direction                TEXT NOT NULL CHECK(direction IN ('pending', 'outbound', 'inbound', 'bidirectional')),
  status                   TEXT NOT NULL CHECK(status IN ('pending', 'established', 'rejected')),
  remote_transport         TEXT,
  rfi_digest               BLOB,                      -- SHA2-256 digest of the winning RFI payload
  rfa_reply_digest         BLOB,                      -- SHA2-256 digest of the RFA reply payload
  personhood_status        TEXT CHECK(personhood_status IS NULL OR personhood_status IN ('acknowledged', 'verified')),
                                                      -- VRC ceremony: NULL → acknowledged → verified
  recorded_by_node         TEXT,
  replicated_at            INTEGER,
  created_at               INTEGER,
  updated_at               INTEGER,
  UNIQUE(local_identity_uuid, remote_identity_uuid)
);

CREATE INDEX IF NOT EXISTS idx_relationships_local_uuid ON relationships(local_identity_uuid);
CREATE INDEX IF NOT EXISTS idx_relationships_remote_uuid ON relationships(remote_identity_uuid);