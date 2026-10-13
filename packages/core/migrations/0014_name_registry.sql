-- 0016_name_registry: Namespace-scoped human-readable name → DID mapping.
--
-- Managed by the utility server's name resolver. Agents claim names
-- by sending TSP name_register messages. Names are scoped to a
-- namespace (configured per utility server) so different networks
-- can have independent name registries.
--
-- Future bridging: the `source_namespace` column allows names from
-- federated utility servers to be cached locally, enabling
-- cross-network resolution.

CREATE TABLE IF NOT EXISTS name_registry (
    uuid             TEXT PRIMARY KEY,       -- UUIDv7 for replication dedup (standard pattern)
    namespace        TEXT NOT NULL,
    name             TEXT NOT NULL,
    identity_uuid    TEXT,                   -- identities.uuid FK (UUIDv5 of DID) — portable cross-node ref
    did              TEXT NOT NULL,
    profile_uuid     TEXT,                   -- profiles.uuid FK — portable cross-node ref (set by identity_push)
    credential_uuid  TEXT,                   -- credentials.uuid FK — portable cross-node ref
    source_namespace TEXT,                   -- null for local names; set for cached federated names
    proof_type       TEXT,                   -- 'alsoKnownAs' | 'vrc' | 'utility_managed' — how this name was verified
    proof_reference  TEXT,                   -- rotation entry digest or VRC credential_digest
    recorded_by_node TEXT,                   -- provenance tracking
    replicated_at    INTEGER,
    claimed_at       INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at       INTEGER,
    expires_at       INTEGER,
    revoked_at       INTEGER,
    UNIQUE(namespace, name)
);

CREATE INDEX IF NOT EXISTS idx_name_registry_did ON name_registry(did);
CREATE INDEX IF NOT EXISTS idx_name_registry_identity_uuid ON name_registry(identity_uuid);
CREATE INDEX IF NOT EXISTS idx_name_registry_profile_uuid ON name_registry(profile_uuid);