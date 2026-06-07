CREATE TABLE IF NOT EXISTS audit_ledger (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    agent_id TEXT NOT NULL,
    intent_fingerprint TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    component TEXT NOT NULL,
    status TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    attestation TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_ledger_timestamp_idx
    ON audit_ledger (timestamp);

CREATE INDEX IF NOT EXISTS audit_ledger_agent_idx
    ON audit_ledger (agent_id, timestamp);
