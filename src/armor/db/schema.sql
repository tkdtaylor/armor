-- armor database schema (v0.1)

-- Enable WAL mode for concurrent reader support
PRAGMA journal_mode = WAL;

-- Session table: per-session state, risk tracking, signal history
CREATE TABLE IF NOT EXISTS Session (
    session_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    state TEXT NOT NULL DEFAULT 'Normal' CHECK(state IN ('Normal', 'Watching', 'Elevated', 'High', 'Blocked')),
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK(risk_score >= 0 AND risk_score <= 100),
    turn_count INTEGER NOT NULL DEFAULT 0,
    signal_history TEXT NOT NULL DEFAULT '[]', -- JSON: [{ts, kind, signal_id, severity}, ...]
    UNIQUE(session_id)
);

-- Incident table: forensic log, append-only
CREATE TABLE IF NOT EXISTS Incident (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    session_id TEXT REFERENCES Session(session_id),
    attack_category TEXT NOT NULL,
    signal_id TEXT,
    input_hash TEXT NOT NULL,
    output_hash TEXT,
    triggered_canary TEXT,
    destinations TEXT, -- JSON: ["hostname1", "hostname2", ...]
    encoding_flag BOOLEAN DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    action TEXT DEFAULT 'blocked' CHECK(action IN ('blocked', 'advisory_only', 'passed_with_warning')),
    quarantine_id INTEGER REFERENCES QuarantinedPayload(id)
);

-- Indices on Incident for common queries
CREATE INDEX IF NOT EXISTS idx_incident_session_ts ON Incident(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_incident_category_ts ON Incident(attack_category, ts);

-- QuarantinedPayload table: encrypted input/output texts, TTL-purged
CREATE TABLE IF NOT EXISTS QuarantinedPayload (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    input_text TEXT NOT NULL,  -- Fernet-encrypted
    output_text TEXT,          -- Fernet-encrypted, nullable
    expires_at TEXT NOT NULL DEFAULT (datetime('now', '+168 hours'))
);

-- Index on QuarantinedPayload for TTL sweep
CREATE INDEX IF NOT EXISTS idx_quarantined_expires_at ON QuarantinedPayload(expires_at);
