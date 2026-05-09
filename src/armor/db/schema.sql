-- armor database schema (v0.1)

-- Enable WAL mode for concurrent reader support
PRAGMA journal_mode = WAL;

-- Session table: per-session state, risk tracking, signal history
CREATE TABLE IF NOT EXISTS Session (
    session_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    current_state TEXT NOT NULL DEFAULT 'Normal' CHECK(current_state IN ('Normal', 'Watching', 'Elevated', 'High', 'Blocked')),
    risk_score REAL NOT NULL DEFAULT 0.0,
    turn_count INTEGER NOT NULL DEFAULT 0,
    signal_history TEXT NOT NULL DEFAULT '[]', -- JSON: [{ts, kind, signal_id, severity}, ...]
    last_signal_at REAL NOT NULL DEFAULT 0.0,
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
    severity TEXT NOT NULL DEFAULT 'low' CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    action TEXT DEFAULT 'blocked' CHECK(action IN ('blocked', 'advisory_only', 'passed_with_warning')),
    quarantine_id INTEGER REFERENCES QuarantinedPayload(id),
    source_tool TEXT NULL,
    chunk_index INTEGER NULL,
    chunk_metadata TEXT NULL
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

-- SessionRollingBuffer table: append-only rolling output buffer per session (ADR-025)
CREATE TABLE IF NOT EXISTS SessionRollingBuffer (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES Session(session_id),
    turn_id TEXT NOT NULL,          -- Turn identifier (e.g., "turn_5")
    text TEXT NOT NULL,              -- Output text for this turn
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index on SessionRollingBuffer for fast lookups by session_id
CREATE INDEX IF NOT EXISTS idx_rolling_buffer_session_ts ON SessionRollingBuffer(session_id, created_at);

-- OperatorAuditLog table: audit trail for operator actions
CREATE TABLE IF NOT EXISTS OperatorAuditLog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (datetime('now')),
    actor TEXT NOT NULL DEFAULT 'operator',  -- Who performed the action (e.g., "operator", username if available)
    action TEXT NOT NULL,                     -- Action type (e.g., "unblock", "clear", "review_passed")
    session_id TEXT NOT NULL REFERENCES Session(session_id),
    reason TEXT                               -- Optional reason provided by operator
);

-- Index on OperatorAuditLog for session lookups
CREATE INDEX IF NOT EXISTS idx_operator_audit_session_ts ON OperatorAuditLog(session_id, ts);
