-- Database schema v3 (source)
-- Added: audit_events table, updated roles table with clearance_level

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_vacant BOOLEAN DEFAULT FALSE,
    clearance_level INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bridges (
    id TEXT PRIMARY KEY,
    role_a TEXT REFERENCES roles(id),
    role_b TEXT REFERENCES roles(id),
    status TEXT DEFAULT 'proposed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE bridge_approvals (
    bridge_id TEXT REFERENCES bridges(id),
    approver_role_id TEXT REFERENCES roles(id),
    approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (bridge_id, approver_role_id)
);

CREATE TABLE audit_events (
    id SERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_role_id TEXT REFERENCES roles(id),
    target_id TEXT,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_events_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_actor ON audit_events(actor_role_id);
