-- Database schema v2 (target -- older than source)
-- Missing: audit_events table, missing clearance_level on roles

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_vacant BOOLEAN DEFAULT FALSE,
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
