"""API route definitions v1 -- identical in source and target."""

ROUTES = {
    "POST /api/roles": {
        "handler": "create_role",
        "permissions": ["admin"],
    },
    "GET /api/roles": {
        "handler": "list_roles",
        "permissions": ["admin", "manager"],
    },
    "POST /api/bridges": {
        "handler": "propose_bridge",
        "permissions": ["admin", "manager"],
    },
    "PUT /api/bridges/:id/approve": {
        "handler": "approve_bridge",
        "permissions": ["admin", "manager"],
    },
    "GET /api/audit": {
        "handler": "list_audit_events",
        "permissions": ["admin"],
    },
}
