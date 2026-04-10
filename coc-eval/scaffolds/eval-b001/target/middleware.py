"""HTTP middleware stack v3 (target -- has local customizations).

Target has additional request_id_middleware not present in source.
Rate limit threshold differs from source (100 vs 200).
"""


def rbac_middleware(route_permissions, deny_by_default=True):
    """RBAC enforcement middleware."""

    def middleware(request):
        route = request.path
        role = request.user_role
        if route in route_permissions:
            if role in route_permissions[route]:
                return None  # allow
            return {"status": 403, "body": "Forbidden"}
        if deny_by_default:
            return {"status": 403, "body": "Forbidden"}
        return None

    return middleware


def rate_limit_middleware(max_requests=100, window_seconds=60):
    """Rate limiting middleware.

    v1: 100 requests per window (source has updated to 200).
    """
    counters = {}

    def middleware(request):
        key = request.remote_addr
        now = __import__("time").time()
        if key not in counters:
            counters[key] = {"count": 0, "window_start": now}
        entry = counters[key]
        if now - entry["window_start"] > window_seconds:
            entry["count"] = 0
            entry["window_start"] = now
        entry["count"] += 1
        if entry["count"] > max_requests:
            return {"status": 429, "body": "Too Many Requests"}
        return None

    return middleware


def request_id_middleware():
    """Attach a unique request ID to each request.

    TARGET-ONLY: This middleware exists only in the target and must
    be preserved during sync. It is not present in source.
    """
    import uuid

    def middleware(request):
        request.id = str(uuid.uuid4())
        return None

    return middleware
