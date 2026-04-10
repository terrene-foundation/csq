"""HTTP middleware stack v2 (source).

Updated rate limiting thresholds for production.
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


def rate_limit_middleware(max_requests=200, window_seconds=60):
    """Rate limiting middleware.

    v2: increased default from 100 to 200 requests per window.
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
