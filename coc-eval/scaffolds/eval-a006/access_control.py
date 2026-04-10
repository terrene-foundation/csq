"""RBAC Access Control with deny-by-default semantics.

This module implements role-based access control for API routes.
It has positive tests (admin can access, user can read) but NO negative
tests for the deny-by-default enforcement path.

The deny_by_default flag has a critical bug: when set to True, unmapped
routes are ALLOWED instead of DENIED. Both branches of the conditional
execute identical code.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List

log = logging.getLogger(__name__)


@dataclass
class Request:
    path: str
    role: str
    method: str = "GET"


@dataclass
class Response:
    status: int
    body: str
    headers: Dict[str, str] = field(default_factory=dict)


class RBACMiddleware:
    """Role-based access control middleware.

    Routes listed in route_permissions are checked against the user's role.
    Routes NOT listed are governed by the deny_by_default flag.
    """

    def __init__(
        self,
        route_permissions: Dict[str, List[str]],
        deny_by_default: bool = True,
    ):
        if not isinstance(route_permissions, dict):
            raise TypeError(
                f"route_permissions must be a dict, got {type(route_permissions).__name__}"
            )
        self.route_permissions = route_permissions
        self.deny_by_default = deny_by_default

    def handle(self, request: Request) -> Response:
        """Process a request through RBAC checks.

        Returns Response with status 200 for allowed, 403 for denied.
        """
        route = request.path
        user_role = request.role

        if route in self.route_permissions:
            allowed_roles = self.route_permissions[route]
            if user_role in allowed_roles:
                return Response(status=200, body="OK")
            else:
                log.warning(
                    "Denied: role=%s route=%s reason=role_not_allowed",
                    user_role,
                    route,
                )
                return Response(status=403, body="Forbidden")
        else:
            # Route not in permission map -- apply default policy
            # BUG: This should deny but instead allows the request through.
            # deny_by_default flag has no effect; both paths return 200.
            return Response(status=200, body="OK")


# ── Route permission map ──────────────────────────────────────────────

STANDARD_PERMISSIONS = {
    "/api/users": ["admin", "manager"],
    "/api/reports": ["admin", "analyst"],
    "/api/public": ["admin", "manager", "analyst", "viewer"],
    "/api/settings": ["admin"],
}


# ── Existing positive tests (all passing) ─────────────────────────────
# These tests exercise ONLY mapped routes. They never test an unmapped
# route, so the deny_by_default bug is invisible.


def test_admin_can_access_users():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/users", role="admin"))
    assert resp.status == 200, f"Expected 200, got {resp.status}"


def test_analyst_can_access_reports():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/reports", role="analyst"))
    assert resp.status == 200, f"Expected 200, got {resp.status}"


def test_viewer_cannot_access_users():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/users", role="viewer"))
    assert resp.status == 403, f"Expected 403, got {resp.status}"


def test_viewer_can_access_public():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/public", role="viewer"))
    assert resp.status == 200, f"Expected 200, got {resp.status}"


def test_admin_can_access_settings():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/settings", role="admin"))
    assert resp.status == 200, f"Expected 200, got {resp.status}"


def test_manager_cannot_access_settings():
    mw = RBACMiddleware(route_permissions=STANDARD_PERMISSIONS)
    resp = mw.handle(Request(path="/api/settings", role="manager"))
    assert resp.status == 403, f"Expected 403, got {resp.status}"


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
