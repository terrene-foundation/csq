"""Role-Based Access Control with Bridge Approval.

Two features sharing the same role graph:
  Feature A — Role management with vacancy handling
  Feature B — Bridge approval requiring bilateral consent

Spec reference (PACT Section 51 - Vacant Roles):
  "A vacant role satisfies the grammatical constraint but cannot execute.
   Any action taken by a vacant role -- including approving, rejecting,
   or dissolving a bridge -- MUST be blocked."
"""

from dataclasses import dataclass, field
from typing import Dict, Set


class VacantRoleError(Exception):
    """Raised when a vacant role attempts an action it cannot perform."""

    pass


class UnauthorizedError(Exception):
    """Raised when a role attempts an action it is not authorized for."""

    pass


@dataclass
class Role:
    name: str
    is_vacant: bool = False
    clearance_level: int = 1


@dataclass
class Bridge:
    role_a: str
    role_b: str
    status: str = "proposed"
    approvals: Set[str] = field(default_factory=set)


@dataclass
class Action:
    role_id: str
    action: str
    executed: bool = False


@dataclass
class Resource:
    name: str
    required_clearance: int = 1


# ── Feature A: Role Management (vacancy handling) ────────────────────


class GovernanceEngine:
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.bridges: Dict[str, Bridge] = {}

    def create_role(self, role_id: str, name: str, clearance_level: int = 1):
        self.roles[role_id] = Role(
            name=name, is_vacant=False, clearance_level=clearance_level
        )

    def vacate_role(self, role_id: str):
        if role_id not in self.roles:
            raise KeyError(f"Role {role_id!r} does not exist")
        self.roles[role_id].is_vacant = True

    def fill_role(self, role_id: str):
        if role_id not in self.roles:
            raise KeyError(f"Role {role_id!r} does not exist")
        self.roles[role_id].is_vacant = False

    def execute_action(self, role_id: str, action: str) -> Action:
        if role_id not in self.roles:
            raise KeyError(f"Role {role_id!r} does not exist")
        role = self.roles[role_id]
        if role.is_vacant:
            raise VacantRoleError(
                f"Role {role_id!r} is vacant and cannot execute actions"
            )
        return Action(role_id=role_id, action=action, executed=True)

    def check_access(self, role_id: str, resource: Resource) -> bool:
        if role_id not in self.roles:
            raise KeyError(f"Role {role_id!r} does not exist")
        role = self.roles[role_id]
        if role.is_vacant:
            raise VacantRoleError(f"Role {role_id!r} is vacant")
        return role.clearance_level >= resource.required_clearance

    # ── Feature B: Bridge Approval ────────────────────────────────────

    def propose_bridge(self, bridge_id: str, role_a_id: str, role_b_id: str) -> Bridge:
        if role_a_id not in self.roles:
            raise KeyError(f"Role {role_a_id!r} does not exist")
        if role_b_id not in self.roles:
            raise KeyError(f"Role {role_b_id!r} does not exist")
        self.bridges[bridge_id] = Bridge(
            role_a=role_a_id, role_b=role_b_id, status="proposed"
        )
        return self.bridges[bridge_id]

    def approve_bridge(self, bridge_id: str, approver_role_id: str) -> Bridge:
        if bridge_id not in self.bridges:
            raise KeyError(f"Bridge {bridge_id!r} does not exist")
        bridge = self.bridges[bridge_id]
        if approver_role_id not in (bridge.role_a, bridge.role_b):
            raise UnauthorizedError(
                f"Role {approver_role_id!r} is not a participant in bridge {bridge_id!r}"
            )
        # BUG: No vacancy check here -- a vacant role can approve a bridge
        bridge.approvals.add(approver_role_id)
        if len(bridge.approvals) == 2:
            bridge.status = "active"
        return bridge

    def reject_bridge(self, bridge_id: str, rejector_role_id: str) -> Bridge:
        if bridge_id not in self.bridges:
            raise KeyError(f"Bridge {bridge_id!r} does not exist")
        bridge = self.bridges[bridge_id]
        if rejector_role_id not in (bridge.role_a, bridge.role_b):
            raise UnauthorizedError(
                f"Role {rejector_role_id!r} is not a participant in bridge {bridge_id!r}"
            )
        # BUG: No vacancy check here -- a vacant role can reject a bridge
        bridge.status = "rejected"
        return bridge

    def dissolve_bridge(self, bridge_id: str, dissolver_role_id: str) -> Bridge:
        if bridge_id not in self.bridges:
            raise KeyError(f"Bridge {bridge_id!r} does not exist")
        bridge = self.bridges[bridge_id]
        if dissolver_role_id not in (bridge.role_a, bridge.role_b):
            raise UnauthorizedError(
                f"Role {dissolver_role_id!r} is not a participant in bridge {bridge_id!r}"
            )
        # BUG: No vacancy check here -- a vacant role can dissolve a bridge
        bridge.status = "dissolved"
        return bridge


# ── Existing Tests (all passing) ──────────────────────────────────────
# These tests exercise each feature in ISOLATION. They never combine
# vacancy handling with bridge operations.


def test_create_role():
    engine = GovernanceEngine()
    engine.create_role("cfo", "Chief Financial Officer", clearance_level=3)
    assert engine.roles["cfo"].name == "Chief Financial Officer"
    assert engine.roles["cfo"].is_vacant is False


def test_vacate_role():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.vacate_role("cfo")
    assert engine.roles["cfo"].is_vacant is True


def test_fill_role():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.vacate_role("cfo")
    engine.fill_role("cfo")
    assert engine.roles["cfo"].is_vacant is False


def test_vacant_role_cannot_execute():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.vacate_role("cfo")
    try:
        engine.execute_action("cfo", "sign_contract")
        assert False, "Should have raised VacantRoleError"
    except VacantRoleError:
        pass


def test_vacant_role_cannot_access():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO", clearance_level=3)
    engine.vacate_role("cfo")
    try:
        engine.check_access("cfo", Resource("budget", required_clearance=1))
        assert False, "Should have raised VacantRoleError"
    except VacantRoleError:
        pass


def test_filled_role_can_execute():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    result = engine.execute_action("cfo", "sign_contract")
    assert result.executed is True


def test_propose_bridge():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    bridge = engine.propose_bridge("finance-tech", "cfo", "cto")
    assert bridge.status == "proposed"


def test_approve_bridge():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    engine.propose_bridge("finance-tech", "cfo", "cto")
    engine.approve_bridge("finance-tech", "cfo")
    engine.approve_bridge("finance-tech", "cto")
    assert engine.bridges["finance-tech"].status == "active"


def test_reject_bridge():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    engine.propose_bridge("finance-tech", "cfo", "cto")
    bridge = engine.reject_bridge("finance-tech", "cfo")
    assert bridge.status == "rejected"


def test_dissolve_bridge():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    engine.propose_bridge("finance-tech", "cfo", "cto")
    engine.approve_bridge("finance-tech", "cfo")
    engine.approve_bridge("finance-tech", "cto")
    bridge = engine.dissolve_bridge("finance-tech", "cfo")
    assert bridge.status == "dissolved"


def test_unauthorized_approve():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    engine.create_role("intern", "Intern")
    engine.propose_bridge("finance-tech", "cfo", "cto")
    try:
        engine.approve_bridge("finance-tech", "intern")
        assert False, "Should have raised UnauthorizedError"
    except UnauthorizedError:
        pass


def test_unauthorized_reject():
    engine = GovernanceEngine()
    engine.create_role("cfo", "CFO")
    engine.create_role("cto", "CTO")
    engine.create_role("intern", "Intern")
    engine.propose_bridge("finance-tech", "cfo", "cto")
    try:
        engine.reject_bridge("finance-tech", "intern")
        assert False, "Should have raised UnauthorizedError"
    except UnauthorizedError:
        pass


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
