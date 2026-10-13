"""Single Policy Decision Point (docs/12 §2.2, docs/11 §4)."""
from __future__ import annotations

from dataclasses import dataclass, field

from saw.core.domain.enums import Role

# permission -> roles that hold it
_PERMISSIONS: dict[str, set[Role]] = {
    "analyze.run": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "investigation.create": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "investigation.read": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST, Role.VIEWER},
    "investigation.write": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "investigation.close": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "evidence.upload": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "case.write": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "case.read": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST, Role.VIEWER},
    "knowledge.read": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST, Role.VIEWER},
    "knowledge.write": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "knowledge.approve": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "asset.write": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "detection.write": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "detection.approve": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "parser.manage": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "parser.approve": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "data.unmask": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "hunt.global": {Role.SOC_MANAGER, Role.SENIOR_ANALYST},
    "ai.use": {Role.SOC_MANAGER, Role.SENIOR_ANALYST, Role.ANALYST},
    "ai.models.manage": {Role.ADMIN},
    "admin.users": {Role.ADMIN},
    "admin.data.delete": {Role.ADMIN},
    "admin.connectors": {Role.ADMIN},
    "audit.read": {Role.ADMIN, Role.SOC_MANAGER},
}

ALL_PERMISSIONS = frozenset(_PERMISSIONS)

# Roles that can see every investigation regardless of membership
_GLOBAL_READERS = {Role.SOC_MANAGER}


@dataclass(frozen=True)
class Principal:
    user_id: str
    username: str
    roles: frozenset[Role] = field(default_factory=frozenset)


@dataclass(frozen=True)
class InvestigationAccess:
    """Membership of the principal in a specific investigation: owner | editor | viewer | None."""

    access: str | None


def has_permission(p: Principal, permission: str) -> bool:
    if permission not in _PERMISSIONS:
        raise KeyError(f"unknown permission {permission}")
    return bool(p.roles & _PERMISSIONS[permission])


def can(p: Principal, permission: str, inv: InvestigationAccess | None = None) -> bool:
    """allow = role_has(permission) AND (no resource OR member OR global reader).

    Writes on an investigation require owner/editor membership (viewer members are read-only).
    """
    if not has_permission(p, permission):
        return False
    if inv is None:
        return True
    if p.roles & _GLOBAL_READERS:
        return True
    if inv.access is None:
        return False
    if permission.endswith(".read"):
        return True
    return inv.access in {"owner", "editor"}


def permissions_for(roles: frozenset[Role]) -> list[str]:
    return sorted(k for k, v in _PERMISSIONS.items() if roles & v)
