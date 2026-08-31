"""统一处置接口的动作级权限映射。"""

DISPATCH_ACTION_PERMISSIONS = {
    "block": "firewall:block",
    "unblock": "firewall:unblock",
    "confirm": "events:write",
    "ignore": "events:write",
    "escalate": "events:write",
    "status": "firewall:view",
}


def permission_for_dispatch(action: str) -> str:
    normalized = (action or "").strip().lower()
    try:
        return DISPATCH_ACTION_PERMISSIONS[normalized]
    except KeyError as exc:
        raise ValueError(f"未知处置动作: {normalized or '<empty>'}") from exc
