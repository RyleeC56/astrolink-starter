"""
Docstring for app.permissions

Role-based access control (RBAC)

Each role gets a list of permissions. Pages or actions require a permission, 
and only roles that have it are allowed.
"""

from functools import wraps
from flask import abort
from flask_login import current_user

## Lists which actions each role is allowed to do.
## Anything not listed is denied

ROLE_PERMISSIONS = {
    "viewer":   set(),
    "intern":   {"view_satellites"},
    "operator": {"view_satellites", "send_low_risk", "send_medium_risk"},
    "senior":   {"view_satellites", "send_low_risk", "send_medium_risk",
                 "send_high_risk", "approve_commands", "view_audit_log"},
    "admin":    {"view_satellites", "send_low_risk", "send_medium_risk",
                 "send_high_risk", "approve_commands", "view_audit_log",
                 "view_subscribers", "manage_users"},
}

def has_permission(user, permission):
    """True if this user's role includes the permission."""
    # Unknown roles get an empty set, so they can do nothing (deny by default)
    allowed = ROLE_PERMISSIONS.get(user.role, set())
    return permission in allowed

def permission_required(permission):
    """Put @permission_required("view_subscribers") above a route to restrict it."""
    def decorator(view_function):
        @wraps(view_function)
        def wrapper(*args, **kwargs):
            # Not logged in counts as no permission at all
            if not current_user.is_authenticated:
                abort(401)
            if not has_permission(current_user, permission):
                abort(403)  # 403 = "Forbidden": logged in, but not allowed
            return view_function(*args, **kwargs)
        return wrapper
    return decorator


