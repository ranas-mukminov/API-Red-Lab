"""Fixed API functions matching api/vuln.py, case for case."""

from vuln import OBJECTS, SESSIONS, USERS

PUBLIC_PROFILE_FIELDS = ("id", "name")


def get_object_fixed(object_id, caller):
    """FIXED (BOLA): a caller reads only their own objects."""
    obj = OBJECTS.get(object_id)
    if obj is None:
        return None
    if obj["owner"] != caller:
        raise PermissionError("caller may read only their own objects")
    return obj


def authenticate_fixed(token):
    """FIXED (authentication): the token must be a session that was
    actually issued. Guessing the format is not enough."""
    for user, issued in SESSIONS.items():
        if token == issued:
            return user
    return None


def get_profile_fixed(user_id, caller):
    """FIXED (excessive data exposure): only public fields leave the API,
    and only for the caller themselves in this lab."""
    if user_id != caller:
        raise PermissionError("caller may read only their own profile")
    user = USERS.get(user_id)
    if user is None:
        return None
    return {k: user[k] for k in PUBLIC_PROFILE_FIELDS}


class RateLimiterFixed:
    """FIXED (rate limiting): a small per-caller budget for the lab."""

    def __init__(self, limit=3):
        self.limit = limit
        self.counts = {}

    def allow(self, caller):
        used = self.counts.get(caller, 0)
        if used >= self.limit:
            return False
        self.counts[caller] = used + 1
        return True
