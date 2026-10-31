"""Intentionally vulnerable API functions — LAB ONLY.

Each function has a fixed counterpart in api/fixed.py. The vulnerable
versions exist so the flaw can be demonstrated and tested locally.
"""

# Fictional lab data only.
USERS = {
    "lab-alice": {"id": "lab-alice", "name": "Alice (lab)", "email": "alice@example.invalid", "internal_note": "lab-only note"},
    "lab-bob": {"id": "lab-bob", "name": "Bob (lab)", "email": "bob@example.invalid", "internal_note": "lab-only note"},
}
OBJECTS = {
    "obj-1": {"owner": "lab-alice", "title": "Alice lab object", "content": "lab content"},
    "obj-2": {"owner": "lab-bob", "title": "Bob lab object", "content": "lab content"},
}
# Deliberately weak: a token that can be guessed from the user id.
SESSIONS = {"lab-alice": "token-lab-alice", "lab-bob": "token-lab-bob"}


def get_object_vuln(object_id, caller):
    """VULNERABLE (BOLA): no ownership check."""
    return OBJECTS.get(object_id)


def authenticate_vuln(token):
    """VULNERABLE (broken authentication): any token of the form
    'token-<user>' is accepted, even if no session was issued."""
    if token and token.startswith("token-"):
        user = token[len("token-"):]
        return user if user in USERS else None
    return None


def get_profile_vuln(user_id, caller):
    """VULNERABLE (excessive data exposure): returns the whole record,
    including internal notes and private email, to any caller."""
    return USERS.get(user_id)


class RateLimiterVuln:
    """VULNERABLE (no rate limiting): every request is allowed."""

    def allow(self, caller):
        return True
