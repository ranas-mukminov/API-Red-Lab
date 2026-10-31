# Case walkthrough

## API-01 — Broken Object Level Authorisation (BOLA)

Vulnerable: `get_object_vuln("obj-2", "lab-alice")` returns Bob's
object. Fixed: the same call raises `PermissionError`, because the
object's owner is not the caller. The fix is a server-side ownership
check on every object access, not a client-side hiding of the link.

## API-02 — Broken Authentication

Vulnerable: `authenticate_vuln("token-lab-alice")` accepts a token
that was never issued — it only has the right shape. Fixed:
`authenticate_fixed` accepts only tokens present in the issued
session table. In a real system, sessions are random, unguessable,
and expire; the lab's issued-token table stands in for that.

## API-03 — Excessive Data Exposure

Vulnerable: `get_profile_vuln` returns the whole user record,
including an internal note and a private email, to any caller.
Fixed: `get_profile_fixed` returns only public fields, and only to
the owner. The fix is to filter at the API boundary, not to hope
the client ignores extra fields — clients, and attackers, do not.

## API-04 — Lack of Resources and Rate Limiting

Vulnerable: `RateLimiterVuln.allow` always returns True. Fixed:
`RateLimiterFixed` allows a small budget per caller (3 in the lab)
and then rejects. In a real system the budget, the window, and the
response (429 with Retry-After) are tuned to the API; the principle
is the same: an unbounded endpoint is a denial-of-service flaw.
