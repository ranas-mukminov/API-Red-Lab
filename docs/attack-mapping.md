# MITRE ATT&CK mapping — API-Red-Lab (illustrative, lab only)

This mapping is an exercise aid for the local lab cases. It is not
a formal ATT&CK assessment and makes no claim about any real system.

| Case | Mapping (illustrative) | Detection idea |
|------|------------------------|----------------|
| API-01 BOLA | T1078 Valid Accounts — a valid session used to read another user's object | API logs where caller and object owner differ |
| API-02 Broken authentication | T1078 Valid Accounts / T1110 Brute Force (tactic family) — a guessed token shape accepted as a session | Auth logs with tokens that were never issued |
| API-03 Excessive data exposure | T1005 Data from Local System (tactic family) — internal fields leaving the API boundary | Response-body checks for internal field names |
| API-04 Rate limiting | T1499 Endpoint Denial of Service (tactic family) — an unbounded endpoint | Request-rate spikes from a single caller |

See `detections/sigma-rules.yml` for Sigma-style rules in lab
log format. They are detection format examples only; no live
telemetry claim is made for them.
