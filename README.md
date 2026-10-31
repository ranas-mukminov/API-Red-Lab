> **Problem:** OWASP API flaws — BOLA, broken authentication, excessive data exposure, missing rate limiting — are easy to describe and hard to recognise in real responses.
>
> **What this is:** an API security lab with a localhost-only HTTP server: each flaw shown twice, vulnerable and fixed, with tests and curl examples. **Localhost only, fictional data only, no real API.**
>
> **Who it is for:** API developers and testers learning to find and fix API authorisation and data-exposure flaws.
>
> **Quickstart:**
>
> ```bash
> git clone https://github.com/ranas-mukminov/API-Red-Lab.git
> cd API-Red-Lab
> python3 -m unittest discover -s tests -v
> python3 api/server.py --mode vuln --port 12701
> curl "http://127.0.0.1:12701/objects/obj-2?caller=lab-alice"
> ```
>
> **Sample result (verified):** the vulnerable server returns Bob's lab object for Alice's request; the fixed server returns 403 for the same request. Tests: `15 OK`.
>
[![CI](https://github.com/ranas-mukminov/API-Red-Lab/actions/workflows/tests.yml/badge.svg)](https://github.com/ranas-mukminov/API-Red-Lab/actions) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---
# API-Red-Lab

A local lab for OWASP API security flaws, with each flaw shown twice:
vulnerable, then fixed. No network service, no real API, no real data.

## The four cases

| Case | OWASP API Top 10 | Vulnerable behaviour | Fixed behaviour |
|---|---|---|---|
| API-01 | Broken Object Level Authorisation (BOLA) | Any caller reads any user's object | Ownership check per object |
| API-02 | Broken Authentication | A weak, guessable token is accepted | Token must match a session issued to that user |
| API-03 | Excessive Data Exposure | The response includes fields the caller should not see (internal notes, private email) | Response is filtered to public fields |
| API-04 | Lack of Resources and Rate Limiting | Unlimited requests, no limit | Per-caller request budget; over-budget requests are rejected |

## How the lab works

The lab is pure functions in `api/vuln.py` and `api/fixed.py`, exercised by `tests/test_api_lab.py`, plus a localhost-only HTTP server in `api/server.py` (see `docs/curl-examples.md`).
That keeps the lab runnable anywhere Python runs, with no port, no
deployment, and no chance of accidentally exposing a vulnerable service.

```bash
python3 -m unittest discover -s tests -v
```

See `docs/cases.md` for a walkthrough of each case: what the flaw is,
what the lab demonstration shows, and why the fix works.

## Data

All users, objects, tokens and fields are fictional lab data
(`lab-alice`, `lab-bob`, and their lab objects). Nothing here refers
to a real person, a real account, or a real API.

## Recent additions

- `api/server.py`: a real localhost-only HTTP server wrapping the vulnerable/fixed functions, with curl examples in `docs/curl-examples.md` and HTTP smoke tests.
- `docs/attack-mapping.md` and `detections/sigma-rules.yml`: illustrative MITRE ATT&CK mapping and Sigma-style detection rules in lab log format.
