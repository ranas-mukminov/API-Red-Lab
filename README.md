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

There is no HTTP server here on purpose: the lab is pure functions in
`api/vuln.py` and `api/fixed.py`, exercised by `tests/test_api_lab.py`.
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
