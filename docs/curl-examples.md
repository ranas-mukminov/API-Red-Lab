# Curl examples — API-Red-Lab (localhost only)

Start one mode at a time. Both servers bind to 127.0.0.1 only.

```bash
python3 api/server.py --mode vuln --port 12701
# in another terminal, with the fixed server on a different port:
python3 api/server.py --mode fixed --port 12702
```

## BOLA

```bash
# Vulnerable: Alice reads Bob's object (200)
curl "http://127.0.0.1:12701/objects/obj-2?caller=lab-alice"
# Fixed: the same request is 403
curl "http://127.0.0.1:12702/objects/obj-2?caller=lab-alice"
```

## Broken authentication

```bash
# Vulnerable: a guessed token shape is accepted (200)
curl "http://127.0.0.1:12701/auth?token=token-lab-alice"
# Fixed: an unissued token is 401
curl "http://127.0.0.1:12702/auth?token=garbage"
```

## Excessive data exposure

```bash
# Vulnerable: the whole record, including internal fields, is returned
curl "http://127.0.0.1:12701/profile/lab-bob?caller=lab-alice"
# Fixed: only public fields, and only for the owner
curl "http://127.0.0.1:12702/profile/lab-alice?caller=lab-alice"
```

## Rate limiting

```bash
# Fixed: the 4th and 5th requests in a row are 429
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " "http://127.0.0.1:12702/rate?caller=lab-alice"; done; echo
# Vulnerable: every request is 200
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " "http://127.0.0.1:12701/rate?caller=lab-alice"; done; echo
```

Never expose these servers beyond 127.0.0.1, and never point them
at real data.
