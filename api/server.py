"""Localhost-only HTTP server for API-Red-Lab.

Binds to 127.0.0.1 only. Any other host is refused. The server wraps
the existing vulnerable/fixed functions, so the same cases that the
unit tests cover can also be exercised over HTTP with curl. Fictional
lab data only; no real API, no real users, no network beyond localhost.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixed  # noqa: E402
import vuln  # noqa: E402


def make_handler(mode):
    get_object = vuln.get_object_vuln if mode == "vuln" else fixed.get_object_fixed
    authenticate = vuln.authenticate_vuln if mode == "vuln" else fixed.authenticate_fixed
    get_profile = vuln.get_profile_vuln if mode == "vuln" else fixed.get_profile_fixed
    limiter = vuln.RateLimiterVuln() if mode == "vuln" else fixed.RateLimiterFixed(limit=3)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            try:
                if parsed.path.startswith("/objects/"):
                    obj_id = parsed.path.split("/objects/")[1]
                    obj = get_object(obj_id, qs.get("caller", [""])[0])
                    self._send_json(404 if obj is None else 200, obj or {"error": "not found"})
                elif parsed.path.startswith("/profile/"):
                    user_id = parsed.path.split("/profile/")[1]
                    profile = get_profile(user_id, qs.get("caller", [""])[0])
                    self._send_json(404 if profile is None else 200, profile or {"error": "not found"})
                elif parsed.path == "/auth":
                    user = authenticate(qs.get("token", [""])[0])
                    self._send_json(200 if user else 401, {"user": user} if user else {"error": "unauthorised"})
                elif parsed.path == "/rate":
                    caller = qs.get("caller", [""])[0]
                    if limiter.allow(caller):
                        self._send_json(200, {"allowed": True})
                    else:
                        self._send_json(429, {"error": "rate limit exceeded"})
                else:
                    self._send_json(200, {
                        "lab": "API-Red-Lab (local lab only)",
                        "routes": [
                            "/objects/<id>?caller=<user>",
                            "/profile/<id>?caller=<user>",
                            "/auth?token=<token>",
                            "/rate?caller=<user>",
                        ],
                    })
            except PermissionError as exc:
                self._send_json(403, {"error": str(exc)})

        def _send_json(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["vuln", "fixed"], required=True)
    parser.add_argument("--port", type=int, default=12701)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args(argv)
    if args.host != "127.0.0.1":
        parser.error("this lab server binds to 127.0.0.1 only")
    print(f"WARNING: intentionally vulnerable lab server, mode={args.mode}, "
          f"listening on 127.0.0.1:{args.port} only. Do not expose it.")
    HTTPServer(("127.0.0.1", args.port), make_handler(args.mode)).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
