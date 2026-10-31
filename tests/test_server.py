import json
import sys
import threading
import unittest
import urllib.request
import urllib.error
from http.server import HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "api"))
from server import make_handler  # noqa: E402


def start(mode):
    httpd = HTTPServer(("127.0.0.1", 0), make_handler(mode))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def get(httpd, path):
    url = f"http://127.0.0.1:{httpd.server_address[1]}{path}"
    try:
        with urllib.request.urlopen(url) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


class TestServer(unittest.TestCase):
    def test_vuln_bola_over_http(self):
        httpd = start("vuln")
        try:
            status, body = get(httpd, "/objects/obj-2?caller=lab-alice")
            self.assertEqual(status, 200)
            self.assertEqual(body["owner"], "lab-bob")
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_fixed_bola_over_http_is_403(self):
        httpd = start("fixed")
        try:
            status, _ = get(httpd, "/objects/obj-2?caller=lab-alice")
            self.assertEqual(status, 403)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_fixed_rate_limit_over_http_is_429(self):
        httpd = start("fixed")
        try:
            codes = [get(httpd, "/rate?caller=lab-alice")[0] for _ in range(5)]
            self.assertEqual(codes, [200, 200, 200, 429, 429])
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_fixed_auth_over_http(self):
        httpd = start("fixed")
        try:
            self.assertEqual(get(httpd, "/auth?token=token-lab-alice")[0], 200)
            self.assertEqual(get(httpd, "/auth?token=garbage")[0], 401)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
