"""Offline unit tests of the health-only shell (standard library unittest; writes nothing)."""

import importlib
import io
import json
import sys
import threading
import unittest
from pathlib import Path

_SRC = str(Path(__file__).resolve().parents[2] / "src")
if sys.path[:1] != [_SRC]:
    sys.path.insert(0, _SRC)


def _call(app, method, path):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = dict(headers)

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "0",
        "wsgi.input": io.BytesIO(b""),
    }
    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


class HealthShellTest(unittest.TestCase):
    def test_import_starts_no_thread(self):
        before = threading.active_count()
        for name in ("planeon_model.health", "planeon_model.health.app"):
            sys.modules.pop(name, None)
        importlib.import_module("planeon_model.health")
        self.assertEqual(threading.active_count(), before)

    def test_health_mapping_is_closed(self):
        from planeon_model.health import health

        self.assertEqual(health(), {"status": "ok", "plane": "model"})

    def test_get_health_answers_200_json(self):
        from planeon_model.health import application, health

        status, headers, body = _call(application, "GET", "/health")
        self.assertEqual(status, "200 OK")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body.decode("utf-8")), health())

    def test_get_missing_answers_404(self):
        from planeon_model.health import application

        status, _headers, body = _call(application, "GET", "/missing")
        self.assertEqual(status.split()[0], "404")
        self.assertNotIn(b"missing", body)

    def test_post_health_answers_405(self):
        from planeon_model.health import application

        status, _headers, _body = _call(application, "POST", "/health")
        self.assertEqual(status.split()[0], "405")


if __name__ == "__main__":
    unittest.main()
