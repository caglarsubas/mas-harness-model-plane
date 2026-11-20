"""Health-only shell of the model plane: a closed health mapping and a standard-library WSGI callable.

Importing this module starts no thread, socket, subprocess or listener and reads no environment variable or file.
"""

import json

_HEALTH_PATH = "/health"


def health():
    """Return the plane's closed health mapping."""
    return {"status": "ok", "plane": "model"}


def _respond(start_response, status, body, content_type):
    start_response(status, [("Content-Type", content_type), ("Content-Length", str(len(body)))])
    return [body]


def application(environ, start_response):
    """WSGI callable: GET /health answers 200 with health() as JSON; never echoes the request."""
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "")
    if path != _HEALTH_PATH:
        return _respond(start_response, "404 Not Found", b"not found\n", "text/plain; charset=utf-8")
    if method != "GET":
        start_response(
            "405 Method Not Allowed",
            [("Content-Type", "text/plain; charset=utf-8"), ("Allow", "GET"), ("Content-Length", "19")],
        )
        return [b"method not allowed\n"]
    body = json.dumps(health(), sort_keys=True).encode("utf-8")
    return _respond(start_response, "200 OK", body, "application/json")
