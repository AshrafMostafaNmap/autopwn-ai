"""A local single-page app with planted client-side weaknesses, for the browser
toolset and its benchmark. Everything it serves is fake and harmless.

Planted (ground truth):
  dom_xss                    /#/search?q=  is written into the page with innerHTML
  sensitive_client_storage   a JWT-shaped token kept in localStorage
  vulnerable_js_library      jQuery 1.12.4 banner in /static/jquery.js
  exposed_source_map         /static/app.js.map is downloadable
  weak_csp                   CSP with 'unsafe-inline' and 'unsafe-eval'
  cors_misconfig             /api/* answers any Origin with credentials allowed
  cookie_flags               session cookie without HttpOnly / Secure / SameSite
  info_leak_console          a stack trace logged to the console
Plus pages only reachable through JavaScript navigation, an API called with
fetch(), a login form, and a secret-looking key inside the JS bundle.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GROUND_TRUTH = frozenset({"dom_xss", "sensitive_client_storage", "vulnerable_js_library", "exposed_source_map",
                          "weak_csp", "cors_misconfig", "cookie_flags", "info_leak_console"})

FAKE_AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"     # AWS's documented example key, assembled
FAKE_JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJsYWItdXNlciIsInJvbGUiOiJhZG1pbiJ9."
            "c2lnbmF0dXJlLWZvci10aGUtbGFiLW9ubHk")

INDEX = """<!doctype html><html><head><meta charset="utf-8"><title>Lab Shop</title>
<link rel="manifest" href="/manifest.json">
<script src="/static/jquery.js"></script></head>
<body><nav><a href="/">Home</a> <a href="#/products">Products</a> <a href="#/search?q=shoes">Search</a>
<a href="/login">Login</a></nav>
<main id="view">loading…</main>
<script src="/static/app.js"></script></body></html>"""

APP_JS = """// Lab Shop bundle
const API_KEY = "__FAKE_AWS_KEY__";
const routes = {
  "/products": async () => {
    const r = await fetch("/api/products?limit=10", {credentials: "include"});
    const items = await r.json();
    return "<h1>Products</h1>" + items.map(i => `<a href="#/product/${i.id}">${i.name}</a>`).join(" ");
  },
  "/search": async (q) => {
    const r = await fetch("/api/search?q=" + encodeURIComponent(q || ""));
    await r.json();
    return "<h1>Results for " + (q || "") + "</h1>";       // planted DOM XSS sink (innerHTML)
  },
  "/admin": async () => "<h1>Admin</h1><a href='/api/admin/users'>users</a>",
};
async function render() {
  const [path, query] = (location.hash.slice(1) || "/products").split("?");
  const q = new URLSearchParams(query || "").get("q");
  const fn = routes[path.replace(/\\/\\d+$/, "")] || routes["/products"];
  document.getElementById("view").innerHTML = await fn(q);
}
localStorage.setItem("auth_token", "__JWT__");
sessionStorage.setItem("cart", JSON.stringify({items: 2}));
try { null.boom(); } catch (e) { console.error("Unhandled error at /srv/app/handlers.js:42", e.stack); }
document.cookie = "theme=dark; path=/";
window.addEventListener("hashchange", render);
render();
//# sourceMappingURL=/static/app.js.map
""".replace("__JWT__", FAKE_JWT).replace("__FAKE_AWS_KEY__", FAKE_AWS_KEY)

JQUERY = "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\nwindow.jQuery = window.$ = {fn: {jquery: '1.12.4'}};\n"

LOGIN = """<!doctype html><html><head><title>Login</title></head><body>
<form method="post" action="/login"><input name="user"><input name="password" type="password">
<input type="hidden" name="next" value="/"><button>Sign in</button></form>
<a href="/">back</a></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/html", code=200, extra=None):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _cors(self):
        origin = self.headers.get("Origin") or "*"
        return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/":
            return self._send(INDEX, extra={"Set-Cookie": "session=lab-session-123; Path=/"})
        if u.path == "/login":
            return self._send(LOGIN)
        if u.path == "/go":                                   # open redirect, used by the scope tests
            self.send_response(302)
            self.send_header("Location", q.get("to", "/"))
            self.end_headers()
            return None
        if u.path == "/static/app.js":
            return self._send(APP_JS, "application/javascript")
        if u.path == "/static/app.js.map":
            return self._send(json.dumps({"version": 3, "sources": ["src/app.ts", "src/secrets.ts"],
                                          "mappings": ""}), "application/json")
        if u.path == "/static/jquery.js":
            return self._send(JQUERY, "application/javascript")
        if u.path == "/manifest.json":
            return self._send(json.dumps({"name": "Lab Shop", "start_url": "/"}), "application/manifest+json")
        if u.path == "/api/products":
            limit = int(q["limit"]) if q.get("limit", "").isdigit() else 3
            items = [{"id": i, "name": f"Item {i}"} for i in range(1, min(limit, 50) + 1)]
            return self._send(json.dumps(items), "application/json", extra=self._cors())
        if u.path == "/api/search":
            return self._send(json.dumps({"q": q.get("q", ""), "results": []}), "application/json",
                              extra=self._cors())
        if u.path == "/api/admin/users":
            return self._send(json.dumps([{"user": "admin"}]), "application/json", extra=self._cors())
        return self._send("<h1>not found</h1>", code=404)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        return self._send("<p>bad credentials</p><a href='/login'>retry</a>", code=401)


class WebLab:
    def __init__(self):
        self._server: ThreadingHTTPServer | None = None
        self.base_url = ""

    def __enter__(self) -> WebLab:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
