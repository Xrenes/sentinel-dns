"""Build a static, clickable copy of the dashboard (no server needed) into ./demo-site.

It starts the real app in demo mode against a throw-away database, saves every page and the
JSON the pages ask for, and patches the API client to answer from that saved data. Writes
(add rule, save settings, ...) "succeed" in the browser only. Host the folder on GitHub Pages.

    python scripts/build_static_demo.py
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dnscore.config import Config  # noqa: E402
from web import create_app  # noqa: E402
from web.views import PAGES  # noqa: E402

OUT = ROOT / "demo-site"
PASSWORD = "demo-site-build-2026"
SAMPLE_QUERIES = ("www.lab.local", "google.com", "github.com", "doubleclick.net", "mail.lab.local")


def page_file(path: str) -> str:
    return "index.html" if path == "/" else f"{path.strip('/')}.html"


def relativize(html: str) -> str:
    """Absolute links -> relative files so the site works under /<repo>/ on GitHub Pages."""
    for _, path, *_ in PAGES:
        html = re.sub(rf'href="{re.escape(path)}(\?[^"]*)?"', f'href="{page_file(path)}"', html)
    html = html.replace('"/static/', '"static/').replace("'/static/", "'static/")
    html = re.sub(r'<form([^>]*?)method="post" action="/logout"', r'<form\1method="get" action="login.html"', html)
    html = re.sub(r'<form([^>]*?)method="post" action="/login[^"]*"', r'<form\1method="get" action="index.html"', html)
    banner = ('<div style="position:fixed;bottom:12px;right:12px;z-index:9999;padding:6px 12px;border-radius:8px;'
              'background:#f59e0b;color:#111;font:600 12px system-ui">Static UI demo · sample data</div>')
    html = html.replace("</body>", f'<script src="static/js/demo-data.js"></script>{banner}</body>')
    # demo-data.js must load before the module scripts run; classic scripts at body end do, modules are deferred.
    return html


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config(mode="demo", db_path=Path(tmp) / "demo.db", secret_key="static-demo-build-key-0123456789",
                     simulate=False, seed_history=True, background_jobs=False, admin_password=PASSWORD)
        app = create_app(cfg)
        client = app.test_client()
        client.get("/login")
        with client.session_transaction() as sess:
            csrf = sess.get("_csrf", "")
        assert client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": csrf}).status_code == 302
        with client.session_transaction() as sess:
            csrf = sess.get("_csrf", "")  # rotated on login

        def get(url: str):
            response = client.get(url)
            assert response.status_code == 200, (url, response.status_code)
            return response.get_json()

        mock: dict[str, object] = {}
        for url in ("/api/dashboard", "/api/activity", "/api/status", "/api/system", "/api/policies",
                    "/api/users", "/api/settings", "/api/dnssec", "/api/zones",
                    "/api/analytics?range=24h", "/api/analytics?range=7d"):
            mock[url] = get(url)
        for zone in mock["/api/zones"]["data"]:
            name = quote(zone["name"], safe="")
            for part in ("records", "zonefile"):
                mock[f"/api/zones/{name}/{part}"] = get(f"/api/zones/{name}/{part}")
        for page in range(1, 11):
            data = get(f"/api/threats?page={page}&per_page=25")
            mock[f"/api/threats?page={page}"] = data
            if not data["data"]:
                break
        queries = []
        for name in SAMPLE_QUERIES:
            response = client.post("/api/query", json={"domain": name, "type": "A"}, headers={"X-CSRF-Token": csrf})
            if response.status_code == 200:
                queries.append(response.get_json())
        mock["POST /api/query"] = queries

        if OUT.exists():
            shutil.rmtree(OUT)
        shutil.copytree(ROOT / "web" / "static", OUT / "static")
        for key, path, *_ in PAGES:
            html = client.get(path).get_data(as_text=True)
            (OUT / page_file(path)).write_text(relativize(html), encoding="utf-8")
        client.post("/logout", data={"csrf_token": csrf})
        (OUT / "login.html").write_text(relativize(client.get("/login").get_data(as_text=True)), encoding="utf-8")

    (OUT / "static/js/demo-data.js").write_text(f"window.__MOCK__ = {json.dumps(mock)};\n", encoding="utf-8")
    patch_core(OUT / "static/js/core.js")
    (OUT / ".nojekyll").write_text("")
    print(f"Static demo written to {OUT}")


MOCK_CLIENT = r"""
/* Static demo: answer API calls from saved sample data (scripts/build_static_demo.py). */
async function mockApi(path, method, body) {
  await new Promise((r) => setTimeout(r, 120));
  const M = window.__MOCK__ || {};
  const url = new URL(path, 'http://x');
  if (method === 'GET') {
    let key = url.pathname;
    if (url.searchParams.has('range')) key += `?range=${url.searchParams.get('range')}`;
    if (url.pathname === '/api/threats') key += `?page=${url.searchParams.get('page') || 1}`;
    const hit = M[key] || M[url.pathname] || M[`/api/threats?page=1`];
    if (!hit) throw new ApiError('Not available in the static demo.', 404);
    return { data: hit.data, meta: hit.meta || {} };
  }
  if (url.pathname === '/api/query') {
    const samples = M['POST /api/query'] || [];
    const name = (body?.domain || '').toLowerCase();
    const hit = samples.find((s) => s.data?.domain === name) || samples[1] || samples[0];
    if (!hit) throw new ApiError('Not available in the static demo.', 404);
    return { data: { ...hit.data, domain: body?.domain || hit.data.domain }, meta: hit.meta || {} };
  }
  return { data: { ...(body || {}), id: Date.now() }, meta: { demo: true } };
}
"""


def patch_core(core: Path) -> None:
    text = core.read_text(encoding="utf-8")
    marker = "export async function api(path, { method = 'GET', body } = {}) {"
    assert marker in text, "core.js api() signature changed"
    text = text.replace(marker, MOCK_CLIENT + marker + "\n  if (window.__MOCK__) return mockApi(path, method, body);")
    text = text.replace("'/static/img/icons.svg'", "'static/img/icons.svg'")
    core.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
