"""Self-test for the OAuth gate and the visibility rules. No network, no GitHub.

    python selftest.py

Checks: the server refuses to start without auth settings; unauthenticated
requests get 401 with a resource_metadata pointer; only an allowed callback
may register; an allowed GitHub login can read, any other login gets
Forbidden; excluded folders and sensitive notes stay hidden for the allowed
login too.
"""
import base64
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
tmp = Path(tempfile.mkdtemp())
vault = tmp / "vault"
(vault / "Knowledge").mkdir(parents=True)
(vault / "Tasks").mkdir()
(vault / "Archive").mkdir()
(vault / "Knowledge/a.md").write_text("# hello\n", encoding="utf-8")
(vault / "Knowledge/private.md").write_text("# diary\nsalary talk\n", encoding="utf-8")
(vault / "Knowledge/export-old.md").write_text("old export\n", encoding="utf-8")
(vault / "Tasks/t.md").write_text("stale hello\n", encoding="utf-8")
(vault / "Archive/old.md").write_text("superseded hello\n", encoding="utf-8")

os.environ["VAULT_ROOT"] = str(vault)
os.environ["VAULT_EXCLUDE_PREFIXES"] = "Tasks/,Knowledge/export-"
os.environ["VAULT_SENSITIVE_PATTERN"] = "salary"
for k in ("TASKS_MD_PATH", "TODOIST_API_KEY", "ALLOWED_GITHUB_LOGINS"):
    os.environ.pop(k, None)

ok = True


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS " if cond else "FAIL ") + name + (f"  ({detail})" if detail and not cond else ""))


# 1. No auth settings: refuses to start.
r = subprocess.run([sys.executable, "-c", "import server"], env=dict(os.environ),
                   capture_output=True, text=True, cwd=HERE)
check("refuses to start without auth", r.returncode != 0 and "refusing to start" in r.stderr, r.stderr[-200:])

from cryptography.fernet import Fernet  # noqa: E402

os.environ.update(
    ALLOWED_GITHUB_LOGINS="octocat", GITHUB_CLIENT_ID="Ov23test", GITHUB_CLIENT_SECRET="x",
    PUBLIC_BASE_URL="https://mcp.example.test", JWT_SIGNING_KEY="k" * 64,
    STORAGE_ENCRYPTION_KEY=Fernet.generate_key().decode(), STATE_DIR=str(tmp / "state"),
)
sys.path.insert(0, str(HERE))
import server  # noqa: E402
from fastmcp.server.auth.auth import AccessToken  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402


async def fake_verify(token):
    users = {"good": "octocat", "bad": "someone-else"}
    if token in users:
        return AccessToken(token=token, client_id="c", scopes=["read:user"], expires_at=None,
                           claims={"login": users[token]})
    return None


server.mcp.auth.verify_token = fake_verify
app = server.mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
H = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


def call(tool, **args):
    return {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": tool, "arguments": args}}


READ = call("read_note", path="Knowledge/a.md")
REG = {"token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
       "response_types": ["code"]}

with TestClient(app) as c:
    r = c.post("/mcp", headers=H, json=READ)
    check("no token -> 401", r.status_code == 401, r.status_code)
    check("401 points at resource metadata", "resource_metadata=" in r.headers.get("www-authenticate", ""))
    prm = c.get("/.well-known/oauth-protected-resource/mcp").json()
    check("metadata resource matches URL", prm.get("resource") == "https://mcp.example.test/mcp", prm)
    check("scope is read:user only", prm.get("scopes_supported") == ["read:user"], prm)

    r = c.post("/register", json={**REG, "redirect_uris": ["https://evil.example/cb"]})
    check("foreign callback cannot register", r.status_code == 400, r.status_code)
    r = c.post("/register", json={**REG, "redirect_uris": ["http://localhost:5555/callback"]})
    check("loopback callback cannot register", r.status_code == 400, r.status_code)
    r = c.post("/register", json={**REG, "redirect_uris": [CALLBACK, "https://evil.example/cb"]})
    check("mixed callbacks cannot register", r.status_code == 400, r.status_code)
    r = c.post("/register", json={**REG, "redirect_uris": [CALLBACK]})
    check("Claude's callback can register", r.status_code == 201, r.status_code)
    cid = r.json().get("client_id")
    ch = base64.urlsafe_b64encode(hashlib.sha256(b"v" * 50).digest()).rstrip(b"=").decode()
    r = c.get("/authorize", follow_redirects=False, params={
        "response_type": "code", "client_id": cid, "redirect_uri": CALLBACK,
        "code_challenge": ch, "code_challenge_method": "S256", "state": "s", "scope": "read:user"})
    check("authorize goes to the consent page", r.status_code == 302 and "/consent" in r.headers.get("location", ""))

    bad = {**H, "Authorization": "Bearer bad"}
    r = c.post("/mcp", headers=bad, json=READ)
    check("other GitHub login -> Forbidden", "Forbidden" in r.text and "hello" not in r.text, r.text[:120])
    r = c.post("/mcp", headers=bad, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    check("other GitHub login cannot list tools", "Forbidden" in r.text, r.text[:120])

    good = {**H, "Authorization": "Bearer good"}
    r = c.post("/mcp", headers=good, json=READ)
    check("allowed login reads a note", "hello" in r.text, r.text[:120])
    r = c.post("/mcp", headers=good, json=call("read_note", path="Tasks/t.md"))
    check("excluded folder cannot be read", "Not accessible" in r.text, r.text[:120])
    r = c.post("/mcp", headers=good, json=call("read_note", path="Knowledge/export-old.md"))
    check("excluded filename prefix cannot be read", "Not accessible" in r.text, r.text[:120])
    r = c.post("/mcp", headers=good, json=call("read_note", path="Knowledge/private.md"))
    check("sensitive note cannot be read", "Not accessible" in r.text and "diary" not in r.text, r.text[:120])
    r = c.post("/mcp", headers=good, json=call("read_note", path="../outside.md"))
    check("path outside the vault refused", "Not accessible" in r.text, r.text[:120])
    r = c.post("/mcp", headers=good, json=call("list_folder", path=""))
    check("root listing hides excluded folder", "Knowledge/" in r.text and "Tasks" not in r.text, r.text[:200])
    r = c.post("/mcp", headers=good, json=call("list_folder", path="Knowledge"))
    check("folder listing hides sensitive and excluded notes",
          "a.md" in r.text and "private" not in r.text and "export-old" not in r.text, r.text[:200])
    r = c.post("/mcp", headers=good, json=call("search_vault", query="hello"))
    check("search skips excluded folder and archive",
          "Knowledge/a.md" in r.text and "Tasks/" not in r.text and "Archive/" not in r.text, r.text[:200])
    r = c.post("/mcp", headers=good, json=call("search_vault", query="hello", include_archive=True))
    check("search includes the archive on request", "Archive/old.md" in r.text, r.text[:200])
    r = c.post("/mcp", headers=good, json=call("search_vault", query="diary|salary"))
    check("search never returns a sensitive note", "No matches" in r.text, r.text[:200])

print("ALL PASS" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
