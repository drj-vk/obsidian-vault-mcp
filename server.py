"""Read-only MCP server over an Obsidian vault, for Claude custom connectors.

Runs on your own server behind a reverse proxy. Streamable HTTP, stateless,
JSON responses. There are no write tools on the vault. The one optional write
is add_task, which posts a task to a Todoist inbox.

Auth: OAuth 2.1 through FastMCP's GitHub provider. Claude registers itself
(dynamic client registration), you sign in with GitHub, and every MCP request
is then checked against ALLOWED_GITHUB_LOGINS. The server refuses to start
without its OAuth settings, so a broken env file never leaves it open.

Configuration is by environment variables only; see .env.example.
"""
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp import McpError
from mcp.types import ErrorData


def _list_env(name: str, default: str = "") -> tuple:
    return tuple(s.strip() for s in os.environ.get(name, default).split(",") if s.strip())


VAULT = Path(os.environ["VAULT_ROOT"]).resolve()

# Folder names hidden at any depth (plumbing and binaries).
EXCLUDE_PARTS = set(_list_env("VAULT_EXCLUDE_DIRS", ".git,.obsidian,.trash,Attachments"))
# Vault-relative paths (a folder or a filename prefix) never listed, searched or read.
EXCLUDE_PREFIXES = tuple(s.lstrip("/") for s in _list_env("VAULT_EXCLUDE_PREFIXES"))
# Superseded material: readable by path, left out of search unless asked for.
ARCHIVE_PREFIX = os.environ.get("VAULT_ARCHIVE_PREFIX", "Archive/").strip("/") + "/"
MAX_FILE_BYTES = 2_000_000  # anything bigger is not a note

# Optional content filter. Any note whose FILENAME or BODY matches this regex is
# withheld from every tool. Filenames count as much as bodies: a meeting title
# can give something away by itself. Fails closed: unreadable means withheld.
_sensitive_src = os.environ.get("VAULT_SENSITIVE_PATTERN", "").strip()
SENSITIVE_RX = re.compile(_sensitive_src, re.I) if _sensitive_src else None
_sens_cache: dict = {}


def _sensitive(p: Path) -> bool:
    """True when this note must be withheld from the caller."""
    if SENSITIVE_RX is None:
        return False
    if SENSITIVE_RX.search(p.name):
        return True
    try:
        mtime = p.stat().st_mtime
    except OSError:
        return True
    cached = _sens_cache.get(p)
    if cached and cached[0] == mtime:
        return cached[1]
    try:
        flag = bool(SENSITIVE_RX.search(p.read_text(encoding="utf-8", errors="ignore")))
    except OSError:
        return True
    _sens_cache[p] = (mtime, flag)
    return flag


# --- Auth ----------------------------------------------------------------------
def _env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"vault-mcp: {name} is not set; refusing to start without auth")
    return v


ALLOWED_LOGINS = {x.lower() for x in _list_env("ALLOWED_GITHUB_LOGINS")}
if not ALLOWED_LOGINS:
    raise SystemExit("vault-mcp: ALLOWED_GITHUB_LOGINS is not set; refusing to start without auth")

# The hosted Claude apps (web, desktop, mobile) all use this callback. Loopback
# redirects, as a local CLI client uses, are refused by default: on your own
# machine you read the vault from disk, not through this server.
CLIENT_CALLBACKS = _list_env("ALLOWED_CLIENT_CALLBACKS", "https://claude.ai/api/mcp/auth_callback")


def _build_auth():
    from cryptography.fernet import Fernet
    from fastmcp.server.auth.providers.github import GitHubProvider
    from key_value.aio.stores.disk import DiskStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
    from mcp.server.auth.provider import RegistrationError

    class KnownCallbacksOnly(GitHubProvider):
        """Refuse dynamic registration for any redirect URI outside the list.

        FastMCP's redirect patterns only ADD to what a client registers. Without
        this check a stranger could register a client with their own callback,
        send you an /authorize link and receive a code for your account. Here a
        client whose redirect URIs are not all on the list never gets registered."""

        async def register_client(self, client_info):
            uris = [str(u) for u in (client_info.redirect_uris or [])]
            if not uris or any(u not in CLIENT_CALLBACKS for u in uris):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description="This redirect URI may not register.",
                )
            return await super().register_client(client_info)

    return KnownCallbacksOnly(
        client_id=_env("GITHUB_CLIENT_ID"),
        client_secret=_env("GITHUB_CLIENT_SECRET"),
        base_url=_env("PUBLIC_BASE_URL"),
        allowed_client_redirect_uris=list(CLIENT_CALLBACKS),
        jwt_signing_key=_env("JWT_SIGNING_KEY"),
        # Registered clients and upstream tokens survive restarts, encrypted at rest.
        client_storage=FernetEncryptionWrapper(
            key_value=DiskStore(directory=os.environ.get("STATE_DIR", "/var/lib/vault-mcp")),
            fernet=Fernet(_env("STORAGE_ENCRYPTION_KEY")),
        ),
        # read:user is enough to learn the login and grants no write access.
        required_scopes=["read:user"],
        require_authorization_consent=True,
    )


class OnlyAllowedUsers(Middleware):
    """Every MCP request must carry a token for an allowed GitHub login.

    OAuth proves who signed in; this decides who may read. A stranger who
    completes the GitHub sign-in gets a token, and every call is refused."""

    async def on_request(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        login = str((token.claims or {}).get("login", "")).lower() if token else ""
        if login not in ALLOWED_LOGINS:
            raise McpError(ErrorData(code=-32001, message="Forbidden"))
        return await call_next(context)


DEFAULT_INSTRUCTIONS = (
    "Read-only access to an Obsidian vault, the owner's knowledge base and "
    "source of truth for their projects, people and decisions. Search before "
    "answering from general knowledge, and cite the note paths you used. "
    "The archive folder holds superseded material and is left out of search "
    "unless asked for."
)

mcp = FastMCP(
    os.environ.get("SERVER_NAME", "obsidian-vault"),
    instructions=os.environ.get("SERVER_INSTRUCTIONS", "").strip() or DEFAULT_INSTRUCTIONS,
    auth=_build_auth(),
    middleware=[OnlyAllowedUsers()],
)


# --- Vault tools ---------------------------------------------------------------
def _visible(rel: str, include_archive: bool = False) -> bool:
    if any(part in EXCLUDE_PARTS for part in rel.split("/")):
        return False
    # "Tasks/" hides that folder and everything under it; an entry without a
    # trailing slash is a plain prefix ("Exports/context-" hides
    # Exports/context-2026.md).
    for e in EXCLUDE_PREFIXES:
        if e.endswith("/"):
            if rel == e[:-1] or rel.startswith(e):
                return False
        elif rel.startswith(e):
            return False
    if not include_archive and (rel + "/").startswith(ARCHIVE_PREFIX):
        return False
    return True


def _notes(include_archive: bool = False):
    for p in VAULT.rglob("*.md"):
        try:
            if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = p.relative_to(VAULT).as_posix()
        if _visible(rel, include_archive) and not _sensitive(p):
            yield p, rel


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def _regex(query: str):
    try:
        return re.compile(query, re.I)
    except re.error:
        return re.compile(re.escape(query), re.I)


@mcp.tool()
def search_vault(query: str, folder: str = "", max_results: int = 20,
                 include_archive: bool = False) -> str:
    """Search all vault notes (case-insensitive, regex allowed). Returns
    path:line with a snippet per matching note, title matches and recently
    modified notes first. Optionally restrict to a folder, e.g. 'Projects'."""
    rx = _regex(query)
    prefix = _norm(folder).lower()
    hits = []
    for p, rel in _notes(include_archive):
        low = rel.lower()
        if prefix and not low.startswith(prefix + "/") and low != prefix:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
            mtime = p.stat().st_mtime
        except OSError:
            continue
        title_hit = bool(rx.search(p.stem))
        first, count = None, 0
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if rx.search(line):
                count += 1
                if first is None:
                    first = (i + 1, "\n".join(lines[max(0, i - 1):i + 2])[:400])
        if first or title_hit:
            line_no, snippet = first or (1, lines[0][:200] if lines else "")
            hits.append((not title_hit, -mtime, rel, line_no, count, snippet))
    hits.sort()
    out = []
    for _, neg_mtime, rel, line_no, count, snippet in hits[:min(max_results, 40)]:
        day = datetime.fromtimestamp(-neg_mtime).strftime("%Y-%m-%d")
        out.append(f"{rel}:{line_no}  ({count} match(es), modified {day})\n{snippet}")
    if not out:
        return "No matches. Try a broader query, or include_archive=true."
    return "\n\n---\n\n".join(out)[:20000]


@mcp.tool()
def read_note(path: str) -> str:
    """Read one note by vault-relative path, e.g. 'Projects/roadmap.md'."""
    p = (VAULT / _norm(path)).resolve()
    if not p.is_relative_to(VAULT) or p.suffix.lower() != ".md":
        return "Not accessible."
    rel = p.relative_to(VAULT).as_posix()
    if not _visible(rel, include_archive=True) or _sensitive(p):
        return "Not accessible."
    if not p.is_file():
        return f"Not found: {rel}"
    text = p.read_text(encoding="utf-8", errors="ignore")
    return text[:40000] + ("\n\n[truncated]" if len(text) > 40000 else "")


@mcp.tool()
def list_folder(path: str = "") -> str:
    """List folders and notes one level below the given vault folder ('' = root)."""
    base = (VAULT / _norm(path)).resolve()
    if not base.is_relative_to(VAULT) or not base.is_dir():
        return "Not accessible."
    if base != VAULT and not _visible(base.relative_to(VAULT).as_posix(), include_archive=True):
        return "Not accessible."
    rows = []
    for child in sorted(base.iterdir()):
        rel = child.relative_to(VAULT).as_posix()
        if not _visible(rel, include_archive=True):
            continue
        if child.is_dir():
            if SENSITIVE_RX is not None and SENSITIVE_RX.search(child.name):
                continue
            rows.append(rel + "/")
        elif child.suffix.lower() == ".md" and not _sensitive(child):
            rows.append(rel)
    return "\n".join(rows) or "Empty."


@mcp.tool()
def recent_notes(days: int = 14, folder: str = "") -> str:
    """Notes modified in the last N days, newest first."""
    cutoff = datetime.now() - timedelta(days=max(1, days))
    prefix = _norm(folder).lower()
    rows = []
    for p, rel in _notes():
        if prefix and not rel.lower().startswith(prefix + "/"):
            continue
        m = datetime.fromtimestamp(p.stat().st_mtime)
        if m >= cutoff:
            rows.append((m, rel))
    rows.sort(reverse=True)
    return "\n".join(f"{m:%Y-%m-%d}  {rel}" for m, rel in rows[:40]) or "Nothing."


# --- Optional task tools ---------------------------------------------------------
# search_tasks appears when TASKS_MD_PATH points at a Markdown task file in
# Obsidian Tasks format (one "- [ ] ..." line per task). add_task appears when
# TODOIST_API_KEY is set. Neither writes to the vault or to the task file.
TASKS_MD = os.environ.get("TASKS_MD_PATH", "")
TASKS_DONE_MD = os.environ.get("TASKS_DONE_PATH", "")
TODOIST_KEY = os.environ.get("TODOIST_API_KEY", "")

if TASKS_MD:
    @mcp.tool()
    def search_tasks(query: str = "", status: str = "", project: str = "",
                     include_done: bool = False, max_results: int = 40) -> str:
        """Search the task file (one task per checkbox line). Filters: status
        matches the tag #status/<value>, project matches the tag #<value>, query
        is free text or a regex over the line. Lines are returned verbatim."""
        rx = _regex(query) if query else None
        files = [Path(TASKS_MD)]
        if include_done and TASKS_DONE_MD:
            files.append(Path(TASKS_DONE_MD))
        rows, total = [], 0
        for f in files:
            if not f.is_file():
                continue
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                s = line.strip()
                if not (s.startswith("- [") and "] " in s):
                    continue
                low = line.lower()
                if status and f"#status/{status.lower().strip()}" not in low:
                    continue
                if project and f"#{project.lower().strip()}" not in low:
                    continue
                if rx and not rx.search(line):
                    continue
                total += 1
                if len(rows) < min(max_results, 80):
                    rows.append(s)
        if not rows:
            return "No matching tasks."
        head = f"{total} match(es)"
        if total > len(rows):
            head += f" (showing first {len(rows)})"
        return head + ":\n" + "\n".join(rows)

if TODOIST_KEY:
    @mcp.tool()
    def add_task(title: str, note: str = "", priority: str = "") -> str:
        """Capture a new task in the Todoist inbox. This is the only write this
        server can make. priority: p1, p2 or p3 (optional). Keep the title to
        one line."""
        import httpx
        prio = {"p1": 4, "p2": 3, "p3": 2}.get(priority.lower().strip(), 1)
        payload = {"content": title.strip(), "priority": prio}
        if note.strip():
            payload["description"] = note.strip()
        try:
            r = httpx.post("https://api.todoist.com/api/v1/tasks", json=payload,
                           headers={"Authorization": f"Bearer {TODOIST_KEY}"},
                           timeout=15)
        except httpx.HTTPError as e:
            return f"Todoist unreachable: {e}"
        if r.status_code in (200, 204):
            return f"Captured to the Todoist inbox: {title.strip()}"
        return f"Todoist API error {r.status_code}: {r.text[:200]}"


app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
