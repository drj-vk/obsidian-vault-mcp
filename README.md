# obsidian-vault-mcp

A small, read-only MCP server that lets Claude search and read an Obsidian vault
that lives on your own server. You add it to Claude as a custom connector, sign
in with GitHub, and from then on Claude on the web, desktop, or phone can answer
from your notes and cite the note it used.

The vault never leaves your server. The server has no tool that writes to it.

## Why I built it

My notes are the record of my work: projects, people, and decisions. Claude on
my laptop could read them from disk, but Claude on my phone could not, so it
answered from memory or from stale exports. I wanted the same notes everywhere,
without uploading the vault to a third party and without opening it to anyone
who learns a URL.

The first version was protected by a secret path in the URL plus an IP
allowlist. That was not good enough: connectors call from Anthropic's cloud, and
that address range is shared by every Claude user, so the URL was the only real
credential. This version replaces it with a proper sign-in.

## How access is controlled

| Layer | What it does |
|---|---|
| Identity | OAuth 2.1 with GitHub sign-in (FastMCP's GitHub provider), scope `read:user` only |
| Who may read | Every MCP request is checked against `ALLOWED_GITHUB_LOGINS`; any other GitHub account gets `Forbidden` |
| Who may register | Only Claude's callback URL may register as an OAuth client, so a stranger cannot register their own callback and trick you into approving it |
| Network | The reverse proxy lets only Anthropic's address range reach the MCP endpoints; the sign-in pages stay open for your own browser |
| Fail-safe | The server refuses to start without its OAuth settings |
| At rest | Client registrations and tokens are stored encrypted |
| Read-only | No write tools on the vault; the systemd unit can write to its state directory and nowhere else |
| Revocation | Revoke the OAuth App in your GitHub settings and every connection is gone |

On top of that you decide what is in scope: folders to hide, filename prefixes to
hide, and a regular expression that withholds any note whose filename or body
matches it.

## Tools

| Tool | Purpose |
|---|---|
| `search_vault(query, folder?, max_results?, include_archive?)` | Case-insensitive search, regex allowed; title matches and recent notes first |
| `read_note(path)` | One note, capped at 40,000 characters |
| `list_folder(path?)` | One level of the folder tree |
| `recent_notes(days?, folder?)` | What changed lately |
| `search_tasks(...)` | Optional: search a Markdown task file in Obsidian Tasks format |
| `add_task(title, note?, priority?)` | Optional: capture a task in a Todoist inbox, the only write the server can make |

## Set-up

You need a Linux server that already holds the vault (for example through
Nextcloud, Syncthing, or git), a domain name for it, Python 3.10 or newer, and a
reverse proxy with TLS. The examples use Apache and systemd.

1. Clone and install.

   ```bash
   git clone <this repository> /opt/obsidian-vault-mcp
   cd /opt/obsidian-vault-mcp
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

2. Create a GitHub OAuth App at github.com/settings/developers. Homepage URL
   `https://mcp.example.com`, callback URL exactly
   `https://mcp.example.com/auth/callback`. Leave device flow off.

3. Copy `.env.example` to `/etc/vault-mcp.env`, fill it in, and restrict it:
   `chown root:root /etc/vault-mcp.env && chmod 600 /etc/vault-mcp.env`.

4. Install `deploy/vault-mcp.service` as `/etc/systemd/system/vault-mcp.service`,
   set the service user and the path, then
   `systemctl daemon-reload && systemctl enable --now vault-mcp`.

5. Get a certificate for the domain and install
   `deploy/apache-vhost.conf.example` as a site. Check Anthropic's current
   address range before you copy the one in the file.

6. Check it from the server itself:

   | Request | Expected |
   |---|---|
   | `curl -X POST http://127.0.0.1:8788/mcp` | 401, no token |
   | `curl https://mcp.example.com/mcp` | 403, you are outside the allowed range |
   | `curl https://mcp.example.com/authorize` | 400, reachable but missing parameters |

7. In Claude on the web: Settings, Connectors, Add custom connector, URL
   `https://mcp.example.com/mcp`, leave the OAuth fields empty. Connect, approve
   the consent page, and sign in with GitHub. The connector then follows your
   account to the desktop and phone apps.

To stop it at once: `systemctl stop vault-mcp`.

## Test

```bash
.venv/bin/python selftest.py
```

It runs without a network or a GitHub account and checks the gate and the
visibility rules: no start without auth settings, 401 without a token, only
Claude's callback may register, another GitHub login is refused, and hidden
folders and sensitive notes stay hidden for the allowed login as well.

## Limits, stated plainly

- Whatever Claude reads through the connector passes through Anthropic's
  service, as with any conversation. This server keeps the vault off third-party
  storage; it does not keep note content out of the conversations you have.
- The content filter is a regular expression, not a classifier. Treat it as a
  second line behind the folder exclusions.
- Search is a plain scan of the Markdown files. It is fast enough for a few
  thousand notes and needs no index.
- I run it for one person. More than a handful of users would want per-user
  scopes, which it does not have.
- Tested with FastMCP 2.14.7 behind Apache 2.4 on Ubuntu 24.04.

## Licence

MIT, see `LICENSE`.
