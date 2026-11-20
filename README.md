# Visual Expert for Claude Code

A Claude Code plugin that connects Claude to a [Visual Expert](https://www.visual-expert.com) web server so you can work
with Code Inspection findings in plain language:

- "List all of the Critical issues"
- "Summarize the open vulnerabilities in PFCApps-Git"
- "Address finding VE-2745" - Claude reads the rule and the flagged code, fixes your local source, and offers to mark it Pending Validation
- "Mark the status of finding VE-31 as Risk Accepted with this comment: legacy code, replaced in v3"

It contains an MCP server (Python) and a skill that tells Claude how to use it. It always works against the **latest
analysis** of the chosen project, so you never need to paste a new URL after an analysis runs.

## Requirements

- Claude Code
- Python 3.10+ on `PATH` as `python` (check with `python --version`). The plugin creates its own private
  environment on first start (about 30 seconds, once) - you don't need to install any packages.
- A Visual Expert web server account.

## Install

In Claude Code, add this repository as a marketplace and install the plugin:

```
/plugin marketplace add <git URL or folder path of this repository>
/plugin install visual-expert@visual-expert-tools
```

Claude Code then asks for the settings below. The password is stored in your operating system's secure credential store,
not in a settings file. To change them later: `/plugin configure visual-expert@visual-expert-tools`.

| Setting | |
|---|---|
| Visual Expert URL | e.g. `https://visualexpert.mycompany.local` |
| Sign-in method | `windows` (your Windows logon, nothing stored - needs Windows authentication enabled on the VE server), `form` (email + password), or `cookie` |
| Email / Password | for `form` sign-in |
| Cookie header | for `cookie` sign-in only - the `Cookie` request header copied from a signed-in browser (expires with the session) |
| Default project | optional - project name or id; otherwise Claude asks or you say "use project X" |
| Analysis | `latest` (recommended) or a fixed analysis id |
| Verify TLS certificate | turn off only for a self-signed on-prem server |

Restart Claude Code (or run `/reload-plugins`), then check `/mcp` shows **visual-expert** as connected.

## Tools

| Tool | Does |
|---|---|
| `list_projects` | projects you can see |
| `set_context(project, analysis, url)` | pick the project (name, id or URL); analysis defaults to latest |
| `list_defects(severity, status, type, rule, container, search, limit)` | list findings (default: active = Open + Pending Validation) |
| `summarize_defects(status)` | counts by severity / type / status / rule |
| `get_defect(defect_id)` | rule description, location, flagged lines, source excerpt |
| `set_defect_status(defect_ids, status, comment)` | Open, Risk Accepted, False Positive, On Hold, Pending Validation |
| `set_defect_severity(defect_ids, severity, comment)` | Critical, Major, Minor, Low, Information |

Claude asks before changing a status or severity unless you told it to make that exact change.

## How "latest analysis" works

The Visual Expert web app redirects `/codeinspection/{project}` to that project's current analysis. The server follows
that redirect, then checks whether any newer analysis exists, and caches the answer for 5 minutes.

## Troubleshooting

- **visual-expert not connected in `/mcp`**: run `python --version`. If Python is missing or older than 3.10, install it
  from python.org (tick "Add python.exe to PATH"). The first start can take ~30 s while it installs dependencies.
- **Authentication errors**: re-check the settings with `/plugin configure visual-expert@visual-expert-tools`.
  Test sign-in from a terminal (replace values):

  ```powershell
  $env:VE_BASE_URL="https://your-server"; $env:VE_AUTH="form"; $env:VE_EMAIL="you@company.com"; $env:VE_PASSWORD="..."; python plugins\visual-expert\server\launcher.py --check
  ```

## Caveat

The server uses the same internal endpoints as the Visual Expert web UI (`/api/codeinspection/...`). They are not a
documented public API, so a Visual Expert upgrade may require an update to `server.py`. Tested against Visual Expert
2026.10.
