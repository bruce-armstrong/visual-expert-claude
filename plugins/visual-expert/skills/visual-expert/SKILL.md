---
name: visual-expert
description: Work with Visual Expert Code Inspection findings (defects, issues, "VE-1234") through the visual-expert MCP tools - list or summarize findings by severity/type/status, explain a finding, fix ("address") a finding in the local PowerBuilder/SQL source, and change a finding's status (Risk Accepted, False Positive, On Hold, Pending Validation, Open) or severity with a comment. Use whenever the user mentions Visual Expert, a VE-#### id, code inspection findings/defects, or asks to triage static-analysis issues.
---

# Visual Expert findings

The `visual-expert` MCP server talks to the Visual Expert web app. Its tools:

| Tool | Use |
|---|---|
| `list_projects()` | Projects the account can see (id, name, which is current). |
| `set_context(project, analysis, url)` | Choose the project by name, id, or any VE URL. The **latest analysis is used automatically**; pass `analysis="<id>"` only to look at an older one, `analysis="latest"` to go back. |
| `list_defects(severity, status, type, rule, container, search, limit)` | List findings. `status` defaults to `active` (Open + Pending Validation); use `all` or explicit names otherwise. |
| `summarize_defects(status)` | Counts by severity / type / status / top rules. |
| `get_defect(defect_id, full_source, context_lines)` | Rule description, location, occurrence lines, source excerpt (`>>` marks flagged lines). |
| `set_defect_status(defect_ids, status, comment)` | Change status. |
| `set_defect_severity(defect_ids, severity, comment)` | Change severity. |

Vocabulary: "finding", "issue", "defect" all mean a VE defect. Ids are `VE-<n>`; a bare number means `VE-<n>`.

## Listing

- "List all the Critical issues" → `list_defects(severity="Critical")` (active only, unless they say all/closed/accepted).
- Present a compact table: Id, Severity, Type, Rule, Container, Occurrences, Status. If more than ~40 rows, show the table for the first 40 and group the rest by rule with counts; say how many there are in total and whether `truncated` was true.
- For "how bad is it / overview" use `summarize_defects`.

## Addressing a finding ("Address / fix VE-xxx")

1. `get_defect(id)`. Read the rule description and benefit: that is what "fixed" means.
2. Find the object in the local source. `location` looks like `F:\Build\Solution>appexamp.pbl>w_findreplacerte` - the server's path, not yours. Search the current workspace for the object named in the last `>` segment:
   - PowerBuilder 2025 solution format: a file `<object>.sr?` (`.srw` window, `.sru` user object, `.srd` DataWindow, `.srf` function, `.srm` menu, `.srs` structure, `.sra` application) usually under a folder named after the library (`appexamp\`).
   - Workspace/PBL-based projects: look for exported sources (`*.sr?`) or tell the user the object must be exported/checked out first - never edit `.pbl` binaries.
   - `container` may be a script (event/function) inside the object, e.g. `ue_apply` - find `event ue_apply` / `function ... ue_apply` within the object file.
3. Locate each occurrence by **matching the code text** from the excerpt, not just the line number - the local file may have drifted from the analyzed version. If the code no longer exists or already complies, say so and suggest marking it rather than editing.
4. Make the smallest change that satisfies the rule, keeping the file's existing style (tabs, casing, PowerScript conventions). Fix every occurrence listed for that finding. Typical cases:
   - *CASE should end with ELSE*: add `CASE ELSE` with the appropriate handling (often a comment or logging) - don't invent behaviour; ask if the right default is unclear.
   - *SQL injection*: replace string-concatenated dynamic SQL with bound parameters (`DECLARE ... DYNAMIC CURSOR`/`PREPARE` with `?`, or `SetSQLSelect` with retrieval arguments), or validate/escape input when parameters aren't possible.
   - *Unused code elements*: confirm it's really unused (search the workspace) before removing.
5. If a PowerBuilder syntax checker is available (e.g. the `pbunit` plugin's `check_source`), run it on the changed object.
6. Show the diff and explain it in a line or two. Then **ask** whether to mark the finding `Pending Validation` with a short comment describing the fix (the next analysis will mark it Resolved). Don't change the status without that yes, unless the user's request already said to.

For several findings ("address all CASE/ELSE findings in w_treeview"), list them first, confirm the batch, then fix them one object at a time.

## Changing status or severity

- "Mark VE-yyy as Risk Accepted with this comment: ..." is an explicit instruction - call `set_defect_status(["VE-yyy"], "Risk Accepted", comment)` directly, with the user's comment verbatim, and report the result.
- Statuses that can be set: Open, Risk Accepted, False Positive, On Hold, Pending Validation. `Resolved` is only set by a re-analysis - if asked, explain and offer Pending Validation.
- If the user asks for Risk Accepted / False Positive **without a comment**, ask for one (teams audit these). For bulk changes (more than one id, or "all X"), list the affected ids and confirm before calling.
- Never change status or severity on your own initiative (e.g. after deciding something is a false positive) - recommend it and let the user decide.

## Errors

- "No project set" → call `list_projects`; if there's only one or the user's request/workspace makes it obvious, `set_context(project=...)`, otherwise ask which one.
- Authentication errors → the plugin's sign-in settings need fixing: tell the user to run `/plugin configure visual-expert@visual-expert-tools`. Don't retry in a loop.
- Tool results include `project` and `analysis`; mention the analysis number when it matters (e.g. "as of analysis 14"). New analyses are picked up automatically within about 5 minutes.
