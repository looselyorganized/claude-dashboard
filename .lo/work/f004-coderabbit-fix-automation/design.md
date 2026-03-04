# CodeRabbit Fix Automation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Automate the CodeRabbit comment resolution loop. When CodeRabbit reviews a PR and posts comments, a local daemon automatically spawns Claude Code fix sessions, pushes fixes, and tracks progress — all visible in a new Dashboard tab.

**Architecture:** Thin webhook server on Railway receives GitHub `pull_request_review` events, writes to Supabase. Local daemon subscribes via Supabase Realtime, creates git worktrees, spawns Claude Code sessions to fix comments, pushes results. Dashboard tab 4 shows live fix session status. Events flow through existing `events.log` pipeline.

**Tech Stack:** TypeScript/Bun (webhook server + daemon), Python/Textual (dashboard tab), Supabase/PostgreSQL (coordination + config), Railway (webhook deployment)

---

## System Overview

```
GitHub ──webhook──> Railway server ──INSERT──> Supabase cr_fix_requests
                    (validate,                  |
                     filter LO repos,           | Realtime push
                     write row)                 v
                                          Local CR daemon
                                            |
                                            |-- Create git worktree
                                            |-- Fetch CR comments via gh API
                                            |-- Spawn claude --print --output-format stream-json
                                            |-- Write events to ~/.claude/events.log
                                            |-- Update Supabase with progress
                                            |-- Push fix commit
                                            |-- Clean up worktree when done
```

**Scope:** LO-scoped repos only. All comment severities fixed. Configurable max round limit. Supabase config table for per-repo overrides.

---

## New Components

| Component | Location | Runtime | Purpose |
|-----------|----------|---------|---------|
| CR Webhook Server | `cr-webhook/` | Railway (Bun) | Receive GitHub events, write to Supabase |
| CR Fix Daemon | `cr-daemon/` | Local launchd (Bun) | Orchestrate fix sessions |
| Dashboard Tab 4 | `dashboard.py` | Local (Python) | Visualize fix session status |
| Supabase tables | migrations/ | PostgreSQL | Coordination, config, history |

---

## Supabase Schema

### cr_fix_config

Per-repo configuration with defaults. Single source of truth read by webhook, daemon, and dashboard.

```sql
create table cr_fix_config (
  repo          text primary key,       -- "__default__" for global defaults
  enabled       boolean default true,
  max_rounds    int default 5,
  severities    text[] default '{critical,major,minor,trivial}',
  notify        boolean default true,
  notify_on     text[] default '{stuck,clean,failed}',
  created_at    timestamptz default now(),
  updated_at    timestamptz default now()
);

insert into cr_fix_config (repo) values ('__default__');
```

Resolution order: repo-specific -> `__default__` row -> hardcoded fallbacks.

### cr_fix_requests

Main coordination table. One active row per PR.

```sql
create table cr_fix_requests (
  id            uuid primary key default gen_random_uuid(),
  repo          text not null,
  pr_number     int not null,
  pr_url        text not null,
  branch        text not null,
  base_branch   text not null,
  status        text not null default 'pending',
  current_round int not null default 0,
  max_rounds    int not null default 5,
  comments_total    int default 0,
  comments_fixed    int default 0,
  comments_critical int default 0,
  comments_major    int default 0,
  comments_minor    int default 0,
  triggered_by  text,
  created_at    timestamptz default now(),
  updated_at    timestamptz default now(),
  completed_at  timestamptz
);
```

### cr_fix_rounds

Per-round history. One row per fix attempt.

```sql
create table cr_fix_rounds (
  id            uuid primary key default gen_random_uuid(),
  request_id    uuid references cr_fix_requests(id),
  round_number  int not null,
  comments_found    int not null,
  comments_fixed    int default 0,
  comments_skipped  int default 0,
  commit_sha    text,
  claude_session_id text,
  started_at    timestamptz default now(),
  finished_at   timestamptz,
  duration_ms   int,
  status        text not null default 'running',
  error         text
);
```

### State Machine

```
pending --> fixing --> waiting_review --> fixing (loop)
                                     --> clean (done)
                   --> stuck (max rounds)
                   --> failed (error)
any --> cancelled (user intervention)
```

Transitions:
- pending -> fixing: daemon creates worktree, starts Claude
- fixing -> waiting_review: Claude pushed fix commit
- waiting_review -> fixing: new webhook with CR re-review, still has comments
- waiting_review -> clean: no unresolved comments remain
- fixing -> stuck: round counter >= max_rounds
- Escalation guard: if comment count increases 2 rounds in a row, mark stuck

---

## Component Designs

### Task 1: Supabase migration

**Files:** `cr-webhook/migrations/001_cr_fix_tables.sql`

Create all three tables (cr_fix_config, cr_fix_requests, cr_fix_rounds) and seed defaults. Enable Realtime on cr_fix_requests.

```sql
alter publication supabase_realtime add table cr_fix_requests;
```

---

### Task 2: CR Webhook Server

**Files:**
```
cr-webhook/
  index.ts          -- HTTP server, POST /cr-webhook route
  verify.ts         -- GitHub HMAC-SHA256 signature verification
  package.json
  railway.toml
  Dockerfile
  .env.example      -- GITHUB_WEBHOOK_SECRET, SUPABASE_URL, SUPABASE_KEY
```

**Route handler logic:**
1. Verify `X-Hub-Signature-256` header
2. Check `X-GitHub-Event == "pull_request_review"`
3. Filter: `review.user.login == "coderabbitai[bot]"`
4. Filter: repo in LO allowlist (query cr_fix_config where enabled=true)
5. Check existing row for repo+pr:
   - Status `waiting_review`: UPDATE to `fixing`
   - Status `fixing`/`pending`: ignore (already working)
   - No row: INSERT with status `pending`
6. Return 200

**Dependencies:** `@supabase/supabase-js`

Under 200 lines total. No business logic beyond validate-filter-write.

---

### Task 3: CR Fix Daemon

**Files:**
```
cr-daemon/
  index.ts              -- Supabase Realtime subscription + orchestrator
  fix-session.ts        -- Single fix session lifecycle
  comments.ts           -- Fetch + parse CodeRabbit comments via gh API
  worktree.ts           -- Git worktree create/cleanup in ~/.claude-cr/worktrees/
  claude.ts             -- Spawn claude --print, parse stream-json output
  events.ts             -- Write events to ~/.claude/events.log
  notify.ts             -- Push notifications via ntfy.sh
  config.ts             -- Read cr_fix_config from Supabase, merge defaults
  package.json
  com.lo.cr-fix-daemon.plist  -- launchd service config
```

**Orchestration (index.ts):**
- Subscribe to Supabase Realtime on `cr_fix_requests` where status in (pending, fixing)
- Guard against concurrent sessions for same PR via `activeSessions` Map
- On startup: scan for orphaned rows stuck in `fixing` > 30 minutes, reset to `pending`
- Cleanup stale worktrees in `~/.claude-cr/worktrees/`

**Fix session lifecycle (fix-session.ts):**
1. Log `cr-review-received` event
2. Create git worktree for repo+branch
3. Fetch unresolved CodeRabbit comments via `gh api`
4. If no comments -> mark `clean`, notify, return
5. Check round limit, check escalation guard (comments increasing)
6. Increment round, insert cr_fix_rounds row
7. Log `cr-fix-started` event
8. Build prompt from grouped comments
9. Spawn `claude --print --output-format stream-json` in worktree
10. Parse result, push commit
11. Post PR comment with round summary
12. Update status to `waiting_review`
13. Log `cr-fix-complete` event
14. Cleanup worktree

**Error handling:**
- Claude exit non-zero: log `cr-fix-failed`, update round, notify
- Git push fails: log error, mark round failed
- PR closed/merged: check `gh pr view --json state` before push, mark cancelled
- Crash recovery: startup scan resets orphaned rows

**Comment fetching (comments.ts):**
- `gh api repos/{repo}/pulls/{pr}/comments` filtered by `coderabbitai[bot]`
- Filter to unresolved threads only
- Parse severity from CodeRabbit's formatting
- Group by file path for prompt building

**Prompt template (claude.ts):**
```
You are fixing CodeRabbit review comments on PR #{n}.
Branch: {branch}
Round: {round} of {max}

Fix ALL of the following review comments. For each one, make the minimal
change needed to resolve the issue. Do not refactor surrounding code.

## {file_path}
- Line {line} [{severity}]: {comment_body}
...

After fixing, commit with message:
"fix: resolve CodeRabbit review comments (round {round})"
```

**Dependencies:** `@supabase/supabase-js`

---

### Task 4: Event log format

New event types written by daemon to `~/.claude/events.log`:

```
{ts}|{project}|{branch}|🐰|cr-review-received|PR #{n}: {total} comments ({crit} critical, {maj} major, {min} minor)
{ts}|{project}|{branch}|🔨|cr-fix-started|PR #{n} round {r}/{max} -- fixing {count} comments
{ts}|{project}|{branch}|✅|cr-fix-complete|PR #{n} round {r}/{max} -- fixed {fixed}, skipped {skipped}, pushed {sha}
{ts}|{project}|{branch}|❌|cr-fix-failed|PR #{n} round {r}/{max} -- {error}
{ts}|{project}|{branch}|🏁|cr-clean|PR #{n} -- all comments resolved after {rounds} rounds
{ts}|{project}|{branch}|⚠️|cr-stuck|PR #{n} -- max rounds ({max}) reached, {remaining} unresolved
{ts}|{project}|{branch}|🐰|cr-waiting|PR #{n} -- pushed round {r}, waiting for re-review
```

These flow through existing pipeline: dashboard reads from events.log, exporter syncs to Supabase events table. No changes to event-log.sh or exporter needed.

---

### Task 5: Dashboard Tab 4 — CR Fixes

**Files:** Modify `dashboard.py`

**New data classes:**

```python
class CRFixSession:
    pr_number: int
    repo: str
    branch: str
    pr_url: str
    status: str        # pending|fixing|waiting_review|clean|stuck|cancelled
    current_round: int
    max_rounds: int
    comments_total: int
    comments_fixed: int
    comments_by_severity: dict
    rounds: list       # per-round detail
    started_at: datetime
    last_activity: datetime

class CodeRabbitTracker:
    sessions: dict[str, CRFixSession]  # keyed by "repo:pr_number"

    def process_entries(self, entries: list[LogEntry]):
        # Parse cr-* events, build/update session state

    def active_sessions(self) -> list[CRFixSession]:
        # status in (pending, fixing, waiting_review)

    def recent_completed(self, limit=10) -> list[CRFixSession]:
        # status in (clean, stuck, cancelled), sorted by last_activity desc
```

**Tab layout:**

```
1.Live  2.Stats  3.Instances  4.CR Fixes

+-----------------------------------------------+------------------+
|                                                |                  |
|  Active Fix Sessions                           |  Summary         |
|  ------------------                            |  -------         |
|                                                |  Today: 3 PRs    |
|  PR #147  feature/auth       round 2/5  fixing |  Fixed: 2        |
|  |  repo: lo/platform                          |  Stuck: 0        |
|  |  comments: 3 crit, 2 major, 1 minor         |  Active: 1       |
|  |  fixed so far: 5/6                          |                  |
|  |  -> github.com/.../pull/147                 |  This Week       |
|  |                                             |  ---------       |
|  |  Round 1  ok  5/6 fixed  2m14s  abc1234     |  PRs: 12         |
|  |  Round 2  ... in progress                   |  Rounds: 28      |
|  |                                             |  Avg: 2.3        |
|  -----------------------------------------------                  |
|                                                |  Config          |
|  Recent (completed)                            |  ------          |
|  ------------------                            |  Max rounds: 5   |
|                                                |  Scope: LO       |
|  PR #145  refactor/api   clean  2r  4m30s      |  Daemon: running |
|  PR #143  feat/dash      clean  1r  1m52s      |                  |
|  PR #139  fix/parser     stuck  5r  (2 left)   |  m: max  s: sev  |
|                                                |                  |
+-----------------------------------------------+------------------+
```

**Key bindings:**
- `4` — switch to CR Fixes tab
- `m` — change max rounds (inline input, writes to Supabase)
- `s` — change severities (inline input, writes to Supabase)

**Polling:** Reuses existing 0.5s _poll_new_entries cycle. CodeRabbitTracker.process_entries() runs on same new entries. No additional I/O.

**Emoji styling:** Add to EVENT_STYLES: `"🐰": "bold #FF8C00"` (orange, stands out)

---

### Task 6: Notifications

Push via ntfy.sh. Daemon sends on: clean, stuck, failed, daemon start, Supabase connection loss.

| Event | Priority | Message |
|-------|----------|---------|
| cr-clean | default | "PR #147 clean after 2 rounds" |
| cr-stuck | high | "PR #147 stuck -- 2 unresolved after 5 rounds" |
| cr-fix-failed | high | "PR #147 round 2 failed: {error}" |
| daemon start | default | "CR fix daemon online" |
| supabase disconnect | high | "Supabase connection lost, reconnecting..." |

---

### Task 7: Stuck PR escalation comment

When max rounds reached, daemon posts to PR:

```markdown
**CR Fix Daemon reached maximum rounds ({round}/{max})**

{n} comments remain unresolved:

- `{path}:{line}` [{severity}] -- {summary}
...

These may require manual intervention.

_CR Fix Daemon -- {succeeded} rounds succeeded -- {fixed}/{total} comments resolved_
```

---

### Task 8: Launchd service

`cr-daemon/com.lo.cr-fix-daemon.plist` — starts on load, restarts on crash, logs to `~/.claude-cr/logs/`.

Managed alongside existing `com.lo.telemetry-exporter.plist`. Potential extension of `lo-open`/`lo-close` to start/stop the CR daemon.

---

## Testing Strategy

**Phase 1:** Deploy webhook server to Railway. Use GitHub webhook delivery tab to redeliver a past `pull_request_review` event. Verify Supabase row.

**Phase 2:** Run daemon with `--dry-run` flag. Subscribes to Realtime, logs intended actions, doesn't spawn Claude or push. Validates Supabase connection, worktree creation, comment fetching, prompt building.

**Phase 3:** Open test PR on an LO repo with intentional issues. Let CodeRabbit review. Daemon picks up, fixes, pushes. Watch in dashboard tab 4.

**Phase 4:** Branch dashboard, add tab 4 + tracker. Test with manual events injected into events.log.

---

## Error Handling Summary

| Failure | Detection | Response |
|---------|-----------|----------|
| Webhook server down | Railway health check | Auto-restart. Missed webhooks retried by GitHub. |
| Supabase unreachable | INSERT/subscribe fails | Webhook: 503, GitHub retries. Daemon: auto-reconnect. |
| Daemon crash mid-fix | Orphaned row in `fixing` | Startup scan resets rows stuck > 30min. Worktree cleanup. |
| Claude session fails | Non-zero exit | Log failed, retry if rounds left, else mark stuck. |
| Claude makes things worse | Comment count increases 2 rounds in a row | Mark stuck, notify. |
| Git push fails | Non-zero exit | Log error, mark round failed, notify. |
| PR closed during fix | `gh pr view --json state` before push | Mark cancelled, cleanup. |
| Max rounds reached | round >= max_rounds | Mark stuck, post escalation comment, notify. |
| Duplicate webhook for same PR | activeSessions guard + upsert | Skip if already processing. |
