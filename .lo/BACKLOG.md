---
updated: 2026-03-03
---

## Features

### f001 — LO Open Startup Command
Replace the naive `lo-open` facility switch with a comprehensive preflight + startup command that only reports "open" when the entire telemetry pipeline is verified healthy.
Status: done -> .lo/work/f001-lo-open/

### f002 — LO Scope Toggle
Add a binary scope filter (`l` key) that toggles between All (default) and LO. Independent of and composable with the existing `p` (project) and `t` (time range) filters.
Status: done -> .lo/work/f002-lo-scope-toggle/

### f003 — Message Event Tracking
Track inter-agent message events across the dashboard TUI and Supabase exporter with per-project breakdown and Today/7d/All time aggregation.
Status: done -> .lo/work/f003-message-event-tracking/

### f004 — CodeRabbit Fix Automation
Automate the CodeRabbit comment resolution loop. Thin webhook server on Railway receives GitHub review events, writes to Supabase. Local daemon subscribes via Realtime, spawns Claude Code fix sessions in git worktrees, pushes fixes. New Dashboard tab 4 shows fix session status. Events flow through existing events.log pipeline.
Status: designed -> .lo/work/f004-coderabbit-fix-automation/


## Tasks

- [ ] t001 Review PROJECT.md and fill any TODO placeholders
