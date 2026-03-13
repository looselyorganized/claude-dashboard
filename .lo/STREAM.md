---
type: stream
---

<entry>
date: 2026-02-25
title: "LO scope toggle for dashboard"
<description>
Added `l` keybinding to toggle LO-scoped view across all dashboard tabs — event log, sidebar, stats summary, daily tokens, instances. Project scanning from session file paths identifies LO projects automatically. Renamed lorf → lo across exporter, plist, and service label.
</description>
</entry>

<entry>
date: 2026-02-25
title: "lo-open startup command"
<description>
Replaced naive facility switch with comprehensive `lo-open` running 8 sequential preflight checks — environment, Supabase, deployment health, site reachability, launchd, exporter process, telemetry flow, and status flip. Self-heals launchd and exporter. Matching `lo-close` performs graceful shutdown: SIGTERM, launchd unload. PID guard and strict project scanning added to exporter.
</description>
</entry>

<entry>
date: 2026-02-24
title: "Facility switch and telemetry refresh"
<description>
Added manual facility open/close switch and sliding-window activity detection. Fixed stale token and lifetime counter refresh by re-reading JSONL every 5 minutes.
</description>
</entry>

<entry>
date: 2026-02-23
title: "Project identity and event tracking"
<description>
Unified project identity under `content_slug`. Added LO-only filtering to skip non-LO projects. Added message event tracking. Initialized `.lo/` project structure.
</description>
</entry>

<entry>
date: 2026-02-19
title: "Supabase exporter launched"
<description>
Added TypeScript/Bun daemon syncing events, daily metrics, projects, and facility status to Supabase. Per-project event counts and agent tracking. README and docs overhaul covering setup, quick start, and architecture.
</description>
</entry>

<entry>
date: 2026-02-13
title: "Performance and reliability fixes"
<description>
Fixed ghost spinner bug (stale agents expire after 1h), cached sidebar computations to reduce CPU, fixed false 'wants input' detection. Extracted shared helpers to simplify codebase.
</description>
</entry>

<entry>
date: 2026-02-12
title: "Dashboard initial release"
<description>
Migrated TUI from `~/.claude/dashboard` to standalone repo. Added stats tab with live today data, pagination, skill tracking, agent tree indentation. First PR merged.
</description>
</entry>
