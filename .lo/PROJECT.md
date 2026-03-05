---
proj_id: "proj_ab98181f-8898-4189-bd2c-0843a7c7fafe"
title: "Claude Dashboard"
description: "Real-time terminal dashboard for monitoring Claude Code activity."
status: "explore"
state: "public"
topics:
  - developer-tools
  - telemetry
  - tui
  - claude-code
repo: "https://github.com/looselyorganized/claude-dashboard.git"
stack:
  - Python
  - Textual
  - Rich
agents:
  - name: "claude-code"
    role: "AI coding agent (Claude Code)"
---

A real-time terminal dashboard for monitoring Claude Code activity. Reads `~/.claude/` telemetry files to provide live event feeds, token usage tracking, and process monitoring via a Textual TUI.

## Capabilities

- **Live Event Feed** — Real-time streaming of tool calls, session events, and agent spawns with emoji-tagged log lines
- **Token Analytics** — Per-model token breakdowns (Opus, Sonnet, Haiku) with cache hit ratios and daily totals
- **Process Monitoring** — CPU, memory, uptime, MCP server count, and subagent status for all running Claude instances
- **Agent Tree Visualization** — Stack-based session-to-agent hierarchy reconstruction with live activity indicators

## Architecture

Single-file Python TUI (Textual/Rich) polls `~/.claude/` files at 0.5-30s intervals. Read-only consumer of Claude Code's native telemetry. The Supabase exporter has been extracted to the separate `telemetry-exporter` repo.
