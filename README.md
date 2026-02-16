# Claude Code Dashboard

A real-time terminal dashboard for monitoring everything Claude Code is doing across your machine. Track live events, token usage, running instances, and agent hierarchies — all from a single TUI built with [Textual](https://textual.textualize.io/) and [Rich](https://rich.readthedocs.io/).

![Claude Dashboard](screenshot.png)

## What It Does

Claude Code writes event logs, token stats, and process data to `~/.claude/` as it works. This dashboard reads those files and presents a live, read-only view of all Claude activity on your system — no configuration or API keys needed.

- **Watch every tool call in real time** — see file reads, searches, edits, bash commands, MCP calls, and agent spawns as they happen
- **Track token spend per model** — per-model breakdowns (Opus, Sonnet, Haiku) with cache hit ratios, daily totals, and historical trends
- **Monitor all running instances** — CPU, memory, uptime, working directory, MCP server count, active shell commands, and subagent status for every Claude process
- **Visualize agent trees** — nested session and agent hierarchies with live spinner indicators showing which agents are active
- **Filter and search** — narrow the event feed by project, event type, text search, or time range (Today / 7d / All)
- **Compact mode** — collapse consecutive same-type events into grouped counts to reduce noise

## Quick Start

```bash
git clone https://github.com/mhofwell/claude-dashboard.git
cd claude-dashboard
pip install textual rich
python3 dashboard.py
```

The dashboard picks up data from `~/.claude/` automatically — just make sure [Claude Code](https://claude.ai/code) is installed and has been used at least once.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1` `2` `3` | Switch tabs (Live, Stats, Instances) |
| `t` | Cycle time range: Today / 7d / All |
| `/` | Open text filter |
| `p` | Cycle project filter |
| `e` | Cycle event type filter |
| `c` | Toggle compact mode |
| `n` | Next page (daily token table) |
| `j` / `k` | Scroll down / up |
| `G` / `g` | Jump to end / start |
| `Esc` | Clear all filters |
| `q` | Quit |

## Tabs

### 1. Live

Real-time event log with a sidebar showing:
- Event counts by type (tool calls, reads, searches, agents, sessions, etc.)
- Token usage per model for the current time range
- Running Claude instances with status indicators and project colors

### 2. Stats

- Session and message totals with daily averages
- Paginated daily token usage table broken down by model
- Supplemented with live data when the stats cache is stale

### 3. Instances

Full table of every running Claude process with:
- CPU / memory / uptime
- Claude version and MCP server count
- Active shell commands and subagent status
- Working directory

## Data Sources

The dashboard is read-only and monitors these files in `~/.claude/`:

| File | What it provides |
|------|-----------------|
| `events.log` | Real-time event stream (tool calls, session starts/ends, agent activity) |
| `token-stats` | Aggregate token counts across all models |
| `model-stats` | Per-model token breakdown (input, output, cache read/write) |
| `stats-cache.json` | Historical daily activity, token data, and model usage |

## Requirements

- Python 3.10+
- macOS (uses `ps` and `lsof` for process detection)
- [Claude Code](https://claude.ai/code) writing to `~/.claude/`

## License

MIT
