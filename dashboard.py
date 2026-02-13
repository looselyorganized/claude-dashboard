#!/usr/bin/env python3
"""Claude Code Dashboard — Textual TUI for monitoring Claude Code events."""

import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from rich.table import Table
from rich.text import Text

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.timer import Timer
from textual.widgets import Footer, Input, RichLog, Static, TabbedContent, TabPane

# ─── Paths ────────────────────────────────────────────────────────────────────
CLAUDE_DIR = Path.home() / ".claude"
LOG_FILE = CLAUDE_DIR / "events.log"
TOKEN_FILE = CLAUDE_DIR / "token-stats"
MODEL_FILE = CLAUDE_DIR / "model-stats"
STATS_CACHE_FILE = CLAUDE_DIR / "stats-cache.json"

# ─── ANSI ─────────────────────────────────────────────────────────────────────
ANSI_RE = re.compile(r"\033\[[0-9;]*m")

# ─── Event styles ─────────────────────────────────────────────────────────────
EVENT_STYLES = {
    "👋": "bold #ff87d7",
    "🔐": "bold #ff87d7",
    "💭": "bold #ff87d7",
    "❓": "bold #ff87d7",
    "🏁": "bold #00ff00",
    "🛬": "bold #00ff00",
    "✅": "bold #00ff00",
    "⚠️": "bold #d75f5f",
    "⚡": "bold #5fafff",
    "🔌": "bold #af87ff",
    "📐": "bold #2e8b57",
    "🚀": "bold #5fd7d7",
    "🤖": "bold #5fd7d7",
    "👥": "bold #5fd7d7",
}

# Stable color palette for project names
PROJECT_COLORS = [
    "#5fafff", "#af87ff", "#ff87d7", "#5fd7d7", "#d7af5f",
    "#87d787", "#ff875f", "#d787d7", "#87d7d7", "#d7d75f",
]

# Event type to emoji mapping for cycling filter
EVENT_TYPE_MAP = {
    "tools": "🔧",
    "reads": "📖",
    "searches": "🔍",
    "skills": "⚡",
    "mcp": "🔌",
    "agents": "🚀",
    "tasks": "📋",
    "sessions": "🟢",
    "finished": "🏁",
    "permission": "🔐",
    "attention": "👋",
}


# ─── Data layer ───────────────────────────────────────────────────────────────

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def style_for_line(line: str) -> str:
    """Determine Rich style based on emoji in the line."""
    clean = strip_ansi(line)
    if "Task (Plan)" in clean:
        return "bold #00875f"
    for emoji, style in EVENT_STYLES.items():
        if emoji in clean:
            return style
    return ""


def format_model_name(model_id: str) -> str:
    """claude-opus-4-6 → Opus 4.6, claude-opus-4-5-20251101 → Opus 4.5"""
    name = model_id.replace("claude-", "")
    parts = name.split("-")
    if len(parts) >= 3:
        # Filter out date-like version suffixes (8+ digit numbers)
        version_parts = [p for p in parts[1:] if not (p.isdigit() and len(p) >= 8)]
        return f"{parts[0].title()} {'.'.join(version_parts)}"
    return name.title()


def read_token_stats() -> dict:
    """Read aggregate token stats."""
    if not TOKEN_FILE.exists():
        return {}
    try:
        parts = TOKEN_FILE.read_text().strip().split()
        if len(parts) >= 4:
            return {
                "input": int(parts[0]),
                "cache_write": int(parts[1]),
                "cache_read": int(parts[2]),
                "output": int(parts[3]),
            }
    except Exception:
        pass
    return {}


def read_model_stats() -> list[dict]:
    """Read per-model token stats."""
    if not MODEL_FILE.exists():
        return []
    models = []
    try:
        for line in MODEL_FILE.read_text().strip().splitlines():
            parts = line.split()
            if len(parts) >= 6:
                models.append({
                    "model": parts[0],
                    "total": int(parts[1]),
                    "input": int(parts[2]),
                    "cache_write": int(parts[3]),
                    "cache_read": int(parts[4]),
                    "output": int(parts[5]),
                })
    except Exception:
        pass
    return models


# Emoji → count key mapping for event tallying
EMOJI_COUNT_MAP = {
    "🔧": "tools", "📖": "reads", "🔍": "searches", "🌐": "fetches",
    "🔌": "mcp", "⚡": "skills", "🚀": "agents", "🤖": "subagents",
    "🛬": "landed", "🏁": "finished", "📐": "plans", "🟢": "sessions",
    "🔴": "ended", "👋": "input", "🔐": "permission", "❓": "questions",
    "✅": "completed", "⚠️": "compacts",
}

# "📋 Task created" needs a substring match, not just emoji presence
_TASK_CREATED_MARKER = "📋 Task created"


def count_events(lines: list[str]) -> dict:
    """Count events by emoji from log lines."""
    counts = {key: 0 for key in EMOJI_COUNT_MAP.values()}
    counts["tasks"] = 0
    for line in lines:
        clean = strip_ansi(line)
        for emoji, key in EMOJI_COUNT_MAP.items():
            if emoji in clean:
                counts[key] += 1
        if _TASK_CREATED_MARKER in clean:
            counts["tasks"] += 1
    return counts


# ─── Log entry ────────────────────────────────────────────────────────────────

@dataclass
class LogEntry:
    """Parsed log line."""
    raw: str
    timestamp: str = ""
    project: str = ""
    branch: str = ""
    event: str = ""
    emoji: str = ""
    style: str = ""

    def matches_filter(self, text_filter: str, project_filter: str, event_type_filter: str) -> bool:
        if text_filter and text_filter.lower() not in self.raw.lower():
            return False
        if project_filter and self.project != project_filter:
            return False
        if event_type_filter:
            emoji = EVENT_TYPE_MAP.get(event_type_filter, "")
            if emoji and emoji not in self.event:
                return False
        return True


# All emojis to search for when identifying event type (EVENT_STYLES keys + extras)
_ALL_EVENT_EMOJIS = list(EVENT_STYLES.keys()) + ["🔧", "📖", "🔍", "📋", "🟢", "🔴", "📐"]
# Deduplicate while preserving order (EVENT_STYLES takes priority)
_ALL_EVENT_EMOJIS = list(dict.fromkeys(_ALL_EVENT_EMOJIS))


def parse_log_line(raw_line: str) -> LogEntry:
    """Parse a pipe-delimited log line into a LogEntry."""
    clean = strip_ansi(raw_line)
    style = style_for_line(raw_line)

    timestamp = ""
    project = ""
    branch = ""
    event = clean.strip()

    parts = clean.split("│")
    if len(parts) >= 4:
        timestamp = parts[0].strip()
        project = parts[1].strip()
        branch = parts[2].strip()
        event = "│".join(parts[3:]).strip()
    elif len(parts) >= 2:
        timestamp = parts[0].strip()
        event = "│".join(parts[1:]).strip()

    emoji = ""
    for e in _ALL_EVENT_EMOJIS:
        if e in event:
            emoji = e
            break

    return LogEntry(
        raw=clean,
        timestamp=timestamp,
        project=project,
        branch=branch,
        event=event,
        emoji=emoji,
        style=style,
    )


class LogTailer:
    """Efficient incremental file reader — tracks offset, reads only new bytes."""

    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self._all_entries: list[LogEntry] = []

    def poll(self) -> list[LogEntry]:
        """Read new lines since last poll. Returns only new entries."""
        if not self.path.exists():
            return []
        try:
            size = self.path.stat().st_size
            if size < self.offset:
                self.offset = 0
                self._all_entries.clear()
            if size == self.offset:
                return []

            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read().decode("utf-8", errors="replace")
                self.offset = f.tell()

            new_entries = []
            for line in data.strip().splitlines():
                line = line.strip()
                if line:
                    entry = parse_log_line(line)
                    new_entries.append(entry)
                    self._all_entries.append(entry)
            return new_entries
        except Exception:
            return []

    @property
    def all_entries(self) -> list[LogEntry]:
        return self._all_entries

    def load_existing(self):
        """Load entire file on startup."""
        if not self.path.exists():
            return
        try:
            data = self.path.read_text(errors="replace")
            self.offset = len(data.encode("utf-8"))
            for line in data.strip().splitlines():
                line = line.strip()
                if line:
                    self._all_entries.append(parse_log_line(line))
        except Exception:
            pass


def _normalize_project_key(name: str) -> str:
    """Normalize a project name for fuzzy matching (lowercase, no separators)."""
    return name.lower().replace("-", "").replace("_", "")


def _project_color(project: str, known: dict[str, str]) -> str:
    """Stable color for a project name."""
    if project not in known:
        idx = len(known) % len(PROJECT_COLORS)
        known[project] = PROJECT_COLORS[idx]
    return known[project]


# ─── Stats cache loader ─────────────────────────────────────────────────────

def load_stats_cache() -> dict:
    """Load ~/.claude/stats-cache.json, return empty dict on failure."""
    if not STATS_CACHE_FILE.exists():
        return {}
    try:
        return json.loads(STATS_CACHE_FILE.read_text())
    except Exception:
        return {}


def _format_tokens(n: int) -> str:
    """Format token count as B/M/K."""
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.0f}K"
    return str(n)


TIME_RANGE_LABELS = {"Today": "Today", "7d": "7 Days", "All": "All Time"}


# ─── Time helpers ────────────────────────────────────────────────────────────

def _parse_timestamp(ts: str) -> datetime | None:
    """Parse timestamp string, trying multiple formats."""
    ts = ts.strip()
    for fmt in ("%m/%d %I:%M %p", "%I:%M %p", "%m/%d %I:%M:%S %p", "%I:%M:%S %p"):
        try:
            dt = datetime.strptime(ts, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue
    return None


def _time_diff_minutes(start: str, end: str) -> float:
    """Calculate minutes between two timestamp strings."""
    s = _parse_timestamp(start)
    e = _parse_timestamp(end)
    if not s or not e:
        return 0.0
    diff = (e - s).total_seconds() / 60.0
    if diff < 0:
        diff += 24 * 60
    return diff


# ─── Agent tree data ────────────────────────────────────────────────────────

@dataclass
class AgentNode:
    """An agent spawned within a session."""
    agent_type: str
    agent_id: str
    start_time: str
    end_time: str = ""
    duration_minutes: float = 0.0
    is_running: bool = True
    children: list = field(default_factory=list)


@dataclass
class SessionNode:
    """A session with nested agents."""
    project: str
    start_time: str
    model: str = ""
    is_active: bool = False
    last_event_time: str = ""
    agents: list[AgentNode] = field(default_factory=list)


BRAILLE_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def build_agent_tree(entries: list[LogEntry]) -> list[SessionNode]:
    """Build agent tree from log entries using stack-based inference."""
    sessions: list[SessionNode] = []
    current_sessions: dict[str, SessionNode] = {}
    agent_map: dict[str, AgentNode] = {}

    for entry in entries:
        if "🟢" in entry.event and "Session started" in entry.event:
            if entry.project in current_sessions:
                sessions.append(current_sessions[entry.project])
            model = ""
            m = re.search(r"\[([^\]]+)\]", entry.event)
            if m:
                model = m.group(1)
            node = SessionNode(
                project=entry.project,
                start_time=entry.timestamp,
                last_event_time=entry.timestamp,
                model=model,
            )
            current_sessions[entry.project] = node

        elif "🔴" in entry.event and "Session ended" in entry.event:
            if entry.project in current_sessions:
                sessions.append(current_sessions.pop(entry.project))

        elif "🚀" in entry.event and "Spawned agent" in entry.event:
            m = re.search(r"Spawned agent:?\s*(?:(\S+)\s+)?\(?(\w+)\)?", entry.event)
            if m:
                atype = m.group(1) or "Agent"
                aid = m.group(2)
                agent = AgentNode(
                    agent_type=atype,
                    agent_id=aid,
                    start_time=entry.timestamp,
                )
                agent_map[aid] = agent

                proj = entry.project
                if proj in current_sessions:
                    current_sessions[proj].last_event_time = entry.timestamp
                    # Always add as top-level agent — the event log
                    # doesn't indicate parent/child relationships, so
                    # stack-based nesting incorrectly nests parallel
                    # agents (e.g. multiple Explore agents) as children.
                    current_sessions[proj].agents.append(agent)

        elif "🛬" in entry.event and "Agent finished" in entry.event:
            m = re.search(r"Agent finished:?\s*(?:\S+\s+)?\(?(\w+)\)?", entry.event)
            if m:
                aid = m.group(1)
                if aid in agent_map:
                    agent = agent_map[aid]
                    agent.is_running = False
                    agent.end_time = entry.timestamp
                    agent.duration_minutes = _time_diff_minutes(agent.start_time, agent.end_time)

                proj = entry.project
                if proj in current_sessions:
                    current_sessions[proj].last_event_time = entry.timestamp

        else:
            # Track any event for this project to keep session fresh
            if entry.project in current_sessions:
                current_sessions[entry.project].last_event_time = entry.timestamp

    # Mark remaining open sessions as active (no end event seen)
    for sess in current_sessions.values():
        sess.is_active = True
        sessions.append(sess)

    # Expire stale agents: if spawned >1 hour ago with no finish event,
    # assume the finish event was lost and stop showing them as running.
    now = datetime.now()
    for sess in sessions:
        for agent in sess.agents:
            if agent.is_running:
                started = _parse_timestamp(agent.start_time)
                if started and (now - started).total_seconds() > 3600:
                    agent.is_running = False

    return sessions


def _count_active_sessions(sessions: list[SessionNode]) -> int:
    """Count sessions that are currently active."""
    return sum(1 for s in sessions if s.is_active)


def _build_active_session_map(sessions: list[SessionNode]) -> dict[str, SessionNode]:
    """Build a lookup from normalized project key to the active session."""
    session_map: dict[str, SessionNode] = {}
    for sess in sessions:
        if sess.is_active:
            session_map[_normalize_project_key(sess.project)] = sess
    return session_map


# ─── Process scanner ─────────────────────────────────────────────────────────

@dataclass
class ProcessInstance:
    """A running Claude process detected from the system."""
    pid: int
    tty: str
    cpu_percent: float
    mem_mb: float
    uptime_raw: str  # raw etime from ps
    uptime_display: str  # formatted for display
    cwd: str
    project_name: str
    is_active: bool  # CPU > 1%
    claude_version: str = ""  # e.g. "2.1.39"
    mcp_server_count: int = 0  # npm→node child pairs
    has_shell: bool = False  # zsh/bash child = running a command
    shell_command: str = ""  # actual command being run (e.g. "bun dev")
    has_caffeinate: bool = False  # caffeinate = actively working


def _format_uptime(etime: str) -> str:
    """Format ps etime (DD-HH:MM:SS or HH:MM:SS or MM:SS) to short form."""
    etime = etime.strip()
    days = 0
    if "-" in etime:
        day_part, time_part = etime.split("-", 1)
        days = int(day_part)
        etime = time_part
    parts = etime.split(":")
    if len(parts) == 3:
        hours, minutes = int(parts[0]), int(parts[1])
    elif len(parts) == 2:
        hours = 0
        minutes = int(parts[0])
    else:
        return etime
    if days > 0:
        return f"{days}d {hours}h"
    if hours > 0:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m"


def _derive_project_name(cwd: str) -> str:
    """Derive a display-friendly project name from the CWD path."""
    if not cwd or cwd == "/":
        return "unknown"
    p = Path(cwd)
    # If inside a monorepo subdir (e.g. .../nexus-2/apps/cli), use parent project name
    # Heuristic: if grandparent is 'projects', use parent name
    parts = p.parts
    try:
        idx = parts.index("projects")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    except ValueError:
        pass
    return p.name


class ProcessScanner:
    """Scans running Claude processes from the system."""

    def __init__(self):
        self._instances: list[ProcessInstance] = []
        self.generation: int = 0

    def scan(self) -> list[ProcessInstance]:
        """Scan for running Claude processes using ps + lsof."""
        self.generation += 1
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,tty,pcpu,rss,etime,comm"],
                capture_output=True, text=True, timeout=5,
            )
        except Exception:
            return self._instances

        pid_info: list[tuple[int, str, float, float, str]] = []
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[-1] == "claude":
                try:
                    pid = int(parts[0])
                    tty = parts[1]
                    cpu = float(parts[2])
                    rss_kb = int(parts[3])
                    mem_mb = round(rss_kb / 1024, 1)
                    etime = parts[4]
                    pid_info.append((pid, tty, cpu, mem_mb, etime))
                except (ValueError, IndexError):
                    continue

        if not pid_info:
            self._instances = []
            return self._instances

        # Batch CWD lookup
        pid_csv = ",".join(str(p[0]) for p in pid_info)
        cwd_map: dict[int, str] = {}
        try:
            result = subprocess.run(
                ["lsof", "-d", "cwd", "-a", "-p", pid_csv, "-Fn"],
                capture_output=True, text=True, timeout=5,
            )
            current_pid = None
            for line in result.stdout.splitlines():
                if line.startswith("p"):
                    try:
                        current_pid = int(line[1:])
                    except ValueError:
                        current_pid = None
                elif line.startswith("n") and current_pid is not None:
                    cwd_map[current_pid] = line[1:]
        except Exception:
            pass

        # Batch child process lookup — collect ALL parent→child relationships
        all_children: dict[int, list[tuple[int, str]]] = {}
        child_map: dict[int, list[tuple[int, str]]] = {p[0]: [] for p in pid_info}
        # Also collect full args for command resolution
        pid_args: dict[int, str] = {}
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,ppid,comm"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) >= 3:
                    try:
                        cpid = int(parts[0])
                        ppid = int(parts[1])
                        cname = parts[2].strip()
                        all_children.setdefault(ppid, []).append((cpid, cname))
                        if ppid in child_map:
                            child_map[ppid].append((cpid, cname))
                    except ValueError:
                        continue
        except Exception:
            pass

        # Get full command args for all processes (for resolving shell commands)
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,args"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.strip().splitlines()[1:]:
                parts = line.strip().split(None, 1)
                if len(parts) >= 2:
                    try:
                        pid_args[int(parts[0])] = parts[1].strip()
                    except ValueError:
                        continue
        except Exception:
            pass

        instances = []
        for pid, tty, cpu, mem_mb, etime in pid_info:
            cwd = cwd_map.get(pid, "")
            project_name = _derive_project_name(cwd)
            children = child_map.get(pid, [])

            # Parse child processes
            claude_version = ""
            mcp_count = 0
            has_shell = False
            shell_command = ""
            has_caffeinate = False
            shell_pids: list[int] = []
            for cpid, cname in children:
                if cname == "<defunct>":
                    continue
                if "claude/versions/" in cname:
                    # Extract version from path like .../versions/2.1.39/...
                    m = re.search(r"versions/(\d+\.\d+\.\d+)", cname)
                    if m:
                        claude_version = m.group(1)
                elif cname == "npm":
                    mcp_count += 1
                elif cname in ("zsh", "bash", "sh", "/bin/zsh", "/bin/bash"):
                    has_shell = True
                    shell_pids.append(cpid)
                elif cname == "caffeinate":
                    has_caffeinate = True

            # Resolve actual command running inside the shell
            if has_shell and shell_pids:
                for shell_pid in shell_pids:
                    grandchildren = all_children.get(shell_pid, [])
                    for gcpid, gcname in grandchildren:
                        if gcname == "<defunct>":
                            continue
                        cmd_name = gcname.rsplit("/", 1)[-1]
                        if cmd_name in ("zsh", "bash", "sh"):
                            continue
                        # Use full args if available for richer display
                        full_args = pid_args.get(gcpid, "")
                        if full_args:
                            # Shorten all path-like args to basename
                            # e.g. "find /Users/x/Documents/github/proj" → "find proj"
                            arg_parts = full_args.split()
                            for i, part in enumerate(arg_parts):
                                if "/" in part:
                                    arg_parts[i] = part.rsplit("/", 1)[-1] or part
                            shell_command = " ".join(arg_parts)
                            if len(shell_command) > 25:
                                shell_command = shell_command[:22] + "..."
                        else:
                            shell_command = cmd_name
                        break
                    if shell_command:
                        break

            instances.append(ProcessInstance(
                pid=pid,
                tty=tty,
                cpu_percent=cpu,
                mem_mb=mem_mb,
                uptime_raw=etime,
                uptime_display=_format_uptime(etime),
                cwd=cwd,
                project_name=project_name,
                is_active=cpu > 1.0 or has_caffeinate,
                claude_version=claude_version,
                mcp_server_count=mcp_count,
                has_shell=has_shell,
                shell_command=shell_command,
                has_caffeinate=has_caffeinate,
            ))

        # Active first (by CPU desc), then idle (alphabetical)
        instances.sort(key=lambda x: (-x.is_active, -x.cpu_percent, x.project_name.lower()))
        self._instances = instances
        return instances

    @property
    def instances(self) -> list[ProcessInstance]:
        return self._instances

    @property
    def active_count(self) -> int:
        return sum(1 for i in self._instances if i.is_active)

    @property
    def total_mem_mb(self) -> float:
        return sum(i.mem_mb for i in self._instances)


# ─── Textual App ──────────────────────────────────────────────────────────────

class ClaudeDashboardApp(App):
    """Interactive TUI dashboard for Claude Code — 3 tabs: Live, Stats, Instances."""

    DEFAULT_CSS = """
    Screen {
        background: transparent;
    }

    #header-bar {
        dock: top;
        height: 3;
        background: transparent;
        color: $text;
        text-style: bold;
        padding: 1 1 1 1;
    }

    #tabs {
        height: 1fr;
    }

    TabbedContent ContentSwitcher {
        height: 1fr;
    }

    TabPane {
        height: 1fr;
        padding: 0;
    }

    /* ── Tab 1: Live ── */
    #main-content {
        height: 1fr;
    }

    #log-pane {
        width: 4fr;
    }

    #event-log {
        background: transparent;
        height: 1fr;
        border: solid #444444;
        scrollbar-size: 1 1;
    }

    #event-log:focus {
        border: solid $accent;
    }

    #filter-input {
        dock: bottom;
        display: none;
        height: 3;
        margin: 0 0;
    }

    #filter-input.visible {
        display: block;
    }

    #sidebar {
        width: 1fr;
        min-width: 32;
        max-width: 42;
    }

    #stats-panel {
        background: transparent;
        height: auto;
        max-height: 50%;
        border: solid #444444;
        padding: 0 1;
    }

    #token-panel {
        background: transparent;
        height: auto;
        border: solid #444444;
        padding: 0 1;
    }

    #instances-panel {
        background: transparent;
        height: 1fr;
        border: solid #444444;
        padding: 0;
        overflow-y: auto;
    }

    #instances-panel-header {
        padding: 0 1;
        text-style: bold;
    }

    #instances-panel-body {
        background: transparent;
        height: auto;
        padding: 0 1;
    }

    #filter-indicators {
        dock: bottom;
        height: 2;
        display: none;
        padding: 0 1 1 1;
        background: transparent;
        color: $text;
    }

    #filter-indicators.visible {
        display: block;
    }

    /* ── Tab 2: Stats ── */
    #stats-view {
        height: 1fr;
        padding: 1 2;
    }

    #stats-summary {
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
        border: solid #5fafff;
    }

    #stats-daily-tokens {
        height: 1fr;
        padding: 0 1;
        overflow-y: auto;
        border: solid #5fafff;
    }

    /* ── Tab 3: Instances ── */
    #instances-view {
        height: 1fr;
        padding: 1 2;
    }

    #instances-header-bar {
        height: auto;
        padding: 0 1;
        margin: 0 0 1 0;
    }

    #instances-table {
        height: 1fr;
        background: transparent;
        border: solid #444444;
        padding: 0 1;
        overflow-y: auto;
    }

    #instances-footer {
        height: auto;
        padding: 0 1;
        margin: 1 0 0 0;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "switch_tab('tab-live')", "Live", show=False),
        Binding("2", "switch_tab('tab-stats')", "Stats", show=False),
        Binding("3", "switch_tab('tab-instances')", "Instances", show=False),
        Binding("slash", "toggle_filter", "Filter", show=True, key_display="/"),
        Binding("p", "cycle_project", "Project", show=True),
        Binding("e", "cycle_event_type", "Event", show=True),
        Binding("c", "toggle_compact", "Compact", show=True),
        Binding("t", "cycle_time_range", "Time", show=True),
        Binding("n", "next_page", "Next Page", show=True),
        Binding("escape", "clear_filters", "Clear", show=True),
        Binding("j", "scroll_down", "Down", show=False),
        Binding("k", "scroll_up", "Up", show=False),
        Binding("G", "scroll_end", "End", show=False),
        Binding("g", "scroll_home", "Home", show=False),
    ]

    # Reactive state
    text_filter: reactive[str] = reactive("", layout=False)
    project_filter: reactive[str] = reactive("", layout=False)
    event_type_filter: reactive[str] = reactive("", layout=False)
    compact_mode: reactive[bool] = reactive(False, layout=False)
    live_tail: reactive[bool] = reactive(True, layout=False)

    def __init__(self):
        super().__init__()
        self.tailer = LogTailer(LOG_FILE)
        self.scanner = ProcessScanner()
        self._project_colors: dict[str, str] = {}
        self._projects: list[str] = []
        self._event_types = list(EVENT_TYPE_MAP.keys())
        self._project_idx = 0  # 0 = All
        self._event_type_idx = 0  # 0 = All
        self._filter_debounce_timer: Timer | None = None
        self._stats_cache: dict = {}
        self._active_tab: str = "tab-live"
        self._spinner_idx: int = 0
        self._stats_time_range: str = "Today"
        self._time_range_options: list[str] = ["Today", "7d", "All"]
        self._daily_tokens_page: int = 0
        # Sidebar cache — avoid recomputing on every 0.5s tick
        self._sidebar_entry_count: int = 0
        self._sidebar_scan_gen: int = 0  # bumped each process scan
        self._cached_event_counts: dict = {}
        self._cached_sessions: list[SessionNode] = []

    def compose(self) -> ComposeResult:
        yield Static("", id="header-bar")
        with TabbedContent(id="tabs"):
            # Tab 1: Live log + sidebar
            with TabPane("1.Live", id="tab-live"):
                with Horizontal(id="main-content"):
                    with Vertical(id="log-pane"):
                        yield RichLog(id="event-log", highlight=False, markup=False, wrap=False, max_lines=5000)
                        yield Input(placeholder="Filter logs (fuzzy)...", id="filter-input")
                    with Vertical(id="sidebar"):
                        yield Static("", id="stats-panel")
                        yield Static("", id="token-panel")
                        with Vertical(id="instances-panel"):
                            yield Static("", id="instances-panel-header")
                            yield Static("", id="instances-panel-body")
                yield Static("", id="filter-indicators")
            # Tab 2: Stats
            with TabPane("2.Stats", id="tab-stats"):
                with Vertical(id="stats-view"):
                    yield Static("", id="stats-summary")
                    yield Static("", id="stats-daily-tokens")
            # Tab 3: Instances
            with TabPane("3.Instances", id="tab-instances"):
                with Vertical(id="instances-view"):
                    yield Static("", id="instances-header-bar")
                    yield Static("", id="instances-table")
                    yield Static("", id="instances-footer")
        yield Footer()

    def on_mount(self) -> None:
        self.tailer.load_existing()
        self.scanner.scan()
        self._discover_projects()
        self._rebuild_log()
        self._update_sidebar()
        self._update_header()

        self._stats_cache = load_stats_cache()
        self._refresh_stats_tab()
        self._refresh_instances_tab()

        self.query_one("#event-log", RichLog).focus()

        # Timers: poll + sidebar at 0.5s, header at 1s, processes at 3s, stats cache at 30s
        self.set_interval(0.5, self._poll_new_entries)
        self.set_interval(0.5, self._update_sidebar)
        self.set_interval(1.0, self._update_header)
        self.set_interval(3.0, self._poll_processes)
        self.set_interval(30.0, self._reload_stats_cache)

    # ─── Tab switching ─────────────────────────────────────────────────────

    def action_switch_tab(self, tab_id: str) -> None:
        """Switch to a specific tab by ID."""
        tabs = self.query_one("#tabs", TabbedContent)
        tabs.active = tab_id
        self._active_tab = tab_id
        if tab_id == "tab-stats":
            self._refresh_stats_tab()
        elif tab_id == "tab-instances":
            self._refresh_instances_tab()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Track active tab when user clicks tab headers."""
        self._active_tab = event.pane.id or ""
        if self._active_tab == "tab-stats":
            self._refresh_stats_tab()
        elif self._active_tab == "tab-instances":
            self._refresh_instances_tab()

    def _is_live_tab(self) -> bool:
        return self._active_tab == "tab-live"

    def _is_stats_tab(self) -> bool:
        return self._active_tab == "tab-stats"

    # ─── Header ───────────────────────────────────────────────────────────

    def _update_header(self) -> None:
        now = datetime.now().strftime("%I:%M %p")
        total = len(self.scanner.instances)
        active = self.scanner.active_count
        mem = self.scanner.total_mem_mb
        mem_str = f"{mem / 1024:.1f}GB" if mem >= 1024 else f"{mem:.0f}MB"
        header = self.query_one("#header-bar", Static)
        header.update(
            f" 🟢 Claude Dashboard  │  {total} instances ({active} active)  │  {mem_str} RAM  │  {now}"
        )

    # ─── Polling ──────────────────────────────────────────────────────────

    def _poll_new_entries(self) -> None:
        new_entries = self.tailer.poll()
        if not new_entries:
            return

        self._discover_projects()

        if not self._has_active_filters() and not self.compact_mode:
            log_widget = self.query_one("#event-log", RichLog)
            for entry in new_entries:
                self._write_entry(log_widget, entry)
            if self.live_tail:
                log_widget.scroll_end(animate=False)
        else:
            self._rebuild_log()

    def _has_active_filters(self) -> bool:
        return bool(self.text_filter or self.project_filter or self.event_type_filter or self._stats_time_range != "All")

    # ─── Log rendering ────────────────────────────────────────────────────

    def _rebuild_log(self) -> None:
        """Full rebuild of the log display with current filters."""
        log_widget = self.query_one("#event-log", RichLog)
        log_widget.clear()

        entries = self._filter_entries_by_time(self.tailer.all_entries)
        filtered = [
            e for e in entries
            if e.matches_filter(self.text_filter, self.project_filter, self.event_type_filter)
        ]

        if self.compact_mode:
            filtered = self._compact_entries(filtered)

        prev_entry = None
        for entry in filtered:
            if isinstance(entry, LogEntry) and "🟢" in entry.event and "Session started" in entry.event:
                if prev_entry is not None:
                    sep = Text("─" * 60, style="dim")
                    log_widget.write(sep)
            self._write_entry(log_widget, entry)
            prev_entry = entry

        if self.live_tail:
            log_widget.scroll_end(animate=False)

        self._update_filter_indicators()

    def _build_entry_prefix(self, entry: LogEntry) -> Text:
        """Build the shared timestamp | project | branch prefix for a log line."""
        text = Text()
        text.append(entry.timestamp, style="dim")
        if entry.project:
            color = _project_color(entry.project, self._project_colors)
            text.append(" │ ", style="dim")
            text.append(entry.project, style=color)
            text.append(" │ ", style="dim")
            text.append(entry.branch or "-", style="dim")
        text.append(" │ ", style="dim")
        return text

    def _write_entry(self, log_widget: RichLog, entry) -> None:
        """Write a single LogEntry (or compact group) to the log widget."""
        if isinstance(entry, dict):
            sample = entry["sample"]
            count = entry["count"]
            text = self._build_entry_prefix(sample)
            text.append(f"{sample.emoji} ", style=sample.style)
            base = sample.event
            if sample.emoji:
                base = base.replace(sample.emoji, "").strip()
            if ":" in base:
                base = base.split(":")[0].strip()
            text.append(f"{base} (x{count})", style=sample.style)
            log_widget.write(text)
        else:
            text = self._build_entry_prefix(entry)
            display_event = entry.event.replace("📋 Task created", "📋 Todo created").replace("📋 Task completed", "📋 Todo completed")
            # Shorten model IDs in session started lines: [claude-opus-4-6] → [Opus 4.6]
            m = re.search(r"\[(claude-[^\]]+)\]", display_event)
            if m:
                display_event = display_event.replace(m.group(0), f"[{format_model_name(m.group(1))}]")
            text.append(display_event, style=entry.style)
            log_widget.write(text)

    def _compact_entries(self, entries: list[LogEntry]) -> list:
        """Collapse consecutive same-type events."""
        if not entries:
            return []
        result = []
        run_emoji = entries[0].emoji
        run_project = entries[0].project
        run_entries = [entries[0]]

        for entry in entries[1:]:
            if entry.emoji == run_emoji and entry.project == run_project and run_emoji:
                run_entries.append(entry)
            else:
                if len(run_entries) > 1:
                    result.append({"sample": run_entries[0], "count": len(run_entries)})
                else:
                    result.append(run_entries[0])
                run_emoji = entry.emoji
                run_project = entry.project
                run_entries = [entry]

        if len(run_entries) > 1:
            result.append({"sample": run_entries[0], "count": len(run_entries)})
        else:
            result.append(run_entries[0])

        return result

    # ─── Sidebar ──────────────────────────────────────────────────────────

    def _filter_entries_by_time(self, entries: list[LogEntry]) -> list[LogEntry]:
        """Filter log entries by the current time range selection (Today, 7d, or All)."""
        rng = self._stats_time_range
        if rng == "All":
            return entries

        now = datetime.now()
        if rng == "Today":
            valid_dates = {now.strftime("%m/%d")}
        elif rng == "7d":
            valid_dates = {(now - timedelta(days=i)).strftime("%m/%d") for i in range(7)}
        else:
            return entries

        filtered = []
        for entry in entries:
            ts = entry.timestamp.strip()
            m = re.match(r"(\d{2}/\d{2})", ts)
            if m and m.group(1) in valid_dates:
                filtered.append(entry)
        return filtered

    def _update_sidebar(self) -> None:
        """Update all sidebar panels. Also increments spinner for instances."""
        self._spinner_idx = (self._spinner_idx + 1) % len(BRAILLE_SPINNER)

        # Only recompute expensive data when entries or processes change
        entry_count = len(self.tailer.all_entries)
        scan_gen = self.scanner.generation
        data_changed = (
            entry_count != self._sidebar_entry_count
            or scan_gen != self._sidebar_scan_gen
        )

        if data_changed:
            self._sidebar_entry_count = entry_count
            self._sidebar_scan_gen = scan_gen
            filtered_entries = self._filter_entries_by_time(self.tailer.all_entries)
            raw_lines = [e.raw for e in filtered_entries]
            self._cached_event_counts = count_events(raw_lines)
            self._cached_sessions = build_agent_tree(self.tailer.all_entries)
            self._update_stats_panel(self._cached_event_counts)
            self._update_token_panel()

        # Instances panel always re-renders (cheap) for spinner animation
        self._update_instances_panel()

    def _update_stats_panel(self, counts: dict) -> None:
        table = Table(
            show_header=False, show_edge=False, box=None, padding=(0, 1),
            title="[bold]📊 Stats[/]", title_style="bold",
            expand=True,
        )
        table.add_column(style="bold", width=12)
        table.add_column(justify="right")

        table.add_row("🔧 Tool use", str(counts["tools"]))
        table.add_row("📖 Read", str(counts["reads"]))
        table.add_row("🔍 Search", str(counts["searches"]))
        table.add_row("🌐 Fetch", str(counts["fetches"]))
        table.add_row("🔌 MCP call", str(counts["mcp"]))
        table.add_row("⚡ Skill use", str(counts["skills"]))
        table.add_row("🚀 Agent spawn", str(counts["agents"]))
        table.add_row("🤖 Agent task", str(counts["subagents"]))
        table.add_row("🛬 Agent finished", str(counts["landed"]))
        table.add_row("🏁 Finished responding", str(counts["finished"]))
        table.add_row("📐 Plan mode", str(counts["plans"]))
        table.add_row("📋 Todo created", str(counts["tasks"]))
        table.add_row("🟢 Session start", str(counts["sessions"]))
        table.add_row("🔴 Session end", str(counts["ended"]))
        table.add_row("👋 Wants input", str(counts["input"]))
        table.add_row("🔐 Need permission", str(counts["permission"]))
        table.add_row("❓ Ask question", str(counts["questions"]))
        table.add_row("✅ Todo complete", str(counts["completed"]))
        table.add_row("⚠️  Compact", str(counts["compacts"]))
        table.add_row("", "")
        total = sum(counts.values())
        table.add_row("[bold]Total[/]", f"[bold]{total}[/]")

        self.query_one("#stats-panel", Static).update(table)

    def _get_daily_token_dates(self) -> set[str] | None:
        """Return the set of YYYY-MM-DD dates for the current time range, or None for All."""
        rng = self._stats_time_range
        if rng == "All":
            return None
        now = datetime.now()
        if rng == "Today":
            return {now.strftime("%Y-%m-%d")}
        elif rng == "7d":
            return {(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)}
        return None

    def _update_token_panel(self) -> None:
        """Token panel — shows per-model tokens for the selected time range."""
        rng = self._stats_time_range
        title_label = TIME_RANGE_LABELS.get(rng, rng)
        table = Table(
            show_header=False, show_edge=False, box=None, padding=(0, 1),
            title=f"[bold]🪙 Tokens ({title_label})[/]", title_style="bold",
            expand=True,
        )
        table.add_column(style="bold", width=16)
        table.add_column(justify="right")

        date_filter = self._get_daily_token_dates()

        if date_filter is None:
            # All Time — use modelUsage for full breakdown with cache ratios
            model_usage = self._stats_cache.get("modelUsage", {})
            if model_usage:
                table.add_row("", "")
                for model_id, usage in sorted(model_usage.items(), key=lambda x: -(
                    x[1].get("inputTokens", 0) + x[1].get("outputTokens", 0)
                    + x[1].get("cacheReadInputTokens", 0) + x[1].get("cacheCreationInputTokens", 0)
                )):
                    name = format_model_name(model_id)
                    inp = usage.get("inputTokens", 0)
                    out = usage.get("outputTokens", 0)
                    cache_read = usage.get("cacheReadInputTokens", 0)
                    cache_write = usage.get("cacheCreationInputTokens", 0)
                    total = inp + out + cache_read + cache_write
                    if out > 0:
                        cache_ratio = cache_read / out
                        table.add_row(f"🧠 {name}", f"{_format_tokens(total)} [dim](cache {cache_ratio:.0f}x)[/]")
                    else:
                        table.add_row(f"🧠 {name}", _format_tokens(total))
                grand_total = sum(
                    u.get("inputTokens", 0) + u.get("outputTokens", 0)
                    + u.get("cacheReadInputTokens", 0) + u.get("cacheCreationInputTokens", 0)
                    for u in model_usage.values()
                )
                table.add_row("", "")
                table.add_row("[bold]Total[/]", f"[bold]{_format_tokens(grand_total)}[/]")
            else:
                table.add_row("[dim]Waiting...[/]", "")
        else:
            # Today / 7d — aggregate dailyModelTokens + live model-stats
            daily_model = self._stats_cache.get("dailyModelTokens", [])
            today_str = datetime.now().strftime("%Y-%m-%d")

            # Aggregate cached daily data for the date range
            model_totals: dict[str, int] = {}
            for day in daily_model:
                if day.get("date", "") in date_filter:
                    for model_id, tokens in day.get("tokensByModel", {}).items():
                        model_totals[model_id] = model_totals.get(model_id, 0) + tokens

            # If today is in the range and cache is stale, add live model-stats
            live_models = []
            if today_str in date_filter and self._is_cache_stale_for_today():
                live_models = read_model_stats()
                for m in live_models:
                    mid = m["model"]
                    model_totals[mid] = model_totals.get(mid, 0) + m["total"]

            if model_totals:
                table.add_row("", "")
                for model_id, total in sorted(model_totals.items(), key=lambda x: -x[1]):
                    name = format_model_name(model_id)
                    table.add_row(f"🧠 {name}", _format_tokens(total))
                grand_total = sum(model_totals.values())
                table.add_row("", "")
                table.add_row("[bold]Total[/]", f"[bold]{_format_tokens(grand_total)}[/]")
            else:
                table.add_row("[dim]No data[/]", "")

        self.query_one("#token-panel", Static).update(table)

    def _update_instances_panel(self) -> None:
        """Sidebar: clean list of instances — just status icon + project name.

        Shows all unique projects (deduped), active first.
        Subagents shown inline for active instances.
        """
        instances = self.scanner.instances
        total = len(instances)
        active = self.scanner.active_count

        header_text = Text()
        header_text.append(f"🖥️  Instances ", style="bold")
        header_text.append(f"({total}", style="bold")
        if active > 0:
            header_text.append(f", {active} active", style="bold #87d787")
        header_text.append(")", style="bold")
        self.query_one("#instances-panel-header", Static).update(header_text)

        if not instances:
            self.query_one("#instances-panel-body", Static).update(
                Text("  No Claude instances detected", style="dim")
            )
            return

        spinner = BRAILLE_SPINNER[self._spinner_idx % len(BRAILLE_SPINNER)]

        # Use cached sessions for enrichment (subagents)
        session_map = _build_active_session_map(self._cached_sessions)

        # Deduplicate: one entry per project, keep most active
        by_project: dict[str, ProcessInstance] = {}
        for inst in instances:
            key = inst.project_name.lower()
            prev = by_project.get(key)
            if prev is None or inst.cpu_percent > prev.cpu_percent:
                by_project[key] = inst

        sorted_instances = sorted(
            by_project.values(),
            key=lambda x: (-x.is_active, -x.cpu_percent, x.project_name.lower()),
        )

        text = Text()
        max_sidebar = 30
        shown = 0
        total_to_show = min(len(sorted_instances), max_sidebar)

        for idx, inst in enumerate(sorted_instances):
            if shown >= max_sidebar:
                remaining = len(sorted_instances) - shown
                text.append("  ⋮ +", style="dim")
                text.append(f"{remaining} more\n", style="dim")
                break

            is_last_inst = (idx == total_to_show - 1)
            branch = "└── " if is_last_inst else "├── "
            continuation = "    " if is_last_inst else "│   "

            color = _project_color(inst.project_name, self._project_colors)
            name = inst.project_name[:20]

            # Match with event log for subagents
            norm_key = _normalize_project_key(inst.project_name)
            session = session_map.get(norm_key)
            running_agents = []
            if session:
                running_agents = [a for a in session.agents if a.is_running]

            # Branch + status icon + name
            text.append(f"  {branch}", style="dim #555555")
            if inst.is_active:
                text.append(f"🟢 {name}", style=f"bold {color}")
            else:
                text.append(f"🟡 {name}", style=color)
            text.append("\n")

            # Show running shell command with actual command name
            if inst.has_shell:
                cmd_label = inst.shell_command or "running command"
                has_more = len(running_agents) > 0
                child_branch = "├── " if has_more else "└── "
                text.append(f"  {continuation}{child_branch}", style="dim #555555")
                text.append(f"{spinner} ", style="bold #d7af5f")
                text.append(cmd_label, style="#d7af5f")
                text.append("\n")

            # Show running subagents from event log
            for i, agent in enumerate(running_agents):
                is_last = (i == len(running_agents) - 1)
                self._render_agent_text(text, agent, spinner, is_last=is_last, prefix=f"  {continuation}")

            shown += 1

        self.query_one("#instances-panel-body", Static).update(text)

    def _render_agent_text(self, text: Text, agent: AgentNode, spinner: str, is_last: bool, prefix: str) -> None:
        """Render a running agent node with ASCII tree branching."""
        branch = "└── " if is_last else "├── "
        text.append(prefix, style="dim #555555")
        text.append(branch, style="dim #555555")

        atype = agent.agent_type[:14]
        color = "#2e8b57" if atype == "Plan" else "#5fd7d7"
        text.append(f"{spinner} ", style=f"bold {color}")
        text.append(atype, style=f"bold {color}")
        text.append("\n")

        running_children = [c for c in agent.children if c.is_running]
        child_prefix = prefix + ("    " if is_last else "│   ")
        for i, child in enumerate(running_children):
            child_is_last = (i == len(running_children) - 1)
            self._render_agent_text(text, child, spinner, is_last=child_is_last, prefix=child_prefix)

    # ─── Process polling ──────────────────────────────────────────────────

    def _poll_processes(self) -> None:
        """Rescan running Claude processes."""
        self.scanner.scan()
        if self._is_instances_tab():
            self._refresh_instances_tab()

    def _is_instances_tab(self) -> bool:
        return self._active_tab == "tab-instances"

    def _refresh_instances_tab(self) -> None:
        """Full render of the Instances tab table with child process info."""
        instances = self.scanner.instances
        total = len(instances)
        active = self.scanner.active_count
        mem = self.scanner.total_mem_mb

        # Header bar
        header = Text()
        header.append("  🖥️  Running Claude Instances ", style="bold")
        header.append(f"({total})", style="bold")
        if active > 0:
            header.append(f"  •  {active} active", style="bold #87d787")
        self.query_one("#instances-header-bar", Static).update(header)

        if not instances:
            self.query_one("#instances-table", Static).update(
                Text("  No Claude instances detected.\n  Start Claude in a terminal to see it here.", style="dim")
            )
            self.query_one("#instances-footer", Static).update("")
            return

        # Build session map for enrichment
        sessions = build_agent_tree(self.tailer.all_entries)
        session_map = _build_active_session_map(sessions)

        spinner = BRAILLE_SPINNER[self._spinner_idx % len(BRAILLE_SPINNER)]

        # Build Rich Table
        table = Table(
            show_header=True, show_edge=False, box=None, padding=(0, 1),
            expand=True,
        )
        table.add_column("", width=2)  # status icon
        table.add_column("Project", style="bold", min_width=14, max_width=20)
        table.add_column("CPU", justify="right", width=6)
        table.add_column("Mem", justify="right", width=6)
        table.add_column("Uptime", justify="right", width=7)
        table.add_column("Ver", width=6)
        table.add_column("Info", min_width=12, max_width=20)
        table.add_column("Directory", style="dim", ratio=1)

        for inst in instances:
            color = _project_color(inst.project_name, self._project_colors)

            # Status
            status = Text("🟢" if inst.is_active else "🟡")

            # Project name
            proj = Text(inst.project_name[:20], style=f"bold {color}")

            # CPU
            cpu_val = f"{inst.cpu_percent:.1f}%"
            if inst.cpu_percent > 30:
                cpu = Text(cpu_val, style="bold #ff5f5f")
            elif inst.is_active:
                cpu = Text(cpu_val, style="bold #87d787")
            else:
                cpu = Text(cpu_val, style="dim")

            # Mem
            mem_text = Text(f"{inst.mem_mb:.0f}MB", style="dim")

            # Uptime
            uptime = Text(inst.uptime_display, style="dim")

            # Version
            ver = Text(inst.claude_version or "-", style="dim")

            # Info column: MCP count, shell, caffeinate badges
            info = Text()
            if inst.mcp_server_count > 0:
                info.append(f"{inst.mcp_server_count} MCP", style="#af87ff")
            if inst.has_shell:
                if len(info) > 0:
                    info.append("  ", style="")
                cmd_label = inst.shell_command or "cmd"
                info.append(f"{spinner} {cmd_label}", style="bold #d7af5f")
            if inst.has_caffeinate:
                if len(info) > 0:
                    info.append("  ", style="")
                info.append("☕", style="#87d787")

            # Match with event log for model info
            norm_key = _normalize_project_key(inst.project_name)
            session = session_map.get(norm_key)
            if session and session.model:
                if len(info) > 0:
                    info.append("  ", style="")
                info.append(format_model_name(session.model), style="dim")

            # Directory (shortened)
            cwd = inst.cwd.replace(str(Path.home()), "~")
            dir_text = Text(cwd, style="dim")

            table.add_row(status, proj, cpu, mem_text, uptime, ver, info, dir_text)

            # Show running subagents as indented sub-rows
            if session:
                running_agents = [a for a in session.agents if a.is_running]
                for agent in running_agents:
                    atype = agent.agent_type[:14]
                    color = "#2e8b57" if atype == "Plan" else "#5fd7d7"
                    agent_text = Text()
                    agent_text.append(f"  {spinner} ", style=f"bold {color}")
                    agent_text.append(atype, style=color)
                    empty = Text("")
                    table.add_row(empty, agent_text, empty, empty, empty, empty, empty, empty)

        self.query_one("#instances-table", Static).update(table)

        # Footer
        mem_str = f"{mem / 1024:.1f}GB" if mem >= 1024 else f"{mem:.0f}MB"
        footer = Text()
        footer.append(f"  Total: {mem_str} RAM across {total} instances", style="dim")
        self.query_one("#instances-footer", Static).update(footer)

    # ─── Project discovery ────────────────────────────────────────────────

    def _discover_projects(self) -> None:
        seen = set()
        for entry in self.tailer.all_entries:
            if entry.project:
                seen.add(entry.project)
        self._projects = sorted(seen)

    # ─── Filter indicators ────────────────────────────────────────────────

    def _build_time_label(self) -> str:
        """Build descriptive time range label for the filter bar."""
        rng = self._stats_time_range
        if rng == "Today":
            today_mmdd = datetime.now().strftime("%m/%d")
            first_time = ""
            for entry in self.tailer.all_entries:
                if "🟢" in entry.event and "Session started" in entry.event:
                    if entry.timestamp.strip().startswith(today_mmdd):
                        first_time = entry.timestamp.strip()
                        break
            return f"Today since {first_time}" if first_time else "Today"
        elif rng == "7d":
            start = (datetime.now() - timedelta(days=6)).strftime("%m/%d")
            end = datetime.now().strftime("%m/%d")
            return f"7d ({start}–{end})"
        elif rng == "All":
            first_date = self._stats_cache.get("firstSessionDate", "")
            if first_date:
                try:
                    dt = datetime.fromisoformat(first_date.replace("Z", "+00:00"))
                    return f"All time since {dt.strftime('%b %d, %Y')}"
                except Exception:
                    pass
            return "All time"
        return rng

    def _update_filter_indicators(self) -> None:
        filters = []
        if self.project_filter:
            filters.append(f"project:{self.project_filter}")
        if self.event_type_filter:
            filters.append(f"event:{self.event_type_filter}")
        if self.text_filter:
            filters.append(f"text:\"{self.text_filter}\"")
        if self.compact_mode:
            filters.append("compact:on")

        time_label = self._build_time_label()
        indicator = self.query_one("#filter-indicators", Static)

        if filters:
            right = "  ".join(filters)
            indicator.update(f"{time_label}  │  {right}  (t)")
        else:
            indicator.update(f"{time_label}  (t)")
        indicator.add_class("visible")

    # ─── Tab 2: Stats ────────────────────────────────────────────────────

    def _reload_stats_cache(self) -> None:
        self._stats_cache = load_stats_cache()
        if self._is_stats_tab():
            self._refresh_stats_tab()

    def _count_live_today_activity(self) -> tuple[int, int]:
        """Count today's sessions and messages from the live event log.

        Returns (sessions, messages) for entries matching today's date.
        """
        live_entries = self._filter_entries_by_time(self.tailer.all_entries)
        today_mmdd = datetime.now().strftime("%m/%d")
        sessions = 0
        messages = 0
        for entry in live_entries:
            ts = entry.timestamp.strip()
            if not re.match(r"\d{2}/\d{2}", ts) or not ts.startswith(today_mmdd):
                continue
            if "🟢" in entry.event and "Session started" in entry.event:
                sessions += 1
            if "🏁" in entry.event:
                messages += 1
        return sessions, messages

    def _is_cache_stale_for_today(self) -> bool:
        """Check if the stats cache is missing today's data."""
        today_str = datetime.now().strftime("%Y-%m-%d")
        return self._stats_cache.get("lastComputedDate", "") != today_str

    def _refresh_stats_tab(self) -> None:
        data = self._stats_cache
        if not data:
            return
        self._update_stats_summary(data)
        self._update_daily_tokens_table(data)

    def _filter_daily_by_range(self, daily: list[dict]) -> list[dict]:
        """Filter daily data by the current time range selection."""
        if not daily:
            return daily
        valid = self._get_daily_token_dates()
        if valid is None:
            return daily
        return [d for d in daily if d.get("date", "") in valid]

    def _update_stats_summary(self, data: dict) -> None:
        """Stats summary — respects time range filter."""
        rng = self._stats_time_range
        title_label = TIME_RANGE_LABELS.get(rng, rng)
        daily = self._filter_daily_by_range(data.get("dailyActivity", []))

        if rng == "All":
            sessions = data.get("totalSessions", 0)
            messages = data.get("totalMessages", 0)
            days_active = len(daily)
        else:
            sessions = sum(d.get("sessionCount", 0) for d in daily)
            messages = sum(d.get("messageCount", 0) for d in daily)
            days_active = len(daily)

            # Supplement with live event log if cache is stale for today
            if self._is_cache_stale_for_today():
                live_sessions, live_messages = self._count_live_today_activity()
                sessions += live_sessions
                messages += live_messages
                if days_active == 0 and (live_sessions > 0 or live_messages > 0):
                    days_active = 1

        first_date = data.get("firstSessionDate", "")

        box = Text()
        box.append(f"  Claude Code Stats ({title_label})\n", style="bold #5fafff")
        box.append(f"  {sessions:,} sessions", style="bold")
        box.append("  |  ", style="dim")
        box.append(f"{messages:,} messages", style="bold")
        if days_active > 0 and rng != "All":
            avg_msgs = messages // days_active
            box.append("  |  ", style="dim")
            box.append(f"Avg {avg_msgs:,} msgs/day", style="dim")
        if days_active > 1:
            box.append("  |  ", style="dim")
            box.append(f"{days_active} days active", style="bold")
        box.append("\n")

        if rng == "All" and first_date:
            try:
                dt = datetime.fromisoformat(first_date.replace("Z", "+00:00"))
                since = dt.strftime("%b %d, %Y")
            except Exception:
                since = first_date[:10]
            avg_msgs = messages // days_active if days_active else 0
            box.append(f"  Since {since}", style="dim")
            box.append("  |  ", style="dim")
            box.append(f"Avg {avg_msgs:,} msgs/day", style="dim")
            longest = data.get("longestSession", {})
            if longest:
                longest_msgs = longest.get("messageCount", 0) if isinstance(longest, dict) else longest
                if isinstance(longest_msgs, int) and longest_msgs > 0:
                    box.append("  |  ", style="dim")
                    box.append(f"Longest session: {longest_msgs} msgs", style="dim")

        self.query_one("#stats-summary", Static).update(box)

    def _update_daily_tokens_table(self, data: dict) -> None:
        """Last 30 days of token usage per model."""
        daily_model = data.get("dailyModelTokens", [])
        daily_activity = data.get("dailyActivity", [])
        # Check if live data might be available even if cache is empty
        has_live = self._is_cache_stale_for_today() and read_model_stats()
        if not daily_model and not has_live:
            self.query_one("#stats-daily-tokens", Static).update(
                Text("  No daily token data available", style="dim")
            )
            return

        # Build activity lookup for messages/sessions
        activity_map: dict[str, dict] = {}
        for d in daily_activity:
            activity_map[d.get("date", "")] = d

        # Collect all models seen across all days
        all_models: set[str] = set()
        for day in daily_model:
            all_models.update(day.get("tokensByModel", {}).keys())
        model_list = sorted(all_models)

        # Filter by current time range
        rng = self._stats_time_range
        title_label = TIME_RANGE_LABELS.get(rng, rng)
        filtered = self._filter_daily_by_range(daily_model)

        # Supplement with live data for today if cache is stale
        today_str = datetime.now().strftime("%Y-%m-%d")
        date_filter = self._get_daily_token_dates()
        if date_filter is None or today_str in date_filter:
            if self._is_cache_stale_for_today():
                live_models = read_model_stats()
                if live_models:
                    # Find or create today's entry
                    today_entry = None
                    for d in filtered:
                        if d.get("date") == today_str:
                            today_entry = d
                            break
                    if today_entry is None:
                        today_entry = {"date": today_str, "tokensByModel": {}}
                        filtered.append(today_entry)
                    for m in live_models:
                        mid = m["model"]
                        today_entry["tokensByModel"][mid] = today_entry["tokensByModel"].get(mid, 0) + m["total"]
                        all_models.add(mid)
                    model_list = sorted(all_models)

                # Also add live activity data for today
                live_sessions, live_messages = self._count_live_today_activity()
                if live_sessions > 0 or live_messages > 0:
                    act = activity_map.get(today_str, {})
                    act["messageCount"] = act.get("messageCount", 0) + live_messages
                    act["sessionCount"] = act.get("sessionCount", 0) + live_sessions
                    act["date"] = today_str
                    activity_map[today_str] = act

        filtered.sort(key=lambda d: d.get("date", ""), reverse=True)

        table = Table(
            show_header=True, show_edge=False, box=None, padding=(0, 1),
            title=f"[bold]🪙 Daily Token Usage ({title_label})[/]", title_style="bold",
            expand=True,
        )
        table.add_column("Date", style="dim", width=12)
        for mid in model_list:
            table.add_column(format_model_name(mid), justify="right", min_width=10)
        table.add_column("Total", justify="right", style="bold", min_width=10)
        table.add_column("Msgs", justify="right", style="dim", width=7)
        table.add_column("Sessions", justify="right", style="dim", width=8)

        # Paginate: show 30 days at a time, navigable with 'n' key
        page_size = 30
        total_days = len(filtered)
        total_pages = max(1, (total_days + page_size - 1) // page_size)
        # Clamp page index
        if self._daily_tokens_page >= total_pages:
            self._daily_tokens_page = 0
        page_start = self._daily_tokens_page * page_size
        display = filtered[page_start:page_start + page_size]

        for day in display:
            date_str = day.get("date", "")
            tokens_by_model = day.get("tokensByModel", {})

            # Format date as Mon MM/DD
            try:
                dt = datetime.strptime(date_str, "%Y-%m-%d")
                display_date = dt.strftime("%a %m/%d")
            except ValueError:
                display_date = date_str

            row = [display_date]
            day_total = 0
            for mid in model_list:
                t = tokens_by_model.get(mid, 0)
                day_total += t
                row.append(_format_tokens(t) if t > 0 else "—")
            row.append(_format_tokens(day_total))

            # Add activity data
            act = activity_map.get(date_str, {})
            msgs = act.get("messageCount", 0)
            sess = act.get("sessionCount", 0)
            row.append(f"{msgs:,}" if msgs else "—")
            row.append(str(sess) if sess else "—")

            table.add_row(*row)

        # Totals row (over displayed page)
        totals = ["[bold]Total[/]"]
        grand = 0
        for mid in model_list:
            model_sum = sum(d.get("tokensByModel", {}).get(mid, 0) for d in display)
            grand += model_sum
            totals.append(f"[bold]{_format_tokens(model_sum)}[/]")
        totals.append(f"[bold]{_format_tokens(grand)}[/]")
        total_msgs = sum(activity_map.get(d.get("date", ""), {}).get("messageCount", 0) for d in display)
        total_sess = sum(activity_map.get(d.get("date", ""), {}).get("sessionCount", 0) for d in display)
        totals.append(f"[bold]{total_msgs:,}[/]")
        totals.append(f"[bold]{total_sess}[/]")
        table.add_row(*totals)

        if total_pages > 1:
            page_num = self._daily_tokens_page + 1
            hint = f"[dim]  Page {page_num}/{total_pages} ({total_days} days) — press [bold]n[/bold] for next page[/]"
            table.add_row(*[""] * (len(model_list) + 4))
            empty = [""] * (len(model_list) + 3)
            table.add_row(hint, *empty)

        self.query_one("#stats-daily-tokens", Static).update(table)

    # ─── Actions ──────────────────────────────────────────────────────────

    def action_cycle_time_range(self) -> None:
        """Cycle time range globally: Today → 7d → All."""
        idx = self._time_range_options.index(self._stats_time_range)
        idx = (idx + 1) % len(self._time_range_options)
        self._stats_time_range = self._time_range_options[idx]
        self._daily_tokens_page = 0  # Reset page on time range change
        self._rebuild_log()
        self._update_sidebar()
        if self._is_stats_tab():
            self._refresh_stats_tab()

    def action_next_page(self) -> None:
        """Cycle to next page of daily token table (Stats tab)."""
        if not self._is_stats_tab():
            return
        self._daily_tokens_page += 1  # Will wrap in _update_daily_tokens_table
        self._refresh_stats_tab()

    def action_toggle_filter(self) -> None:
        """Show/hide the filter input (Tab 1 only)."""
        if not self._is_live_tab():
            return
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            filter_input.remove_class("visible")
            filter_input.value = ""
            self.text_filter = ""
            self.query_one("#event-log", RichLog).focus()
        else:
            filter_input.add_class("visible")
            filter_input.focus()

    def action_cycle_project(self) -> None:
        """Cycle project filter: All → proj1 → proj2 → ... → All (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        if not self._projects:
            return
        self._project_idx = (self._project_idx + 1) % (len(self._projects) + 1)
        if self._project_idx == 0:
            self.project_filter = ""
        else:
            self.project_filter = self._projects[self._project_idx - 1]
        self._rebuild_log()

    def action_cycle_event_type(self) -> None:
        """Cycle event type filter: All → tools → reads → ... → All (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self._event_type_idx = (self._event_type_idx + 1) % (len(self._event_types) + 1)
        if self._event_type_idx == 0:
            self.event_type_filter = ""
        else:
            self.event_type_filter = self._event_types[self._event_type_idx - 1]
        self._rebuild_log()

    def action_toggle_compact(self) -> None:
        """Toggle compact mode (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self.compact_mode = not self.compact_mode
        self._rebuild_log()

    def action_clear_filters(self) -> None:
        """Clear all filters and close filter input (Tab 1 only)."""
        if not self._is_live_tab():
            return
        filter_input = self.query_one("#filter-input", Input)
        filter_input.remove_class("visible")
        filter_input.value = ""
        self.text_filter = ""
        self.project_filter = ""
        self.event_type_filter = ""
        self.compact_mode = False
        self._project_idx = 0
        self._event_type_idx = 0
        self._rebuild_log()
        self.query_one("#event-log", RichLog).focus()

    def action_scroll_down(self) -> None:
        """Scroll log down, disable live tail (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self.live_tail = False
        self.query_one("#event-log", RichLog).scroll_down(animate=False)

    def action_scroll_up(self) -> None:
        """Scroll log up, disable live tail (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self.live_tail = False
        self.query_one("#event-log", RichLog).scroll_up(animate=False)

    def action_scroll_end(self) -> None:
        """Jump to bottom, resume live tail (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self.live_tail = True
        self.query_one("#event-log", RichLog).scroll_end(animate=False)

    def action_scroll_home(self) -> None:
        """Jump to top (Tab 1 only)."""
        if not self._is_live_tab():
            return
        if self.query_one("#filter-input", Input).has_focus:
            return
        self.live_tail = False
        self.query_one("#event-log", RichLog).scroll_home(animate=False)

    # ─── Input events ─────────────────────────────────────────────────────

    def on_input_changed(self, event: Input.Changed) -> None:
        """Debounced filter on text input change."""
        if event.input.id == "filter-input":
            if self._filter_debounce_timer is not None:
                self._filter_debounce_timer.stop()
            self._filter_debounce_timer = self.set_timer(
                0.15, self._apply_text_filter
            )

    def _apply_text_filter(self) -> None:
        """Apply the text filter from the input widget."""
        value = self.query_one("#filter-input", Input).value
        self.text_filter = value
        self._rebuild_log()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """On Enter in filter input, close filter bar and keep filter active."""
        if event.input.id == "filter-input":
            self.query_one("#filter-input", Input).remove_class("visible")
            self.query_one("#event-log", RichLog).focus()


def main():
    app = ClaudeDashboardApp()
    app.run()


if __name__ == "__main__":
    main()
