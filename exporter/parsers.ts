/**
 * Parsers for Claude Code telemetry files.
 * Mirrors the Python parsing logic in dashboard.py.
 */

import { readFileSync, statSync } from "fs";
import { homedir } from "os";
import { join } from "path";

// ─── Paths ──────────────────────────────────────────────────────────────────

const CLAUDE_DIR = join(homedir(), ".claude");
export const LOG_FILE = join(CLAUDE_DIR, "events.log");
export const MODEL_FILE = join(CLAUDE_DIR, "model-stats");
export const STATS_CACHE_FILE = join(CLAUDE_DIR, "stats-cache.json");

// ─── ANSI stripping ────────────────────────────────────────────────────────

const ANSI_RE = /\033\[[0-9;]*m/g;

function stripAnsi(text: string): string {
  return text.replace(ANSI_RE, "");
}

// ─── Emoji → event_type mapping ────────────────────────────────────────────

const EMOJI_TYPE_MAP: Record<string, string> = {
  "🔧": "tool",
  "📖": "read",
  "🔍": "search",
  "🌐": "fetch",
  "🔌": "mcp",
  "⚡": "skill",
  "🚀": "agent_spawn",
  "🤖": "agent_task",
  "🛬": "agent_finish",
  "🟢": "session_start",
  "🔴": "session_end",
  "🏁": "response_finish",
  "📐": "plan",
  "👋": "input_needed",
  "🔐": "permission",
  "❓": "question",
  "✅": "completed",
  "⚠️": "compact",
  "📋": "task",
};

// Ordered for priority matching (check more specific emojis first)
const EMOJI_SEARCH_ORDER = Object.keys(EMOJI_TYPE_MAP);

// ─── Log entry type ────────────────────────────────────────────────────────

export interface LogEntry {
  timestamp: string; // raw timestamp string from log
  parsedTimestamp: Date | null; // parsed to Date for DB
  project: string;
  branch: string;
  emoji: string;
  eventType: string;
  eventText: string;
}

// ─── Timestamp parsing ─────────────────────────────────────────────────────

/**
 * Parse timestamp strings from events.log.
 * Formats: "MM/DD HH:MM AM/PM", "HH:MM AM/PM", with optional seconds and timezone.
 */
export function parseTimestamp(ts: string): Date | null {
  ts = ts.trim();
  if (!ts) return null;

  // Remove timezone abbreviations like "PST", "PDT", etc.
  ts = ts.replace(/\s+(PST|PDT|EST|EDT|CST|CDT|MST|MDT|UTC)\s*$/i, "");

  const now = new Date();
  const year = now.getFullYear();

  // Try MM/DD HH:MM:SS AM/PM
  let m = ts.match(
    /^(\d{2})\/(\d{2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)$/i
  );
  if (m) {
    const [, month, day, hourStr, min, sec, ampm] = m;
    let hour = parseInt(hourStr);
    if (ampm.toUpperCase() === "PM" && hour !== 12) hour += 12;
    if (ampm.toUpperCase() === "AM" && hour === 12) hour = 0;
    return new Date(
      year,
      parseInt(month) - 1,
      parseInt(day),
      hour,
      parseInt(min),
      sec ? parseInt(sec) : 0
    );
  }

  // Try HH:MM:SS AM/PM (no date)
  m = ts.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?\s*(AM|PM)$/i);
  if (m) {
    const [, hourStr, min, sec, ampm] = m;
    let hour = parseInt(hourStr);
    if (ampm.toUpperCase() === "PM" && hour !== 12) hour += 12;
    if (ampm.toUpperCase() === "AM" && hour === 12) hour = 0;
    return new Date(
      year,
      now.getMonth(),
      now.getDate(),
      hour,
      parseInt(min),
      sec ? parseInt(sec) : 0
    );
  }

  return null;
}

// ─── Log line parser ───────────────────────────────────────────────────────

export function parseLogLine(rawLine: string): LogEntry | null {
  const clean = stripAnsi(rawLine).trim();
  if (!clean) return null;

  let timestamp = "";
  let project = "";
  let branch = "";
  let event = clean;

  const parts = clean.split("│");
  if (parts.length >= 4) {
    timestamp = parts[0].trim();
    project = parts[1].trim();
    branch = parts[2].trim();
    event = parts.slice(3).join("│").trim();
  } else if (parts.length >= 2) {
    timestamp = parts[0].trim();
    event = parts.slice(1).join("│").trim();
  }

  // Find the first matching emoji
  let emoji = "";
  let eventType = "unknown";
  for (const e of EMOJI_SEARCH_ORDER) {
    if (event.includes(e)) {
      emoji = e;
      eventType = EMOJI_TYPE_MAP[e];
      break;
    }
  }

  // Skip entries without a project (can't attribute them)
  if (!project) return null;

  return {
    timestamp,
    parsedTimestamp: parseTimestamp(timestamp),
    project,
    branch: branch === "-" ? "" : branch,
    emoji,
    eventType,
    eventText: event,
  };
}

// ─── Log tailer (incremental reads) ────────────────────────────────────────

export class LogTailer {
  private offset = 0;

  constructor(private path: string = LOG_FILE) {}

  /** Read all existing lines (for backfill). */
  readAll(): LogEntry[] {
    try {
      const data = readFileSync(this.path, "utf-8");
      this.offset = Buffer.byteLength(data, "utf-8");
      return this.parseLines(data);
    } catch {
      return [];
    }
  }

  /** Read only new lines since last poll. */
  poll(): LogEntry[] {
    try {
      const stat = statSync(this.path);
      if (stat.size < this.offset) {
        // File was truncated/rotated
        this.offset = 0;
      }
      if (stat.size === this.offset) {
        return [];
      }

      const allBytes = readFileSync(this.path);
      const newBytes = allBytes.subarray(this.offset);
      this.offset = allBytes.length;
      const text = newBytes.toString("utf-8");

      return this.parseLines(text);
    } catch {
      return [];
    }
  }

  private parseLines(data: string): LogEntry[] {
    const entries: LogEntry[] = [];
    for (const line of data.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const entry = parseLogLine(trimmed);
      if (entry) entries.push(entry);
    }
    return entries;
  }
}

// ─── Model stats reader ────────────────────────────────────────────────────

export interface ModelStats {
  model: string;
  total: number;
  input: number;
  cacheWrite: number;
  cacheRead: number;
  output: number;
}

export function readModelStats(): ModelStats[] {
  try {
    const models: ModelStats[] = [];
    for (const line of readFileSync(MODEL_FILE, "utf-8").trim().split("\n")) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 6) {
        models.push({
          model: parts[0],
          total: parseInt(parts[1]),
          input: parseInt(parts[2]),
          cacheWrite: parseInt(parts[3]),
          cacheRead: parseInt(parts[4]),
          output: parseInt(parts[5]),
        });
      }
    }
    return models;
  } catch {
    return [];
  }
}

// ─── Stats cache reader ────────────────────────────────────────────────────

export interface StatsCache {
  dailyActivity: Array<{
    date: string;
    messageCount: number;
    sessionCount: number;
    toolCallCount: number;
  }>;
  dailyModelTokens: Array<{
    date: string;
    tokensByModel: Record<string, number>;
  }>;
  modelUsage: Record<
    string,
    {
      inputTokens: number;
      outputTokens: number;
      cacheReadInputTokens: number;
      cacheCreationInputTokens: number;
    }
  >;
  totalSessions: number;
  totalMessages: number;
  firstSessionDate: string;
  hourCounts: Record<string, number>;
}

export function readStatsCache(): StatsCache | null {
  try {
    return JSON.parse(readFileSync(STATS_CACHE_FILE, "utf-8"));
  } catch {
    return null;
  }
}
