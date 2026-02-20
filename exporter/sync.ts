/**
 * Supabase sync layer.
 * Pushes parsed telemetry data to the lorf-site database.
 */

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { LogEntry, StatsCache } from "./parsers";
import type { ModelStats } from "./parsers";
import type { ProjectTokenMap } from "./project-scanner";

let supabase: SupabaseClient;

export function initSupabase(url: string, serviceRoleKey: string) {
  supabase = createClient(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export function getSupabase(): SupabaseClient {
  return supabase;
}

// ─── Projects ──────────────────────────────────────────────────────────────

/**
 * Ensure a project exists in the projects table.
 * Upserts on content_slug (canonical PK). Tracks local directory names
 * in the local_names array.
 */
export async function upsertProject(
  slug: string,
  localName: string,
  visibility: "public" | "classified",
  timestamp?: Date
) {
  const now = timestamp ?? new Date();
  const { error } = await supabase.from("projects").upsert(
    {
      content_slug: slug,
      visibility,
      first_seen: now.toISOString(),
      last_active: now.toISOString(),
    },
    { onConflict: "content_slug", ignoreDuplicates: false }
  );

  if (error) {
    // If upsert fails because first_seen shouldn't change, just update last_active
    await supabase
      .from("projects")
      .update({ last_active: now.toISOString(), visibility })
      .eq("content_slug", slug);
  }

  // Ensure localName is in the local_names array
  if (localName && localName !== slug) {
    const { data: existing } = await supabase
      .from("projects")
      .select("local_names")
      .eq("content_slug", slug)
      .single();

    const currentNames: string[] = (existing?.local_names as string[]) ?? [];
    if (!currentNames.includes(localName)) {
      await supabase
        .from("projects")
        .update({ local_names: [...currentNames, localName] })
        .eq("content_slug", slug);
    }
  }
}

/**
 * Update a project's event count and last_active time.
 */
export async function updateProjectActivity(
  slug: string,
  eventCount: number,
  lastActive: Date
) {
  const { data: current } = await supabase
    .from("projects")
    .select("total_events")
    .eq("content_slug", slug)
    .single();

  if (current) {
    await supabase
      .from("projects")
      .update({
        total_events: current.total_events + eventCount,
        last_active: lastActive.toISOString(),
      })
      .eq("content_slug", slug);
  }
}

// ─── Events ────────────────────────────────────────────────────────────────

/**
 * Insert a batch of events.
 * Handles batching to stay within Supabase limits.
 */
export async function insertEvents(entries: LogEntry[]) {
  if (entries.length === 0) return { inserted: 0, errors: 0, insertedByProject: {} as Record<string, number> };

  const rows = entries
    .filter((e) => e.parsedTimestamp) // Skip entries we can't timestamp
    .map((e) => ({
      timestamp: e.parsedTimestamp!.toISOString(),
      project: e.project,
      branch: e.branch || null,
      emoji: e.emoji || null,
      event_type: e.eventType,
      event_text: e.eventText,
    }));

  let inserted = 0;
  let errors = 0;
  const insertedByProject: Record<string, number> = {};
  const BATCH_SIZE = 500;

  for (let i = 0; i < rows.length; i += BATCH_SIZE) {
    const batch = rows.slice(i, i + BATCH_SIZE);
    // Use upsert with ignoreDuplicates to skip events that already exist
    // (unique index on project, event_type, event_text, timestamp)
    const { error } = await supabase
      .from("events")
      .upsert(batch, { onConflict: "project,event_type,event_text,timestamp", ignoreDuplicates: true });
    if (error) {
      console.error(
        `  Error inserting batch ${i}-${i + batch.length}:`,
        error.message
      );
      errors += batch.length;
    } else {
      inserted += batch.length;
      for (const row of batch) {
        if (row.project) {
          insertedByProject[row.project] = (insertedByProject[row.project] ?? 0) + 1;
        }
      }
    }
  }

  return { inserted, errors, insertedByProject };
}

// ─── Per-project event aggregation type ───────────────────────────────────

/** project → date → { sessions, messages, toolCalls, agentSpawns } */
export type ProjectEventAggregates = Map<
  string,
  Map<string, { sessions: number; messages: number; toolCalls: number; agentSpawns: number }>
>;

// ─── Daily Metrics ─────────────────────────────────────────────────────────

/**
 * Sync global daily metrics from stats-cache.json.
 */
export async function syncDailyMetrics(statsCache: StatsCache) {
  if (!statsCache.dailyActivity) return;

  // Build a map of token data by date
  const tokensByDate: Record<string, Record<string, number>> = {};
  for (const dt of statsCache.dailyModelTokens ?? []) {
    tokensByDate[dt.date] = dt.tokensByModel;
  }

  const rows = statsCache.dailyActivity.map((day) => ({
    date: day.date,
    project: null, // NULL = global aggregate
    messages: day.messageCount,
    sessions: day.sessionCount,
    tool_calls: day.toolCallCount,
    tokens: tokensByDate[day.date] ?? null,
  }));

  // Upsert each row individually to handle the COALESCE unique index
  let synced = 0;
  for (const row of rows) {
    // Check if exists
    const { data: existing } = await supabase
      .from("daily_metrics")
      .select("id")
      .eq("date", row.date)
      .is("project", null)
      .maybeSingle();

    if (existing) {
      await supabase
        .from("daily_metrics")
        .update({
          messages: row.messages,
          sessions: row.sessions,
          tool_calls: row.tool_calls,
          tokens: row.tokens,
        })
        .eq("id", existing.id);
    } else {
      await supabase.from("daily_metrics").insert(row);
    }
    synced++;
  }

  return synced;
}

/**
 * Sync per-project daily metrics from JSONL token scan and event aggregates.
 * Upserts rows with project != null into daily_metrics.
 */
export async function syncProjectDailyMetrics(
  tokenMap: ProjectTokenMap,
  eventAggregates?: ProjectEventAggregates
) {
  let synced = 0;
  let errors = 0;

  // Build a unified set of (project, date) keys from both sources
  const keys = new Map<string, { tokens?: Record<string, number>; events?: { sessions: number; messages: number; toolCalls: number; agentSpawns: number } }>();

  const makeKey = (project: string, date: string) => `${project}\0${date}`;

  for (const [project, dateMap] of tokenMap) {
    for (const [date, modelTokens] of dateMap) {
      keys.set(makeKey(project, date), { tokens: modelTokens });
    }
  }

  if (eventAggregates) {
    for (const [project, dateMap] of eventAggregates) {
      for (const [date, counts] of dateMap) {
        const k = makeKey(project, date);
        const existing = keys.get(k) ?? {};
        existing.events = counts;
        keys.set(k, existing);
      }
    }
  }

  // Process all rows
  const allRows = [...keys.entries()].map(([k, v]) => {
    const [project, date] = k.split("\0");
    return { project, date, ...v };
  });

  const BATCH_SIZE = 500;
  for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
    const batch = allRows.slice(i, i + BATCH_SIZE);

    for (const row of batch) {
      try {
        const { data: existing } = await supabase
          .from("daily_metrics")
          .select("id, tokens, sessions, messages, tool_calls, agent_spawns")
          .eq("date", row.date)
          .eq("project", row.project)
          .maybeSingle();

        if (existing) {
          // Only update fields we have new data for — don't overwrite with null
          const updates: Record<string, any> = {};
          if (row.tokens) updates.tokens = row.tokens;
          if (row.events) {
            updates.sessions = row.events.sessions;
            updates.messages = row.events.messages;
            updates.tool_calls = row.events.toolCalls;
            updates.agent_spawns = row.events.agentSpawns;
          }
          if (Object.keys(updates).length > 0) {
            await supabase
              .from("daily_metrics")
              .update(updates)
              .eq("id", existing.id);
          }
        } else {
          await supabase.from("daily_metrics").insert({
            date: row.date,
            project: row.project,
            tokens: row.tokens ?? null,
            sessions: row.events?.sessions ?? null,
            messages: row.events?.messages ?? null,
            tool_calls: row.events?.toolCalls ?? null,
            agent_spawns: row.events?.agentSpawns ?? null,
          });
        }
        synced++;
      } catch (err) {
        console.error(`  Error syncing project metric ${row.project}/${row.date}:`, err);
        errors++;
      }
    }
  }

  if (errors > 0) {
    console.error(`  ${errors} errors during project daily metrics sync`);
  }

  return synced;
}

// ─── Facility Status ───────────────────────────────────────────────────────

export interface FacilityUpdate {
  status: "active" | "dormant";
  activeAgents: number;
  activeProjects: Array<{ name: string; active: boolean }>;
  tokensLifetime: number;
  tokensToday: number;
  sessionsLifetime: number;
  messagesLifetime: number;
  modelStats: Record<string, any>;
  hourDistribution: Record<string, number>;
  firstSessionDate: string | null;
  tokensByProject: Record<string, number>;
  agentsByProject: Record<string, { count: number; active: number }>;
}

/**
 * Update the singleton facility_status row.
 */
export async function updateFacilityStatus(update: FacilityUpdate) {
  const { error } = await supabase
    .from("facility_status")
    .update({
      status: update.status,
      active_agents: update.activeAgents,
      active_projects: update.activeProjects,
      tokens_lifetime: update.tokensLifetime,
      tokens_today: update.tokensToday,
      sessions_lifetime: update.sessionsLifetime,
      messages_lifetime: update.messagesLifetime,
      model_stats: update.modelStats,
      hour_distribution: update.hourDistribution,
      first_session_date: update.firstSessionDate,
      tokens_by_project: update.tokensByProject,
      agents_by_project: update.agentsByProject,
      updated_at: new Date().toISOString(),
    })
    .eq("id", 1);

  if (error) {
    console.error("Error updating facility status:", error.message);
  }
}

// ─── Event Pruning ──────────────────────────────────────────────────────────

/**
 * Delete events older than the retention period.
 * Aggregated data lives in daily_metrics; old events only bloat the table.
 */
export async function pruneOldEvents(retentionDays = 14) {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - retentionDays);

  const { count, error } = await supabase
    .from("events")
    .delete({ count: "exact" })
    .lt("timestamp", cutoff.toISOString());

  if (error) {
    console.error("Error pruning old events:", error.message);
    return 0;
  }

  return count ?? 0;
}
