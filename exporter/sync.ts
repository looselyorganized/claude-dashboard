/**
 * Supabase sync layer.
 * Pushes parsed telemetry data to the lorf-site database.
 */

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { LogEntry, StatsCache } from "./parsers";
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
  const { data, error } = await supabase
    .from("projects")
    .upsert(
      {
        content_slug: slug,
        visibility,
        first_seen: now.toISOString(),
        last_active: now.toISOString(),
      },
      { onConflict: "content_slug", ignoreDuplicates: false }
    )
    .select("local_names")
    .single();

  if (error) {
    // If upsert fails because first_seen shouldn't change, just update last_active
    // and fetch local_names in the same step
    const { data: fallback } = await supabase
      .from("projects")
      .update({ last_active: now.toISOString(), visibility })
      .eq("content_slug", slug)
      .select("local_names")
      .single();

    if (localName && localName !== slug && fallback) {
      const currentNames: string[] = (fallback.local_names as string[]) ?? [];
      if (!currentNames.includes(localName)) {
        await supabase
          .from("projects")
          .update({ local_names: [...currentNames, localName] })
          .eq("content_slug", slug);
      }
    }
    return;
  }

  // Merge localName into local_names using the data from the upsert response
  if (localName && localName !== slug && data) {
    const currentNames: string[] = (data.local_names as string[]) ?? [];
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
  if (!statsCache.dailyActivity) return 0;

  // Build a map of token data by date
  const tokensByDate: Record<string, Record<string, number>> = {};
  for (const dt of statsCache.dailyModelTokens ?? []) {
    tokensByDate[dt.date] = dt.tokensByModel;
  }

  const rows = statsCache.dailyActivity.map((day) => ({
    date: day.date,
    project: null as string | null, // NULL = global aggregate
    messages: day.messageCount,
    sessions: day.sessionCount,
    tool_calls: day.toolCallCount,
    tokens: tokensByDate[day.date] ?? null,
  }));

  if (rows.length === 0) return 0;

  // Batch fetch all existing global daily_metrics rows
  const dates = rows.map((r) => r.date);
  const { data: existingRows } = await supabase
    .from("daily_metrics")
    .select("id, date")
    .in("date", dates)
    .is("project", null);

  const existingByDate = new Map<string, number>();
  for (const row of existingRows ?? []) {
    existingByDate.set(row.date, row.id);
  }

  // Split into updates vs inserts
  const toInsert: typeof rows = [];
  const toUpdate: Array<{ id: number; data: Omit<typeof rows[0], "date" | "project"> }> = [];

  for (const row of rows) {
    const existingId = existingByDate.get(row.date);
    if (existingId) {
      toUpdate.push({
        id: existingId,
        data: {
          messages: row.messages,
          sessions: row.sessions,
          tool_calls: row.tool_calls,
          tokens: row.tokens,
        },
      });
    } else {
      toInsert.push(row);
    }
  }

  // Bulk insert new rows
  if (toInsert.length > 0) {
    await supabase.from("daily_metrics").insert(toInsert);
  }

  // Batch update existing rows (Supabase doesn't support bulk update by different IDs,
  // so we batch these into reasonable chunks to limit sequential calls)
  const UPDATE_BATCH = 50;
  for (let i = 0; i < toUpdate.length; i += UPDATE_BATCH) {
    const batch = toUpdate.slice(i, i + UPDATE_BATCH);
    await Promise.all(
      batch.map((u) =>
        supabase.from("daily_metrics").update(u.data).eq("id", u.id)
      )
    );
  }

  return rows.length;
}

/**
 * Sync per-project daily metrics from JSONL token scan and event aggregates.
 * Upserts rows with project != null into daily_metrics.
 */
export async function syncProjectDailyMetrics(
  tokenMap: ProjectTokenMap,
  eventAggregates?: ProjectEventAggregates
) {
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

  const allRows = [...keys.entries()].map(([k, v]) => {
    const [project, date] = k.split("\0");
    return { project, date, ...v };
  });

  if (allRows.length === 0) return 0;

  // Batch fetch all existing per-project daily_metrics rows
  const projects = [...new Set(allRows.map((r) => r.project))];
  const dates = [...new Set(allRows.map((r) => r.date))];

  // Fetch in chunks to stay within Supabase query limits
  const existingByKey = new Map<string, { id: number }>();
  const FETCH_BATCH = 500;
  for (let i = 0; i < projects.length; i += FETCH_BATCH) {
    const projectBatch = projects.slice(i, i + FETCH_BATCH);
    const { data: existingRows } = await supabase
      .from("daily_metrics")
      .select("id, date, project")
      .in("project", projectBatch)
      .in("date", dates);

    for (const row of existingRows ?? []) {
      existingByKey.set(makeKey(row.project, row.date), { id: row.id });
    }
  }

  // Split into updates vs inserts
  const toInsert: Array<Record<string, any>> = [];
  const toUpdate: Array<{ id: number; data: Record<string, any> }> = [];

  for (const row of allRows) {
    const existing = existingByKey.get(makeKey(row.project, row.date));
    if (existing) {
      const updates: Record<string, any> = {};
      if (row.tokens) updates.tokens = row.tokens;
      if (row.events) {
        updates.sessions = row.events.sessions;
        updates.messages = row.events.messages;
        updates.tool_calls = row.events.toolCalls;
        updates.agent_spawns = row.events.agentSpawns;
      }
      if (Object.keys(updates).length > 0) {
        toUpdate.push({ id: existing.id, data: updates });
      }
    } else {
      toInsert.push({
        date: row.date,
        project: row.project,
        tokens: row.tokens ?? null,
        sessions: row.events?.sessions ?? null,
        messages: row.events?.messages ?? null,
        tool_calls: row.events?.toolCalls ?? null,
        agent_spawns: row.events?.agentSpawns ?? null,
      });
    }
  }

  // Bulk insert new rows in batches
  const INSERT_BATCH = 500;
  for (let i = 0; i < toInsert.length; i += INSERT_BATCH) {
    const batch = toInsert.slice(i, i + INSERT_BATCH);
    const { error } = await supabase.from("daily_metrics").insert(batch);
    if (error) {
      console.error(`  Error bulk inserting project metrics:`, error.message);
    }
  }

  // Batch update existing rows with concurrent requests
  const UPDATE_BATCH = 50;
  for (let i = 0; i < toUpdate.length; i += UPDATE_BATCH) {
    const batch = toUpdate.slice(i, i + UPDATE_BATCH);
    await Promise.all(
      batch.map((u) =>
        supabase.from("daily_metrics").update(u.data).eq("id", u.id)
      )
    );
  }

  return allRows.length;
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
