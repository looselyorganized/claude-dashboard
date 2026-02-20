#!/usr/bin/env bun
/**
 * LORF Telemetry Exporter
 *
 * Reads Claude Code telemetry from ~/.claude/ and pushes it to Supabase
 * for the Loosely Organized Research Facility operations dashboard.
 *
 * Usage:
 *   bun run index.ts              # Start the daemon (incremental sync)
 *   bun run index.ts --backfill   # Backfill all historical data, then run daemon
 */

import {
  LogTailer,
  readTokenStats,
  readModelStats,
  readStatsCache,
  type LogEntry,
} from "./parsers";
import { scanProcesses, getFacilityState } from "./process-scanner";
import { scanProjectTokens, computeTokensByProject } from "./project-scanner";
import {
  initSupabase,
  getSupabase,
  upsertProject,
  updateProjectActivity,
  insertEvents,
  syncDailyMetrics,
  syncProjectDailyMetrics,
  updateFacilityStatus,
  pruneOldEvents,
  type FacilityUpdate,
  type ProjectEventAggregates,
} from "./sync";
import {
  loadVisibilityCache,
  getVisibility,
} from "./visibility-cache";
import { buildSlugMap, clearSlugCache } from "./slug-resolver";
import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";

// ─── Config ────────────────────────────────────────────────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const PUSH_ACTIVE = parseInt(process.env.PUSH_INTERVAL_ACTIVE ?? "30") * 1000;
const PUSH_DORMANT = parseInt(process.env.PUSH_INTERVAL_DORMANT ?? "300") * 1000;
const IS_BACKFILL = process.argv.includes("--backfill");

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
  console.error("Copy .env.example to .env and fill in your credentials.");
  process.exit(1);
}

// ─── Init ──────────────────────────────────────────────────────────────────

console.log("LORF Telemetry Exporter starting...");
console.log(`  Supabase: ${SUPABASE_URL}`);
console.log(`  Push interval: ${PUSH_ACTIVE / 1000}s active / ${PUSH_DORMANT / 1000}s dormant`);
console.log(`  Mode: ${IS_BACKFILL ? "BACKFILL + daemon" : "daemon (incremental)"}`);
console.log();

initSupabase(SUPABASE_URL, SUPABASE_KEY);
loadVisibilityCache();

const tailer = new LogTailer();

// Track projects we've already ensured exist in the DB (by slug)
const knownProjects = new Set<string>();

// Directory name → slug mapping, refreshed every 10 cycles
let slugMap: Map<string, string> = new Map();

const SLUG_MAPPING_FILE = join(dirname(new URL(import.meta.url).pathname), ".slug-mapping.json");

function loadSavedSlugMapping(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(SLUG_MAPPING_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function saveSlugMapping(mapping: Record<string, string>) {
  writeFileSync(SLUG_MAPPING_FILE, JSON.stringify(mapping, null, 2));
}

async function refreshSlugMap() {
  clearSlugCache();
  slugMap = buildSlugMap();
  console.log(`  Slug map: ${slugMap.size} projects mapped`);

  // Detect slug changes: if a dir name previously mapped to a different slug
  const saved = loadSavedSlugMapping();
  const current: Record<string, string> = {};
  for (const [dirName, slug] of slugMap) {
    current[dirName] = slug;
    const oldSlug = saved[dirName];
    if (oldSlug && oldSlug !== slug) {
      console.log(`  Slug change detected: ${dirName}: ${oldSlug} → ${slug}`);
      // Migrate existing telemetry data from old slug to new slug
      try {
        const sb = getSupabase();
        await sb.from("events").update({ project: slug }).eq("project", oldSlug);
        await sb.from("daily_metrics").update({ project: slug }).eq("project", oldSlug);
        console.log(`  Migrated telemetry data: ${oldSlug} → ${slug}`);
      } catch (err) {
        console.error(`  Error migrating slug ${oldSlug} → ${slug}:`, err);
      }
    }
  }
  saveSlugMapping(current);
}

/** Map a directory name (from events.log) to its content_slug, or null if not a LORF project */
function toSlug(dirName: string): string | null {
  return slugMap.get(dirName) ?? null;
}

/** Filter entries to only LORF projects and map project fields to slugs */
function filterAndMapEntries(entries: LogEntry[]): LogEntry[] {
  return entries
    .filter((e) => e.project && toSlug(e.project) !== null)
    .map((e) => ({
      ...e,
      project: toSlug(e.project)!,
    }));
}

// Cache project token totals for facility status updates
let cachedTokensByProject: Record<string, number> = {};

// ─── Ensure projects exist ─────────────────────────────────────────────────

async function ensureProjects(entries: LogEntry[]) {
  const newSlugs = new Set<string>();
  const slugToLocalName = new Map<string, string>();

  for (const entry of entries) {
    if (!entry.project) continue;
    const slug = toSlug(entry.project);
    if (!slug) continue; // Not a LORF project — skip
    if (!knownProjects.has(slug)) {
      newSlugs.add(slug);
      slugToLocalName.set(slug, entry.project);
    }
  }

  for (const slug of newSlugs) {
    const localName = slugToLocalName.get(slug) ?? slug;
    const visibility = getVisibility(localName);
    const firstEntry = entries.find((e) => toSlug(e.project) === slug);
    await upsertProject(
      slug,
      localName,
      visibility,
      firstEntry?.parsedTimestamp ?? undefined
    );
    knownProjects.add(slug);
    console.log(`  Project registered: ${slug}${slug !== localName ? ` (dir: ${localName})` : ""} (${visibility})`);
  }
}

// ─── Compute today's tokens ────────────────────────────────────────────────

function computeTodayTokens(): number {
  const statsCache = readStatsCache();
  if (!statsCache?.dailyModelTokens) return 0;

  const today = new Date().toISOString().split("T")[0];
  const todayEntry = statsCache.dailyModelTokens.find((d) => d.date === today);
  if (!todayEntry) return 0;

  return Object.values(todayEntry.tokensByModel).reduce((a, b) => a + b, 0);
}

// ─── Compute lifetime tokens from modelUsage ───────────────────────────────

function computeLifetimeTokens(
  statsCache: ReturnType<typeof readStatsCache>
): number {
  if (!statsCache?.modelUsage) return 0;
  let total = 0;
  for (const model of Object.values(statsCache.modelUsage)) {
    total +=
      (model.inputTokens ?? 0) +
      (model.outputTokens ?? 0) +
      (model.cacheReadInputTokens ?? 0) +
      (model.cacheCreationInputTokens ?? 0);
  }
  return total;
}

// ─── Aggregate per-project events ─────────────────────────────────────────

function aggregateProjectEvents(entries: LogEntry[]): ProjectEventAggregates {
  const agg: ProjectEventAggregates = new Map();

  for (const entry of entries) {
    if (!entry.project || !entry.parsedTimestamp) continue;

    const slug = toSlug(entry.project);
    if (!slug) continue; // Not a LORF project
    const date = entry.parsedTimestamp.toISOString().split("T")[0];

    let dateMap = agg.get(slug);
    if (!dateMap) {
      dateMap = new Map();
      agg.set(slug, dateMap);
    }

    let counts = dateMap.get(date);
    if (!counts) {
      counts = { sessions: 0, messages: 0, toolCalls: 0, agentSpawns: 0 };
      dateMap.set(date, counts);
    }

    if (entry.eventType === "session_start") counts.sessions++;
    else if (entry.eventType === "response_finish") counts.messages++;
    else if (entry.eventType === "tool") counts.toolCalls++;
    else if (entry.eventType === "agent_spawn") counts.agentSpawns++;
  }

  return agg;
}

// ─── Backfill ──────────────────────────────────────────────────────────────

async function backfill() {
  console.log("Starting backfill...");

  // 0. Build slug map
  await refreshSlugMap();

  // 1. Read all events
  console.log("  Reading events.log...");
  const allEntries = tailer.readAll();
  console.log(`  Found ${allEntries.length} events`);

  // 2. Ensure all projects exist
  console.log("  Registering projects...");
  await ensureProjects(allEntries);

  // 3. Insert events in batches (with project mapped to slug)
  console.log("  Inserting events...");
  const lorfEntries = filterAndMapEntries(allEntries);
  const { inserted, errors, insertedByProject } = await insertEvents(lorfEntries);
  console.log(`  Inserted: ${inserted}, Errors: ${errors}`);

  // 4. Update project activity counts (insertedByProject keys are already slugs from lorfEntries)
  console.log("  Updating project activity...");
  const slugLastActive: Record<string, Date> = {};
  for (const entry of lorfEntries) {
    if (!entry.project || !entry.parsedTimestamp) continue;
    if (!slugLastActive[entry.project] || entry.parsedTimestamp > slugLastActive[entry.project]) {
      slugLastActive[entry.project] = entry.parsedTimestamp;
    }
  }
  for (const [slug, count] of Object.entries(insertedByProject)) {
    const lastActive = slugLastActive[slug] ?? new Date();
    await updateProjectActivity(slug, count, lastActive);
  }

  // 5. Sync daily metrics from stats-cache.json
  console.log("  Syncing daily metrics...");
  const statsCache = readStatsCache();
  if (statsCache) {
    const synced = await syncDailyMetrics(statsCache);
    console.log(`  Synced ${synced} daily metric rows`);
  }

  // 6. Scan and sync per-project token metrics + event counts from JSONL files
  console.log("  Scanning JSONL files for per-project tokens...");
  const projectTokenMap = scanProjectTokens();
  cachedTokensByProject = computeTokensByProject(projectTokenMap);
  const projectEventAggregates = aggregateProjectEvents(allEntries);
  const projectSynced = await syncProjectDailyMetrics(projectTokenMap, projectEventAggregates);
  console.log(`  Synced ${projectSynced} per-project daily metric rows`);

  // 7. Update facility status
  console.log("  Updating facility status...");
  await syncFacilityStatus();

  console.log("Backfill complete.\n");
}

// ─── Incremental sync ──────────────────────────────────────────────────────

async function incrementalSync() {
  const newEntries = tailer.poll();

  if (newEntries.length > 0) {
    // Ensure projects exist
    await ensureProjects(newEntries);

    // Insert new events (only LORF projects, mapped to slug)
    const lorfEntries = filterAndMapEntries(newEntries);
    const { inserted, errors, insertedByProject } = await insertEvents(lorfEntries);
    if (inserted > 0 || errors > 0) {
      console.log(
        `  ${new Date().toLocaleTimeString()} — ${inserted} events synced${errors > 0 ? `, ${errors} errors` : ""}`
      );
    }

    // Update project activity (insertedByProject keys are already slugs from lorfEntries)
    const slugLastActive: Record<string, Date> = {};
    for (const entry of lorfEntries) {
      if (!entry.project || !entry.parsedTimestamp) continue;
      if (!slugLastActive[entry.project] || entry.parsedTimestamp > slugLastActive[entry.project]) {
        slugLastActive[entry.project] = entry.parsedTimestamp;
      }
    }
    for (const [slug, count] of Object.entries(insertedByProject)) {
      const lastActive = slugLastActive[slug] ?? new Date();
      await updateProjectActivity(slug, count, lastActive);
    }
  }

  // Always update facility status (live processes change independently)
  await syncFacilityStatus();
}

// ─── Facility status sync ──────────────────────────────────────────────────

async function syncFacilityStatus() {
  const facility = getFacilityState();
  const statsCache = readStatsCache();
  const modelStats = readModelStats();
  const tokenStats = readTokenStats();

  // Compute per-project agent breakdown (keyed by slug)
  const agentsByProject: Record<string, { count: number; active: number }> = {};
  for (const proc of facility.processes) {
    if (proc.slug === "unknown") continue;
    if (!agentsByProject[proc.slug]) {
      agentsByProject[proc.slug] = { count: 0, active: 0 };
    }
    agentsByProject[proc.slug].count++;
    if (proc.isActive) agentsByProject[proc.slug].active++;
  }

  const update: FacilityUpdate = {
    status: facility.status,
    activeAgents: facility.activeAgents,
    activeProjects: facility.activeProjects,
    tokensLifetime: computeLifetimeTokens(statsCache),
    tokensToday: computeTodayTokens(),
    sessionsLifetime: statsCache?.totalSessions ?? 0,
    messagesLifetime: statsCache?.totalMessages ?? 0,
    modelStats: Object.fromEntries(
      modelStats.map((m) => [
        m.model,
        {
          total: m.total,
          input: m.input,
          cacheWrite: m.cacheWrite,
          cacheRead: m.cacheRead,
          output: m.output,
        },
      ])
    ),
    hourDistribution: statsCache?.hourCounts ?? {},
    firstSessionDate: statsCache?.firstSessionDate ?? null,
    tokensByProject: cachedTokensByProject,
    agentsByProject,
  };

  await updateFacilityStatus(update);
}

// ─── Periodic daily metrics sync ───────────────────────────────────────────

let lastDailySync = "";

async function maybeSyncDailyMetrics() {
  const today = new Date().toISOString().split("T")[0];
  if (today === lastDailySync) return; // Already synced today's data this cycle

  const statsCache = readStatsCache();
  if (statsCache) {
    await syncDailyMetrics(statsCache);
    lastDailySync = today;
  }
}

// ─── Periodic project daily metrics sync ────────────────────────────────────

let lastProjectSync = "";
let lastPruneDate = "";

async function maybeSyncProjectDailyMetrics() {
  const today = new Date().toISOString().split("T")[0];
  if (today === lastProjectSync) return;

  try {
    const projectTokenMap = scanProjectTokens();
    cachedTokensByProject = computeTokensByProject(projectTokenMap);
    const aggregationTailer = new LogTailer();
    const allEntries = aggregationTailer.readAll();
    const projectEventAggregates = aggregateProjectEvents(allEntries);
    await syncProjectDailyMetrics(projectTokenMap, projectEventAggregates);
    lastProjectSync = today;
  } catch (err) {
    console.error("Error syncing project daily metrics:", err);
  }
}

async function maybePruneEvents() {
  const today = new Date().toISOString().split("T")[0];
  if (today === lastPruneDate) return;

  try {
    const pruned = await pruneOldEvents(14);
    if (pruned > 0) {
      console.log(`  Pruned ${pruned} events older than 14 days`);
    }
    lastPruneDate = today;
  } catch (err) {
    console.error("Error pruning events:", err);
  }
}

// ─── Main loop ─────────────────────────────────────────────────────────────

async function main() {
  if (IS_BACKFILL) {
    await backfill();
  } else {
    // Build initial slug map
    await refreshSlugMap();

    // Prime the tailer — read existing file to set offset, but don't backfill
    console.log("Priming log tailer (skipping existing entries)...");
    tailer.readAll(); // Sets offset to end of file

    // Seed token cache from existing facility_status to avoid writing {}
    console.log("  Loading cached tokens from Supabase...");
    const { data: facility } = await getSupabase()
      .from("facility_status")
      .select("tokens_by_project")
      .eq("id", 1)
      .single();
    if (facility?.tokens_by_project) {
      cachedTokensByProject = facility.tokens_by_project as Record<string, number>;
      console.log(`  Loaded ${Object.keys(cachedTokensByProject).length} project token entries`);
    }

    console.log("  Ready — will only sync new events from this point.\n");
  }

  console.log("Daemon running. Press Ctrl+C to stop.\n");

  let cycleCount = 0;

  while (true) {
    try {
      await incrementalSync();

      // Refresh slug map + sync daily metrics + prune every ~10 cycles
      if (cycleCount % 10 === 0) {
        await refreshSlugMap();
        await maybeSyncDailyMetrics();
        await maybeSyncProjectDailyMetrics();
        await maybePruneEvents();
      }
      cycleCount++;
    } catch (err) {
      console.error("Sync error:", err);
    }

    // Adaptive sleep: shorter when active, longer when dormant
    const facility = getFacilityState();
    const sleepMs = facility.status === "active" ? PUSH_ACTIVE : PUSH_DORMANT;
    await Bun.sleep(sleepMs);
  }
}

// ─── Start ─────────────────────────────────────────────────────────────────

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
