/**
 * Caches GitHub repo visibility (public vs private).
 * Fetches all repos in one `gh repo list` call, then caches locally.
 */

import { execSync } from "child_process";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join, dirname } from "path";

const CACHE_FILE = join(
  dirname(new URL(import.meta.url).pathname),
  ".visibility-cache.json"
);

let cache: Record<string, "public" | "classified"> = {};
let ghRepoMap: Record<string, boolean> | null = null; // name → isPrivate

/** Load cache from disk. */
export function loadVisibilityCache() {
  try {
    if (existsSync(CACHE_FILE)) {
      cache = JSON.parse(readFileSync(CACHE_FILE, "utf-8"));
    }
  } catch {
    cache = {};
  }
}

/** Save cache to disk. */
function saveCache() {
  try {
    writeFileSync(CACHE_FILE, JSON.stringify(cache, null, 2));
  } catch {}
}

/**
 * Fetch all repos from GitHub in one call.
 * Maps repo name → isPrivate. Only needs to run once per session.
 */
function ensureGhRepoMap() {
  if (ghRepoMap !== null) return;

  ghRepoMap = {};
  try {
    const output = execSync(
      `gh repo list --limit 200 --json name,isPrivate -q '.[] | "\\(.name) \\(.isPrivate)"'`,
      { encoding: "utf-8", timeout: 15000, stdio: ["pipe", "pipe", "pipe"] }
    ).trim();

    for (const line of output.split("\n")) {
      const [name, isPrivate] = line.trim().split(" ");
      if (name) {
        ghRepoMap[name] = isPrivate === "true";
      }
    }
    console.log(`  Loaded ${Object.keys(ghRepoMap).length} repos from GitHub`);
  } catch (err) {
    console.warn("  Warning: Could not fetch GitHub repos. Defaulting to classified.");
  }
}

/**
 * Check if a project is public or classified (private).
 * Uses the cached GitHub repo list for fast lookups.
 */
export function getVisibility(projectName: string): "public" | "classified" {
  if (cache[projectName]) return cache[projectName];

  ensureGhRepoMap();

  let visibility: "public" | "classified";

  if (ghRepoMap && projectName in ghRepoMap) {
    visibility = ghRepoMap[projectName] ? "classified" : "public";
  } else {
    // Not found on GitHub — default to classified (safer)
    visibility = "classified";
  }

  cache[projectName] = visibility;
  saveCache();
  return visibility;
}

