/**
 * Slug resolver for the LORF telemetry exporter.
 *
 * Maps project directory paths to their content_slug by reading
 * .lorf/project.md frontmatter. Falls back to directory basename
 * when no .lorf/ exists.
 */

import { readdirSync, readFileSync, statSync } from "fs";
import { basename, join } from "path";

const PROJECT_ROOT = "/Users/bigviking/Documents/github/projects";

const cache = new Map<string, string>();

/**
 * Minimal YAML frontmatter parser.
 * Extracts key: value pairs between --- fences.
 * No external dependencies.
 */
function parseFrontmatter(content: string): Record<string, string> {
  const match = content.match(/^---\s*\n([\s\S]*?)\n---/);
  if (!match) return {};

  const result: Record<string, string> = {};
  for (const line of match[1].split("\n")) {
    const kv = line.match(/^(\w[\w-]*)\s*:\s*(.+)/);
    if (kv) {
      result[kv[1]] = kv[2].replace(/^["']|["']$/g, "").trim();
    }
  }
  return result;
}

/**
 * Resolve a project directory path to its content_slug.
 *
 * 1. Check in-memory cache
 * 2. Try reading {projectDir}/.lorf/project.md
 * 3. Parse YAML frontmatter
 * 4. Return content_slug ?? slug ?? basename(projectDir)
 * 5. Cache result
 */
export function resolveSlug(projectDir: string): string {
  const cached = cache.get(projectDir);
  if (cached) return cached;

  let slug = basename(projectDir);

  try {
    const lorfPath = join(projectDir, ".lorf", "project.md");
    const content = readFileSync(lorfPath, "utf-8");
    const fm = parseFrontmatter(content);
    slug = fm.content_slug ?? fm.slug ?? basename(projectDir);
  } catch {
    // No .lorf/project.md — use directory basename
  }

  cache.set(projectDir, slug);
  return slug;
}

/**
 * Build a complete directory-name-to-slug mapping.
 * Scans all directories under PROJECT_ROOT.
 * Called at startup + refreshed every 10 cycles (5 min at 30s intervals).
 */
export function buildSlugMap(): Map<string, string> {
  const map = new Map<string, string>();

  try {
    const dirs = readdirSync(PROJECT_ROOT).filter((d) => {
      try {
        return statSync(join(PROJECT_ROOT, d)).isDirectory();
      } catch {
        return false;
      }
    });

    for (const dir of dirs) {
      const slug = resolveSlug(join(PROJECT_ROOT, dir));
      map.set(dir, slug);
    }
  } catch {
    // PROJECT_ROOT doesn't exist or isn't readable
  }

  return map;
}

/**
 * Clear the in-memory slug cache.
 * Call before refreshing the slug map.
 */
export function clearSlugCache(): void {
  cache.clear();
}
