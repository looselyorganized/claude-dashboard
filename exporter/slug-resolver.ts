/**
 * Slug resolver for the LORF telemetry exporter.
 *
 * Maps project directory paths to their content_slug by reading
 * .lorf/project.md frontmatter. Only LORF projects (those with .lorf/)
 * are tracked — all others are silently ignored.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "fs";
import { basename, join } from "path";

const PROJECT_ROOT = "/Users/bigviking/Documents/github/projects/looselyorganized";

const cache = new Map<string, string | null>();

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
 * Returns null if the project is not a LORF project (no .lorf/ directory).
 *
 * 1. Check in-memory cache
 * 2. Check for .lorf/ directory existence
 * 3. Try reading {projectDir}/.lorf/project.md
 * 4. Parse YAML frontmatter
 * 5. Return content_slug ?? slug ?? basename(projectDir)
 * 6. Cache result
 */
export function resolveSlug(projectDir: string): string | null {
  if (cache.has(projectDir)) return cache.get(projectDir)!;

  // Only track LORF projects — those with a .lorf/ directory
  const lorfDir = join(projectDir, ".lorf");
  if (!existsSync(lorfDir)) {
    cache.set(projectDir, null);
    return null;
  }

  let slug = basename(projectDir);

  try {
    const lorfPath = join(lorfDir, "project.md");
    const content = readFileSync(lorfPath, "utf-8");
    const fm = parseFrontmatter(content);
    slug = fm.content_slug ?? fm.slug ?? basename(projectDir);
  } catch {
    // .lorf/ exists but no project.md — use directory basename
  }

  cache.set(projectDir, slug);
  return slug;
}

/**
 * Build a complete directory-name-to-slug mapping.
 * Only includes LORF projects (those with .lorf/ directories).
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
      if (slug) {
        map.set(dir, slug);
      }
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
