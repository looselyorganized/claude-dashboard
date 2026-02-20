/**
 * Detects running Claude Code processes on the local machine.
 * Mirrors the ProcessScanner from dashboard.py.
 */

import { execSync } from "child_process";
import { resolve } from "path";
import { resolveSlug } from "./slug-resolver";

const PROJECT_ROOT = "/Users/bigviking/Documents/github/projects";

export interface ClaudeProcess {
  pid: number;
  cpuPercent: number;
  memMb: number;
  uptime: string;
  cwd: string;
  projectName: string;
  slug: string;
  isActive: boolean;
  model: string;
}

/**
 * Derive project name from working directory.
 * Looks for a "projects" parent directory, otherwise uses basename.
 */
export function deriveProjectName(cwd: string): string {
  if (!cwd || cwd === "/") return "unknown";
  const parts = cwd.split("/");
  const idx = parts.indexOf("projects");
  if (idx !== -1 && idx + 1 < parts.length) {
    return parts[idx + 1];
  }
  return parts[parts.length - 1] || "unknown";
}

/**
 * Derive content_slug from a working directory.
 * Uses deriveProjectName to get the dir name, then resolveSlug to get the slug.
 */
export function deriveSlug(cwd: string): string {
  const dirName = deriveProjectName(cwd);
  if (dirName === "unknown") return "unknown";
  return resolveSlug(`${PROJECT_ROOT}/${dirName}`);
}

/**
 * Scan for running Claude Code processes.
 */
export function scanProcesses(): ClaudeProcess[] {
  try {
    // Step 1: Find Claude processes
    const psOutput = execSync("ps -eo pid,pcpu,rss,etime,comm", {
      encoding: "utf-8",
      timeout: 5000,
    });

    const claudePids: Array<{
      pid: number;
      cpu: number;
      memMb: number;
      uptime: string;
    }> = [];

    for (const line of psOutput.split("\n").slice(1)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 5) continue;

      const comm = parts[parts.length - 1];
      if (comm !== "claude") continue;

      claudePids.push({
        pid: parseInt(parts[0]),
        cpu: parseFloat(parts[1]),
        memMb: Math.round(parseInt(parts[2]) / 1024),
        uptime: parts[3],
      });
    }

    if (claudePids.length === 0) return [];

    // Step 2: Get working directories via lsof
    const pidCsv = claudePids.map((p) => p.pid).join(",");
    let cwdMap: Record<number, string> = {};
    try {
      const lsofOutput = execSync(
        `lsof -d cwd -a -p ${pidCsv} -Fn`,
        { encoding: "utf-8", timeout: 5000 }
      );

      let currentPid = 0;
      for (const line of lsofOutput.split("\n")) {
        if (line.startsWith("p")) {
          currentPid = parseInt(line.substring(1));
        } else if (line.startsWith("n") && currentPid) {
          cwdMap[currentPid] = line.substring(1);
        }
      }
    } catch {
      // lsof may fail for permission reasons — continue without CWDs
    }

    // Step 3: Check for caffeinate children (indicates active work)
    let cafPids = new Set<number>();
    try {
      const childOutput = execSync("ps -eo pid,ppid,comm", {
        encoding: "utf-8",
        timeout: 5000,
      });
      for (const line of childOutput.split("\n").slice(1)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 3 && parts[2] === "caffeinate") {
          cafPids.add(parseInt(parts[1])); // parent pid
        }
      }
    } catch {}

    // Build results
    return claudePids.map((p) => {
      const cwd = cwdMap[p.pid] || "";
      const projectName = deriveProjectName(cwd);
      return {
        pid: p.pid,
        cpuPercent: p.cpu,
        memMb: p.memMb,
        uptime: p.uptime,
        cwd,
        projectName,
        slug: deriveSlug(cwd),
        isActive: p.cpu > 1 || cafPids.has(p.pid),
        model: "", // Can't determine from ps alone
      };
    });
  } catch {
    return [];
  }
}

/**
 * Get a summary of active facility state from running processes.
 */
export function getFacilityState() {
  const processes = scanProcesses();
  const activeProcesses = processes.filter((p) => p.isActive);
  const slugs = [
    ...new Set(processes.map((p) => p.slug).filter((s) => s !== "unknown")),
  ];

  return {
    status: activeProcesses.length > 0 ? ("active" as const) : ("dormant" as const),
    activeAgents: activeProcesses.length,
    totalProcesses: processes.length,
    activeProjects: slugs.map((slug) => ({
      name: slug,
      active: processes.some((p) => p.slug === slug && p.isActive),
    })),
    processes,
  };
}
