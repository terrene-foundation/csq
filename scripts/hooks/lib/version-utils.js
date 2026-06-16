/**
 * Version tracking utilities for CO/COC artifact ecosystem.
 *
 * Each repo has a .claude/VERSION file (JSON) with:
 *   - version: semver string (this repo's artifact version)
 *   - upstream: { name, repo, version, version_url } or null
 *   - changelog: array of version entries
 *
 * The session-start hook calls checkVersion() to:
 *   1. Read local VERSION
 *   2. If upstream defined, try to fetch upstream VERSION
 *   3. Compare upstream.version (what we last synced from) vs remote version
 *   4. Return status for human-facing output
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

/**
 * Read the local .claude/VERSION file.
 * @param {string} cwd - project root
 * @returns {object|null} parsed VERSION or null if missing
 */
function readLocalVersion(cwd) {
  const versionPath = path.join(cwd, ".claude", "VERSION");
  try {
    const content = fs.readFileSync(versionPath, "utf8");
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Fetch upstream VERSION from GitHub (via curl, no dependencies).
 * Times out after 3 seconds to avoid blocking session start.
 * @param {string} url - raw GitHub URL to VERSION file
 * @returns {object|null} parsed remote VERSION or null on failure
 */
function fetchUpstreamVersion(url) {
  if (!url) return null;
  try {
    const result = execSync(
      `curl -sf --max-time 3 "${url}" 2>/dev/null`,
      { encoding: "utf8", timeout: 5000 }
    );
    return JSON.parse(result);
  } catch {
    return null;
  }
}

/**
 * Compare local tracked upstream version vs actual remote version.
 * @param {object} local - local VERSION object
 * @param {object} remote - remote VERSION object (fetched from GitHub)
 * @returns {object} { status, message, localVersion, remoteVersion, changelog }
 *   status: "current" | "update-available" | "unknown"
 */
function compareVersions(local, remote) {
  if (!local || !local.upstream) {
    return { status: "source", message: "This is a source repo (no upstream)" };
  }

  if (!remote) {
    return {
      status: "unknown",
      message: `Could not reach upstream (${local.upstream.name}). Offline or repo not public.`,
      localVersion: local.version,
      trackedUpstream: local.upstream.version,
    };
  }

  const tracked = local.upstream.version;
  const actual = remote.version;

  if (tracked === actual) {
    return {
      status: "current",
      message: `Artifacts current with ${local.upstream.name} v${actual}`,
      localVersion: local.version,
      trackedUpstream: tracked,
    };
  }

  // Find changelog entries newer than what we track
  const newEntries = (remote.changelog || []).filter((entry) => {
    return entry.version !== tracked && isNewer(entry.version, tracked);
  });

  const changeSummary = newEntries
    .map((e) => `  v${e.version} (${e.date}): ${e.summary}`)
    .join("\n");

  return {
    status: "update-available",
    message: `Update available: ${local.upstream.name} v${tracked} → v${actual}`,
    localVersion: local.version,
    trackedUpstream: tracked,
    remoteVersion: actual,
    changelog: changeSummary || `  v${actual}: (no changelog details)`,
  };
}

/**
 * Simple semver comparison: is a newer than b?
 */
function isNewer(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true;
    if ((pa[i] || 0) < (pb[i] || 0)) return false;
  }
  return false;
}

/**
 * Main entry point for session-start hook.
 * @param {string} cwd - project root
 * @returns {object} { status, messages[] } for stderr output
 */
function checkVersion(cwd) {
  const local = readLocalVersion(cwd);
  if (!local) {
    return { status: "no-version", messages: [] };
  }

  const messages = [`[VERSION] ${local.description || local.type} v${local.version}`];

  if (!local.upstream) {
    messages.push("[VERSION] Source repo — no upstream to check");
    return { status: "source", messages };
  }

  const remote = fetchUpstreamVersion(local.upstream.version_url);
  const result = compareVersions(local, remote);

  if (result.status === "current") {
    messages.push(`[VERSION] ${result.message}`);
  } else if (result.status === "update-available") {
    messages.push(`[VERSION] ⚠ ${result.message}`);
    messages.push("[VERSION] Changes:");
    messages.push(result.changelog);
    messages.push("[VERSION] Run /sync to update artifacts");
  } else {
    messages.push(`[VERSION] ${result.message}`);
  }

  return { status: result.status, messages };
}

module.exports = {
  readLocalVersion,
  fetchUpstreamVersion,
  compareVersions,
  checkVersion,
};
