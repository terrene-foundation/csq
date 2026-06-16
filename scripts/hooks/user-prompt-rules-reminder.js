#!/usr/bin/env node
/**
 * Hook: user-prompt-rules-reminder
 * Event: UserPromptSubmit
 * Purpose: Inject a small, claude-squad-relevant context block on every
 *          user turn. Survives context compression because it runs fresh.
 *
 * Scope: claude-squad. No LLM model/env discovery (csq is not an LLM
 * framework). No workspace/session-note scanning unless workspaces/ exists.
 *
 * Exit codes: 0 always (never blocks the turn).
 */

const fs = require("fs");
const path = require("path");

const TIMEOUT_MS = 2000;
const timeout = setTimeout(() => {
  console.log(JSON.stringify({ continue: true }));
  process.exit(0);
}, TIMEOUT_MS);

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  clearTimeout(timeout);
  try {
    const data = JSON.parse(input);
    const result = buildReminder(data);
    console.log(JSON.stringify(result));
    process.exit(0);
  } catch {
    console.log(JSON.stringify({ continue: true }));
    process.exit(0);
  }
});

function buildReminder(data) {
  const cwd = data.cwd || process.cwd();
  const lines = [];

  // Single zero-tolerance line. Survives compaction.
  lines.push(
    "[ZERO-TOLERANCE] Fix pre-existing failures, don't report them. " +
      "No stubs/TODOs/placeholders. No silent error fallbacks. " +
      "No workarounds for upstream bugs — reproduce, document, file upstream.",
  );

  // Session notes, only if present (no expensive scanning).
  const sessionNotePaths = [
    path.join(cwd, "SESSION_NOTES.md"),
    path.join(cwd, ".session-notes.md"),
  ];
  for (const p of sessionNotePaths) {
    if (fs.existsSync(p)) {
      try {
        const stat = fs.statSync(p);
        const ageMs = Date.now() - stat.mtimeMs;
        const ageStr = formatAge(ageMs);
        const stale = ageMs > 24 * 3600 * 1000 ? " (STALE)" : "";
        lines.push(
          `[SESSION-NOTES] ${path.basename(p)} updated ${ageStr}${stale} — read before starting`,
        );
        break;
      } catch {}
    }
  }

  return {
    continue: true,
    hookSpecificOutput: {
      hookEventName: "UserPromptSubmit",
      suppressOutput: false,
      message: lines.join("\n"),
    },
  };
}

function formatAge(ms) {
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
