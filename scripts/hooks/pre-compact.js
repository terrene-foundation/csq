#!/usr/bin/env node
/**
 * Hook: pre-compact
 * Event: PreCompact
 * Purpose: Remind the user to write session notes before context compaction.
 *
 * csq-specific. The original Kailash version did framework detection
 * (DataFlow/Nexus/Kaizen), workflow extraction, and called a non-existent
 * `../learning/checkpoint-manager` module. All of that has been removed —
 * csq has no workflows, no frameworks to detect, and the checkpoint manager
 * never existed in this repo.
 *
 * Exit Codes:
 *   0 = success (continue)
 *   2 = blocking error (stop tool execution)
 *   other = non-blocking error (warn and continue)
 */

const { detectActiveWorkspace } = require("./lib/workspace-utils");

// Timeout fallback — prevents hanging the Claude Code session
const TIMEOUT_MS = 5000;
const _timeout = setTimeout(() => {
  console.log(JSON.stringify({ continue: true }));
  process.exit(1);
}, TIMEOUT_MS);

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  try {
    const data = JSON.parse(input);
    const cwd = data.cwd || process.cwd();

    // Workspace reminder — encourage writing session notes before context loss
    try {
      const ws = detectActiveWorkspace(cwd);
      if (ws) {
        console.error(
          `[WORKSPACE] Context compacting. Before losing context, write session notes to workspaces/${ws.name}/.session-notes (or run /wrapup).`,
        );
      } else {
        console.error(
          `[WRAPUP] Context compacting. Consider running /wrapup to save session notes.`,
        );
      }
    } catch {}

    console.log(JSON.stringify({ continue: true }));
    clearTimeout(_timeout);
    process.exit(0);
  } catch (error) {
    console.error(`[HOOK ERROR] ${error.message}`);
    console.log(JSON.stringify({ continue: true }));
    clearTimeout(_timeout);
    process.exit(1);
  }
});
