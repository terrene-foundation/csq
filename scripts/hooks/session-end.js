#!/usr/bin/env node
/**
 * Hook: session-end
 * Event: SessionEnd
 * Purpose: Save a session checkpoint to ~/.claude/sessions/ for resume,
 *          log a session_summary observation, clean up old session files.
 *
 * csq-specific. The original Kailash version called auto-processing functions
 * in `../learning/instinct-processor` and `../learning/instinct-evolver` —
 * neither of those modules exists in this repo. Their require()s threw and
 * were silently swallowed by the surrounding try/catch, so the "auto-evolve"
 * loop never actually ran. Removed.
 *
 * Exit Codes:
 *   0 = success (continue)
 *   2 = blocking error (stop tool execution)
 *   other = non-blocking error (warn and continue)
 */

const fs = require("fs");
const path = require("path");
const {
  resolveLearningDir,
  ensureLearningDir,
  logObservation: logLearningObservation,
} = require("./lib/learning-utils");

// Timeout fallback — prevents hanging the Claude Code session
const TIMEOUT_MS = 10000;
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
    saveSession(data);
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

function saveSession(data) {
  // Sanitize session_id to prevent path traversal
  const session_id = (data.session_id || "").replace(/[^a-zA-Z0-9_-]/g, "_");
  const cwd = data.cwd;
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  const sessionDir = path.join(homeDir, ".claude", "sessions");

  // Ensure directories exist
  try {
    fs.mkdirSync(sessionDir, { recursive: true });
  } catch {}
  ensureLearningDir(cwd);

  const sessionData = {
    session_id,
    cwd,
    endedAt: new Date().toISOString(),
  };

  try {
    // Save to session-specific file
    const sessionFile = path.join(sessionDir, `${session_id}.json`);
    fs.writeFileSync(sessionFile, JSON.stringify(sessionData, null, 2));

    // Save as last session for quick resume
    const lastSessionFile = path.join(sessionDir, "last-session.json");
    fs.writeFileSync(lastSessionFile, JSON.stringify(sessionData, null, 2));

    // Log a minimal session_summary observation for the learning system
    try {
      logLearningObservation(
        cwd,
        "session_summary",
        { duration_estimate: estimateSessionDuration(session_id, sessionDir) },
        { session_id },
      );
    } catch {}

    // Clean up old sessions (keep last 20)
    cleanupOldSessions(sessionDir, 20);
  } catch {}
}

function estimateSessionDuration(sessionId, sessionDir) {
  try {
    const sessionFile = path.join(sessionDir, `${sessionId}.json`);
    if (fs.existsSync(sessionFile)) {
      const data = JSON.parse(fs.readFileSync(sessionFile, "utf8"));
      if (data.startedAt) {
        const start = new Date(data.startedAt).getTime();
        const end = Date.now();
        return Math.round((end - start) / 1000); // seconds
      }
    }
    return null;
  } catch {
    return null;
  }
}

function cleanupOldSessions(sessionDir, keepCount) {
  try {
    const files = fs
      .readdirSync(sessionDir)
      .filter((f) => f.endsWith(".json") && f !== "last-session.json")
      .map((f) => ({
        name: f,
        path: path.join(sessionDir, f),
        mtime: fs.statSync(path.join(sessionDir, f)).mtime,
      }))
      .sort((a, b) => b.mtime - a.mtime);

    for (const file of files.slice(keepCount)) {
      try {
        fs.unlinkSync(file.path);
      } catch {}
    }
  } catch {}
}
