/**
 * Shared utility: Per-project learning directory resolution and observation logging.
 *
 * Used by all hooks and learning scripts to ensure observations are stored
 * per-project (in <project>/.claude/learning/) rather than globally.
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Resolve the learning directory for a given project.
 *
 * Priority:
 *   1. CSQ_LEARNING_DIR env var (for testing)
 *   2. <cwd>/.claude/learning/ (per-project)
 *   3. ~/.claude/csq-learning/ (fallback when no cwd given)
 *
 * @param {string} [cwd] - Project working directory
 * @returns {string} Absolute path to the learning directory
 */
function resolveLearningDir(cwd) {
  if (process.env.CSQ_LEARNING_DIR) {
    return process.env.CSQ_LEARNING_DIR;
  }
  if (cwd) {
    return path.join(cwd, ".claude", "learning");
  }
  return path.join(os.homedir(), ".claude", "csq-learning");
}

/**
 * Ensure the learning directory and its subdirectories exist.
 *
 * @param {string} [cwd] - Project working directory
 * @returns {string} The resolved learning directory path
 */
function ensureLearningDir(cwd) {
  const learningDir = resolveLearningDir(cwd);

  // Only create the top-level dir + observations archive. The instincts/
  // and evolved/ subdirectories were used by the auto-evolution loop in the
  // original Kailash template, but `scripts/learning/instinct-processor.js`
  // doesn't exist in this repo so the loop never ran. Removed.
  const dirs = [learningDir, path.join(learningDir, "observations.archive")];

  for (const dir of dirs) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch {}
  }

  // Create identity file if it doesn't exist
  const identityFile = path.join(learningDir, "identity.json");
  if (!fs.existsSync(identityFile)) {
    try {
      const identity = {
        system: "claude-squad",
        version: "2.0.0",
        created_at: new Date().toISOString(),
        learning_enabled: true,
        per_project: true,
      };
      fs.writeFileSync(identityFile, JSON.stringify(identity, null, 2));
    } catch {}
  }

  return learningDir;
}

/**
 * Append an observation to the per-project observations.jsonl file.
 *
 * @param {string} cwd - Project working directory
 * @param {string} type - Observation type (e.g. "workflow_pattern", "error_occurrence")
 * @param {Object} data - Observation data payload
 * @param {Object} [context] - Additional context (session_id, framework, etc.)
 */
function logObservation(cwd, type, data, context) {
  try {
    const learningDir = ensureLearningDir(cwd);
    const observationsFile = path.join(learningDir, "observations.jsonl");

    const observation = {
      id: `obs_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      type,
      data,
      context: {
        session_id: "unknown",
        cwd: cwd || process.cwd(),
        framework: "unknown",
        ...context,
      },
    };

    fs.appendFileSync(observationsFile, JSON.stringify(observation) + "\n");
    return observation.id;
  } catch {
    return null;
  }
}

/**
 * Count observations in the current observations.jsonl file.
 *
 * @param {string} learningDir - Learning directory path
 * @returns {number} Number of observations
 */
function countObservations(learningDir) {
  try {
    const observationsFile = path.join(learningDir, "observations.jsonl");
    if (!fs.existsSync(observationsFile)) return 0;
    const content = fs.readFileSync(observationsFile, "utf8");
    return content
      .trim()
      .split("\n")
      .filter((l) => l).length;
  } catch {
    return 0;
  }
}

module.exports = {
  resolveLearningDir,
  ensureLearningDir,
  logObservation,
  countObservations,
};
