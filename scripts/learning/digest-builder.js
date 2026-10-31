#!/usr/bin/env node
"use strict";
// The delivered hook library owns aggregation; this file retains the CLI.
const { buildDigest, loadObservations, getStats } = require("../../.claude/hooks/lib/learning-digest");

// --- Main execution ---
if (require.main === module) {
  const args = process.argv.slice(2);

  if (args.includes("--help")) {
    console.log(`
Digest Builder for Learning System

Reads observations.jsonl and produces learning-digest.json for /codify.

Usage:
  node digest-builder.js          Build digest from observations
  node digest-builder.js --stats  Show observation statistics
  node digest-builder.js --help   Show this help
`);
    process.exit(0);
  }

  if (args.includes("--stats")) {
    console.log(JSON.stringify(getStats(), null, 2));
    process.exit(0);
  }

  // Default: build digest
  const cwd = process.cwd();
  const digest = buildDigest(cwd);
  if (digest) {
    console.log(
      JSON.stringify(
        {
          success: true,
          period: digest.period,
          corrections: digest.corrections.length,
          error_patterns: digest.error_patterns.length,
          accomplishments: digest.accomplishments.length,
          decisions: digest.decisions.length,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(JSON.stringify({ success: false, reason: "no observations" }));
  }
  process.exit(0);
}

module.exports = { buildDigest, loadObservations, getStats };
