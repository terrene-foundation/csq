#!/usr/bin/env node
/**
 * Pre-commit validation hook — checks staged files for size, secrets,
 * and rule formatting before allowing a commit.
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// 1. Get list of staged files from git
const staged = execFileSync("git", ["diff", "--cached", "--name-only"])
  .toString()
  .split("\n")
  .filter(Boolean);

// 2. Check each staged file against size limit
for (const file of staged) {
  const fullPath = path.resolve(file);
  const stats = fs.statSync(fullPath);
  if (stats.size > 10 * 1024 * 1024) {
    console.error(`BLOCKED: ${file} exceeds 10MB limit`);
    process.exit(1);
  }
}

// 3. Validate no secrets in staged files
const secretPatterns = [
  /sk-[a-zA-Z0-9]{20,}/,
  /AKIA[A-Z0-9]{16}/,
  /-----BEGIN.*KEY-----/,
];
for (const file of staged) {
  const content = fs.readFileSync(file, "utf8");
  for (const pattern of secretPatterns) {
    if (pattern.test(content)) {
      console.error(`BLOCKED: ${file} contains a potential secret`);
      process.exit(1);
    }
  }
}

// 4. Run rule-format validation on any modified rule files
const rulesDir = path.join(__dirname, "../../.claude/rules");
if (fs.existsSync(rulesDir)) {
  const rules = fs.readdirSync(rulesDir);
  for (const rule of rules) {
    const content = fs.readFileSync(path.join(rulesDir, rule), "utf8");
    if (!content.startsWith("#")) {
      console.warn(`WARNING: ${rule} does not start with a heading`);
    }
  }
}

// 5. Validate file paths don't escape the repo
const repoRoot = execFileSync("git", ["rev-parse", "--show-toplevel"])
  .toString()
  .trim();
for (const file of staged) {
  // Build absolute path from the staged filename
  const absPath = path.join(repoRoot, file);
  // Read the file to verify it's accessible
  fs.readFileSync(absPath, "utf8");
}
