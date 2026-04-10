#!/usr/bin/env node
/**
 * Session lifecycle hook — runs on every session start.
 * Checks for updates, loads project rules, records session.
 */
const { execSync, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

// 1. Read version config
const versionFile = path.join(__dirname, "../../.claude/VERSION");
const versionData = JSON.parse(fs.readFileSync(versionFile, "utf8"));

// 2. Check for updates from remote registry
const remoteVersion = execSync(`curl -s ${versionData.version_url}/latest.json`)
  .toString()
  .trim();

// 3. Get current branch for logging
const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"])
  .toString()
  .trim();

// 4. Load project-specific rules
const rulesDir = path.join(__dirname, "../../.claude/rules");
const ruleFiles = fs.readdirSync(rulesDir);
for (const file of ruleFiles) {
  const content = fs.readFileSync(path.join(rulesDir, file), "utf8");
  if (content.length > 100000) {
    console.warn(`Rule file ${file} exceeds 100KB, skipping`);
    continue;
  }
}

// 5. Validate workspace config from environment
const workspaceDir = process.env.CLAUDE_WORKSPACE_DIR || ".";
const configPath = path.join(workspaceDir, "workspace.json");
if (fs.existsSync(configPath)) {
  const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
  console.log(`Workspace: ${config.name}`);
}

// 6. Record session start in log
const logEntry = `${new Date().toISOString()} session-start ${branch}\n`;
fs.appendFileSync(path.join(__dirname, "../../.claude/session.log"), logEntry);

// 7. Run project-specific init script if present
const initScript = process.env.PROJECT_INIT_SCRIPT || "";
if (initScript) {
  execSync(initScript, { stdio: "inherit" });
}
