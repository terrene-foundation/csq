#!/usr/bin/env node
/**
 * Hook: validate-workflow
 * Event: PostToolUse (matcher: Edit|Write)
 * Purpose: Block csq-specific anti-patterns in modified Python/bash files.
 *
 * Replaced the 1060-line Kailash Rust SDK version with a csq-specific stub.
 * csq is a Python + bash OAuth rotation tool. The patterns we care about
 * are different from the Kailash SDK's (no Rust, no Cargo, no nodes/workflows).
 *
 * Anti-patterns we BLOCK (exit 2):
 *   - Hardcoded refresh tokens / access tokens / API keys in source
 *   - shell=True with f-string interpolation in subprocess.run
 *   - bare `except: pass` in non-test files (silently swallowing errors)
 *
 * Anti-patterns we WARN about (exit 0 with stderr message):
 *   - Direct `os.replace()` instead of `_atomic_replace()` in rotation-engine.py
 *   - Direct `os.kill(pid, 0)` instead of `_is_pid_alive()` (cross-platform)
 *
 * Exit Codes:
 *   0 = success / warn-only
 *   2 = blocking error (hard anti-pattern in production code)
 */

const fs = require("fs");

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
    const data = JSON.parse(input || "{}");
    const filePath = (data.tool_input || {}).file_path || "";

    // Only check our source files (skip tests)
    const relevant =
      /\.(py|sh|js)$/i.test(filePath) &&
      !/(test_|_test\.|\.test\.|\.spec\.|__tests__\/|\/tests\/)/i.test(
        filePath,
      );

    if (!relevant) {
      console.log(JSON.stringify({ continue: true }));
      clearTimeout(_timeout);
      return;
    }

    let contents = "";
    try {
      contents = fs.readFileSync(filePath, "utf8");
    } catch {
      console.log(JSON.stringify({ continue: true }));
      clearTimeout(_timeout);
      return;
    }

    const lines = contents.split("\n");
    const blockingFindings = [];
    const warningFindings = [];

    // BLOCK: hardcoded OAuth/API tokens
    const tokenPatterns = [
      /["'](sk-ant-ort01-[A-Za-z0-9_-]{20,})["']/, // Anthropic refresh token
      /["'](sk-ant-oat01-[A-Za-z0-9_-]{20,})["']/, // Anthropic OAuth access token
      /["'](sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{20,})["']/, // Anthropic API key
    ];
    lines.forEach((line, i) => {
      for (const pat of tokenPatterns) {
        if (pat.test(line)) {
          blockingFindings.push(
            `${filePath}:${i + 1}: hardcoded Anthropic token in source`,
          );
        }
      }
    });

    // BLOCK: shell=True with f-string in subprocess
    if (filePath.endsWith(".py")) {
      lines.forEach((line, i) => {
        if (
          /subprocess\.(run|Popen|call|check_output)\([^)]*shell\s*=\s*True/.test(
            line,
          ) &&
          /f["']/.test(line)
        ) {
          blockingFindings.push(
            `${filePath}:${i + 1}: shell=True with f-string interpolation (command injection risk)`,
          );
        }
      });
    }

    // BLOCK: bare except: pass in production .py files (not tests)
    if (filePath.endsWith(".py")) {
      const text = contents;
      const bareExceptPass = /except\s*:\s*\n\s*pass\b/g;
      let m;
      while ((m = bareExceptPass.exec(text)) !== null) {
        const lineNum = text.substring(0, m.index).split("\n").length;
        blockingFindings.push(
          `${filePath}:${lineNum}: bare 'except: pass' silently swallows errors`,
        );
      }
    }

    // WARN: direct os.replace() in rotation-engine.py (use _atomic_replace)
    if (/rotation-engine\.py$/.test(filePath)) {
      lines.forEach((line, i) => {
        if (/\bos\.replace\(/.test(line) && !/_atomic_replace/.test(line)) {
          // Allow inside the definition of _atomic_replace itself: scan
          // up to 10 preceding lines for `def _atomic_replace`.
          let insideAtomicReplace = false;
          for (let j = Math.max(0, i - 10); j < i; j++) {
            if (/def _atomic_replace/.test(lines[j])) {
              insideAtomicReplace = true;
              break;
            }
          }
          if (!insideAtomicReplace) {
            warningFindings.push(
              `${filePath}:${i + 1}: prefer _atomic_replace() over os.replace() (Windows retry handling)`,
            );
          }
        }
        if (/\bos\.kill\([^)]*,\s*0\)/.test(line)) {
          warningFindings.push(
            `${filePath}:${i + 1}: prefer _is_pid_alive() over os.kill(pid, 0) (cross-platform)`,
          );
        }
      });
    }

    if (blockingFindings.length > 0) {
      console.error("[validate-workflow] BLOCKING anti-patterns found:");
      blockingFindings.forEach((f) => console.error("  " + f));
      console.log(
        JSON.stringify({
          continue: false,
          stopReason: blockingFindings.join("\n"),
        }),
      );
      clearTimeout(_timeout);
      process.exit(2);
    }

    if (warningFindings.length > 0) {
      console.error("[validate-workflow] warnings:");
      warningFindings.forEach((f) => console.error("  " + f));
    }

    console.log(JSON.stringify({ continue: true }));
    clearTimeout(_timeout);
  } catch (e) {
    console.error("[validate-workflow] error:", e.message);
    console.log(JSON.stringify({ continue: true }));
    clearTimeout(_timeout);
    process.exit(0); // non-blocking on error
  }
});
