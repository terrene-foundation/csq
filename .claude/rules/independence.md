---
name: independence
description: Foundation independence rules — no commercial references, no proprietary awareness, Terrene Foundation ownership.
---

# Foundation Independence Rules

## Scope

These rules apply to ALL files in this repository — code, documentation, configuration, comments, commit messages, and agent conversations.

## MUST Rules

### 1. claude-squad Is a Terrene Foundation Tool

claude-squad is owned by the Terrene Foundation (Singapore CLG). It is an independent open-source tool for managing Claude Code multi-account rotation. All design decisions must be made on the tool's own merits — what is best for its users and the open-source community.

**Why**: claude-squad is Foundation-owned and irrevocably open. It has no structural relationship with any commercial entity.

**How to apply**: Features land if they help the people who run multiple Claude Code sessions. They don't land because they benefit any commercial product.

### 2. No Commercial References

MUST NOT reference, discuss, compare with, or design against any commercial or proprietary product:

- Proprietary product names (do not name them, do not compare against them)
- Commercial entities (no company names, no commercial partnerships)
- Market positioning or competitive differentiation
- Commercial deployment models (managed hosting, enterprise pricing, SaaS)

**Why**: Introducing commercial references — even for comparison — creates implicit coupling and suggests a relationship that does not exist.

**How to apply**: If you find yourself writing "unlike X" or "the open-source version of Y" — stop. Describe what claude-squad does on its own terms.

### 3. Foundation-Only and Upstream Dependencies

claude-squad MUST depend only on:

- **Python 3 standard library** (the engine is intentionally stdlib-only, plus `ctypes` on Windows)
- **POSIX/macOS/Windows system tools** available by default (`bash`, `jq`, `security` on macOS, `mklink` on Windows)
- **Claude Code itself** — the one upstream we integrate with

MUST NOT add PyPI dependencies, Node modules, Rust crates, or any other third-party runtime requirement. The tool must remain installable with a single `./install.sh` on a vanilla system.

**Why**: Every dependency is a potential point of failure across 15 concurrent terminals and five platforms. The tool manages credentials; every imported package is attack surface. stdlib-only keeps both blast radius and install friction near zero.

**How to apply**: Before adding `import foo`, check if it's in the stdlib. If not, write it yourself or don't do it.

### 4. No "Open-Source Version Of" Language

MUST NOT describe claude-squad as "the open-source version of [anything]" or "the [X] port of [anything]." claude-squad IS the tool — it is not a derivative, port, or counterpart.

**Correct**: "claude-squad is a Terrene Foundation tool for Claude Code multi-account rotation."
**Incorrect**: "claude-squad is the open-source version of [product name]."

**Why:** "Open-source version of X" framing positions claude-squad as derivative of a commercial product and creates an implicit trademark entanglement that does not legally exist.

### 5. Design for csq Users

All feature decisions, architectural choices, and roadmap priorities must be driven by:

- What csq users need (people running many CC sessions on many accounts)
- What Python/bash developers expect from a cross-platform CLI tool
- What the open-source community contributes

Never by what any commercial product does, doesn't do, or plans to do.

**Why:** Designing for a hypothetical commercial consumer biases the API surface away from the actual csq user base, making the tool awkward for the people who actually depend on it.

## MUST NOT Rules

### 1. No Proprietary Codebase Awareness

Code, comments, and documentation MUST NOT demonstrate awareness of any proprietary codebase. Do not:

- Reference proprietary file paths, module names, or architecture patterns
- Suggest "compatibility" or "interop" with proprietary systems
- Design APIs "so that [proprietary product] can also use them"

**Why**: claude-squad's only upstream is Claude Code itself, which is Anthropic's official CLI. That integration is inherent. Every other integration is gratuitous coupling.

### 2. No Commercial Strategy Discussion

MUST NOT discuss in any file:

- Revenue models, pricing, or monetization
- Enterprise vs community feature splits
- Commercial licensing considerations
- Market competition or positioning

**Why:** Commercial strategy content drifts the tool's design into "what would a buyer want" territory, distorting feature priority away from the user base the Foundation actually serves.

### 3. No Cross-Codebase Coupling

MUST NOT:

- Share code, interfaces, or protocols designed for a specific proprietary product
- Create abstractions whose primary purpose is proprietary product compatibility
- Design extension points that assume a specific proprietary implementation

**Why:** Every proprietary-shaped abstraction constrains future architecture decisions and ties claude-squad's evolution to a product it has no agreement with.

## Clarification

Third parties may build commercial products on top of csq. That is the intended open-source model. But the tool itself has zero knowledge of, zero dependency on, and zero design consideration for any such product.
