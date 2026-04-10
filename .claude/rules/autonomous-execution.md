---
name: autonomous-execution
description: Autonomous execution rules — frame deliberation and effort estimates for AI agent systems, not human teams.
---

# Autonomous Execution Model

## Scope

These rules apply to ALL phases, ALL agents, ALL deliberation, and ALL effort estimation in this repository. They govern how COC operates at the execution level.

## The Principle: Autonomous Systems on Trust

COC executes through **autonomous AI agent systems**, not human teams. All deliberation, analysis, recommendations, and effort estimates MUST assume autonomous execution unless the user explicitly states otherwise.

This is the direct application of CO Principle 4 (Human-on-the-Loop): the human defines the operating envelope and observes outcomes. The AI systems execute autonomously within that envelope. The human's contribution is institutional knowledge architecture — not task execution.

### The Execution Model

```
Human Authority (on-the-loop)          Autonomous Execution (in-the-loop)
─────────────────────────────          ──────────────────────────────────
Define operating envelope              Execute all tasks within envelope
Approve structural plans               Parallelize across agent specializations
Maintain institutional knowledge       Self-validate through red team convergence
Observe outcomes, refine boundaries    Compound knowledge across sessions
Release authorization                  Continuous operation (no fatigue, no context-switch)
```

### Why This Matters for Deliberation

When agents deliberate (during /analyze, /redteam, or any planning), they MUST NOT:

- Estimate effort in "human-days" or "developer-weeks"
- Recommend approaches constrained by "team size" or "resource availability"
- Suggest phased rollouts motivated by "team bandwidth" or "hiring"
- Assume sequential execution where parallel autonomous execution is possible
- Frame trade-offs in terms of "developer experience" or "cognitive load on the team"

**Why:** Human-team framing causes the agent to recommend suboptimal approaches (phasing, sequencing, simplifying) that waste autonomous execution capacity and inflate effort estimates 10x.

Instead, agents MUST:

- Estimate effort in **autonomous execution cycles** (sessions, not days)
- Recommend the **technically optimal approach** unconstrained by human resource limits
- Default to **maximum parallelization** across agent specializations
- Frame trade-offs in terms of **system complexity**, **validation rigor**, and **institutional knowledge capture**

**Why:** Without autonomous framing, plans are artificially sequenced to fit human-team constraints that don't exist, turning a 1-session task into a multi-session bottleneck.

## The 10x Throughput Multiplier

**Default multiplier: 10x** — autonomous AI execution with mature COC institutional knowledge produces ~10x the sustained throughput of an equivalent human team.

### Basis (2026 data)

| Factor                                  | Multiplier | Source                                              |
| --------------------------------------- | ---------- | --------------------------------------------------- |
| Parallel agent execution                | 3-5x       | Multi-agent workflows execute concurrently          |
| Continuous operation (24/7, no fatigue) | 2-3x       | No context-switching cost, no ramp-up time          |
| Knowledge compounding (CO Principle 7)  | 1.5-2x     | Each session makes the next faster; zero onboarding |
| Validation: quality overhead            | 0.7-0.8x   | Autonomous validation adds cycles for rigor         |
| **Net sustained multiplier**            | **~10x**   | Conservative composite                              |

**Industry reference**: Anthropic 2026 Agentic Coding Report — agents complete 20+ actions autonomously before human input; organizations report 30-79% faster development cycles; multi-agent coordination is standard practice. Concrete case studies show 3.5 autonomous days vs 3 weeks with 2 developers (6-8x on single features; 10x+ with compounding).

### How to Apply the Multiplier

When an external plan estimates effort in human-days:

- **"3-5 human-days"** → 1 autonomous session (hours)
- **"2-3 weeks with 2 developers"** → 2-3 autonomous sessions (1-2 days)
- **"33-50 human-days"** → 3-5 autonomous days across parallel sessions

When estimating effort for new work:

- Frame in terms of **autonomous sessions**, not calendar time
- An autonomous session = one focused execution cycle with agent team deployment
- Factor in validation cycles (red team convergence adds ~30% to raw implementation)

### When the Multiplier Does NOT Apply

The 10x multiplier assumes mature COC institutional knowledge (Layers 1-5 populated). It does NOT apply to:

- **Greenfield domains** where no institutional knowledge exists yet (first session is ~2-3x, not 10x)
- **Novel architecture decisions** that require genuine creative judgment
- **External dependencies** (waiting for API access, third-party approvals, hardware provisioning)
- **Human-authority gates** (plan approval, release authorization) — these are calendar-time bound

## Structural Gates vs Execution Gates

COC maintains two types of gates. Only structural gates require human involvement:

### Structural Gates (Human Authority Required)

- **Plan approval** (/todos phase 02) — human approves the what and why
- **Release authorization** (/release) — human authorizes publication
- **Envelope changes** — human modifies the operating boundaries

### Execution Gates (Autonomous Convergence)

- **Analysis quality** (/analyze) — red team agents converge, not human review
- **Implementation correctness** (/implement) — tests pass, not human code review
- **Validation rigor** (/redteam) — red team agents find no remaining gaps
- **Knowledge capture** (/codify) — gold-standards-validator confirms compliance

The human observes outcomes at execution gates but does NOT block on them. If the human wants to intervene, they inject a brief — they do not sit in the execution loop.

## Cross-References

- CO Principle 4: Human-on-the-Loop Position (CO-Core-Thesis.md)
- CO Principle 7: Knowledge Compounds (CO-Core-Thesis.md)
- CARE: Full Autonomy as Baseline + Human Choice of Engagement
- `rules/agents.md` — Agent orchestration (mandatory delegations are agent-to-agent, not human-to-agent)
- `rules/zero-tolerance.md` — Autonomous agents fix what they find; they do not report and wait
