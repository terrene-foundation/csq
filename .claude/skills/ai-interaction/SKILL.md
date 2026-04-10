---
name: ai-interaction
description: "AI interaction design patterns adapted for desktop applications. Use when designing how users interact with AI features in the app — quota display, account switching feedback, session state, AI disclosure, or any feature involving AI model access and rotation."
---

# AI Interaction Patterns (Desktop)

AI-specific interaction patterns for desktop applications that manage AI account rotation and quota. Adapted from Shape of AI pattern library for the desktop context.

## How This Differs from Web AI UX

| Aspect              | Web AI App              | Desktop AI Account Manager        |
| ------------------ | ---------------------- | -------------------------------- |
| Session length      | Short, discrete tasks | Long, persistent sessions        |
| State visibility   | Full page re-render   | Incremental status updates       |
| Account context    | Single user            | Multi-account, rotating          |
| Trust surface      | AI output disclosure   | AI access + quota + rotation     |

## Key Patterns for This App

### 1. Quota Display

Show usage as a **progress bar + fraction** (e.g., "67 / 100 messages — 67% used"). Always include:
- Current usage number
- Limit number
- Percentage
- Visual indicator (color-coded: green < 70%, yellow 70-90%, red > 90%)

```svelte
<div class="quota-display">
  <span class="quota-label">Monthly quota</span>
  <div class="progress-bar">
    <div class="fill {quotaLevel}" style="width: {pct}%"></div>
  </div>
  <span class="quota-text">{used} / {limit} — {pct}% used</span>
</div>
```

### 2. Account Switch Feedback

On swap, show **immediate visual confirmation** + **async verification**:

```
[Spinner] Switching to account 2...
  ↓
[Checkmark] Switched to account 2 (claude@...com)
  ↓ (if quota check fails)
[Warning] Account 2 quota exceeded — swap declined
```

Never perform the swap without confirming the new account's quota is available.

### 3. Rotation Decision

When auto-rotate triggers, present **human-in-the-loop** choice:

```
"Account 1 quota exhausted at 67%. Switch to:
  [Account 2] 23/100 — most available
  [Account 3] 89/100 — near limit
  [Account 4] 0/100 — unused
[Auto-switch to most available] [Choose manually] [Pause rotation]"
```

### 4. AI Disclosure

When displaying AI-generated content (suggestions, model names), apply **disclosure pattern**:
- Model name visible when relevant (not hidden)
- No simulated "AI is thinking" when doing simple lookups
- Distinguish API quota (your consumption) from model output (AI response)

### 5. Error Recovery

| Error                    | User Message                                      | Action                      |
| ------------------------ | ------------------------------------------------ | -------------------------- |
| Token expired             | "Session expired — re-authenticating..."         | Auto-refresh + retry       |
| Quota exceeded            | "Quota reached for this account"                  | Prompt swap or wait        |
| Network failure           | "Connection lost — retrying..."                  | Auto-retry with backoff    |
| Refresh token invalid    | "Authentication expired — please log in again"    | Open auth flow             |

## Trust Signals for Multi-Account Management

Users managing multiple AI accounts need these trust signals:
- **Which account is active** — always prominently displayed
- **Quota freshness** — last refreshed timestamp
- **Rotation history** — last N swaps (last 5 is sufficient)
- **Why rotation happened** — "rotated because Account 1 hit 90% quota"

## CRITICAL Gotchas

| Rule                                           | Why                                                     |
| ---------------------------------------------- | ------------------------------------------------------- |
| Never swap without quota check                 | Could land on an exhausted account                      |
| Always show current account + quota            | Core value proposition; hide = erode trust            |
| Auto-rotation requires human override option   | Users must be able to refuse rotation                  |
| Show rotation reason to user                   | "Why did it switch?" is the first question users ask   |
| Quota refresh must be visible (not silent)     | Stale quota data makes users distrust the app           |
