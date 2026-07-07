import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// SessionList calls:
//   invoke('list_sessions', { baseDir })  — on mount + 5s poll

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import SessionList from "./SessionList.svelte";

// Flush async effects: the component's $effect fires fetchSessions
// which awaits homeDir → join → Promise.all(invoke, invoke), then
// Svelte re-renders. State mutations inside the effect add cycles.
async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

// ── Fixtures ───────────────────────────────────────────────────────

const SESSION_1 = {
  pid: 1234,
  cwd: "/Users/example/repos/project-a",
  config_dir: "/Users/example/.claude/accounts/term-1234",
  account_id: 1,
  account_label: "Work",
  five_hour_pct: 25.0,
  seven_day_pct: 40.0,
  started_at: Math.floor(Date.now() / 1000) - 3600,
  tty: "/dev/ttys001",
  term_window: 1,
  term_tab: 1,
  term_pane: 0,
  iterm_profile: "Default",
  terminal_title: null,
};

const SESSION_2 = {
  pid: 5678,
  cwd: "/Users/example/repos/project-b",
  config_dir: "/Users/example/.claude/accounts/term-5678",
  account_id: 2,
  account_label: "Personal",
  five_hour_pct: 90.0,
  seven_day_pct: 100.0,
  started_at: Math.floor(Date.now() / 1000) - 120,
  tty: "/dev/ttys002",
  term_window: 1,
  term_tab: 2,
  term_pane: 0,
  iterm_profile: "Default",
  terminal_title: "My Session",
};

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    list_sessions: [SESSION_1, SESSION_2],
    ...overrides,
  };
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in mockResponses) {
      return Promise.resolve(mockResponses[cmd]);
    }
    return Promise.resolve(undefined);
  });
}

describe("SessionList", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    setupMocks();
    try {
      localStorage.removeItem("csq-session-sort");
      localStorage.removeItem("csq-session-order");
      localStorage.removeItem("csq-session-names");
    } catch {
      // Node.js built-in localStorage may not support all methods
    }
  });

  afterEach(() => {
    cleanup();
  });

  // ── Loading & empty states ──────────────────────────────────

  it("renders loading state on mount", () => {
    const { container } = render(SessionList);
    expect(container.textContent).toContain("Loading sessions");
  });

  it("renders empty state when no sessions", async () => {
    setupMocks({ list_sessions: [] });
    const { container } = render(SessionList);
    await settle();
    expect(container.textContent).toContain("No live Claude Code sessions");
    expect(container.textContent).toContain("claude");
  });

  // ── Session row rendering ───────────────────────────────────

  it("renders session rows with titles", async () => {
    const { container } = render(SessionList);
    await settle();
    // SESSION_1: terminal_title is null, falls through to cwd basename
    expect(container.textContent).toContain("project-a");
    // SESSION_2: terminal_title is "My Session"
    expect(container.textContent).toContain("My Session");
  });

  it("renders session paths", async () => {
    const { container } = render(SessionList);
    await settle();
    // Paths are collapsed to ~ prefix
    const paths = container.querySelectorAll(".session-path");
    expect(paths.length).toBe(2);
    expect(paths[0].textContent).toContain("~/repos/project-a");
  });

  it("renders sort control pills", async () => {
    const { container } = render(SessionList);
    await settle();
    const pills = container.querySelectorAll(".sort-pill");
    expect(pills.length).toBe(3);
    expect(pills[0].textContent).toBe("custom");
    expect(pills[1].textContent).toBe("title");
    expect(pills[2].textContent).toBe("account");
  });

  it("renders account badges for bound sessions", async () => {
    const { container } = render(SessionList);
    await settle();
    const badges = container.querySelectorAll(".account-badge");
    expect(badges.length).toBe(2);
    expect(badges[0].textContent).toContain("#1");
    expect(badges[0].textContent).toContain("Work");
  });

  it("renders quota badges with color classes", async () => {
    const { container } = render(SessionList);
    await settle();
    const quotaBadges = container.querySelectorAll(".quota-badge");
    // 2 sessions × 2 badges each = 4
    expect(quotaBadges.length).toBe(4);
    // SESSION_1: 25% 5h → ok
    expect(quotaBadges[0].classList.contains("quota-ok")).toBe(true);
    // SESSION_2: 90% 5h → warn, 100% 7d → error
    expect(quotaBadges[2].classList.contains("quota-warn")).toBe(true);
    expect(quotaBadges[3].classList.contains("quota-error")).toBe(true);
  });

  it("renders session age", async () => {
    const { container } = render(SessionList);
    await settle();
    const ages = container.querySelectorAll(".age");
    expect(ages.length).toBe(2);
    // SESSION_1: 3600s ago → "1h"
    expect(ages[0].textContent).toBe("1h");
    // SESSION_2: 120s ago → "2m"
    expect(ages[1].textContent).toBe("2m");
  });

  // ── No swap affordance ──────────────────────────────────────
  //
  // 2026-06-11: the per-session swap button + account picker were
  // REMOVED (the swap_session command could only ever return the
  // M4-8 DESKTOP_SWAP_UNAVAILABLE refusal — a dead flow; spec 02
  // §2.8). This regression pins the row as swap-free so the
  // affordance does not come back without a working backend.

  it("session rows render no swap button or account picker", async () => {
    const { container } = render(SessionList);
    await settle();
    expect(container.querySelector(".swap-btn")).toBeNull();
    expect(container.querySelector(".picker")).toBeNull();
    // Sessions tab only needs list_sessions — no get_accounts call.
    const commands = mockInvoke.mock.calls.map((c) => c[0]);
    expect(commands).not.toContain("get_accounts");
    expect(commands).not.toContain("swap_session");
  });

  // ── Error state ─────────────────────────────────────────────

  it("renders error when list_sessions rejects", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_sessions")
        return Promise.reject(new Error("daemon unavailable"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = render(SessionList);
    await settle();
    expect(container.textContent).toContain("daemon unavailable");
  });
});
