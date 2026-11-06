import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// SessionList calls:
//   invoke('list_sessions', { baseDir })  — on mount + 5s poll

const mockInvoke = vi.fn();
const mockHomeDir = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => mockHomeDir(),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import SessionList from "./SessionList.svelte";
import { setMachineRotationEnabled } from "../stores/machineRotation.svelte";

// Flush async effects: the component's $effect fires fetchSessions
// which awaits homeDir → join → Promise.all(invoke, invoke), then
// Svelte re-renders. State mutations inside the effect add cycles.
async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function sessionCalls() {
  return mockInvoke.mock.calls.filter(([cmd]) => cmd === "list_sessions");
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
  handle_pid: 1234,
  rotation_eligible: true,
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
  handle_pid: 5678,
  rotation_eligible: true,
};

function rotationView(
  mode: "default" | "on" | "off" | "unreadable",
  machine_enabled: boolean,
  effective: boolean,
  pid = 1234,
) {
  return { pid, mode, machine_enabled, effective };
}

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    list_sessions: [SESSION_1, SESSION_2],
    get_session_rotation: rotationView("default", false, false),
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
    setMachineRotationEnabled(null);
    mockHomeDir.mockReset().mockResolvedValue("/home/test");
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
    vi.useRealTimers();
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

  it("keeps one session read in flight and resumes polling after it settles", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<(typeof SESSION_1)[]>();
    mockInvoke.mockReturnValue(pending.promise);
    const { container } = render(SessionList);
    await settle();
    expect(sessionCalls()).toHaveLength(1);
    vi.advanceTimersByTime(15000);
    await settle();
    expect(sessionCalls()).toHaveLength(1);

    pending.resolve([SESSION_1]);
    await settle();
    expect(container.textContent).toContain("project-a");
    setupMocks({ list_sessions: [SESSION_2] });
    vi.advanceTimersByTime(5000);
    await settle();
    expect(sessionCalls()).toHaveLength(2);
    expect(container.textContent).toContain("My Session");
    expect(container.textContent).not.toContain("project-a");
  });

  it("resumes session polling after a pending read rejects", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<unknown>();
    mockInvoke.mockReturnValue(pending.promise);
    const { container } = render(SessionList);
    await settle();
    pending.reject(new Error("slow session read failed"));
    await settle();
    expect(container.textContent).toContain("slow session read failed");
    setupMocks();
    vi.advanceTimersByTime(5000);
    await settle();
    expect(sessionCalls()).toHaveLength(2);
    expect(container.textContent).toContain("project-a");
    expect(container.textContent).not.toContain("slow session read failed");
  });

  it("discards a late session error and stops polling on unmount", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<unknown>();
    mockInvoke.mockReturnValue(pending.promise);
    const { unmount } = render(SessionList);
    await settle();
    await unmount();
    const formatError = vi.fn(() => "late failure");
    pending.reject({ toString: formatError });
    await settle();
    // Formatting the rejection would write the error state after teardown.
    expect(formatError).not.toHaveBeenCalled();
    vi.advanceTimersByTime(15000);
    await settle();
    expect(sessionCalls()).toHaveLength(1);
  });

  it("does not start a session invocation if path lookup completes after unmount", async () => {
    const home = deferred<string>();
    mockHomeDir.mockReturnValue(home.promise);
    const { unmount } = render(SessionList);
    await settle();
    await unmount();
    home.resolve("/home/test");
    await settle();
    expect(sessionCalls()).toHaveLength(0);
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

  // C6 (journal `operator-surfaces`, same class as AccountList's C2): a
  // ROW can match (`has_quota=true`) while carrying a window for only
  // ONE of the two labels — e.g. a weekly-only plan with a `seven_day`
  // window and no `five_hour` one. Before this fix, `SessionView`'s
  // `five_hour_pct`/`seven_day_pct` were plain `f64` sourced from the
  // lossy accessors (`unwrap_or(0.0)`), so the absent window and a real
  // 0% reading both serialized as `0` and rendered identically. This
  // pins the fix: the absent window renders "idle"/"—" (the SAME
  // vocabulary AccountList.svelte's `emptyLabel` uses), and the present
  // window still renders its real percentage.
  it("C6: a row with only a 7-day window renders the absent 5-hour window as idle, not 0%", async () => {
    const weeklyOnlySession = {
      ...SESSION_1,
      pid: 9001,
      account_id: 22,
      account_label: "WeeklyOnly",
      has_quota: true,
      five_hour_pct: null,
      seven_day_pct: 12.0,
    };
    setupMocks({ list_sessions: [weeklyOnlySession] });
    const { container } = render(SessionList);
    await settle();
    // Not the whole-row "n/a" fallback — a row DID match.
    expect(
      container.querySelector('[data-testid="session-quota-na"]'),
    ).toBeNull();
    const emptyBadge = container.querySelector(
      '[data-testid="session-quota-5h-na"]',
    );
    expect(emptyBadge).not.toBeNull();
    expect(emptyBadge?.textContent).toContain("idle");
    const presentBadge = container.querySelector(
      '[data-testid="session-quota-7d-na"]',
    );
    expect(presentBadge).toBeNull();
    const badges = container.querySelectorAll(".quota-badge");
    expect(badges.length).toBe(2);
    expect(container.textContent).toContain("12%");
    // The absent 5h window must never be fabricated as a real "0%" reading.
    expect(container.textContent).not.toContain("0%");
  });

  it("C6: a row with only a 5-hour window renders the absent 7-day window as —, not 0%", async () => {
    const dailyOnlySession = {
      ...SESSION_1,
      pid: 9002,
      account_id: 23,
      account_label: "DailyOnly",
      has_quota: true,
      five_hour_pct: 34.0,
      seven_day_pct: null,
    };
    setupMocks({ list_sessions: [dailyOnlySession] });
    const { container } = render(SessionList);
    await settle();
    expect(
      container.querySelector('[data-testid="session-quota-na"]'),
    ).toBeNull();
    const emptyBadge = container.querySelector(
      '[data-testid="session-quota-7d-na"]',
    );
    expect(emptyBadge).not.toBeNull();
    expect(emptyBadge?.textContent).toContain("—");
    expect(container.textContent).toContain("34%");
    expect(container.textContent).not.toContain("0%");
  });

  it("has_quota===false still renders the single n/a fallback badge, not per-window empties", async () => {
    const unpolledSession = {
      ...SESSION_1,
      pid: 9003,
      has_quota: false,
      five_hour_pct: null,
      seven_day_pct: null,
    };
    setupMocks({ list_sessions: [unpolledSession] });
    const { container } = render(SessionList);
    await settle();
    expect(
      container.querySelector('[data-testid="session-quota-na"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-testid="session-quota-5h-na"]'),
    ).toBeNull();
    expect(
      container.querySelector('[data-testid="session-quota-7d-na"]'),
    ).toBeNull();
    expect(container.querySelectorAll(".quota-badge").length).toBe(1);
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
  // ── Per-session auto-swap control ───────────────────────────

  function rotationCalls(cmd: string) {
    return mockInvoke.mock.calls.filter(([c]) => c === cmd);
  }
  function rotationText(container: HTMLElement, pid: number) {
    return container.querySelector(`[data-testid="session-rotation-${pid}"]`)?.textContent ?? "";
  }

  it.each([
    ["default", false, false, "Auto-swap: off (following machine setting)"],
    ["default", true, true, "Auto-swap: on (following machine setting)"],
    ["on", false, true, "Auto-swap: on (this session)"],
    ["off", true, false, "Auto-swap: off (this session)"],
    ["unreadable", true, false, "Setting damaged \u2014 treated as off"],
  ] as const)("renders rotation mode %s (machine %s)", async (mode, machine, effective, text) => {
    setupMocks({ get_session_rotation: rotationView(mode, machine, effective) });
    const { container } = render(SessionList);
    await settle();
    expect(rotationText(container, 1234)).toContain(text);
    expect(rotationCalls("get_session_rotation")[0][1]).toEqual({
      baseDir: "/home/test/.claude/accounts",
      pid: 1234,
    });
  });

  it("clicking On calls set_session_rotation and renders the returned view", async () => {
    const { container, getByTestId } = render(SessionList);
    await settle();
    // The mock answers the write with a view that differs from any local guess
    // (effective stays reported by the backend), proving no optimistic render.
    mockResponses.set_session_rotation = rotationView("on", false, true);
    getByTestId("session-rotation-1234-on").click();
    await settle();
    const calls = rotationCalls("set_session_rotation");
    expect(calls).toHaveLength(1);
    expect(calls[0][1]).toEqual({
      baseDir: "/home/test/.claude/accounts",
      pid: 1234,
      mode: "on",
    });
    expect(rotationText(container, 1234)).toContain("Auto-swap: on (this session)");
    expect(getByTestId("session-rotation-1234-on").getAttribute("aria-pressed")).toBe("true");
  });

  it("does not show the clicked value before the backend answers", async () => {
    const { container, getByTestId } = render(SessionList);
    await settle();
    const pending = deferred<unknown>();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "set_session_rotation" ? pending.promise : Promise.resolve(mockResponses[cmd]),
    );
    getByTestId("session-rotation-1234-on").click();
    await settle();
    expect(rotationText(container, 1234)).toContain("following machine setting");
    pending.resolve(rotationView("on", false, true));
    await settle();
    expect(rotationText(container, 1234)).toContain("(this session)");
  });

  it("renders an inline plain-language error when the write is refused", async () => {
    const { container, getByTestId } = render(SessionList);
    await settle();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "set_session_rotation"
        ? Promise.reject("rotation settings are unreadable")
        : Promise.resolve(mockResponses[cmd]),
    );
    getByTestId("session-rotation-1234-off").click();
    await settle();
    const err = getByTestId("session-rotation-1234-error");
    expect(err.textContent).toContain("Couldn't change this session's auto-swap setting.");
    expect(err.textContent).toContain("rotation settings are unreadable");
    // The stored value stays what the backend last reported.
    expect(rotationText(container, 1234)).toContain("following machine setting");
  });

  it("renders an inline error when the read fails", async () => {
    setupMocks();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_session_rotation") return Promise.reject("rotation settings are unreadable");
      return Promise.resolve(mockResponses[cmd]);
    });
    const { getByTestId } = render(SessionList);
    await settle();
    expect(getByTestId("session-rotation-1234-error").textContent).toContain(
      "Couldn't read this session's auto-swap setting.",
    );
  });

  it("offers a reset to default for a damaged setting", async () => {
    setupMocks({ get_session_rotation: rotationView("unreadable", true, false) });
    const { container, getByTestId } = render(SessionList);
    await settle();
    expect(container.querySelector('[data-testid="session-rotation-1234-on"]')).toBeNull();
    mockResponses.set_session_rotation = rotationView("default", true, true);
    getByTestId("session-rotation-1234-reset").click();
    await settle();
    expect(rotationCalls("set_session_rotation")[0][1]).toMatchObject({ mode: "default" });
    expect(rotationText(container, 1234)).toContain("Auto-swap: on (following machine setting)");
  });

  // C2: the backend's one eligibility answer gates the control.
  it("shows no control on a row the rotator can never move", async () => {
    setupMocks({ list_sessions: [{ ...SESSION_1, rotation_eligible: false }] });
    const { container } = render(SessionList);
    await settle();
    expect(container.querySelector('[data-testid="session-rotation-1234"]')).toBeNull();
    expect(rotationCalls("get_session_rotation")).toHaveLength(0);
  });

  it("shows no control when the backend omits the eligibility answer", async () => {
    const { rotation_eligible: _drop, ...older } = SESSION_1;
    setupMocks({ list_sessions: [older] });
    const { container } = render(SessionList);
    await settle();
    expect(container.querySelector('[data-testid="session-rotation-1234"]')).toBeNull();
  });

  // C1: the control addresses the terminal's handle dir, not the claude process.
  it("reads and writes rotation by handle_pid, not the claude process id", async () => {
    setupMocks({
      list_sessions: [{ ...SESSION_1, pid: 99, handle_pid: 1200 }],
      get_session_rotation: rotationView("default", false, false, 1200),
    });
    const { getByTestId } = render(SessionList);
    await settle();
    expect(rotationCalls("get_session_rotation")[0][1]).toEqual({
      baseDir: "/home/test/.claude/accounts",
      pid: 1200,
    });
    mockResponses.set_session_rotation = rotationView("on", false, true, 1200);
    getByTestId("session-rotation-1200-on").click();
    await settle();
    expect(rotationCalls("set_session_rotation")[0][1]).toMatchObject({ pid: 1200, mode: "on" });
    expect(rotationCalls("get_session_rotation").some(([, a]) => a.pid === 99)).toBe(false);
  });

  it("shows no control for a session without a handle dir", async () => {
    setupMocks({ list_sessions: [{ ...SESSION_1, handle_pid: null }] });
    const { container } = render(SessionList);
    await settle();
    expect(container.querySelector('[data-testid="session-rotation-1234"]')).toBeNull();
    expect(rotationCalls("get_session_rotation")).toHaveLength(0);
  });

  // C6: a row following the machine setting tracks the Settings toggle.
  it("a row following the machine setting re-derives when the machine setting changes", async () => {
    setupMocks({ get_session_rotation: rotationView("default", false, false) });
    const { container } = render(SessionList);
    await settle();
    expect(rotationText(container, 1234)).toContain("Auto-swap: off (following machine setting)");
    setMachineRotationEnabled(true);
    await settle();
    expect(rotationText(container, 1234)).toContain("Auto-swap: on (following machine setting)");
    // A row with its own setting does not follow it.
    setMachineRotationEnabled(false);
    await settle();
    expect(rotationText(container, 1234)).toContain("Auto-swap: off (following machine setting)");
  });

  // Corr N3: the CLI changed the machine setting after Settings last loaded it.
  it("a stale stored machine setting does not override a fresher backend read", async () => {
    setMachineRotationEnabled(true); // stale: Settings loaded it before the CLI turned it off
    setupMocks({ get_session_rotation: rotationView("default", false, false) });
    const { container } = render(SessionList);
    await settle();
    expect(rotationText(container, 1234)).toContain("Auto-swap: off (following machine setting)");
  });

  it("a row with its own setting ignores the machine setting", async () => {
    setupMocks({ get_session_rotation: rotationView("on", false, true) });
    const { container } = render(SessionList);
    await settle();
    setMachineRotationEnabled(false);
    await settle();
    expect(rotationText(container, 1234)).toContain("Auto-swap: on (this session)");
  });

  it("reads rotation once per row, not on the poll", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    render(SessionList);
    await settle();
    const before = rotationCalls("get_session_rotation").length;
    vi.advanceTimersByTime(15000);
    await settle();
    expect(before).toBe(2);
    expect(rotationCalls("get_session_rotation")).toHaveLength(before);
  });
});
