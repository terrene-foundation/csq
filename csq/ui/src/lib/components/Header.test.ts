import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// Post settings-popover refactor, Header itself only calls:
//   invoke('get_daemon_status', { baseDir })  — on mount + 10s poll
//   getVersion()                              — on mount
//
// The Launch-on-login / Hide-Dock-icon / Open-dashboard-at-launch
// toggles moved into <SettingsPopover>. The child component fires its
// own `fetchAll()` on mount which invokes get_autostart_enabled /
// is_dock_hide_supported / get_dock_hidden / get_dashboard_at_launch.
// Those calls must be mocked so the child renders cleanly, but the
// Header-level assertions only care about title, version, and the
// daemon status indicator. Per-test mocks for popover behavior live
// in SettingsPopover.test.ts.

const mockInvoke = vi.fn();
const mockHomeDir = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => mockHomeDir(),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

// `getVersion()` backs the dynamic version string rendered in the
// header (the version-display regression replaced the hardcoded alpha.21 literal).
vi.mock("@tauri-apps/api/app", () => ({
  getVersion: () => Promise.resolve("2.0.0-test"),
}));

import Header from "./Header.svelte";

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

function statusCalls() {
  return mockInvoke.mock.calls.filter(([cmd]) => cmd === "get_daemon_status");
}

// Defaults cover Header's own get_daemon_status call AND the child
// SettingsPopover's fetchAll() chain so neither component throws.
let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    get_daemon_status: { running: false, pid: null },
    get_autostart_enabled: false,
    is_dock_hide_supported: false,
    get_dock_hidden: false,
    get_dashboard_at_launch: true,
    ...overrides,
  };
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in mockResponses) {
      return Promise.resolve(mockResponses[cmd]);
    }
    return Promise.resolve(undefined);
  });
}

describe("Header", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockHomeDir.mockReset().mockResolvedValue("/home/test");
    setupMocks();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  // ── Static content ────────────────────────────────────────────

  it("renders the app title", async () => {
    const { container } = render(Header);
    expect(container.textContent).toContain("Code Squad Q");
  });

  it("renders a version string from getVersion()", async () => {
    const { container } = render(Header);
    // getVersion() resolves asynchronously; needs a few ticks for
    // the promise to resolve and the DOM to reflect the state.
    await tick();
    await tick();
    await tick();
    const versionEl = container.querySelector(".version");
    expect(versionEl).not.toBeNull();
    expect(versionEl?.textContent).toBe("v2.0.0-test");
  });

  // ── Daemon status indicator ───────────────────────────────────
  //
  // The header keeps a compact dot + label ("Running"/"Stopped"). Detailed
  // daemon status info (with the longer "daemon running" phrasing) lives
  // in the SettingsPopover About section.

  it("surfaces the keychain orphan sweep's warning and action-needed states", async () => {
    setupMocks({
      get_daemon_status: {
        running: true,
        pid: 42,
        keychain_orphans: { level: "needs_action", summary: "needs action: enumeration_unavailable" },
      },
    });
    const { container } = render(Header);
    await settle();
    const badge = container.querySelector('[data-testid="keychain-orphans"]');
    expect(badge?.textContent?.trim()).toBe("Keychain: action needed");
    expect(badge?.getAttribute("title")).toContain("enumeration_unavailable");
  });

  it("shows nothing for the orphan sweep when it is ok, info, or never published", async () => {
    for (const keychain_orphans of [
      undefined,
      { level: "ok", summary: "none" },
      { level: "info", summary: "siblings kept" },
    ]) {
      cleanup();
      setupMocks({ get_daemon_status: { running: true, pid: 42, keychain_orphans } });
      const { container } = render(Header);
      await settle();
      expect(container.querySelector('[data-testid="keychain-orphans"]')).toBeNull();
    }
  });

  it("shows 'Stopped' label when daemon is not running", async () => {
    setupMocks({ get_daemon_status: { running: false, pid: null } });
    const { container } = render(Header);
    await tick();
    await tick();
    const statusLabel = container.querySelector(".status-label");
    expect(statusLabel?.textContent).toBe("Stopped");
    const dot = container.querySelector("header .dot") as HTMLElement;
    expect(dot.classList.contains("running")).toBe(false);
  });

  it("shows 'Running' label and green dot when daemon is running", async () => {
    setupMocks({ get_daemon_status: { running: true, pid: 42 } });
    const { container } = render(Header);
    // The daemon status poll resolves asynchronously. Svelte 5's
    // effect scheduling may need extra ticks for the promise to
    // resolve and the DOM to update.
    await tick();
    await tick();
    await tick();
    await tick();
    const statusLabel = container.querySelector(".status-label");
    expect(statusLabel?.textContent).toBe("Running");
    const dot = container.querySelector("header .dot") as HTMLElement;
    expect(dot.classList.contains("running")).toBe(true);
  });

  it("defaults to stopped state if get_daemon_status rejects", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_daemon_status")
        return Promise.reject(new Error("unavailable"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = render(Header);
    await tick();
    await tick();
    const statusLabel = container.querySelector(".status-label");
    expect(statusLabel?.textContent).toBe("Stopped");
  });

  it("keeps one status read in flight and resumes polling after it settles", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<{ running: boolean; pid: number | null }>();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "get_daemon_status"
        ? pending.promise
        : Promise.resolve(mockResponses[cmd]),
    );
    const { container } = render(Header);
    await settle();
    expect(statusCalls()).toHaveLength(1);
    vi.advanceTimersByTime(30000);
    await settle();
    expect(statusCalls()).toHaveLength(1);

    pending.resolve({ running: true, pid: 42 });
    await settle();
    expect(container.querySelector(".status-label")?.textContent).toBe("Running");
    vi.advanceTimersByTime(10000);
    await settle();
    expect(statusCalls()).toHaveLength(2);
  });

  it("resumes status polling after a pending read rejects", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<unknown>();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "get_daemon_status"
        ? pending.promise
        : Promise.resolve(mockResponses[cmd]),
    );
    render(Header);
    await settle();
    pending.reject(new Error("slow status failed"));
    await settle();
    setupMocks({ get_daemon_status: { running: true, pid: 42 } });
    vi.advanceTimersByTime(10000);
    await settle();
    expect(statusCalls()).toHaveLength(2);
  });

  it("discards a late status reply and stops polling on unmount", async () => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    const pending = deferred<{ running: boolean; pid: number | null }>();
    mockInvoke.mockImplementation((cmd: string) =>
      cmd === "get_daemon_status"
        ? pending.promise
        : Promise.resolve(mockResponses[cmd]),
    );
    const { unmount } = render(Header);
    await settle();
    await unmount();
    const readRunning = vi.fn(() => true);
    pending.resolve({ get running() { return readRunning(); }, pid: 42 });
    await settle();
    // Reading the reply would write daemonRunning after teardown.
    expect(readRunning).not.toHaveBeenCalled();
    vi.advanceTimersByTime(30000);
    await settle();
    expect(statusCalls()).toHaveLength(1);
  });

  it("does not start a status invocation if path lookup completes after unmount", async () => {
    const home = deferred<string>();
    mockHomeDir.mockReturnValue(home.promise);
    const { unmount } = render(Header);
    await settle();
    await unmount();
    home.resolve("/home/test");
    await settle();
    expect(statusCalls()).toHaveLength(0);
  });

  // ── Layout: no inline toggles in the header (post-refactor) ──

  it("does not render Launch on login as an inline label in the header", async () => {
    // The header itself contains NO checkbox-label rows; toggles moved
    // into SettingsPopover. The settings trigger button IS rendered,
    // but the inline labels are gone. This pins the "squeezy header"
    // fix — the prior layout packed five elements into the header row.
    const { container } = render(Header);
    await tick();
    await tick();
    const header = container.querySelector("header");
    expect(header).not.toBeNull();
    // Header must contain NO checkbox <input>s directly (the popover
    // panel only renders when open, so a freshly-mounted Header has none).
    const checkboxes = header!.querySelectorAll('input[type="checkbox"]');
    expect(checkboxes.length).toBe(0);
  });

  it("renders the settings trigger button", async () => {
    const { container } = render(Header);
    await tick();
    await tick();
    const trigger = container.querySelector('[data-testid="settings-trigger"]');
    expect(trigger).not.toBeNull();
    expect(trigger?.getAttribute("aria-label")).toBe("Settings");
  });

  // ── Edition badge (get_build_edition) ─────────────────────────

  it("renders a Community edition badge (no enterprise class)", async () => {
    setupMocks({ get_build_edition: "community" });
    const { container } = render(Header);
    await tick();
    await tick();
    await tick();
    const badge = container.querySelector(".edition");
    expect(badge).not.toBeNull();
    expect(badge?.textContent?.trim()).toBe("Community");
    expect(badge?.classList.contains("enterprise")).toBe(false);
  });

  it("renders an Enterprise edition badge with the enterprise class", async () => {
    setupMocks({ get_build_edition: "enterprise" });
    const { container } = render(Header);
    await tick();
    await tick();
    await tick();
    const badge = container.querySelector(".edition");
    expect(badge).not.toBeNull();
    expect(badge?.textContent?.trim()).toBe("Enterprise");
    expect(badge?.classList.contains("enterprise")).toBe(true);
  });

  it("hides the edition badge when get_build_edition rejects", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_build_edition")
        return Promise.reject(new Error("ipc failure"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = render(Header);
    await tick();
    await tick();
    await tick();
    expect(container.querySelector(".edition")).toBeNull();
  });
});
