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

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

// `getVersion()` backs the dynamic version string rendered in the
// header (journal 0063 P1-5 replaced the hardcoded alpha.21 literal).
vi.mock("@tauri-apps/api/app", () => ({
  getVersion: () => Promise.resolve("2.0.0-test"),
}));

import Header from "./Header.svelte";

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
    setupMocks();
  });

  afterEach(() => {
    cleanup();
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
});
