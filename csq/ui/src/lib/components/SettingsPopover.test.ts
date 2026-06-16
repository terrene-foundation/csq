import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// SettingsPopover calls:
//   getVersion()                                — on mount + on open
//   invoke('get_autostart_enabled')             — on mount + on open
//   invoke('set_autostart_enabled', { enabled })— toggle
//   invoke('is_dock_hide_supported')            — on mount + on open (macOS gate)
//   invoke('get_dock_hidden', { baseDir })      — on mount + on open
//   invoke('set_dock_hidden', { baseDir, hidden }) — toggle
//   invoke('get_dashboard_at_launch', { baseDir }) — on mount + on open
//   invoke('set_dashboard_at_launch', { baseDir, enabled }) — toggle

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

vi.mock("@tauri-apps/api/app", () => ({
  getVersion: () => Promise.resolve("2.11.0-test"),
}));

import SettingsPopover from "./SettingsPopover.svelte";

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    get_autostart_enabled: false,
    set_autostart_enabled: undefined,
    is_dock_hide_supported: true,
    get_dock_hidden: false,
    set_dock_hidden: false,
    get_dashboard_at_launch: true,
    set_dashboard_at_launch: true,
    ...overrides,
  };
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in mockResponses) {
      return Promise.resolve(mockResponses[cmd]);
    }
    return Promise.resolve(undefined);
  });
}

async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

async function openPanel(container: HTMLElement) {
  const trigger = container.querySelector(
    '[data-testid="settings-trigger"]',
  ) as HTMLButtonElement;
  await fireEvent.click(trigger);
  await settle();
}

describe("SettingsPopover", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    setupMocks();
  });

  afterEach(() => {
    cleanup();
  });

  // ── Panel lifecycle ───────────────────────────────────────────

  it("renders the trigger but not the panel by default", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    expect(
      container.querySelector('[data-testid="settings-trigger"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-testid="settings-panel"]'),
    ).toBeNull();
  });

  it("opens the panel when the trigger is clicked", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    expect(
      container.querySelector('[data-testid="settings-panel"]'),
    ).not.toBeNull();
  });

  it("closes the panel on Escape", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    await fireEvent.keyDown(document, { key: "Escape" });
    await settle();
    expect(
      container.querySelector('[data-testid="settings-panel"]'),
    ).toBeNull();
  });

  it("closes the panel when the close button is clicked", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const close = container.querySelector(
      '[aria-label="Close settings"]',
    ) as HTMLButtonElement;
    await fireEvent.click(close);
    await settle();
    expect(
      container.querySelector('[data-testid="settings-panel"]'),
    ).toBeNull();
  });

  // ── Focus management (R1 svelte-specialist HIGH) ─────────────

  it("moves focus into the panel when opened", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const panel = container.querySelector(
      '[data-testid="settings-panel"]',
    ) as HTMLElement;
    expect(document.activeElement).toBe(panel);
  });

  it("restores focus to the trigger when closed via the close button", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const close = container.querySelector(
      '[aria-label="Close settings"]',
    ) as HTMLButtonElement;
    await fireEvent.click(close);
    await settle();
    const trigger = container.querySelector('[data-testid="settings-trigger"]');
    expect(document.activeElement).toBe(trigger);
  });

  it("restores focus to the trigger when closed via ESC", async () => {
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    await fireEvent.keyDown(document, { key: "Escape" });
    await settle();
    const trigger = container.querySelector('[data-testid="settings-trigger"]');
    expect(document.activeElement).toBe(trigger);
  });

  // ── Launch on login (Startup section) ─────────────────────────

  it("renders the Launch on login toggle in the panel", async () => {
    setupMocks({ get_autostart_enabled: true });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-launch-on-login"]',
    ) as HTMLInputElement;
    expect(cb).not.toBeNull();
    expect(cb.checked).toBe(true);
  });

  it("reverts the Launch on login toggle if set_autostart_enabled fails", async () => {
    // R1 svelte-specialist NIT: parity with dock-hide / dashboard-at-launch
    // revert-on-failure. Pre-fix the autostart catch left the visible
    // checkbox in a state divergent from the underlying pref.
    setupMocks({ get_autostart_enabled: false });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);

    mockInvoke.mockImplementationOnce(() =>
      Promise.reject(new Error("permission denied")),
    );
    const cb = container.querySelector(
      '[data-testid="setting-launch-on-login"]',
    ) as HTMLInputElement;
    await fireEvent.change(cb);
    await settle();

    expect(warnSpy).toHaveBeenCalled();
    expect(cb.checked).toBe(false);
    warnSpy.mockRestore();
  });

  it("calls set_autostart_enabled when Launch on login is toggled", async () => {
    setupMocks({ get_autostart_enabled: false });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-launch-on-login"]',
    ) as HTMLInputElement;
    await fireEvent.change(cb);
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("set_autostart_enabled", {
      enabled: true,
    });
  });

  // ── Open dashboard at launch (NEW — Startup section) ────────

  it("renders the Open dashboard at launch toggle reflecting persisted state (default true)", async () => {
    setupMocks({ get_dashboard_at_launch: true });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-dashboard-at-launch"]',
    ) as HTMLInputElement;
    expect(cb).not.toBeNull();
    expect(cb.checked).toBe(true);
  });

  it("reflects persisted dashboard_at_launch=false", async () => {
    setupMocks({ get_dashboard_at_launch: false });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-dashboard-at-launch"]',
    ) as HTMLInputElement;
    expect(cb.checked).toBe(false);
  });

  it("calls set_dashboard_at_launch with the new value when toggled", async () => {
    setupMocks({ get_dashboard_at_launch: true });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-dashboard-at-launch"]',
    ) as HTMLInputElement;
    await fireEvent.change(cb);
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("set_dashboard_at_launch", {
      baseDir: "/home/test/.claude/accounts",
      enabled: false,
    });
  });

  it("reverts the dashboard_at_launch toggle if the set call fails", async () => {
    setupMocks({ get_dashboard_at_launch: true });
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);

    mockInvoke.mockImplementationOnce(() =>
      Promise.reject(new Error("save failed")),
    );
    const cb = container.querySelector(
      '[data-testid="setting-dashboard-at-launch"]',
    ) as HTMLInputElement;
    await fireEvent.change(cb);
    await settle();

    // Catch block reverts back to the pre-flip value (true).
    expect(warnSpy).toHaveBeenCalled();
    expect(cb.checked).toBe(true);
    warnSpy.mockRestore();
  });

  // ── Hide Dock icon (Appearance section, macOS gate) ──────────

  it("does NOT render the Hide Dock icon section when unsupported", async () => {
    setupMocks({ is_dock_hide_supported: false });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    expect(
      container.querySelector('[data-testid="setting-hide-dock-icon"]'),
    ).toBeNull();
    // Appearance heading should also be absent on unsupported platforms.
    expect(container.textContent).not.toContain("Hide Dock icon");
  });

  it("renders the Hide Dock icon toggle when supported, reflecting persisted state", async () => {
    setupMocks({ is_dock_hide_supported: true, get_dock_hidden: true });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-hide-dock-icon"]',
    ) as HTMLInputElement;
    expect(cb).not.toBeNull();
    expect(cb.checked).toBe(true);
  });

  it("calls set_dock_hidden when the Hide Dock icon toggle is flipped", async () => {
    setupMocks({ is_dock_hide_supported: true, get_dock_hidden: false });
    const { container } = render(SettingsPopover);
    await settle();
    await openPanel(container);
    const cb = container.querySelector(
      '[data-testid="setting-hide-dock-icon"]',
    ) as HTMLInputElement;
    await fireEvent.change(cb);
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("set_dock_hidden", {
      baseDir: "/home/test/.claude/accounts",
      hidden: true,
    });
  });

  // ── About section ─────────────────────────────────────────────

  it("shows the app version and daemon-running status in the About section", async () => {
    const { container } = render(SettingsPopover, {
      props: { daemonRunning: true },
    });
    await settle();
    await openPanel(container);
    const panel = container.querySelector(
      '[data-testid="settings-panel"]',
    ) as HTMLElement;
    expect(panel.textContent).toContain("v2.11.0-test");
    expect(panel.textContent).toContain("daemon running");
  });

  it("shows daemon-stopped when the prop is false", async () => {
    const { container } = render(SettingsPopover, {
      props: { daemonRunning: false },
    });
    await settle();
    await openPanel(container);
    const panel = container.querySelector(
      '[data-testid="settings-panel"]',
    ) as HTMLElement;
    expect(panel.textContent).toContain("daemon stopped");
  });
});
