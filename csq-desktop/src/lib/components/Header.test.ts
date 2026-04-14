import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// Header calls:
//   invoke('get_daemon_status', { baseDir })  — on mount + 10s poll
//   invoke('get_autostart_enabled')            — on mount
//   invoke('set_autostart_enabled', { enabled }) — checkbox toggle
//
// @tauri-apps/api/path stubbed so the baseDir resolution never
// touches the filesystem.

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import Header from "./Header.svelte";

// Default mock responses by command name. Tests override specific
// commands by replacing entries before rendering.
let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    get_daemon_status: { running: false, pid: null },
    get_autostart_enabled: false,
    set_autostart_enabled: undefined,
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
    expect(container.textContent).toContain("Code Session Quota");
  });

  it("renders a version string", async () => {
    const { container } = render(Header);
    const versionEl = container.querySelector(".version");
    expect(versionEl).not.toBeNull();
    expect(versionEl?.textContent).toMatch(/v\d/);
  });

  // ── Daemon status indicator ───────────────────────────────────

  it("shows 'Daemon stopped' when daemon is not running", async () => {
    setupMocks({ get_daemon_status: { running: false, pid: null } });
    const { container } = render(Header);
    await tick();
    await tick();
    expect(container.textContent).toContain("Daemon stopped");
    const dot = container.querySelector(".dot") as HTMLElement;
    expect(dot.classList.contains("running")).toBe(false);
  });

  it("shows 'Daemon running' when daemon is running", async () => {
    setupMocks({ get_daemon_status: { running: true, pid: 42 } });
    const { container } = render(Header);
    // The daemon status poll resolves asynchronously. Svelte 5's
    // effect scheduling may need extra ticks for the promise to
    // resolve and the DOM to update.
    await tick();
    await tick();
    await tick();
    await tick();
    expect(container.textContent).toContain("Daemon running");
    const dot = container.querySelector(".dot") as HTMLElement;
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
    expect(container.textContent).toContain("Daemon stopped");
  });

  // ── Autostart toggle ──────────────────────────────────────────

  it("renders the Launch on login checkbox", async () => {
    const { container } = render(Header);
    await tick();
    await tick();
    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    expect(checkbox).not.toBeNull();
    expect(container.textContent).toContain("Launch on login");
  });

  it("reflects autostart enabled state in checkbox", async () => {
    setupMocks({ get_autostart_enabled: true });
    const { container } = render(Header);
    await tick();
    await tick();
    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    expect(checkbox.checked).toBe(true);
  });

  it("reflects autostart disabled state in checkbox", async () => {
    setupMocks({ get_autostart_enabled: false });
    const { container } = render(Header);
    await tick();
    await tick();
    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    expect(checkbox.checked).toBe(false);
  });

  it("calls set_autostart_enabled when checkbox is toggled", async () => {
    setupMocks({ get_autostart_enabled: false });
    const { container } = render(Header);
    await tick();
    await tick();

    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    await fireEvent.change(checkbox);
    await tick();
    await tick();

    expect(mockInvoke).toHaveBeenCalledWith("set_autostart_enabled", {
      enabled: true,
    });
  });

  it("checkbox reflects toggled state after successful toggle", async () => {
    setupMocks({ get_autostart_enabled: false });
    const { container } = render(Header);
    await tick();
    await tick();

    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    await fireEvent.change(checkbox);
    await tick();
    await tick();

    expect(checkbox.checked).toBe(true);
  });

  it("reverts toggle if set_autostart_enabled fails", async () => {
    // Start enabled
    mockInvoke
      .mockResolvedValueOnce({ running: false, pid: null })
      .mockResolvedValueOnce(true);
    const { container } = render(Header);
    await tick();
    await tick();

    // Toggle fails
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockInvoke.mockRejectedValueOnce(new Error("permission denied"));
    const checkbox = container.querySelector(
      'input[type="checkbox"]',
    ) as HTMLInputElement;
    await fireEvent.change(checkbox);
    await tick();
    await tick();

    // State should remain true (the catch block does not update autostartEnabled)
    expect(checkbox.checked).toBe(true);
    warnSpy.mockRestore();
  });
});
