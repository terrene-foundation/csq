import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/svelte";
import { tick } from "svelte";

const { mockInvoke, mockHomeDir } = vi.hoisted(() => ({
  mockInvoke: vi.fn(),
  mockHomeDir: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mockInvoke }));
vi.mock("@tauri-apps/api/path", () => ({
  homeDir: mockHomeDir,
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import ClaudeAutoCompactStatusPanel from "./ClaudeAutoCompactStatusPanel.svelte";

const BASE = "/home/test/.claude/accounts";
const GUIDANCE = "Source overlays remain unchanged. csq filters these overrides when preparing terminal settings. Existing terminals receive filtered settings at their next swap or relaunch.";
const CLEAN = { guidance: GUIDANCE, findings: [], unreadable: [] };
const ROOT = {
  findings: [{ location: "config-3/settings.json", root: true, per_model: false, pct_override: false, provider_window: false }],
  guidance: GUIDANCE,
  unreadable: [],
};
const PCT = {
  findings: [{ location: "config-5/settings.json", root: false, per_model: false, pct_override: true, provider_window: false }],
  guidance: GUIDANCE,
  unreadable: [],
};
const PROVIDER_WINDOW = {
  findings: [{ location: "config-6/settings.json", root: false, per_model: false, pct_override: false, provider_window: true }],
  guidance: GUIDANCE,
  unreadable: [],
};
const PER_MODEL = {
  findings: [{ location: "config-4/settings.json", root: false, per_model: true, pct_override: false, provider_window: false }],
  guidance: GUIDANCE,
  unreadable: [],
};

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await tick();
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

describe("ClaudeAutoCompactStatusPanel", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
    mockInvoke.mockReset();
    mockHomeDir.mockReset().mockResolvedValue("/home/test");
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it.each(["no source overrides", "allowed third-party provider window"])(
    "hides the panel when the collector reports %s as clean", async () => {
    mockInvoke.mockResolvedValue(CLEAN);
    const { container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(mockInvoke).toHaveBeenCalledExactlyOnceWith(
      "get_claude_autocompact_status", { baseDir: BASE },
    );
    expect(container.querySelector("section")).toBeNull();
  });

  it.each([
    ["root", ROOT, "root", "autoCompactWindow"],
    ["per-model", PER_MODEL, "per-model", "modelSettings.*.autoCompactWindow"],
    ["percentage", PCT, "pct-override", "env.CLAUDE_AUTOCOMPACT_PCT_OVERRIDE"],
    ["provider window", PROVIDER_WINDOW, "provider-window", "env.CLAUDE_CODE_AUTO_COMPACT_WINDOW"],
  ] as const)("shows the %s override location with its key and no write controls", async (_label, result, kind, key) => {
    mockInvoke.mockResolvedValue(result);
    const { container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(container.querySelector("[data-location]")?.getAttribute("data-location"))
      .toBe(result.findings[0].location);
    const overrides = container.querySelectorAll("[data-override]");
    expect(overrides).toHaveLength(1);
    expect(overrides[0].getAttribute("data-override")).toBe(kind);
    expect(overrides[0].querySelector("code")?.textContent).toBe(key);
    expect(container.querySelector("button, input, textarea")).toBeNull();
  });

  it("shows all override kinds together and keeps unreadable locations distinct", async () => {
    mockInvoke.mockResolvedValue({
      findings: [{ location: "config-3/settings.json", root: true, per_model: true, pct_override: true, provider_window: true }],
      guidance: GUIDANCE,
      unreadable: ["config-4/settings.json"],
    });
    const { container, getByText } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(container.querySelectorAll("[data-location]")).toHaveLength(1);
    expect(container.querySelectorAll("[data-override]")).toHaveLength(4);
    expect(container.querySelector("[data-unreadable]")?.getAttribute("data-unreadable"))
      .toBe("config-4/settings.json");
    expect(getByText("Auto-compact override status is unknown for this location.", { exact: false })).toBeTruthy();
  });

  it("renders the collector guidance verbatim", async () => {
    mockInvoke.mockResolvedValue({ ...ROOT, guidance: "Backend guidance contract." });
    const { container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(container.querySelector("[data-guidance]")?.textContent).toBe("Backend guidance contract.");
  });

  it("shows unchanged source overlays and next-swap guidance from the backend", async () => {
    mockInvoke.mockResolvedValue({ ...ROOT, guidance: GUIDANCE });
    const { container, getByText } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(getByText(GUIDANCE)).toBeTruthy();
    expect(container.querySelector("[data-guidance]")?.textContent).toBe(GUIDANCE);
    expect(container.textContent).not.toContain("Remove these per-terminal overrides.");
  });

  it("keeps the unknown warning when only unreadable settings are reported", async () => {
    mockInvoke.mockResolvedValue({ guidance: GUIDANCE, findings: [], unreadable: ["config-3/settings.json"] });
    const { container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(container.querySelector("section")).not.toBeNull();
    expect(container.querySelectorAll("[data-unreadable]")).toHaveLength(1);
    expect(container.querySelector("[data-location]")).toBeNull();
  });

  it("reports an initial read failure without displaying the raw error", async () => {
    mockInvoke.mockRejectedValue(new Error("private settings contents"));
    const { getByRole } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    expect(getByRole("status").textContent?.replace(/\s+/g, " ").trim()).toBe(
      "Could not refresh Claude auto-compact settings. Override status is unknown.",
    );
  });

  it("retains known findings on failure and clears them only after a successful clean refresh", async () => {
    mockInvoke.mockResolvedValueOnce(ROOT).mockRejectedValueOnce(new Error("read failed"))
      .mockResolvedValueOnce(CLEAN);
    const { container, getByRole } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    await vi.advanceTimersByTimeAsync(10_000);
    await settle();
    expect(container.querySelector("[data-location]")).not.toBeNull();
    expect(getByRole("status").textContent?.replace(/\s+/g, " ").trim()).toBe(
      "Could not refresh Claude auto-compact settings. Showing the last known findings; current settings may differ.",
    );
    await vi.advanceTimersByTimeAsync(10_000);
    await settle();
    expect(container.querySelector("section")).toBeNull();
  });

  it.each(["success", "failure"])("ignores a stale request's %s after a newer result", async (outcome) => {
    const old = deferred<typeof ROOT>();
    mockInvoke.mockReturnValueOnce(old.promise).mockResolvedValueOnce(PER_MODEL);
    const { container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    await vi.advanceTimersByTimeAsync(10_000);
    await settle();
    if (outcome === "success") old.resolve(ROOT);
    else old.reject(new Error("old failure"));
    await settle();
    expect(container.querySelector("[data-location]")?.getAttribute("data-location"))
      .toBe("config-4/settings.json");
    expect(container.querySelector('[role="status"]')).toBeNull();
  });

  it("stops polling and discards pending results when unmounted", async () => {
    const pending = deferred<typeof ROOT>();
    mockInvoke.mockReturnValueOnce(pending.promise);
    const { unmount, container } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    unmount();
    pending.resolve(ROOT);
    await settle();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(container.querySelector("section")).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does not invoke after unmount while the home directory is still resolving", async () => {
    const home = deferred<string>();
    mockHomeDir.mockReturnValueOnce(home.promise);
    const { unmount } = render(ClaudeAutoCompactStatusPanel);
    await settle();
    unmount();
    home.resolve("/home/test");
    await settle();
    expect(mockInvoke).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
