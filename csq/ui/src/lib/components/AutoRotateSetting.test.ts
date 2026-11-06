import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// AutoRotateSetting calls:
//   invoke('get_rotation_config', { baseDir })               — on mount
//   invoke('set_rotation_enabled', { baseDir, enabled })     — toggle

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import AutoRotateSetting from "./AutoRotateSetting.svelte";
import { machineRotation, setMachineRotationEnabled } from "../stores/machineRotation.svelte";

const BASE = "/home/test/.claude/accounts";

type Cfg = {
  enabled: boolean;
  threshold_percent: number;
  cooldown_secs: number;
  exclude_accounts: number[];
};

function cfg(over: Partial<Cfg> = {}): Cfg {
  return {
    enabled: false,
    threshold_percent: 95,
    cooldown_secs: 300,
    exclude_accounts: [],
    ...over,
  };
}

function setup(opts: {
  config?: Cfg | Error | unknown;
  set?: "ok" | Error | Promise<unknown>;
}) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd === "get_rotation_config") {
      const c = "config" in opts ? opts.config : cfg();
      return c instanceof Error ? Promise.reject(c) : Promise.resolve(c);
    }
    if (cmd === "set_rotation_enabled") {
      const s = opts.set ?? "ok";
      if (s === "ok") return Promise.resolve(undefined);
      return s instanceof Error ? Promise.reject(s) : s;
    }
    return Promise.resolve(undefined);
  });
}

async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

function checkbox(container: HTMLElement) {
  return container.querySelector(
    '[data-testid="setting-auto-rotate"]',
  ) as HTMLInputElement;
}

describe("AutoRotateSetting", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    setMachineRotationEnabled(null);
  });
  afterEach(() => {
    cleanup();
  });

  it("reads the config with the accounts base dir and renders it OFF", async () => {
    setup({ config: cfg({ enabled: false }) });
    const { container } = render(AutoRotateSetting);
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("get_rotation_config", {
      baseDir: BASE,
    });
    expect(checkbox(container).checked).toBe(false);
    expect(checkbox(container).disabled).toBe(false);
  });

  it("renders the current state ON", async () => {
    setup({ config: cfg({ enabled: true }) });
    const { container } = render(AutoRotateSetting);
    await settle();
    expect(checkbox(container).checked).toBe(true);
  });

  it("renders threshold and cooldown from the config", async () => {
    setup({ config: cfg({ threshold_percent: 80, cooldown_secs: 600 }) });
    const { getByTestId } = render(AutoRotateSetting);
    await settle();
    const text = (getByTestId("auto-rotate-hint").textContent ?? "")
      .replace(/\s+/g, " ")
      .trim();
    expect(text).toBe(
      "When a terminal's account passes 80% of its 5-hour limit, csq moves that terminal to a less-used account of the same kind. Each terminal waits 10 minutes before moving again.",
    );
  });

  it("formats cooldown units (seconds, singular minute, hours)", async () => {
    for (const [secs, want] of [
      [45, "45 seconds"],
      [60, "1 minute"],
      [7200, "2 hours"],
    ] as const) {
      mockInvoke.mockReset();
      setup({ config: cfg({ cooldown_secs: secs }) });
      const { getByTestId, unmount } = render(AutoRotateSetting);
      await settle();
      expect(getByTestId("auto-rotate-hint").textContent).toContain(
        `waits ${want} before`,
      );
      unmount();
    }
  });

  it("toggling calls set_rotation_enabled with baseDir and the new value", async () => {
    setup({ config: cfg({ enabled: false }) });
    const { container } = render(AutoRotateSetting);
    await settle();
    await fireEvent.click(checkbox(container));
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("set_rotation_enabled", {
      baseDir: BASE,
      enabled: true,
    });
    expect(checkbox(container).checked).toBe(true);
  });

  it("toggling an enabled setting sends enabled:false", async () => {
    setup({ config: cfg({ enabled: true }) });
    const { container } = render(AutoRotateSetting);
    await settle();
    await fireEvent.click(checkbox(container));
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("set_rotation_enabled", {
      baseDir: BASE,
      enabled: false,
    });
    expect(checkbox(container).checked).toBe(false);
  });

  it("shares the machine setting with per-session controls only once it is confirmed", async () => {
    setup({ config: cfg({ enabled: false }) });
    const { container } = render(AutoRotateSetting);
    await settle();
    expect(machineRotation.enabled).toBe(false);
    await fireEvent.click(checkbox(container));
    await settle();
    expect(machineRotation.enabled).toBe(true);
  });

  it("a failed write leaves the shared machine setting unchanged", async () => {
    setup({ config: cfg({ enabled: false }), set: new Error("EACCES") });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container } = render(AutoRotateSetting);
    await settle();
    await fireEvent.click(checkbox(container));
    await settle();
    expect(machineRotation.enabled).toBe(false);
    warn.mockRestore();
  });

  it("updates optimistically while the write is in flight", async () => {
    let resolveSet: (v: unknown) => void = () => {};
    const pending = new Promise((r) => {
      resolveSet = r;
    });
    setup({ config: cfg({ enabled: false }), set: pending });
    const { container } = render(AutoRotateSetting);
    await settle();
    await fireEvent.click(checkbox(container));
    await settle();
    expect(checkbox(container).checked).toBe(true);
    expect(checkbox(container).disabled).toBe(true);
    resolveSet(undefined);
    await settle();
    expect(checkbox(container).checked).toBe(true);
    expect(checkbox(container).disabled).toBe(false);
  });

  it("a failed write reverts the checkbox and shows fixed error text without the raw error", async () => {
    setup({
      config: cfg({ enabled: false }),
      set: new Error("EACCES: /home/test/.claude/accounts/rotation.json"),
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container, getByTestId } = render(AutoRotateSetting);
    await settle();
    await fireEvent.click(checkbox(container));
    await settle();
    expect(checkbox(container).checked).toBe(false);
    const err = getByTestId("auto-rotate-error");
    expect(err.textContent).toBe(
      "Couldn't save the auto-swap setting. It was left unchanged.",
    );
    expect(container.textContent).not.toContain("EACCES");
    expect(container.textContent).not.toContain("/home/test");
    warn.mockRestore();
  });

  it("a failed read shows fixed error text and disables the checkbox", async () => {
    setup({ config: new Error("invalid JSON at /home/test/rotation.json") });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container, getByTestId } = render(AutoRotateSetting);
    await settle();
    expect(getByTestId("auto-rotate-error").textContent).toBe(
      "Couldn't read the auto-swap setting. Try reopening Settings.",
    );
    expect(checkbox(container).disabled).toBe(true);
    expect(container.textContent).not.toContain("/home/test");
    expect(container.querySelector('[data-testid="auto-rotate-hint"]')).toBeNull();
    warn.mockRestore();
  });

  it("a failed read clears the shared machine setting", async () => {
    setMachineRotationEnabled(true);
    setup({ config: new Error("boom") });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    render(AutoRotateSetting);
    await settle();
    expect(machineRotation.enabled).toBeNull();
    warn.mockRestore();
  });

  it("a malformed read payload is treated as a read failure", async () => {
    setup({ config: { enabled: "yes" } });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { container, getByTestId } = render(AutoRotateSetting);
    await settle();
    expect(getByTestId("auto-rotate-error")).toBeTruthy();
    expect(checkbox(container).disabled).toBe(true);
    warn.mockRestore();
  });
});
