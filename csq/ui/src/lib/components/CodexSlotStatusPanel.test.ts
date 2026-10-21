import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import CodexSlotStatusPanel from "./CodexSlotStatusPanel.svelte";

const BASE = "/home/test/.claude/accounts";

async function settle() {
  for (let i = 0; i < 10; i++) await tick();
}

describe("CodexSlotStatusPanel", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });
  afterEach(() => {
    cleanup();
  });

  it("renders nothing when no slot has a recorded condition", async () => {
    mockInvoke.mockResolvedValue([]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    expect(container.querySelector(".codex-status")).toBeNull();
  });

  it("shows the raced row with an acknowledge button that invokes the ack with the slot", async () => {
    let acked = false;
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_codex_slot_write_status") {
        return Promise.resolve(
          acked ? [] : [{ slot: 3, status: ["raced"], ackable: true }],
        );
      }
      if (cmd === "ack_codex_slot_raced") {
        acked = true;
        return Promise.resolve({
          slot: 3,
          cleared: true,
          tmp_removed: 0,
          markers_removed: 0,
        });
      }
      return Promise.reject(new Error("unexpected " + cmd));
    });
    const { container, getByRole } = render(CodexSlotStatusPanel);
    await settle();
    expect(container.querySelector('[data-status="raced"]')).not.toBeNull();
    await fireEvent.click(
      getByRole("button", { name: "Acknowledge raced Codex slot 3" }),
    );
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("ack_codex_slot_raced", {
      baseDir: BASE,
      slot: 3,
    });
    // the row is gone once the backend reports the slot clean
    expect(container.querySelector(".codex-status")).toBeNull();
  });

  it("shows the backend error on the row and keeps the button when the ack fails", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_codex_slot_write_status") {
        return Promise.resolve([{ slot: 3, status: ["raced"], ackable: true }]);
      }
      return Promise.reject("ACK_FAILED: the slot lock timed out");
    });
    const { container, getByRole } = render(CodexSlotStatusPanel);
    await settle();
    await fireEvent.click(
      getByRole("button", { name: "Acknowledge raced Codex slot 3" }),
    );
    await settle();
    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain("ACK_FAILED: the slot lock timed out");
    expect(container.querySelector("button.ack")).not.toBeNull();
  });

  it("offers no acknowledge button on a row that has nothing to acknowledge", async () => {
    mockInvoke.mockResolvedValue([
      { slot: 4, status: ["exchange-unsupported"], ackable: false },
    ]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    expect(
      container.querySelector('[data-status="exchange-unsupported"]'),
    ).not.toBeNull();
    expect(container.querySelector("button.ack")).toBeNull();
  });

  it("shows the purge-failed, carry-skipped and unrecognised-marker lines with no button when nothing is raced", async () => {
    mockInvoke.mockResolvedValue([
      {
        slot: 5,
        status: ["purge-failed", "carry-skipped", "unrecognised-marker"],
        ackable: false,
      },
    ]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    expect(
      container.querySelector('[data-status="purge-failed"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-status="carry-skipped"]'),
    ).not.toBeNull();
    const odd = container.querySelector('[data-status="unrecognised-marker"]');
    expect(odd?.textContent?.replace(/\s+/g, " ").trim()).toBe(
      "unrecognised marker; inspect and remove manually: config-5/.csq-status-markers/<name>",
    );
    expect(container.querySelector("button.ack")).toBeNull();
  });

  it("keeps the unrecognised-marker line next to the button on a raced row", async () => {
    mockInvoke.mockResolvedValue([
      { slot: 6, status: ["raced", "unrecognised-marker"], ackable: true },
    ]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    expect(
      container.querySelector('[data-status="unrecognised-marker"]'),
    ).not.toBeNull();
    expect(container.querySelector("button.ack")).not.toBeNull();
  });

  it("names the overflow marker file when the ack cannot clear it", async () => {
    mockInvoke.mockResolvedValue([
      {
        slot: 7,
        status: ["raced", "purge-failed"],
        ackable: true,
        overflow_stuck: true,
      },
    ]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    const line = container.querySelector('[data-status="overflow-stuck"]');
    expect(line?.textContent?.replace(/\s+/g, " ").trim()).toContain(
      "remove config-7/.csq-status-markers/overflow",
    );
    expect(line?.textContent).not.toContain("/Users/");
  });

  it("shows no overflow line when the overflow is not stuck", async () => {
    mockInvoke.mockResolvedValue([
      { slot: 8, status: ["raced"], ackable: true, overflow_stuck: false },
    ]);
    const { container } = render(CodexSlotStatusPanel);
    await settle();
    expect(container.querySelector('[data-status="overflow-stuck"]')).toBeNull();
  });
});
