import { describe, it, expect, afterEach, vi } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

import KeychainOrphansChip, {
  countLines,
  type KeychainOrphansView,
} from "./KeychainOrphansChip.svelte";

// The ~90-word backend summary the owner reported as an unreadable wall.
const WALL =
  "1 of 53 per-terminal items belong to gone csq terminals (0 still queued, 0 deleted since " +
  "the daemon started, 1 kept as possibly the only copy of a login, 0 kept because a live " +
  "process still runs as the terminal, 0 kept for other reasons)";

function view(over: Partial<KeychainOrphansView> = {}): KeychainOrphansView {
  return {
    level: "warn",
    summary: WALL,
    status: {
      keychain_orphans: undefined,
      orphan_candidates: 1,
      pending: 0,
      deleted_total: 0,
      kept_sole_copy: 1,
      kept_pid_in_use: 0,
      kept_other: 0,
    } as KeychainOrphansView["status"],
    ...over,
  };
}

async function settle() {
  for (let i = 0; i < 4; i++) await tick();
}

function chip(c: HTMLElement) {
  return c.querySelector('[data-testid="keychain-orphans"]') as HTMLButtonElement;
}
function panel(c: HTMLElement) {
  return c.querySelector('[data-testid="keychain-orphans-panel"]') as HTMLElement | null;
}

describe("KeychainOrphansChip", () => {
  afterEach(cleanup);

  it("labels warn as an incomplete cleanup and needs_action as needing attention", () => {
    const warn = render(KeychainOrphansChip, { props: { orphans: view({ level: "warn" }) } });
    expect(chip(warn.container).textContent?.trim()).toBe("Keychain: cleanup incomplete");
    cleanup();
    const act = render(KeychainOrphansChip, {
      props: { orphans: view({ level: "needs_action" }) },
    });
    expect(chip(act.container).textContent?.trim()).toBe("Keychain: needs attention");
    expect(chip(act.container).classList.contains("needs-action")).toBe(true);
  });

  it("uses a short one-line tooltip that carries none of the counters", () => {
    const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
    const title = chip(container).getAttribute("title") ?? "";
    expect(title.length).toBeLessThan(80);
    expect(title).not.toContain("\n");
    expect(title).not.toMatch(/\d/);
    expect(title).not.toContain(WALL.slice(0, 30));
    expect(chip(container).getAttribute("aria-label")).toBeNull();
  });

  it("opens on click, lists only non-zero counters and the one action, then closes on a second click", async () => {
    const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
    expect(panel(container)).toBeNull();
    expect(chip(container).getAttribute("aria-expanded")).toBe("false");

    await fireEvent.click(chip(container));
    await settle();
    const p = panel(container);
    expect(p).not.toBeNull();
    expect(chip(container).getAttribute("aria-expanded")).toBe("true");
    const items = Array.from(p!.querySelectorAll("li")).map((li) => li.textContent);
    expect(items).toEqual([
      "1 leftover item from closed terminals",
      "1 kept because it may be the only copy of a login",
    ]);
    // Zero counters are hidden; the wall of text is not shown.
    expect(p!.textContent).not.toContain("0 ");
    expect(p!.textContent).not.toContain("per-terminal items");
    expect(p!.textContent).toContain("csq doctor");
    expect(p!.querySelector('[data-testid="keychain-orphans-summary"]')).toBeNull();

    await fireEvent.click(chip(container));
    await settle();
    expect(panel(container)).toBeNull();
  });

  it("closes on Escape and returns focus to the chip", async () => {
    const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
    await fireEvent.click(chip(container));
    await settle();
    expect(panel(container)).not.toBeNull();
    await fireEvent.keyDown(document, { key: "Escape" });
    await settle();
    expect(panel(container)).toBeNull();
    expect(document.activeElement).toBe(chip(container));
  });

  it("closes on an outside click but not on a click inside the popover", async () => {
    const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
    await fireEvent.click(chip(container));
    await settle();
    await fireEvent.mouseDown(panel(container)!);
    await settle();
    expect(panel(container)).not.toBeNull();
    await fireEvent.mouseDown(document.body);
    await settle();
    expect(panel(container)).toBeNull();
  });

  it("moves focus into the popover on open so keyboard users land in it", async () => {
    const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
    await fireEvent.click(chip(container));
    await settle();
    expect(document.activeElement).toBe(panel(container));
  });

  it("explains the cause when the sweep is paused or could not read the keychain", async () => {
    const paused = view({
      status: { process_table_unknown: "lineage_broken", kept_process_table_unknown: 2 },
    });
    const a = render(KeychainOrphansChip, { props: { orphans: paused } });
    await fireEvent.click(chip(a.container));
    await settle();
    expect(panel(a.container)!.textContent).toContain("Cleanup is paused");
    expect(panel(a.container)!.textContent).toContain(
      "2 kept because csq could not rule out a program still running",
    );
    cleanup();
    const undetermined = view({ status: { undetermined: "enumeration_unavailable" } });
    const b = render(KeychainOrphansChip, { props: { orphans: undetermined } });
    await fireEvent.click(chip(b.container));
    await settle();
    expect(panel(b.container)!.textContent).toContain("nothing was deleted");
    expect(panel(b.container)!.textContent).not.toContain("enumeration_unavailable");
  });

  it("explains an unreadable status file without leaking the raw token", async () => {
    const { container } = render(KeychainOrphansChip, {
      props: { orphans: view({ status: undefined, error: "corrupt", summary: "x (status.json) is corrupt" }) },
    });
    await fireEvent.click(chip(container));
    await settle();
    expect(panel(container)!.textContent).toContain("The cleanup status file is damaged.");
  });

  it("falls back to the bounded summary when no structured counts arrive", async () => {
    const { container } = render(KeychainOrphansChip, {
      props: { orphans: view({ status: undefined }) },
    });
    await fireEvent.click(chip(container));
    await settle();
    expect(
      panel(container)!.querySelector('[data-testid="keychain-orphans-summary"]')?.textContent,
    ).toBe(WALL);
  });

  it("countLines hides zero and missing counters", () => {
    expect(countLines(undefined)).toEqual([]);
    expect(countLines({ pending: 0, kept_other: 3 })).toEqual(["3 kept for other reasons"]);
  });

  it("removes every document listener it added once the popover closes", async () => {
    const added: string[] = [];
    const removed: string[] = [];
    const add = vi.spyOn(document, "addEventListener").mockImplementation(function (
      this: Document,
      type: string,
      ...rest: unknown[]
    ) {
      if (type === "mousedown" || type === "keydown") added.push(type);
      return EventTarget.prototype.addEventListener.call(this, type, ...(rest as [EventListener]));
    } as typeof document.addEventListener);
    const remove = vi.spyOn(document, "removeEventListener").mockImplementation(function (
      this: Document,
      type: string,
      ...rest: unknown[]
    ) {
      if (type === "mousedown" || type === "keydown") removed.push(type);
      return EventTarget.prototype.removeEventListener.call(this, type, ...(rest as [EventListener]));
    } as typeof document.removeEventListener);
    try {
      const { container } = render(KeychainOrphansChip, { props: { orphans: view() } });
      await fireEvent.click(chip(container));
      await settle();
      expect(added.sort()).toEqual(["keydown", "mousedown"]);
      await fireEvent.keyDown(document, { key: "Escape" });
      await settle();
      expect(removed.sort()).toEqual(["keydown", "mousedown"]);
    } finally {
      add.mockRestore();
      remove.mockRestore();
    }
  });
});
