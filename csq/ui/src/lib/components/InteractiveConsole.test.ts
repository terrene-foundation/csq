import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent, waitFor } from "@testing-library/svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// InteractiveConsole calls (all via invoke):
//   interactive_open   {baseDir, terminalLabel}   → {session_key, state}
//   interactive_submit {baseDir, sessionKey, input}      → StateView
//   interactive_override {baseDir, sessionKey, justification} → StateView
//   interactive_abandon {baseDir, sessionKey}     → StateView
//   interactive_close  {baseDir, sessionKey}      → StateView
//
// The renderer NEVER decides enforcement — it relays input and displays the
// daemon's returned state. These tests assert exactly that: the rendered state
// always follows the daemon's response, and the override/abandon IPC is driven
// verbatim from the operator's input (R1-S7).

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import InteractiveConsole from "./InteractiveConsole.svelte";

function get(container: HTMLElement, testId: string): HTMLElement | null {
  return container.querySelector(`[data-testid="${testId}"]`);
}

/** Route invoke by command name; later mockImplementationOnce wins. */
function routeByCommand(map: Record<string, unknown>) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in map) {
      const v = map[cmd];
      return v instanceof Error ? Promise.reject(v) : Promise.resolve(v);
    }
    return Promise.resolve({ state: "idle" });
  });
}

async function openAndSubmitToBlocked(container: HTMLElement) {
  // Open the session.
  await fireEvent.click(container.querySelector("button.primary")!);
  // The idle turn-input appears once the session key lands.
  const input = (await waitFor(() => {
    const el = get(container, "input-field");
    expect(el).not.toBeNull();
    return el;
  })) as HTMLTextAreaElement;
  // Submit a turn that the daemon will block.
  await fireEvent.input(input, { target: { value: "risky turn" } });
  await fireEvent.click(get(container, "submit-btn")!);
  // Block reason renders.
  await waitFor(() => {
    expect(get(container, "block-reason")).not.toBeNull();
  });
}

describe("InteractiveConsole", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });
  afterEach(() => {
    cleanup();
  });

  it("drives block → override → complete, relaying the daemon's verdict", async () => {
    routeByCommand({
      interactive_open: {
        session_key: "KEY-abc-123",
        state: { state: "idle" },
      },
      interactive_submit: {
        state: "blocked",
        reason: "schema mismatch on 'answer'",
      },
      interactive_override: { state: "complete", content: { answer: "ok" } },
    });

    const { container } = render(InteractiveConsole);
    await openAndSubmitToBlocked(container);

    // The redacted block reason from the daemon is shown verbatim.
    expect(get(container, "block-reason")!.textContent).toContain(
      "schema mismatch on 'answer'",
    );

    // Override is disabled until a justification is entered (UX mirror).
    const overrideBtn = get(container, "override-btn") as HTMLButtonElement;
    expect(overrideBtn.disabled).toBe(true);

    const just = get(container, "justification-input") as HTMLTextAreaElement;
    await fireEvent.input(just, {
      target: { value: "operator accepts the risk" },
    });
    expect(overrideBtn.disabled).toBe(false);

    await fireEvent.click(overrideBtn);

    // The renderer shows whatever the daemon returned — complete.
    await waitFor(() => {
      expect(get(container, "complete-content")).not.toBeNull();
    });
    expect(get(container, "complete-content")!.textContent).toContain("answer");

    // The override IPC was driven with the operator's exact justification.
    const overrideCall = mockInvoke.mock.calls.find(
      (c) => c[0] === "interactive_override",
    );
    expect(overrideCall).toBeDefined();
    expect((overrideCall![1] as { justification: string }).justification).toBe(
      "operator accepts the risk",
    );
    expect((overrideCall![1] as { sessionKey: string }).sessionKey).toBe(
      "KEY-abc-123",
    );
  });

  it("drives block → abandon, returning to idle", async () => {
    routeByCommand({
      interactive_open: { session_key: "KEY-xyz", state: { state: "idle" } },
      interactive_submit: { state: "blocked", reason: "policy violation" },
      interactive_abandon: { state: "idle" },
    });

    const { container } = render(InteractiveConsole);
    await openAndSubmitToBlocked(container);

    await fireEvent.click(get(container, "abandon-btn")!);

    // Back to idle → the turn-input reappears, no block reason.
    await waitFor(() => {
      expect(get(container, "input-field")).not.toBeNull();
      expect(get(container, "block-reason")).toBeNull();
    });

    const abandonCall = mockInvoke.mock.calls.find(
      (c) => c[0] === "interactive_abandon",
    );
    expect(abandonCall).toBeDefined();
    expect((abandonCall![1] as { sessionKey: string }).sessionKey).toBe(
      "KEY-xyz",
    );
  });

  it("shows the inactive notice when the daemon surface is unavailable", async () => {
    routeByCommand({ interactive_open: new Error("interactive_unavailable") });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);

    await waitFor(() => {
      const alert = container.querySelector('[role="alert"]');
      expect(alert).not.toBeNull();
      expect(alert!.textContent).toContain("not active");
    });
    // No session opened → no turn input.
    expect(get(container, "input-field")).toBeNull();
  });

  it("rejects a justification with control characters before calling the daemon", async () => {
    routeByCommand({
      interactive_open: { session_key: "KEY-ctrl", state: { state: "idle" } },
      interactive_submit: { state: "blocked", reason: "blocked" },
    });

    const { container } = render(InteractiveConsole);
    await openAndSubmitToBlocked(container);

    const just = get(container, "justification-input") as HTMLTextAreaElement;
    // A bell control char (0x07) is forbidden by the daemon's rule; build it
    // via fromCharCode so no raw control byte lives in the source.
    const withControl = "bad" + String.fromCharCode(0x07) + "justification";
    await fireEvent.input(just, { target: { value: withControl } });

    const overrideBtn = get(container, "override-btn") as HTMLButtonElement;
    expect(overrideBtn.disabled).toBe(true);

    // Even if the click is forced, no override IPC is sent for invalid text.
    await fireEvent.click(overrideBtn);
    expect(
      mockInvoke.mock.calls.some((c) => c[0] === "interactive_override"),
    ).toBe(false);
  });

  it("renders a completed turn's content coherently", async () => {
    routeByCommand({
      interactive_open: { session_key: "KEY-ok", state: { state: "idle" } },
      interactive_submit: {
        state: "complete",
        content: { answer: "all good" },
      },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);
    const input = (await waitFor(() => {
      const el = get(container, "input-field");
      expect(el).not.toBeNull();
      return el;
    })) as HTMLTextAreaElement;
    await fireEvent.input(input, { target: { value: "clean turn" } });
    await fireEvent.click(get(container, "submit-btn")!);

    await waitFor(() => {
      expect(get(container, "complete-content")).not.toBeNull();
    });
    expect(get(container, "complete-content")!.textContent).toContain(
      "all good",
    );
    // A blocked turn's reason must NOT be present on a completed turn.
    expect(get(container, "block-reason")).toBeNull();
  });

  it("renders the account picker when ≥2 subscription accounts exist (an internal ticket §FD1)", async () => {
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [
          { slot: 1, label: "alice@example.com" },
          { slot: 3, label: "bob@example.com" },
        ],
      },
      interactive_open: { session_key: "KEY-pick", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);

    const select = (await waitFor(() => {
      const el = get(container, "account-select") as HTMLSelectElement | null;
      expect(el).not.toBeNull();
      return el;
    })) as HTMLSelectElement;

    // Two options, lowest-first; default selection is the lowest slot.
    expect(select.options.length).toBe(2);
    expect(select.value).toBe("1");
    expect(select.options[0].textContent).toContain("alice@example.com");
    expect(select.options[1].textContent).toContain("bob@example.com");
  });

  it("defaults to the lowest NON-capped account (PR-3 quota-aware default)", async () => {
    // Slot 1 is 7d-capped (100%); slot 3 is healthy (30%). The default must skip
    // the capped lowest slot and land on slot 3 — the same pick the daemon makes.
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [
          { slot: 1, label: "capped@example.com", seven_day_pct: 100 },
          { slot: 3, label: "healthy@example.com", seven_day_pct: 30 },
        ],
      },
      interactive_open: { session_key: "KEY-q", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    const select = (await waitFor(() => {
      const el = get(container, "account-select") as HTMLSelectElement | null;
      expect(el).not.toBeNull();
      return el;
    })) as HTMLSelectElement;

    expect(select.value).toBe("3");
    // Labels carry the 7d utilization suffix.
    expect(select.options[0].textContent).toContain("7d 100%");
    expect(select.options[1].textContent).toContain("7d 30%");
  });

  it("falls back to the lowest account when every candidate is capped (PR-3)", async () => {
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [
          { slot: 2, label: "a@example.com", seven_day_pct: 99 },
          { slot: 4, label: "b@example.com", seven_day_pct: 100 },
        ],
      },
      interactive_open: { session_key: "KEY-allcap", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    const select = (await waitFor(() => {
      const el = get(container, "account-select") as HTMLSelectElement | null;
      expect(el).not.toBeNull();
      return el;
    })) as HTMLSelectElement;

    // All capped → never strand the operator; default is the lowest candidate.
    expect(select.value).toBe("2");
  });

  it("omits the quota suffix and treats no-quota accounts as pickable (PR-3)", async () => {
    // Slot 1 has no quota row (pickable, no suffix); slot 3 is healthy.
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [
          { slot: 1, label: "noquota@example.com" },
          { slot: 3, label: "healthy@example.com", seven_day_pct: 12 },
        ],
      },
      interactive_open: { session_key: "KEY-nq", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    const select = (await waitFor(() => {
      const el = get(container, "account-select") as HTMLSelectElement | null;
      expect(el).not.toBeNull();
      return el;
    })) as HTMLSelectElement;

    // No-quota lowest account is pickable (absence ≠ capped) → default slot 1.
    expect(select.value).toBe("1");
    expect(select.options[0].textContent).not.toContain("7d");
    expect(select.options[1].textContent).toContain("7d 12%");
  });

  it("passes the operator-chosen slot to interactive_open (an internal ticket §FD1)", async () => {
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [
          { slot: 1, label: "alice@example.com" },
          { slot: 3, label: "bob@example.com" },
        ],
      },
      interactive_open: { session_key: "KEY-pick", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    const select = (await waitFor(() => {
      const el = get(container, "account-select");
      expect(el).not.toBeNull();
      return el;
    })) as HTMLSelectElement;

    // Operator picks the second account (slot 3).
    await fireEvent.change(select, { target: { value: "3" } });
    await fireEvent.click(container.querySelector("button.primary")!);

    await waitFor(() => {
      const openCall = mockInvoke.mock.calls.find(
        (c) => c[0] === "interactive_open",
      );
      expect(openCall).toBeDefined();
      expect((openCall![1] as { slot: number }).slot).toBe(3);
    });
  });

  it("shows no picker for a single subscription account", async () => {
    routeByCommand({
      interactive_options: {
        provider: "claude",
        candidate_slots: [{ slot: 1, label: "solo@example.com" }],
      },
      interactive_open: { session_key: "KEY-solo", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    await waitFor(() => {
      expect(container.querySelector("button.primary")).not.toBeNull();
    });
    expect(get(container, "account-select")).toBeNull();
  });

  it("opens with the daemon default (no slot) when options are unavailable", async () => {
    // interactive_options rejects (gate closed) → picker stays empty, open sends
    // slot: null (daemon default).
    routeByCommand({
      interactive_options: new Error("interactive_unavailable"),
      interactive_open: { session_key: "KEY-def", state: { state: "idle" } },
    });

    const { container } = render(InteractiveConsole);
    await waitFor(() => {
      expect(container.querySelector("button.primary")).not.toBeNull();
    });
    expect(get(container, "account-select")).toBeNull();

    await fireEvent.click(container.querySelector("button.primary")!);
    await waitFor(() => {
      const openCall = mockInvoke.mock.calls.find(
        (c) => c[0] === "interactive_open",
      );
      expect(openCall).toBeDefined();
      expect((openCall![1] as { slot: number | null }).slot).toBeNull();
    });
  });

  it("renders the auth-mode badge from the daemon's open response (an internal ticket)", async () => {
    routeByCommand({
      interactive_open: {
        session_key: "KEY-sub",
        state: { state: "idle" },
        auth_mode: "subscription",
      },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);

    const badge = (await waitFor(() => {
      const el = get(container, "auth-mode-badge");
      expect(el).not.toBeNull();
      return el;
    }))!;
    expect(badge.textContent).toContain("Subscription");
    // Degraded tier is the neutral default — no accent class.
    expect(badge.classList.contains("direct")).toBe(false);
  });

  it("accents the direct-api auth-mode badge (the paid-key moat)", async () => {
    routeByCommand({
      interactive_open: {
        session_key: "KEY-direct",
        state: { state: "idle" },
        auth_mode: "direct-api",
      },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);

    const badge = (await waitFor(() => {
      const el = get(container, "auth-mode-badge");
      expect(el).not.toBeNull();
      return el;
    }))!;
    expect(badge.textContent).toContain("Direct API");
    expect(badge.classList.contains("direct")).toBe(true);
  });

  it("shows no auth-mode badge for an untagged session", async () => {
    // The daemon omits auth_mode for mock/test sessions → no badge.
    routeByCommand({
      interactive_open: {
        session_key: "KEY-untagged",
        state: { state: "idle" },
      },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);

    // Wait for the session to open (turn input appears), then assert no badge.
    await waitFor(() => {
      expect(get(container, "input-field")).not.toBeNull();
    });
    expect(get(container, "auth-mode-badge")).toBeNull();
  });

  it("clears the auth-mode badge on session close", async () => {
    routeByCommand({
      interactive_open: {
        session_key: "KEY-close",
        state: { state: "idle" },
        auth_mode: "subscription",
      },
      interactive_close: { state: "idle" },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);
    await waitFor(() => {
      expect(get(container, "auth-mode-badge")).not.toBeNull();
    });

    // Close the session → the badge is gone.
    await fireEvent.click(container.querySelector("button.link")!);
    await waitFor(() => {
      expect(get(container, "auth-mode-badge")).toBeNull();
    });
  });

  it("renders the enforcing (in-flight) state coherently", async () => {
    routeByCommand({
      interactive_open: { session_key: "KEY-enf", state: { state: "idle" } },
      interactive_submit: { state: "enforcing" },
    });

    const { container } = render(InteractiveConsole);
    await fireEvent.click(container.querySelector("button.primary")!);
    const input = (await waitFor(() => {
      const el = get(container, "input-field");
      expect(el).not.toBeNull();
      return el;
    })) as HTMLTextAreaElement;
    await fireEvent.input(input, { target: { value: "in flight" } });
    await fireEvent.click(get(container, "submit-btn")!);

    await waitFor(() => {
      expect(get(container, "enforcing")).not.toBeNull();
    });
    // The enforcing state shows neither a block reason nor a completed result.
    expect(get(container, "block-reason")).toBeNull();
    expect(get(container, "complete-content")).toBeNull();
  });
});
