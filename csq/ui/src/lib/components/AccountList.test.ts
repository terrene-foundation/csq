import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// AccountList calls:
//   invoke('get_accounts', { baseDir })   — on mount + 5s poll
//   invoke('remove_account', { baseDir, account })
//   invoke('rename_account', { baseDir, account, name })
//
// Child AddAccountModal imports @tauri-apps/plugin-opener — mock it
// so the module resolves without a Tauri runtime.

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(),
}));

import AccountList from "./AccountList.svelte";

// Flush async effects: the component's $effect fires fetchAccounts
// which awaits homeDir → join → invoke, then Svelte re-renders.
// Two ticks suffice for a single invoke; AccountList also mutates
// displayOrder inside the effect, adding a render cycle.
async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

// ── Fixtures ───────────────────────────────────────────────────────

const ACCOUNT_1 = {
  id: 1,
  label: "Work",
  source: "anthropic",
  surface: "claude-code",
  has_credentials: true,
  five_hour_pct: 25.0,
  five_hour_resets_in: 3600,
  seven_day_pct: 40.0,
  seven_day_resets_in: 86400,
  updated_at: 1700000000,
  token_status: "valid",
  expires_in_secs: 3600,
  last_refresh_error: null,
  provider_id: null,
  billing_mode: "subscription" as const,
};

const ACCOUNT_2 = {
  id: 2,
  label: "Personal",
  source: "anthropic",
  surface: "claude-code",
  has_credentials: true,
  five_hour_pct: 80.0,
  five_hour_resets_in: 1800,
  seven_day_pct: 95.0,
  seven_day_resets_in: 43200,
  updated_at: 1700000000,
  token_status: "expired",
  expires_in_secs: null,
  last_refresh_error: "broker_token_invalid",
  provider_id: null,
  billing_mode: "subscription" as const,
};

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    get_accounts: [ACCOUNT_1, ACCOUNT_2],
    remove_account: undefined,
    rename_account: undefined,
    list_providers: [],
    ...overrides,
  };
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in mockResponses) {
      return Promise.resolve(mockResponses[cmd]);
    }
    return Promise.resolve(undefined);
  });
}

describe("AccountList", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    setupMocks();
    try {
      localStorage.removeItem("csq-sort-mode");
      localStorage.removeItem("csq-card-order");
    } catch {
      // Node.js built-in localStorage may not support all methods
    }
  });

  afterEach(() => {
    cleanup();
  });

  // ── Loading & empty states ──────────────────────────────────

  it("renders loading state on mount", () => {
    const { container } = render(AccountList);
    expect(container.textContent).toContain("Loading accounts");
  });

  it("renders empty state when no accounts exist", async () => {
    setupMocks({ get_accounts: [] });
    const { container } = render(AccountList);
    await settle();
    expect(container.textContent).toContain("No accounts configured");
    expect(container.textContent).toContain("csq login 1");
  });

  // ── Account card rendering ──────────────────────────────────

  it("renders account cards with IDs and labels", async () => {
    const { container } = render(AccountList);
    await settle();
    expect(container.textContent).toContain("#1");
    expect(container.textContent).toContain("Work");
    expect(container.textContent).toContain("#2");
    expect(container.textContent).toContain("Personal");
  });

  it("renders sort control pills", async () => {
    const { container } = render(AccountList);
    await settle();
    const pills = container.querySelectorAll(".sort-pill");
    expect(pills.length).toBe(3);
    expect(pills[0].textContent).toBe("custom");
    expect(pills[1].textContent).toBe("5h reset");
    expect(pills[2].textContent).toBe("7d reset");
  });

  it("renders usage bars for each account", async () => {
    const { container } = render(AccountList);
    await settle();
    const bars = container.querySelectorAll(".usage-bars");
    expect(bars.length).toBe(2);
  });

  it("shows reset time info", async () => {
    const { container } = render(AccountList);
    await settle();
    // ACCOUNT_1: 5h=3600s → "1h", 7d=86400s → "24h"
    expect(container.textContent).toContain("5h resets in 1h");
    expect(container.textContent).toContain("7d resets in 24h");
  });

  it("shows refresh error for accounts with failures", async () => {
    const { container } = render(AccountList);
    await settle();
    // ACCOUNT_2 has last_refresh_error: "broker_token_invalid"
    expect(container.textContent).toContain(
      "invalid token \u2014 re-login needed",
    );
  });

  it("shows re-auth button for expired or errored accounts", async () => {
    const { container } = render(AccountList);
    await settle();
    const reauthBtns = container.querySelectorAll(".reauth-btn");
    expect(reauthBtns.length).toBeGreaterThanOrEqual(1);
    expect(reauthBtns[0].textContent).toContain("Re-auth");
  });

  // ── Error state ─────────────────────────────────────────────

  it("renders error when get_accounts rejects", async () => {
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "get_accounts")
        return Promise.reject(new Error("network error"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = render(AccountList);
    await settle();
    expect(container.textContent).toContain("network error");
  });

  // ── Interactions ────────────────────────────────────────────
  //
  // 2026-06-11: the whole-card swap affordance was REMOVED (the
  // desktop swap handler could only ever return the M4-8
  // DESKTOP_SWAP_UNAVAILABLE refusal — a dead flow; spec 02 §2.8).
  // These regressions pin the card body as NON-interactive so the
  // affordance does not silently come back without a working
  // backend behind it.

  it("card body is not an interactive element (no role/tabindex)", async () => {
    const { container } = render(AccountList);
    await settle();

    const cardBodies = container.querySelectorAll(".card-body");
    expect(cardBodies.length).toBe(2);
    for (const body of cardBodies) {
      expect(body.getAttribute("role")).toBeNull();
      expect(body.getAttribute("tabindex")).toBeNull();
    }
  });

  it("clicking the card body invokes no IPC command", async () => {
    const { container } = render(AccountList);
    await settle();
    mockInvoke.mockClear();

    const card = container.querySelector(".card-body") as HTMLElement;
    await fireEvent.click(card);
    await fireEvent.keyDown(card, { key: "Enter" });
    await fireEvent.keyDown(card, { key: " " });
    await settle();

    // The 5s poll is not due yet, so ANY invoke here would be an
    // unintended action fired by the click/keydown.
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it("Enter inside the rename input saves the rename and nothing else", async () => {
    const { container } = render(AccountList);
    await settle();

    const label = container.querySelector(".account-label") as HTMLElement;
    await fireEvent.dblClick(label);
    await settle();

    const input = container.querySelector(".rename-input") as HTMLInputElement;
    expect(input).not.toBeNull();
    input.value = "renamed label";
    await fireEvent.input(input);
    mockInvoke.mockClear();
    await fireEvent.keyDown(input, { key: "Enter" });
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith(
      "rename_account",
      expect.objectContaining({ account: 1, name: "renamed label" }),
    );
    const commands = mockInvoke.mock.calls.map((c) => c[0]);
    expect(commands).not.toContain("swap_account");
  });

  it("shows Add Account button", async () => {
    const { container } = render(AccountList);
    await settle();
    const addBtn = container.querySelector(".add-account");
    expect(addBtn).not.toBeNull();
    expect(addBtn?.textContent).toContain("Add Account");
  });

  it("arms remove on first click and confirms on second", async () => {
    const { container } = render(AccountList);
    await settle();

    const removeBtns = container.querySelectorAll(".remove-btn");
    expect(removeBtns.length).toBe(2);

    // First click arms the button
    await fireEvent.click(removeBtns[0]);
    await tick();
    expect(removeBtns[0].textContent).toContain("Confirm");
    expect(removeBtns[0].classList.contains("armed")).toBe(true);

    // Second click confirms the removal
    await fireEvent.click(removeBtns[0]);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith(
      "remove_account",
      expect.objectContaining({ account: 1 }),
    );
  });

  // ── Move-slot (renumber) flow ───────────────────────────────

  it("renumber button opens the inline picker", async () => {
    const { container } = render(AccountList);
    await settle();

    // Picker is closed by default.
    expect(
      container.querySelector('[data-testid="renumber-picker"]'),
    ).toBeNull();

    const renumberBtns = container.querySelectorAll(
      '[data-testid="renumber-btn"]',
    );
    expect(renumberBtns.length).toBe(2);

    await fireEvent.click(renumberBtns[0]);
    await tick();

    const picker = container.querySelector('[data-testid="renumber-picker"]');
    expect(picker).not.toBeNull();
    // Free slots for source slot 1 with slots [1,2] taken: 3,4,5,6,7,8,9.
    const select = picker!.querySelector(
      '[data-testid="renumber-target"]',
    ) as HTMLSelectElement;
    expect(select).not.toBeNull();
    const optionValues = Array.from(select.options).map((o) => o.value);
    expect(optionValues).toEqual(["3", "4", "5", "6", "7", "8", "9"]);
  });

  it("renumber picker offers slots above 9 when higher slots are occupied", async () => {
    // Slots 1-9 + 11 occupied (highest = 11). Free targets for source slot 1
    // must include the gap (10) AND one past the highest (12) — the pre-fix
    // hardcoded 1-9 cap reported "No free slots in 1-9" here.
    const accounts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11].map((id) => ({
      ...ACCOUNT_1,
      id,
      label: `slot-${id}`,
    }));
    setupMocks({ get_accounts: accounts });
    const { container } = render(AccountList);
    await settle();

    const renumberBtns = container.querySelectorAll(
      '[data-testid="renumber-btn"]',
    );
    await fireEvent.click(renumberBtns[0]); // source slot 1
    await tick();

    const select = container.querySelector(
      '[data-testid="renumber-target"]',
    ) as HTMLSelectElement;
    expect(select).not.toBeNull();
    const optionValues = Array.from(select.options).map((o) => o.value);
    // 1-9 + 11 taken, fromId=1 excluded; upper = max(9, 11+1) = 12.
    // Free = {10, 12}.
    expect(optionValues).toEqual(["10", "12"]);
  });

  it("confirming move invokes move_account with from + to", async () => {
    setupMocks({ move_account: { from: 1, to: 4, config_dir_moved: true } });
    const { container } = render(AccountList);
    await settle();

    const renumberBtns = container.querySelectorAll(
      '[data-testid="renumber-btn"]',
    );
    await fireEvent.click(renumberBtns[0]);
    await tick();

    const select = container.querySelector(
      '[data-testid="renumber-target"]',
    ) as HTMLSelectElement;
    // Pick slot 4.
    select.value = "4";
    await fireEvent.change(select);
    await tick();

    const confirm = container.querySelector(
      '[data-testid="renumber-confirm"]',
    ) as HTMLButtonElement;
    expect(confirm).not.toBeNull();
    await fireEvent.click(confirm);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith(
      "move_account",
      expect.objectContaining({ from: 1, to: 4 }),
    );
  });

  // Phase 3 (M3-6): `SLOT_IN_USE` is retired. The Tauri command returns
  // `MoveAccountSummary` with `live_pids_bound: number[]` telemetry instead
  // of refusing the move. The frontend surfaces a non-blocking info notice
  // when the list is non-empty.
  it("surfaces live-pid info notice after move when summary reports bound PIDs", async () => {
    setupMocks({
      move_account: {
        from: 1,
        to: 4,
        config_dir_moved: true,
        canonical_creds_moved: [],
        profiles_entry_moved: true,
        by_slot_swapped: false,
        quota_entry_moved: false,
        live_pids_bound: [12345, 23456],
      },
    });

    const { container } = render(AccountList);
    await settle();

    const renumberBtns = container.querySelectorAll(
      '[data-testid="renumber-btn"]',
    );
    await fireEvent.click(renumberBtns[0]);
    await tick();
    const select = container.querySelector(
      '[data-testid="renumber-target"]',
    ) as HTMLSelectElement;
    select.value = "4";
    await fireEvent.change(select);
    await tick();
    const confirm = container.querySelector(
      '[data-testid="renumber-confirm"]',
    ) as HTMLButtonElement;
    await fireEvent.click(confirm);
    await settle();

    // Picker closes on success.
    expect(
      container.querySelector('[data-testid="renumber-picker"]'),
    ).toBeNull();
    // Info notice surfaces the live-PID telemetry naming the slot count + PIDs.
    expect(container.textContent).toContain("Moved slot 1 → 4");
    expect(container.textContent).toContain("2 Claude Code session(s)");
    expect(container.textContent).toContain("12345");
    expect(container.textContent).toContain("23456");
  });

  // Empty `live_pids_bound` → no notice rendered (move was unbound).
  it("does not show info notice when live_pids_bound is empty", async () => {
    setupMocks({
      move_account: {
        from: 1,
        to: 4,
        config_dir_moved: true,
        canonical_creds_moved: [],
        profiles_entry_moved: true,
        by_slot_swapped: false,
        quota_entry_moved: false,
        live_pids_bound: [],
      },
    });

    const { container } = render(AccountList);
    await settle();

    const renumberBtns = container.querySelectorAll(
      '[data-testid="renumber-btn"]',
    );
    await fireEvent.click(renumberBtns[0]);
    await tick();
    const select = container.querySelector(
      '[data-testid="renumber-target"]',
    ) as HTMLSelectElement;
    select.value = "4";
    await fireEvent.change(select);
    await tick();
    const confirm = container.querySelector(
      '[data-testid="renumber-confirm"]',
    ) as HTMLButtonElement;
    await fireEvent.click(confirm);
    await settle();

    expect(container.querySelector(".info-notice")).toBeNull();
  });

  // ── PR-C8 surface badge ──────────────────────────────────────

  it("renders 'claude' surface badge for claude-code slots (universal badges, PR #310)", async () => {
    // Pre-PR-#310, the badge hid for `claude-code` ("the default
    // doesn't need a tag"). PR #310 dropped that exclusion so all
    // three CLIs (CLAUDE / CODEX / GEMINI) appear consistently. The
    // displayed text maps `claude-code` → `claude`.
    const { container } = render(AccountList);
    await settle();
    const badges = container.querySelectorAll('[data-testid="surface-badge"]');
    expect(badges.length).toBeGreaterThan(0);
    const claudeBadge = Array.from(badges).find(
      (b) => b.textContent?.trim() === "claude",
    );
    expect(claudeBadge).toBeDefined();
  });

  it("renders keyboard-focusable surface badge for Codex slots", async () => {
    const codexAccount = {
      ...ACCOUNT_1,
      id: 3,
      label: "codex-3",
      source: "codex",
      surface: "codex",
    };
    setupMocks({ get_accounts: [codexAccount] });
    const { container } = render(AccountList);
    await settle();
    const badge = container.querySelector(
      '[data-testid="surface-badge"]',
    ) as HTMLElement | null;
    expect(badge).not.toBeNull();
    expect(badge?.textContent?.trim()).toBe("codex");
    // Keyboard-focusable — matches the PR-C8 acceptance criterion.
    // R1 2026-06-11: the badge is a <span role="status" tabindex="0">
    // (it was a <button>, which nested invalidly inside the card-body
    // container and paired an interactive element with a
    // noninteractive role). Verify focusability via tabindex — the
    // actual PR-C8 criterion — rather than the element tag.
    expect(badge?.getAttribute("tabindex")).toBe("0");
    expect(badge?.tagName.toLowerCase()).toBe("span");
    // aria-label carries the surface for screen readers.
    expect(badge?.getAttribute("aria-label")).toContain("codex");
    // role=status so the badge is announced as a live region on
    // surface transitions (cross-surface swap feedback).
    expect(badge?.getAttribute("role")).toBe("status");
  });

  it("shows Change model button on Codex slots even without provider_id", async () => {
    const codexAccount = {
      ...ACCOUNT_1,
      id: 4,
      label: "codex-4",
      source: "codex",
      surface: "codex",
      provider_id: null,
    };
    setupMocks({ get_accounts: [codexAccount] });
    const { container } = render(AccountList);
    await settle();
    const btn = container.querySelector(".change-model-btn");
    expect(btn).not.toBeNull();
    expect(btn?.textContent).toContain("Change model");
  });

  // ── PR-G5 — Gemini surface rendering (FR-G-UI-03) ───────────

  it("renders distinct surface-gemini badge for Gemini slots", async () => {
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 5,
      label: "gemini-5",
      source: "manual",
      surface: "gemini",
      provider_id: null,
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const badge = container.querySelector(
      '[data-testid="surface-badge"]',
    ) as HTMLElement | null;
    expect(badge).not.toBeNull();
    expect(badge?.textContent?.trim()).toBe("gemini");
    expect(badge?.classList.contains("surface-gemini")).toBe(true);
    // Codex CSS class MUST NOT also be applied — the chip color is
    // distinct (Google blue vs OpenAI green).
    expect(badge?.classList.contains("surface-codex")).toBe(false);
  });

  it("renders 'quota: n/a' for Gemini slot with no counter yet", async () => {
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 6,
      label: "gemini-6",
      surface: "gemini",
      gemini_counter_today: null,
      gemini_rate_limit_reset_at: null,
      gemini_selected_model: null,
      gemini_effective_model: null,
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const na = container.querySelector('[data-testid="gemini-quota-na"]');
    expect(na).not.toBeNull();
    expect(na?.textContent).toContain("n/a");
    // The synthesised 5h/7d UsageBar is suppressed for Gemini.
    expect(container.querySelector(".usage-bars")).toBeNull();
  });

  it("renders counter when Gemini slot has requests today", async () => {
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 7,
      label: "gemini-7",
      surface: "gemini",
      gemini_counter_today: 42,
      gemini_rate_limit_reset_at: null,
      gemini_selected_model: "gemini-2.5-pro",
      gemini_effective_model: "gemini-2.5-pro",
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const counter = container.querySelector('[data-testid="gemini-counter"]');
    expect(counter).not.toBeNull();
    expect(counter?.textContent).toContain("42");
    expect(counter?.textContent).toContain("today");
    // No downgrade chip when selected === effective.
    expect(
      container.querySelector('[data-testid="gemini-downgrade"]'),
    ).toBeNull();
  });

  it("renders downgrade badge when selected_model != effective_model", async () => {
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 8,
      label: "gemini-8",
      surface: "gemini",
      gemini_counter_today: 1,
      gemini_rate_limit_reset_at: null,
      gemini_selected_model: "gemini-3-pro-preview",
      gemini_effective_model: "gemini-2.5-pro",
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const downgrade = container.querySelector(
      '[data-testid="gemini-downgrade"]',
    );
    expect(downgrade).not.toBeNull();
    expect(downgrade?.textContent).toContain("gemini-3-pro-preview");
    expect(downgrade?.textContent).toContain("gemini-2.5-pro");
  });

  it("renders rate-limit countdown when 429 is active", async () => {
    // 30 minutes in the future.
    const future = new Date(Date.now() + 30 * 60 * 1000).toISOString();
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 9,
      label: "gemini-9",
      surface: "gemini",
      gemini_counter_today: 237,
      gemini_rate_limit_reset_at: future,
      gemini_selected_model: "gemini-2.5-pro",
      gemini_effective_model: "gemini-2.5-pro",
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const rl = container.querySelector('[data-testid="gemini-rate-limit"]');
    expect(rl).not.toBeNull();
    expect(rl?.textContent).toContain("rate-limited");
    expect(rl?.textContent).toMatch(/resets in \d+m/);
    // Counter is hidden while rate-limited (the rate-limit message is
    // the more actionable signal).
    expect(
      container.querySelector('[data-testid="gemini-counter"]'),
    ).toBeNull();
  });

  it("shows Change model button on Gemini slots", async () => {
    const geminiAccount = {
      ...ACCOUNT_1,
      id: 10,
      label: "gemini-10",
      surface: "gemini",
    };
    setupMocks({ get_accounts: [geminiAccount] });
    const { container } = render(AccountList);
    await settle();
    const btn = container.querySelector(".change-model-btn");
    expect(btn).not.toBeNull();
    expect(btn?.getAttribute("title")).toContain("Gemini");
  });

  // Phase B billing-mode badge tests removed — the static
  // "API-key billing" / "Local provider" labels were a regression
  // that hid quota data MiniMax + Z.AI's subscription modes
  // expose via direct endpoints, and offered no usage-tracking
  // signal in their place. Proper usage UI tracked in journal 0047.

  // ── RN1-D — inline rename error surface (D8) ────────────────

  // When rename_account Tauri command rejects, the error is rendered
  // inline next to the rename input (data-testid="rename-error") rather
  // than replacing the whole account list with the global error banner.
  // The card list MUST remain visible during the failed rename.
  it("rename_account_error_surfaces_inline_without_replacing_card_list", async () => {
    // Arrange: rename_account rejects with a validation error from
    // the backend (the same message the Rust command produces for
    // oversize labels after the "rename failed: " prefix is stripped).
    setupMocks({
      rename_account: new Error("name exceeds 256 characters (got 300)"),
    });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "rename_account") {
        return Promise.reject(
          new Error("rename failed: name exceeds 256 characters (got 300)"),
        );
      }
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = render(AccountList);
    await settle();

    // Act: double-click the first account label to open the rename input.
    const label = container.querySelector(".account-label") as HTMLElement;
    expect(label).not.toBeNull();
    await fireEvent.dblClick(label);
    await tick();

    // Confirm the rename input is now open.
    const input = container.querySelector(".rename-input") as HTMLInputElement;
    expect(input).not.toBeNull();

    // Blur the input to trigger saveRename (simulates pressing Enter or
    // clicking elsewhere).
    await fireEvent.blur(input);
    await settle();

    // Assert: inline rename error is shown.
    const renameErr = container.querySelector('[data-testid="rename-error"]');
    expect(renameErr).not.toBeNull();
    expect(renameErr?.textContent).toContain("name exceeds 256 characters");

    // Assert: card list is still visible (the global error banner did NOT
    // replace the account list — both account cards are still rendered).
    // Account #1 is still in rename-input mode (editingId not cleared on
    // failure), so its label "Work" is hidden by the input; check the
    // second card's label "Personal" and verify both .account-card
    // elements exist.
    const cards = container.querySelectorAll(".account-card");
    expect(cards.length).toBe(2);
    expect(container.textContent).toContain("Personal");
    // The global .error class replaces the list; it must not be present.
    expect(container.querySelector(".error")).toBeNull();
  });

  // When the rename succeeds, no inline error element is rendered.
  it("rename_account_success_shows_no_inline_error", async () => {
    // Arrange: rename_account resolves (success).
    setupMocks({ rename_account: undefined });
    const { container } = render(AccountList);
    await settle();

    // Act: open rename, blur to trigger save.
    const label = container.querySelector(".account-label") as HTMLElement;
    await fireEvent.dblClick(label);
    await tick();
    const input = container.querySelector(".rename-input") as HTMLInputElement;
    await fireEvent.blur(input);
    await settle();

    // Assert: no rename error element exists.
    expect(container.querySelector('[data-testid="rename-error"]')).toBeNull();
  });
});
