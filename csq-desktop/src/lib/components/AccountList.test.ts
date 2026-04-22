import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// AccountList calls:
//   invoke('get_accounts', { baseDir })   — on mount + 5s poll
//   invoke('swap_account', { baseDir, target })
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
};

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    get_accounts: [ACCOUNT_1, ACCOUNT_2],
    swap_account: undefined,
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

  it("calls swap_account when card body is clicked", async () => {
    const { container } = render(AccountList);
    await settle();

    const cardBodies = container.querySelectorAll(".card-body");
    expect(cardBodies.length).toBe(2);
    await fireEvent.click(cardBodies[0]);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith(
      "swap_account",
      expect.objectContaining({ target: 1 }),
    );
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

  // ── PR-C8 surface badge ──────────────────────────────────────

  it("does not render surface badge for claude-code slots", async () => {
    const { container } = render(AccountList);
    await settle();
    const badges = container.querySelectorAll('[data-testid="surface-badge"]');
    expect(badges.length).toBe(0);
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
    // A `<button>` element is implicitly focusable (no tabindex
    // attribute needed); svelte a11y lint flags `tabindex=0` on a
    // non-interactive span, so we use a native button styled as a
    // badge instead. Verify focusability via the element's tagName.
    expect(badge?.tagName.toLowerCase()).toBe("button");
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
});
