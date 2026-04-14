import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// AddAccountModal calls:
//   invoke('list_providers')                    — when modal opens
//   invoke('get_accounts', { baseDir })         — when modal opens (slot check)
//   invoke('start_claude_login', { baseDir, account })
//   invoke('begin_claude_login', { account })   — paste-code fallback
//   invoke('submit_oauth_code', { baseDir, stateToken, code })
//   invoke('cancel_login', { stateToken })
//   invoke('set_provider_key', { baseDir, providerId, key })

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

const mockOpenUrl = vi.fn();
vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: (...args: unknown[]) => mockOpenUrl(...args),
}));

import AddAccountModal from "./AddAccountModal.svelte";

// ── Fixtures ───────────────────────────────────────────────────────

const ANTHROPIC_PROVIDER = {
  id: "anthropic",
  name: "Anthropic",
  auth_type: "oauth" as const,
  default_base_url: null,
  default_model: "claude-opus-4-6",
};

const MINIMAX_PROVIDER = {
  id: "minimax",
  name: "MiniMax",
  auth_type: "bearer" as const,
  default_base_url: "https://api.minimax.chat/v1",
  default_model: "MiniMax-M1",
};

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    list_providers: [ANTHROPIC_PROVIDER, MINIMAX_PROVIDER],
    get_accounts: [],
    start_claude_login: 1,
    set_provider_key: "abc…xyz",
    ...overrides,
  };
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in mockResponses) {
      return Promise.resolve(mockResponses[cmd]);
    }
    return Promise.resolve(undefined);
  });
}

function renderModal(propsOverrides: Record<string, unknown> = {}) {
  return render(AddAccountModal, {
    props: {
      isOpen: true,
      nextAccountId: 3,
      reauthSlot: null,
      onClose: vi.fn(),
      onAccountAdded: vi.fn(),
      ...propsOverrides,
    },
  });
}

describe("AddAccountModal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockOpenUrl.mockReset();
    setupMocks();
  });

  afterEach(() => {
    cleanup();
  });

  // ── Visibility ──────────────────────────────────────────────

  it("does not render when isOpen is false", () => {
    const { container } = render(AddAccountModal, {
      props: {
        isOpen: false,
        nextAccountId: 1,
        onClose: vi.fn(),
        onAccountAdded: vi.fn(),
      },
    });
    expect(container.querySelector(".modal")).toBeNull();
    expect(container.querySelector(".backdrop")).toBeNull();
  });

  it("renders modal with title when isOpen is true", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    expect(container.querySelector(".modal")).not.toBeNull();
    expect(container.textContent).toContain("Add Account");
  });

  // ── Provider list ───────────────────────────────────────────

  it("loads and displays provider cards", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    const cards = container.querySelectorAll(".provider-card");
    expect(cards.length).toBe(2);
    expect(cards[0].textContent).toContain("Anthropic");
    expect(cards[1].textContent).toContain("MiniMax");
  });

  it("shows default model on provider cards", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    expect(container.textContent).toContain("claude-opus-4-6");
    expect(container.textContent).toContain("MiniMax-M1");
  });

  // ── Slot picker ─────────────────────────────────────────────

  it("shows slot field with nextAccountId", async () => {
    const { container } = renderModal({ nextAccountId: 5 });
    await tick();
    await tick();
    const slotInput = container.querySelector(
      'input[type="number"]',
    ) as HTMLInputElement;
    expect(slotInput).not.toBeNull();
    expect(slotInput.value).toBe("5");
  });

  it("locks slot in re-auth mode", async () => {
    const { container } = renderModal({ reauthSlot: 2, nextAccountId: 2 });
    await tick();
    await tick();
    const slotInput = container.querySelector(
      'input[type="number"]',
    ) as HTMLInputElement;
    expect(slotInput.disabled).toBe(true);
    expect(container.textContent).toContain("Re-authenticate slot #2");
  });

  // ── Close ───────────────────────────────────────────────────

  it("calls onClose when close button is clicked", async () => {
    const onClose = vi.fn();
    const { container } = renderModal({ onClose });
    await tick();

    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    expect(closeBtn).not.toBeNull();
    await fireEvent.click(closeBtn);
    await tick();

    expect(onClose).toHaveBeenCalledOnce();
  });

  // ── Bearer flow ─────────────────────────────────────────────

  it("navigates to bearer form when bearer provider is picked", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    // Click the MiniMax card (bearer provider)
    await fireEvent.click(cards[1]);
    await tick();
    await tick();

    expect(container.textContent).toContain("Paste your MiniMax API key");
    const keyInput = container.querySelector(
      'input[type="password"]',
    ) as HTMLInputElement;
    expect(keyInput).not.toBeNull();
  });

  // ── Error display ───────────────────────────────────────────

  it("shows error banner when provider load fails", async () => {
    setupMocks();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "list_providers")
        return Promise.reject(new Error("backend crashed"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    expect(container.textContent).toContain("Could not load providers");
    expect(container.textContent).toContain("backend crashed");
  });
});
