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

const mockListen = vi.fn();
vi.mock("@tauri-apps/api/event", () => ({
  listen: (...args: unknown[]) => mockListen(...args),
}));

import AddAccountModal from "./AddAccountModal.svelte";

// ── Fixtures ───────────────────────────────────────────────────────

const ANTHROPIC_PROVIDER = {
  id: "anthropic",
  name: "Anthropic",
  auth_type: "oauth" as const,
  default_base_url: null,
  default_model: "claude-opus-4-7",
};

const MINIMAX_PROVIDER = {
  id: "minimax",
  name: "MiniMax",
  auth_type: "bearer" as const,
  default_base_url: "https://api.minimax.chat/v1",
  default_model: "MiniMax-M1",
};

const OLLAMA_PROVIDER = {
  id: "ollama",
  name: "Ollama",
  auth_type: "none" as const,
  default_base_url: "http://localhost:11434",
  default_model: "gemma4",
};

const CODEX_PROVIDER = {
  id: "codex",
  name: "Codex",
  auth_type: "oauth" as const,
  default_base_url: "https://chatgpt.com",
  default_model: "gpt-5.4",
};

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    list_providers: [ANTHROPIC_PROVIDER, MINIMAX_PROVIDER, OLLAMA_PROVIDER],
    get_accounts: [],
    start_claude_login: 1,
    set_provider_key: "abc…xyz",
    bind_keyless_provider: null,
    list_ollama_models: ["gemma4", "qwen3:latest", "gpt-oss:20b"],
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
    mockListen.mockReset();
    mockListen.mockResolvedValue(() => {}); // returns an unlisten fn
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

  // Regression for journal 0063 P1-6 (and journal 0061 pattern): the
  // modal is rendered by AccountList even when closed; the user only
  // flips it open later. Mount with isOpen=false, then flip true via
  // rerender — list_providers MUST fire on the open edge and the
  // provider cards MUST render. ChangeModelModal had an analogous bug
  // that shipped in alpha.21 precisely because its tests all mounted
  // with isOpen=true; locking this down for AddAccountModal prevents
  // the same class regression.
  it("loads providers when isOpen flips from false to true after mount", async () => {
    const { container, rerender } = render(AddAccountModal, {
      props: {
        isOpen: false,
        nextAccountId: 3,
        reauthSlot: null,
        onClose: vi.fn(),
        onAccountAdded: vi.fn(),
      },
    });
    await tick();

    // Mount happened with isOpen=false — no network/IPC should fire.
    expect(mockInvoke).not.toHaveBeenCalled();

    // User clicks "+ Add Account" → parent flips isOpen true.
    await rerender({
      isOpen: true,
      nextAccountId: 3,
      reauthSlot: null,
      onClose: vi.fn(),
      onAccountAdded: vi.fn(),
    });
    for (let i = 0; i < 8; i++) {
      await tick();
    }

    expect(mockInvoke).toHaveBeenCalledWith("list_providers");
    const cards = container.querySelectorAll(".provider-card");
    expect(
      cards.length,
      `expected 3 provider cards after open edge; got HTML: ${container.innerHTML.slice(0, 500)}`,
    ).toBe(3);
  });

  // ── Provider list ───────────────────────────────────────────

  it("loads and displays provider cards", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    const cards = container.querySelectorAll(".provider-card");
    expect(cards.length).toBe(3);
    expect(cards[0].textContent).toContain("Anthropic");
    expect(cards[1].textContent).toContain("MiniMax");
    expect(cards[2].textContent).toContain("Ollama");
  });

  it("shows default model on provider cards", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    expect(container.textContent).toContain("claude-opus-4-7");
    expect(container.textContent).toContain("MiniMax-M1");
    expect(container.textContent).toContain("gemma4");
  });

  it("labels the Ollama card as keyless", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    const cards = container.querySelectorAll(".provider-card");
    expect(cards[2].textContent).toContain("no key");
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

  // ── Keyless flow ───────────────────────────────────────────

  it("navigates to keyless confirm when Ollama is picked", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    await fireEvent.click(cards[2]);
    await tick();
    await tick();

    expect(container.textContent).toContain("Bind");
    expect(container.textContent).toContain("Ollama");
    expect(container.textContent).toContain("http://localhost:11434");
    // Keyless flow must never prompt for a key.
    expect(container.querySelector('input[type="password"]')).toBeNull();
  });

  it("calls bind_keyless_provider with slot and first installed model on Confirm", async () => {
    const onAccountAdded = vi.fn();
    const { container } = renderModal({ nextAccountId: 7, onAccountAdded });
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    await fireEvent.click(cards[2]);
    // Extra ticks for async list_ollama_models to settle.
    await tick();
    await tick();
    await tick();
    await tick();

    // Dropdown should be populated with the installed models.
    const select = container.querySelector("select") as HTMLSelectElement;
    expect(select).not.toBeNull();
    expect(select.value).toBe("gemma4");

    const confirmBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Bind to slot"),
    ) as HTMLButtonElement;
    expect(confirmBtn).not.toBeUndefined();
    await fireEvent.click(confirmBtn);
    await tick();
    await tick();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "bind_keyless_provider",
    );
    expect(call).toBeTruthy();
    expect(call?.[1]).toMatchObject({
      providerId: "ollama",
      slot: 7,
      model: "gemma4",
    });
    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("Ollama bound to slot #7");
  });

  it("passes the chosen model when the user changes the dropdown", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    await fireEvent.click(cards[2]);
    await tick();
    await tick();
    await tick();
    await tick();

    const select = container.querySelector("select") as HTMLSelectElement;
    await fireEvent.change(select, { target: { value: "qwen3:latest" } });
    await tick();

    const confirmBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Bind to slot"),
    ) as HTMLButtonElement;
    await fireEvent.click(confirmBtn);
    await tick();
    await tick();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "bind_keyless_provider",
    );
    expect(call?.[1]).toMatchObject({
      providerId: "ollama",
      model: "qwen3:latest",
    });
  });

  it("shows a warning and uses catalog default when no Ollama models are installed", async () => {
    setupMocks({ list_ollama_models: [] });
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    await fireEvent.click(cards[2]);
    await tick();
    await tick();
    await tick();

    expect(container.querySelector("select")).toBeNull();
    expect(container.textContent).toContain("No Ollama models found locally");
    // Catalog default (gemma4) is mentioned in the ollama-pull hint.
    expect(container.textContent).toContain("gemma4");

    const confirmBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Bind to slot"),
    ) as HTMLButtonElement;
    await fireEvent.click(confirmBtn);
    await tick();
    await tick();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "bind_keyless_provider",
    );
    // Empty selection → model omitted → backend falls back to default.
    expect(call?.[1]).toMatchObject({
      providerId: "ollama",
      model: null,
    });
  });

  it("surfaces backend error on keyless bind failure", async () => {
    setupMocks();
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "bind_keyless_provider")
        return Promise.reject(new Error("ollama unreachable"));
      return Promise.resolve(mockResponses[cmd]);
    });
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const cards = container.querySelectorAll(".provider-card");
    await fireEvent.click(cards[2]);
    await tick();

    const confirmBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Bind to slot"),
    ) as HTMLButtonElement;
    await fireEvent.click(confirmBtn);
    await tick();
    await tick();

    expect(container.textContent).toContain("ollama unreachable");
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

  // ── PR-C8 Codex flow ────────────────────────────────────────

  async function settle(n = 8) {
    for (let i = 0; i < n; i++) await tick();
  }

  it("shows ToS disclosure when Codex picked and marker absent", async () => {
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER, CODEX_PROVIDER],
      start_codex_login: {
        account: 3,
        tos_required: true,
        keychain: "absent",
        awaiting_keychain_decision: false,
      },
    });
    const { container } = renderModal();
    await settle();

    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as
      | HTMLButtonElement
      | undefined;
    expect(codexCard).toBeDefined();
    await fireEvent.click(codexCard!);
    await settle();

    expect(container.textContent).toContain("disclosure");
    expect(container.textContent).toContain("ChatGPT-subscription quota");
    const acceptBtn = container.querySelector(
      '[data-testid="codex-tos-accept"]',
    );
    expect(acceptBtn).not.toBeNull();
  });

  it("skips ToS disclosure when marker already present", async () => {
    // Back-to-back Codex picks: first call reports tos_required=true, user
    // acknowledges, then the re-run reports tos_required=false +
    // keychain=absent so the flow transitions straight into
    // `codex-running`.
    let startCount = 0;
    setupMocks({
      list_providers: [CODEX_PROVIDER],
      start_codex_login: undefined,
      acknowledge_codex_tos: null,
      complete_codex_login: { account: 3, label: "codex-3" },
    });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_codex_login") {
        startCount += 1;
        const tos_required = startCount === 1;
        return Promise.resolve({
          account: 3,
          tos_required,
          keychain: "absent",
          awaiting_keychain_decision: false,
        });
      }
      return Promise.resolve(mockResponses[cmd]);
    });

    const { container } = renderModal();
    await settle();

    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as HTMLButtonElement;
    await fireEvent.click(codexCard);
    await settle();

    // First click surfaced the ToS screen; acknowledging should
    // bypass it on the immediate re-run.
    const accept = container.querySelector(
      '[data-testid="codex-tos-accept"]',
    ) as HTMLButtonElement;
    expect(accept).not.toBeNull();
    await fireEvent.click(accept);
    await settle();

    // After acknowledgement the modal is in `codex-running`.
    expect(container.textContent).toContain("Signing in to Codex account");
    expect(mockInvoke).toHaveBeenCalledWith(
      "acknowledge_codex_tos",
      expect.any(Object),
    );
  });

  it("shows keychain purge prompt when residue is present", async () => {
    setupMocks({
      list_providers: [CODEX_PROVIDER],
      acknowledge_codex_tos: null,
      start_codex_login: {
        account: 3,
        tos_required: false,
        keychain: "present",
        awaiting_keychain_decision: true,
      },
    });
    const { container } = renderModal();
    await settle();

    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as HTMLButtonElement;
    await fireEvent.click(codexCard);
    await settle();

    expect(container.textContent).toContain("Existing Codex keychain entry");
    expect(container.textContent).toContain("Purge and continue");
  });
});
