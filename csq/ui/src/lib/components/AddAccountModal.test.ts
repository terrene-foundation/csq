import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// AddAccountModal calls:
//   invoke('list_providers')                    — when modal opens
//   invoke('get_accounts', { baseDir })         — when modal opens (slot check)
//   invoke('start_claude_login_subprocess', { baseDir, account })
//                                               — Phase 2 of an internal ticket
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
  id: "claude",
  name: "Claude",
  auth_type: "oauth" as const,
  default_base_url: null,
  default_model: "claude-opus-4-7",
};

const MINIMAX_PROVIDER = {
  id: "mm",
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

const GEMINI_PROVIDER = {
  id: "gemini",
  name: "Gemini",
  auth_type: "none" as const,
  default_base_url: "https://generativelanguage.googleapis.com",
  default_model: "gemini-2.5-pro",
};

// Wave 3 W3-5 (an internal journal entry) — native Kimi/Grok session-surface fixtures.
const KIMI_NATIVE_CLI = {
  id: "kimi-cli",
  display_name: "Kimi (native CLI)",
  default_model: "kimi-for-coding",
  surface: "kimi",
  binary: "kimi",
};

const GROK_NATIVE_CLI = {
  id: "grok",
  display_name: "Grok (native CLI)",
  // an internal journal entry Wave A empirical finding — grok-cli's own default model
  // (see csq-core/src/providers/native.rs::GROK); no longer empty.
  default_model: "grok-4.5",
  surface: "grok",
  binary: "grok",
};

const mockOpenDialog = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => mockOpenDialog(...args),
}));

let mockResponses: Record<string, unknown> = {};

function setupMocks(overrides: Record<string, unknown> = {}) {
  mockResponses = {
    list_providers: [ANTHROPIC_PROVIDER, MINIMAX_PROVIDER, OLLAMA_PROVIDER],
    // Wave 3 W3-5: no native CLIs by default — tests exercising the
    // native picker cards override this explicitly.
    list_native_clis: [],
    get_accounts: [],
    // Phase 2 of an internal ticket: claude OAuth is one synchronous-from-frontend
    // invoke that resolves with { account, email } after the
    // `claude auth login` subprocess exits. Tests that exercise the
    // happy path or specific error shapes override this default.
    start_claude_login_subprocess: { account: 3, email: "user@example.com" },
    set_provider_key: "abc…xyz",
    bind_keyless_provider: null,
    list_ollama_models: ["gemma4", "qwen3:latest", "gpt-oss:20b"],
    // Bug A pre-flight: codex/gemini flows probe the CLI's presence first.
    // Default to installed so existing flow tests proceed; the cli-missing
    // test overrides this to false.
    provider_cli_installed: true,
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
    mockOpenDialog.mockReset();
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

  // Regression for an internal journal entry P1-6 (and an internal journal entry pattern): the
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

  /// Round 2 LOW-2: pin the per-provider picker labels so a future
  /// regression to the cascade in AddAccountModal.svelte (e.g.
  /// reverting to the old hardcoded "Sign in with Anthropic" for any
  /// oauth provider) is caught at test time.
  it("labels each provider card with the right identity-provider name", async () => {
    setupMocks({
      list_providers: [
        ANTHROPIC_PROVIDER,
        CODEX_PROVIDER,
        GEMINI_PROVIDER,
        MINIMAX_PROVIDER,
        OLLAMA_PROVIDER,
      ],
    });
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();
    const cards = Array.from(container.querySelectorAll(".provider-card"));
    const text = (i: number) => cards[i]?.textContent ?? "";

    expect(text(0)).toContain("Sign in with Anthropic"); // claude
    expect(text(1)).toContain("Sign in with ChatGPT"); // codex
    expect(text(2)).toContain("AI Studio key or Vertex SA"); // gemini
    expect(text(3)).toContain("Paste an API key"); // minimax (bearer)
    expect(text(4)).toContain("Local provider"); // ollama (none)
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

  // ── Escape / focus trap (F4 i-audit/i-harden fix) ────────────
  //
  // Pre-fix, Escape was wired to the *backdrop's* onkeydown, but
  // `.modal`'s own onkeydown called `e.stopPropagation()`. Keydown
  // bubbles from the focused element upward, so any focus INSIDE the
  // modal — every real interaction — hit stopPropagation before the
  // backdrop's handler ever ran. A test that fires Escape with focus
  // on the backdrop itself would pass against the OLD broken code too
  // (vacuous, since that was the one case the old code handled). The
  // test below fires Escape with focus inside the modal, which is the
  // actual bug this fix closes.

  it("closes on Escape when focus is inside the modal (the actual F4 bug)", async () => {
    const onClose = vi.fn();
    const { container } = renderModal({ onClose });
    await tick();
    await tick();
    await tick();

    const slotInput = container.querySelector(
      'input[type="number"]',
    ) as HTMLInputElement;
    expect(slotInput).not.toBeNull();
    slotInput.focus();
    expect(document.activeElement).toBe(slotInput);

    await fireEvent.keyDown(document, { key: "Escape" });
    await tick();

    expect(onClose).toHaveBeenCalledOnce();
  });

  it("does not escape the focus trap on Tab — wraps from last focusable back to first", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const focusables = Array.from(
      container.querySelectorAll<HTMLElement>(
        ".modal button:not([disabled]), .modal input:not([disabled])",
      ),
    );
    expect(focusables.length).toBeGreaterThan(1);
    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    last.focus();
    expect(document.activeElement).toBe(last);

    await fireEvent.keyDown(document, { key: "Tab" });
    await tick();

    // Focus must land back INSIDE the dialog (at `first`), never on
    // `document.body` / the page behind the modal.
    expect(document.activeElement).toBe(first);
  });

  it("does not escape the focus trap on Shift+Tab — wraps from first focusable back to last", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const focusables = Array.from(
      container.querySelectorAll<HTMLElement>(
        ".modal button:not([disabled]), .modal input:not([disabled])",
      ),
    );
    expect(focusables.length).toBeGreaterThan(1);
    const first = focusables[0];
    const last = focusables[focusables.length - 1];

    first.focus();
    expect(document.activeElement).toBe(first);

    await fireEvent.keyDown(document, { key: "Tab", shiftKey: true });
    await tick();

    expect(document.activeElement).toBe(last);
  });

  it("moves initial focus into the dialog when opened", async () => {
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const modal = container.querySelector(".modal") as HTMLElement;
    expect(modal).not.toBeNull();
    expect(modal.contains(document.activeElement)).toBe(true);
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
        // Round-4 redteam HIGH-A — `start_codex_login` Tauri response
        // carries the ChatGPT Security Settings prerequisite. Round-6
        // redteam LOW-3 — assert the banner actually renders so a
        // refactor that drops these fields fails the test instead of
        // silently regressing the UX.
        device_auth_prereq_message:
          'Codex requires "Device code authorization" to be ENABLED in your ChatGPT Security Settings BEFORE the device code can be redeemed.',
        device_auth_prereq_url: "https://chatgpt.com/#settings/Security",
      },
    });
    const { container } = renderModal();
    await settle();

    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as
      HTMLButtonElement | undefined;
    expect(codexCard).toBeDefined();
    await fireEvent.click(codexCard!);
    await settle();

    expect(container.textContent).toContain("disclosure");
    expect(container.textContent).toContain("ChatGPT-subscription quota");
    const acceptBtn = container.querySelector(
      '[data-testid="codex-tos-accept"]',
    );
    expect(acceptBtn).not.toBeNull();

    // Round-6 redteam LOW-3 — prereq banner must render in codex-tos
    // screen with the message + URL. Without these assertions a future
    // refactor could drop the {#if codexPrereq} block silently.
    const prereqBanner = container.querySelector(
      '[data-testid="codex-device-auth-prereq"]',
    );
    expect(prereqBanner).not.toBeNull();
    expect(prereqBanner!.textContent).toContain("Device code authorization");
    const prereqLink = prereqBanner!.querySelector("a");
    expect(prereqLink).not.toBeNull();
    expect(prereqLink!.getAttribute("href")).toContain("chatgpt.com");
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
          // Round-4 / Round-6 redteam — every start_codex_login response
          // carries the device-auth prereq (backend always populates it).
          device_auth_prereq_message:
            'Codex requires "Device code authorization" to be ENABLED in your ChatGPT Security Settings BEFORE the device code can be redeemed.',
          device_auth_prereq_url: "https://chatgpt.com/#settings/Security",
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
        device_auth_prereq_message:
          'Codex requires "Device code authorization" to be ENABLED in your ChatGPT Security Settings BEFORE the device code can be redeemed.',
        device_auth_prereq_url: "https://chatgpt.com/#settings/Security",
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

  it("renders the device code with a working copy-to-clipboard button", async () => {
    // Bug B: the device-auth code must be selectable AND copyable.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    setupMocks({
      list_providers: [CODEX_PROVIDER],
      start_codex_login: {
        account: 3,
        tos_required: false,
        keychain: "absent",
        awaiting_keychain_decision: false,
        device_auth_prereq_message: "prereq",
        device_auth_prereq_url: "https://chatgpt.com/#settings/Security",
      },
      // Never resolves → the flow stays in `codex-running` so the
      // device-code panel remains mounted for the assertions.
      complete_codex_login: new Promise(() => {}),
    });

    let deviceCodeHandler:
      | ((e: {
          payload: { user_code: string; verification_url: string };
        }) => void)
      | null = null;
    mockListen.mockImplementation((event: string, handler: unknown) => {
      if (event === "codex-device-code") {
        deviceCodeHandler = handler as typeof deviceCodeHandler;
      }
      return Promise.resolve(() => {});
    });

    const { container } = renderModal();
    await settle();
    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as HTMLButtonElement;
    await fireEvent.click(codexCard);
    await settle();

    // Deliver the device code (as the backend event would).
    expect(deviceCodeHandler).not.toBeNull();
    deviceCodeHandler!({
      payload: {
        user_code: "WXYZ-7788",
        verification_url: "https://chatgpt.com/device",
      },
    });
    await settle();

    // The code renders, in a selectable element.
    const codeEl = container.querySelector(".device-code");
    expect(codeEl).not.toBeNull();
    expect(codeEl!.textContent).toContain("WXYZ-7788");

    // The copy button exists and writes the code to the clipboard.
    const copyBtn = container.querySelector(
      '[data-testid="copy-device-code"]',
    ) as HTMLButtonElement;
    expect(copyBtn).not.toBeNull();
    await fireEvent.click(copyBtn);
    await settle();
    expect(writeText).toHaveBeenCalledWith("WXYZ-7788");
  });

  it("shows an install prompt (not a login error) when codex-cli is missing", async () => {
    // Bug A: pre-flight the CLI presence; a missing binary surfaces a friendly
    // install prompt BEFORE launching a login that would fail mid-device-auth.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    setupMocks({
      list_providers: [CODEX_PROVIDER],
      provider_cli_installed: false,
    });
    const { container } = renderModal();
    await settle();
    const codexCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Codex")) as HTMLButtonElement;
    await fireEvent.click(codexCard);
    await settle();

    const prompt = container.querySelector(
      '[data-testid="cli-missing-prompt"]',
    );
    expect(prompt).not.toBeNull();
    expect(prompt!.textContent).toContain("codex-cli is not installed");
    expect(container.textContent).toContain("npm install -g @openai/codex");
    // The pre-flight MUST abort before launching the login.
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "start_codex_login",
      expect.anything(),
    );

    // Copy button writes the install command; Recheck button exists.
    const copyBtn = container.querySelector(
      '[data-testid="copy-install-cmd"]',
    ) as HTMLButtonElement;
    expect(copyBtn).not.toBeNull();
    await fireEvent.click(copyBtn);
    await settle();
    expect(writeText).toHaveBeenCalledWith("npm install -g @openai/codex");
    expect(
      container.querySelector('[data-testid="cli-missing-recheck"]'),
    ).not.toBeNull();
  });

  // ── PR-G5 Gemini flow ───────────────────────────────────────

  it("shows informational disclosure when Gemini picked and marker absent", async () => {
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER, GEMINI_PROVIDER],
      gemini_probe_tos_residue: null,
      is_gemini_tos_acknowledged: false,
    });
    const { container } = renderModal();
    await settle();

    const geminiCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Gemini")) as
      HTMLButtonElement | undefined;
    expect(geminiCard).toBeDefined();
    await fireEvent.click(geminiCard!);
    await settle();

    // Post-journal-0048 copy: neutral framing about how csq wraps
    // the official gemini-cli, not alarmist "ToS rerouting"
    // language. The marker + accept button still gates first-time
    // provisioning so users see the walkthrough.
    expect(container.textContent).toMatch(/spawns the official\s+gemini/i);
    expect(container.textContent).toContain("AI Studio API key");
    const acceptBtn = container.querySelector(
      '[data-testid="gemini-tos-accept"]',
    );
    expect(acceptBtn).not.toBeNull();
  });

  it("shows residue warning on ToS panel when oauth_creds.json exists", async () => {
    setupMocks({
      list_providers: [GEMINI_PROVIDER],
      gemini_probe_tos_residue: "/Users/test/.gemini/oauth_creds.json",
      is_gemini_tos_acknowledged: false,
    });
    const { container } = renderModal();
    await settle();

    const geminiCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Gemini")) as HTMLButtonElement;
    await fireEvent.click(geminiCard);
    await settle();

    const warning = container.querySelector(
      '[data-testid="gemini-residue-warning"]',
    );
    expect(warning).not.toBeNull();
    expect(warning?.textContent).toContain("oauth_creds.json");
  });

  it("skips ToS disclosure when marker already present", async () => {
    setupMocks({
      list_providers: [GEMINI_PROVIDER],
      gemini_probe_tos_residue: null,
      is_gemini_tos_acknowledged: true,
    });
    const { container } = renderModal();
    await settle();

    const geminiCard = Array.from(
      container.querySelectorAll(".provider-card"),
    ).find((el) => el.textContent?.includes("Gemini")) as HTMLButtonElement;
    await fireEvent.click(geminiCard);
    await settle();

    // Should be on the provision panel, not the ToS panel.
    expect(
      container.querySelector('[data-testid="gemini-tos-accept"]'),
    ).toBeNull();
    expect(
      container.querySelector('[data-testid="gemini-tab-api-key"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-testid="gemini-tab-vertex"]'),
    ).not.toBeNull();
  });

  it("submits gemini_provision_api_key on Provision click", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({
      list_providers: [GEMINI_PROVIDER],
      gemini_probe_tos_residue: null,
      is_gemini_tos_acknowledged: true,
      gemini_provision_api_key: undefined,
    });
    const { container } = renderModal({ onAccountAdded });
    await settle();

    await fireEvent.click(
      Array.from(container.querySelectorAll(".provider-card")).find((el) =>
        el.textContent?.includes("Gemini"),
      ) as HTMLButtonElement,
    );
    await settle();

    const input = container.querySelector(
      '[data-testid="gemini-api-key-input"]',
    ) as HTMLInputElement;
    await fireEvent.input(input, {
      target: { value: "AIzaSyTEST_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    });
    await tick();

    const submit = container.querySelector(
      '[data-testid="gemini-api-key-submit"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    await fireEvent.click(submit);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith("gemini_provision_api_key", {
      baseDir: "/home/test/.claude/accounts",
      slot: 3,
      key: "AIzaSyTEST_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    });
    expect(onAccountAdded).toHaveBeenCalled();
    expect(container.textContent).toContain("Gemini account 3 provisioned");
  });

  it("opens file dialog for Vertex SA tab and submits the picked path", async () => {
    setupMocks({
      list_providers: [GEMINI_PROVIDER],
      gemini_probe_tos_residue: null,
      is_gemini_tos_acknowledged: true,
      gemini_provision_vertex_sa: "/abs/picked/sa.json",
    });
    mockOpenDialog.mockResolvedValueOnce("/abs/picked/sa.json");

    const { container } = renderModal();
    await settle();

    await fireEvent.click(
      Array.from(container.querySelectorAll(".provider-card")).find((el) =>
        el.textContent?.includes("Gemini"),
      ) as HTMLButtonElement,
    );
    await settle();

    // Switch to vertex tab.
    const vertexTab = container.querySelector(
      '[data-testid="gemini-tab-vertex"]',
    ) as HTMLButtonElement;
    await fireEvent.click(vertexTab);
    await tick();

    // File picker → mock returns the path.
    const pickBtn = container.querySelector(
      '[data-testid="gemini-vertex-pick"]',
    ) as HTMLButtonElement;
    await fireEvent.click(pickBtn);
    await settle();

    expect(mockOpenDialog).toHaveBeenCalled();
    const pathDisplay = container.querySelector(
      '[data-testid="gemini-vertex-path"]',
    );
    expect(pathDisplay?.textContent).toContain("/abs/picked/sa.json");

    // Submit the vertex SA.
    const submit = container.querySelector(
      '[data-testid="gemini-vertex-submit"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    await fireEvent.click(submit);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith("gemini_provision_vertex_sa", {
      baseDir: "/home/test/.claude/accounts",
      slot: 3,
      saPath: "/abs/picked/sa.json",
    });
    expect(container.textContent).toContain("Vertex SA: /abs/picked/sa.json");
  });

  // ── an internal ticket PR-2: cloud-Claude (Vertex/Bedrock) provisioning ────────────

  it("hides the cloud-Claude card in a community build", async () => {
    setupMocks({ get_build_edition: "community" });
    const { container } = renderModal();
    await settle();
    expect(
      container.querySelector('[data-testid="cloud-claude-card"]'),
    ).toBeNull();
  });

  it("provisions a Claude slot via Vertex from the cloud-Claude card", async () => {
    setupMocks({
      get_build_edition: "enterprise",
      cloud_claude_provision_vertex: undefined,
    });
    mockOpenDialog.mockResolvedValueOnce("/abs/sa.json");

    const { container } = renderModal();
    // Edition loads as the 4th await in the mount chain — flush extra.
    await settle(15);

    // Enterprise-only card is visible; open the cloud-Claude flow.
    const card = container.querySelector(
      '[data-testid="cloud-claude-card"]',
    ) as HTMLButtonElement;
    expect(card).not.toBeNull();
    await fireEvent.click(card);
    await settle();

    // Vertex is the default tab.
    const project = container.querySelector(
      '[data-testid="cloud-claude-vertex-project"]',
    ) as HTMLInputElement;
    await fireEvent.input(project, { target: { value: "my-gcp-project" } });
    const region = container.querySelector(
      '[data-testid="cloud-claude-vertex-region"]',
    ) as HTMLInputElement;
    await fireEvent.input(region, { target: { value: "us-east5" } });

    const pick = container.querySelector(
      '[data-testid="cloud-claude-vertex-pick"]',
    ) as HTMLButtonElement;
    await fireEvent.click(pick);
    await settle();
    expect(mockOpenDialog).toHaveBeenCalled();

    const submit = container.querySelector(
      '[data-testid="cloud-claude-vertex-submit"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    await fireEvent.click(submit);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith("cloud_claude_provision_vertex", {
      baseDir: "/home/test/.claude/accounts",
      slot: 3,
      project: "my-gcp-project",
      region: "us-east5",
      saPath: "/abs/sa.json",
    });
    expect(container.textContent).toContain("Google Vertex AI");
  });

  it("provisions a Claude slot via Bedrock from the cloud-Claude card", async () => {
    setupMocks({
      get_build_edition: "enterprise",
      cloud_claude_provision_bedrock: undefined,
    });

    const { container } = renderModal();
    // Edition loads as the 4th await in the mount chain — flush extra.
    await settle(15);

    await fireEvent.click(
      container.querySelector(
        '[data-testid="cloud-claude-card"]',
      ) as HTMLButtonElement,
    );
    await settle();

    // Switch to the Bedrock tab.
    await fireEvent.click(
      container.querySelector(
        '[data-testid="cloud-claude-tab-bedrock"]',
      ) as HTMLButtonElement,
    );
    await tick();

    const region = container.querySelector(
      '[data-testid="cloud-claude-bedrock-region"]',
    ) as HTMLInputElement;
    await fireEvent.input(region, { target: { value: "us-east-1" } });
    const token = container.querySelector(
      '[data-testid="cloud-claude-bedrock-token"]',
    ) as HTMLInputElement;
    await fireEvent.input(token, { target: { value: "bedrock-bearer-token" } });

    const submit = container.querySelector(
      '[data-testid="cloud-claude-bedrock-submit"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    await fireEvent.click(submit);
    await settle();

    expect(mockInvoke).toHaveBeenCalledWith("cloud_claude_provision_bedrock", {
      baseDir: "/home/test/.claude/accounts",
      slot: 3,
      region: "us-east-1",
      bearerToken: "bedrock-bearer-token",
    });
    expect(container.textContent).toContain("AWS Bedrock");
  });

  it("disables api-key Provision button until key is non-empty", async () => {
    setupMocks({
      list_providers: [GEMINI_PROVIDER],
      gemini_probe_tos_residue: null,
      is_gemini_tos_acknowledged: true,
    });
    const { container } = renderModal();
    await settle();

    await fireEvent.click(
      Array.from(container.querySelectorAll(".provider-card")).find((el) =>
        el.textContent?.includes("Gemini"),
      ) as HTMLButtonElement,
    );
    await settle();

    const submit = container.querySelector(
      '[data-testid="gemini-api-key-submit"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });

  // ── Native Kimi/Grok device-auth flow (an internal journal entry C8) ─────
  //
  // Per-slot vendor-home device-code login, mirroring the Codex
  // device-auth flow: `start_native_login` pre-checks (no side
  // effects), then `complete_native_login` drives the vendor's own
  // sign-in and emits `native-device-code` events. These cards render
  // alongside the bearer/OAuth/keyless `providers` entries in the same
  // picker grid, so native Kimi sits next to the existing 3P-bearer
  // Kimi provider.

  it("renders native Kimi and Grok cards alongside the provider cards", async () => {
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER],
      list_native_clis: [KIMI_NATIVE_CLI, GROK_NATIVE_CLI],
    });
    const { container } = renderModal();
    await settle();

    const cards = Array.from(container.querySelectorAll(".provider-card"));
    // Anthropic (bearer/OAuth) + Kimi (native) + Grok (native) = 3 cards.
    expect(cards.length).toBe(3);
    expect(
      container.querySelector('[data-testid="native-cli-card-kimi-cli"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-testid="native-cli-card-grok"]'),
    ).not.toBeNull();
    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    );
    expect(kimiCard!.textContent).toContain("Kimi (native CLI)");
    const grokCard = container.querySelector(
      '[data-testid="native-cli-card-grok"]',
    );
    expect(grokCard!.textContent).toContain("Grok (native CLI)");
  });

  it("navigates to native-cli-confirm and probes via start_native_login when a native card is picked", async () => {
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
      start_native_login: {
        native_id: "kimi-cli",
        display_name: "Kimi (native CLI)",
        cli_installed: true,
      },
    });
    const { container } = renderModal({ nextAccountId: 4 });
    await settle();

    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    await fireEvent.click(kimiCard);
    await settle();

    const lede = container.querySelector(
      '[data-testid="native-cli-confirm-lede"]',
    );
    expect(lede).not.toBeNull();
    expect(lede!.textContent).toContain("Kimi (native CLI)");
    expect(lede!.textContent).toContain("slot #4");
    // Explains the CLI's own device-code sign-in — no key field anywhere.
    expect(container.textContent).toContain("device-code sign-in");
    expect(container.querySelector('input[type="password"]')).toBeNull();
    // Missing-CLI hint must NOT show once the pre-flight resolves installed=true.
    expect(
      container.querySelector('[data-testid="native-cli-missing-hint"]'),
    ).toBeNull();
    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "start_native_login",
    );
    expect(call?.[1]).toMatchObject({
      baseDir: "/home/test/.claude/accounts",
      nativeId: "kimi-cli",
      slot: 4,
    });
  });

  it("drives complete_native_login on Confirm and shows success after the device-code flow completes", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({
      list_providers: [],
      list_native_clis: [GROK_NATIVE_CLI],
      start_native_login: {
        native_id: "grok",
        display_name: "Grok (native CLI)",
        cli_installed: true,
      },
      complete_native_login: null,
    });
    const { container } = renderModal({ nextAccountId: 9, onAccountAdded });
    await settle();

    const grokCard = container.querySelector(
      '[data-testid="native-cli-card-grok"]',
    ) as HTMLButtonElement;
    await fireEvent.click(grokCard);
    await settle();

    const confirmBtn = container.querySelector(
      '[data-testid="native-cli-confirm-button"]',
    ) as HTMLButtonElement;
    expect(confirmBtn).not.toBeNull();
    expect(confirmBtn.disabled).toBe(false);
    await fireEvent.click(confirmBtn);
    await settle();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "complete_native_login",
    );
    expect(call).toBeTruthy();
    expect(call?.[1]).toMatchObject({
      baseDir: "/home/test/.claude/accounts",
      nativeId: "grok",
      slot: 9,
    });
    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain(
      "Grok (native CLI) bound to slot #9",
    );
  });

  it("renders the native device code from the native-device-code event with a working copy-to-clipboard button", async () => {
    // Mirrors the codex device-code test: complete_native_login never
    // resolves so the flow stays in `native-running` for the assertions.
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
      start_native_login: {
        native_id: "kimi-cli",
        display_name: "Kimi (native CLI)",
        cli_installed: true,
      },
      complete_native_login: new Promise(() => {}),
    });

    let deviceCodeHandler:
      | ((e: {
          payload: {
            surface: string;
            user_code: string;
            verification_url: string;
          };
        }) => void)
      | null = null;
    mockListen.mockImplementation((event: string, handler: unknown) => {
      if (event === "native-device-code") {
        deviceCodeHandler = handler as typeof deviceCodeHandler;
      }
      return Promise.resolve(() => {});
    });

    const { container } = renderModal();
    await settle();
    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    await fireEvent.click(kimiCard);
    await settle();
    const confirmBtn = container.querySelector(
      '[data-testid="native-cli-confirm-button"]',
    ) as HTMLButtonElement;
    await fireEvent.click(confirmBtn);
    await settle();

    expect(deviceCodeHandler).not.toBeNull();
    deviceCodeHandler!({
      payload: {
        surface: "kimi",
        user_code: "WXYZ-1234",
        verification_url:
          "https://www.kimi.com/code/authorize_device?user_code=WXYZ-1234",
      },
    });
    await settle();

    const codeEl = container.querySelector(".device-code");
    expect(codeEl).not.toBeNull();
    expect(codeEl!.textContent).toBe("WXYZ-1234");

    const copyBtn = container.querySelector(
      '[data-testid="copy-native-device-code"]',
    ) as HTMLButtonElement;
    expect(copyBtn).not.toBeNull();
    await fireEvent.click(copyBtn);
    await settle();
    expect(writeText).toHaveBeenCalledWith("WXYZ-1234");
    expect(mockOpenUrl).toHaveBeenCalledWith(
      "https://www.kimi.com/code/authorize_device?user_code=WXYZ-1234",
    );
  });

  it("surfaces backend error on start_native_login rejection and blocks Confirm", async () => {
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
    });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_native_login") {
        return Promise.reject(
          new Error("slot 5 is bound to Codex — run `csq logout 5` to rebind"),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal({ nextAccountId: 5 });
    await settle();

    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    await fireEvent.click(kimiCard);
    await settle();

    expect(container.textContent).toContain(
      "slot 5 is bound to Codex — run `csq logout 5` to rebind",
    );
    // A blocking start_native_login rejection disables Confirm — retrying
    // the spawn would hit the identical conflict.
    const confirmBtn = container.querySelector(
      '[data-testid="native-cli-confirm-button"]',
    ) as HTMLButtonElement;
    expect(confirmBtn.disabled).toBe(true);
  });

  it("surfaces backend error on complete_native_login failure", async () => {
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
      start_native_login: {
        native_id: "kimi-cli",
        display_name: "Kimi (native CLI)",
        cli_installed: true,
      },
    });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "complete_native_login") {
        return Promise.reject(
          new Error("kimi login exited with non-zero status"),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal({ nextAccountId: 5 });
    await settle();

    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    await fireEvent.click(kimiCard);
    await settle();

    const confirmBtn = container.querySelector(
      '[data-testid="native-cli-confirm-button"]',
    ) as HTMLButtonElement;
    await fireEvent.click(confirmBtn);
    await settle();

    expect(container.textContent).toContain(
      "kimi login exited with non-zero status",
    );
  });

  it("shows an install hint with a working Recheck button when the native CLI is missing", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });
    let installed = false;
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
    });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_native_login") {
        return Promise.resolve({
          native_id: "kimi-cli",
          display_name: "Kimi (native CLI)",
          cli_installed: installed,
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settle();

    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    await fireEvent.click(kimiCard);
    await settle();

    // The hint is informational, not blocking — Confirm stays enabled.
    const hint = container.querySelector(
      '[data-testid="native-cli-missing-hint"]',
    );
    expect(hint).not.toBeNull();
    expect(hint!.textContent).toContain("csq cli install kimi");
    const confirmBtn = container.querySelector(
      '[data-testid="native-cli-confirm-button"]',
    ) as HTMLButtonElement;
    expect(confirmBtn.disabled).toBe(false);

    const copyBtn = container.querySelector(
      '[data-testid="copy-native-cli-install-cmd"]',
    ) as HTMLButtonElement;
    expect(copyBtn).not.toBeNull();
    await fireEvent.click(copyBtn);
    await settle();
    expect(writeText).toHaveBeenCalledWith("csq cli install kimi");

    // Recheck re-probes start_native_login; simulate the user having
    // installed the CLI in a terminal between the first probe and now.
    installed = true;
    const recheckBtn = container.querySelector(
      '[data-testid="native-cli-recheck"]',
    ) as HTMLButtonElement;
    expect(recheckBtn).not.toBeNull();
    await fireEvent.click(recheckBtn);
    await settle();

    expect(
      container.querySelector('[data-testid="native-cli-missing-hint"]'),
    ).toBeNull();
  });

  it("respects the slot picker — native cards disabled when slot is taken", async () => {
    setupMocks({
      list_providers: [],
      list_native_clis: [KIMI_NATIVE_CLI],
      get_accounts: [{ id: 4 }],
    });
    const { container } = renderModal({ nextAccountId: 4 });
    await settle();

    const kimiCard = container.querySelector(
      '[data-testid="native-cli-card-kimi-cli"]',
    ) as HTMLButtonElement;
    expect(kimiCard.disabled).toBe(true);
  });

  // ── Claude OAuth subprocess flow (an internal ticket Phase 2) ─────────────
  //
  // The modal now shells out to `claude auth login` via the
  // `start_claude_login_subprocess` Tauri command (Phase 1 output).
  // The frontend's view is synchronous: one invoke that resolves
  // with { account, email } when the subprocess exits and
  // credentials are persisted, or rejects with a String error.
  //
  // No event subscriptions — the race flow's seven `claude-login-*`
  // events were retired alongside the in-process loopback orchestrator.
  // The lock-contention error from `AccountLoginLock::acquire`
  // remains the trigger for the dedicated `login-in-progress`
  // recovery UI.

  /// Settle async work — list_providers, get_accounts, then the
  /// subprocess invoke + state transition. Mirrors `settle()` in
  /// the Codex / Gemini test sections so we don't duplicate the
  /// tick spinner across tests.
  async function settleClaude(n = 8) {
    for (let i = 0; i < n; i++) await tick();
  }

  /// Click the Anthropic card; common preamble for every Claude
  /// OAuth test. Asserts the card was found so a refactor that
  /// renames the card label fails loudly rather than silently
  /// running the rest of the test against the wrong card.
  async function pickAnthropic(container: HTMLElement) {
    const cards = container.querySelectorAll(".provider-card");
    const anthropic = Array.from(cards).find((c) =>
      c.textContent?.includes("Anthropic"),
    ) as HTMLButtonElement | undefined;
    expect(anthropic).toBeDefined();
    await fireEvent.click(anthropic!);
    await settleClaude();
  }

  it("invokes start_claude_login_subprocess with baseDir + chosen slot on Anthropic pick", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    const { container } = renderModal({ nextAccountId: 5 });
    await settleClaude();
    await pickAnthropic(container);

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "start_claude_login_subprocess",
    );
    expect(
      call,
      `expected start_claude_login_subprocess invoke; calls were: ${mockInvoke.mock.calls
        .map((c) => c[0])
        .join(", ")}`,
    ).toBeTruthy();
    expect(call?.[1]).toEqual({
      baseDir: "/home/test/.claude/accounts",
      account: 5,
    });
  });

  it("does NOT subscribe to any claude-login-* events (subprocess flow has no listeners)", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    // Track every listen() call. Phase 2 should never invoke listen()
    // for the Claude OAuth flow — the subprocess command resolves
    // synchronously from the frontend's view.
    const listenedEvents: string[] = [];
    mockListen.mockImplementation(async (name: string) => {
      listenedEvents.push(name);
      return () => {};
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);

    const claudeListens = listenedEvents.filter((n) =>
      n.startsWith("claude-login"),
    );
    expect(
      claudeListens,
      `Phase 2 must not subscribe to claude-login-* events; got: ${claudeListens.join(", ")}`,
    ).toEqual([]);
  });

  it("shows running UI while the subprocess is in flight", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    // Hold the subprocess invoke unresolved so we can observe the
    // running step before resolution.
    let resolveSub: (v: unknown) => void = () => {};
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return new Promise((resolve) => {
          resolveSub = resolve;
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });

    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);

    const lede = container.querySelector(
      '[data-testid="claude-subprocess-lede"]',
    );
    expect(
      lede,
      `expected subprocess-running lede; HTML: ${container.innerHTML.slice(0, 500)}`,
    ).not.toBeNull();
    expect(lede?.textContent).toContain("Signing in to account #3");

    // The legacy race UI must NOT appear — no manual-URL panel,
    // no paste input, no Copy button.
    expect(
      container.querySelector('[data-testid="race-manual-panel"]'),
    ).toBeNull();
    expect(
      container.querySelector('[data-testid="race-paste-input"]'),
    ).toBeNull();

    // Resolve the subprocess so the test doesn't leak a pending Promise.
    resolveSub({ account: 3, email: "user@example.com" });
    await settleClaude();
  });

  it("transitions to success and calls onAccountAdded on subprocess resolve", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER],
      start_claude_login_subprocess: {
        account: 3,
        email: "alice@example.com",
      },
    });
    const { container } = renderModal({ onAccountAdded });
    await settleClaude();
    await pickAnthropic(container);

    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("Account 3 added successfully");
    expect(container.textContent).toContain("alice@example.com");
  });

  it("shows error banner with Try again button on subprocess reject", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return Promise.reject(
          new Error("`claude auth login` exited with non-zero status (1)"),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal({ onAccountAdded });
    await settleClaude();
    await pickAnthropic(container);

    expect(container.textContent).toContain("exited with non-zero status");
    // onAccountAdded MUST NOT fire when the subprocess failed —
    // there are no credentials to surface in the dashboard.
    expect(onAccountAdded).not.toHaveBeenCalled();
    // Try-again button is wired to the error step.
    const tryAgain = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Try again"),
    );
    expect(tryAgain).toBeDefined();
  });

  it("renders login-in-progress recovery UI when AccountLoginLock contends (LOCK_HELD prefix)", async () => {
    // Backend Phase-2 contract: error string starts with the stable
    // tag `LOCK_HELD:` so the renderer branches on the prefix rather
    // than substring-matching prose (round-1 redteam security M1 +
    // deep-analyst M2).
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return Promise.reject(
          new Error(
            "LOCK_HELD: another login is in progress for account 3 (PID 12345) — " +
              "cancel it first or wait for it to finish",
          ),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);
    // Pump again so the error path's state assignment renders.
    await settleClaude();

    const banner = container.querySelector(
      '[data-testid="login-in-progress-banner"]',
    );
    expect(
      banner,
      `expected login-in-progress banner; HTML: ${container.innerHTML.slice(0, 600)}`,
    ).not.toBeNull();
    expect(banner?.textContent).toContain("another login is in progress");
    expect(banner?.textContent).toContain("12345");

    // The generic error banner is NOT used — recovery UI has its
    // own visual treatment so users know the action is "wait for
    // the other login" rather than "retry from scratch".
    expect(container.querySelector(".error-banner")).toBeNull();

    // The Retry button is labelled "Retry" (not "Try again") and
    // present.
    const retryBtn = container.querySelector(
      '[data-testid="login-in-progress-retry"]',
    );
    expect(retryBtn).not.toBeNull();
    expect(retryBtn?.textContent).toContain("Retry");
  });

  it("renders login-in-progress recovery UI on LOCK_FAILED prefix too", async () => {
    // Round-1 redteam security M1 + deep-analyst M2 — `LOCK_FAILED`
    // is the third lock-failure shape (flock syscall error, not a
    // contention case). It still belongs in the recovery UI because
    // the user's action is the same: wait or kill the holder.
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return Promise.reject(
          new Error("LOCK_FAILED: flock open failed: EAGAIN"),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);
    await settleClaude();

    expect(
      container.querySelector('[data-testid="login-in-progress-banner"]'),
    ).not.toBeNull();
    expect(container.querySelector(".error-banner")).toBeNull();
  });

  it("forwards-compat: still detects legacy substring wording", async () => {
    // One release of substring-match forward-compat so a
    // downgrade-then-upgrade dogfood install (a v2.7.5 desktop
    // running against a fresh backend or vice versa) hits a
    // recognized shape. Phase 3 deletes this branch.
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return Promise.reject(
          new Error("login already in progress for account 3"),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);
    await settleClaude();

    expect(
      container.querySelector('[data-testid="login-in-progress-banner"]'),
    ).not.toBeNull();
  });

  it("clicking Retry on login-in-progress re-invokes start_claude_login_subprocess", async () => {
    let startCount = 0;
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        startCount += 1;
        if (startCount === 1) {
          return Promise.reject(
            new Error("LOCK_HELD: another login is in progress for account 3"),
          );
        }
        return Promise.resolve({ account: 3, email: "user@example.com" });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });

    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);
    await settleClaude();

    const retryBtn = container.querySelector(
      '[data-testid="login-in-progress-retry"]',
    ) as HTMLButtonElement;
    expect(
      retryBtn,
      `expected retry button; HTML: ${container.innerHTML.slice(0, 500)}`,
    ).not.toBeNull();
    await fireEvent.click(retryBtn);
    await settleClaude(16);

    expect(startCount).toBe(2);
  });

  it("does NOT call cancel_race_login or any cancel_claude_* when modal closes mid-subprocess", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    // Hold the subprocess in flight so closing happens during the
    // running step.
    let resolveSub: (v: unknown) => void = () => {};
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return new Promise((resolve) => {
          resolveSub = resolve;
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const onClose = vi.fn();
    const { container } = renderModal({ onClose });
    await settleClaude();
    await pickAnthropic(container);

    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    await fireEvent.click(closeBtn);
    await settleClaude();

    expect(onClose).toHaveBeenCalledOnce();
    // Round-1 redteam deep-analyst L2 — wildcard guard so a future
    // maintainer who adds `cancel_claude_*` thinking it was missing
    // breaks this test. CC owns its own subprocess lifecycle once
    // we spawn it; adding a cancel from this side would orphan it.
    const cancelClaude = mockInvoke.mock.calls.find(
      (args) =>
        typeof args[0] === "string" && args[0].startsWith("cancel_claude"),
    );
    expect(
      cancelClaude,
      `no cancel_claude_* invoke expected; got: ${cancelClaude?.[0]}`,
    ).toBeUndefined();
    // Belt-and-suspenders: also explicitly assert the retired
    // race-flow cancel is not called. The race-flow `cancel_race_login`
    // command is no longer registered in `invoke_handler!` and
    // calling it would surface as a noisy IPC error.
    const cancelRace = mockInvoke.mock.calls.find(
      (args) => args[0] === "cancel_race_login",
    );
    expect(cancelRace).toBeUndefined();

    // Resolve the held subprocess so the test doesn't leak a Promise.
    resolveSub({ account: 3, email: "user@example.com" });
    await settleClaude();
  });

  it("late subprocess resolve does NOT touch state after modal close", async () => {
    // Regression for the journal-0061 hang pattern: a Promise that
    // resolves AFTER the modal closed must not flip step back to
    // success. The step.kind guard in startClaudeOAuth is the load-
    // bearing check.
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    let resolveSub: (v: unknown) => void = () => {};
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return new Promise((resolve) => {
          resolveSub = resolve;
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });

    const { container } = renderModal({ onAccountAdded });
    await settleClaude();
    await pickAnthropic(container);

    // Close mid-subprocess.
    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    await fireEvent.click(closeBtn);
    await settleClaude();

    // Now resolve the subprocess — the modal is already closed.
    resolveSub({ account: 3, email: "user@example.com" });
    await settleClaude();

    // onAccountAdded MUST NOT fire — the user closed the modal
    // before the subprocess finished. Firing it would refresh the
    // dashboard with a slot the user wasn't expecting.
    expect(onAccountAdded).not.toHaveBeenCalled();
  });

  it("H1: late resolve from prior invocation does NOT touch state when both invocations were in flight", async () => {
    // Round-1 redteam HIGH-1 + Round-2 redteam L1 — exercise the
    // invocationId guard directly. Hold BOTH invocations pending,
    // resolve the FIRST one while the second is still running, and
    // assert the first's late resolve does not mutate state (the
    // running step is for invocationId=2 and the first resolve's
    // closure captured myInvocation=1).
    //
    // The naive bug shape was: the kind+account guard would PASS
    // on the first's late resolve because step.kind is still
    // 'claude-subprocess-running' and step.account is still the
    // same slot — so onAccountAdded fires for the WRONG
    // invocation. The invocationId discriminator is the fix.
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });

    let resolveFirst: (v: unknown) => void = () => {};
    let resolveSecond: (v: unknown) => void = () => {};
    let callCount = 0;
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        callCount += 1;
        if (callCount === 1) {
          return new Promise((resolve) => {
            resolveFirst = resolve;
          });
        }
        return new Promise((resolve) => {
          resolveSecond = resolve;
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });

    const { container } = renderModal({ onAccountAdded });
    await settleClaude();
    await pickAnthropic(container);

    // User closes the modal mid-subprocess (first invocation still
    // pending — flock is still held in real production).
    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    await fireEvent.click(closeBtn);
    await settleClaude();

    // Re-pick Anthropic for the SAME slot. Second invocation fires
    // (callCount=2) and is also held pending. step is now
    // claude-subprocess-running with invocationId=2.
    await pickAnthropic(container);
    await settleClaude();
    expect(container.textContent).toContain("Signing in to account #3");

    // NOW resolve the FIRST invocation. Its closure captured
    // myInvocation=1; the current step.invocationId is 2; the
    // guard `step.invocationId === myInvocation` is FALSE → bails.
    resolveFirst({ account: 3, email: "first@example.com" });
    await settleClaude();

    // onAccountAdded MUST NOT have fired — the first invocation is
    // stale and bailed at the guard.
    expect(onAccountAdded).not.toHaveBeenCalled();
    // The first email must NOT appear in the DOM (no success
    // banner mutation).
    expect(container.textContent).not.toContain("first@example.com");
    // The running UI is still showing for invocation #2.
    expect(container.textContent).toContain("Signing in to account #3");

    // Now resolve the SECOND invocation. Its closure captured
    // myInvocation=2; matches step.invocationId; success fires.
    resolveSecond({ account: 3, email: "second@example.com" });
    await settleClaude();

    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("second@example.com");
  });

  it("subprocess flow works in reauth mode (reauthSlot prop set)", async () => {
    // Round-1 redteam L1 (svelte) — explicit coverage for the
    // reauth code path, which goes through the same
    // startClaudeOAuth(chosenSlot) function but has the slot
    // input locked at reauthSlot. Verifies the invoke shape and
    // the success transition both still work when reauthSlot is
    // non-null.
    const onAccountAdded = vi.fn();
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER],
      start_claude_login_subprocess: {
        account: 2,
        email: "reauth@example.com",
      },
    });
    const { container } = renderModal({
      reauthSlot: 2,
      nextAccountId: 2,
      onAccountAdded,
    });
    await settleClaude();
    await pickAnthropic(container);

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "start_claude_login_subprocess",
    );
    expect(call?.[1]).toEqual({
      baseDir: "/home/test/.claude/accounts",
      account: 2,
    });
    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("Account 2 added successfully");
    expect(container.textContent).toContain("reauth@example.com");
  });

  it("subprocess flow works after isOpen flips false → true (mount-edge production sequence)", async () => {
    // Round-1 redteam L2 (security) + testing.md MUST Rule 7 —
    // the "loads providers when isOpen flips from false to true"
    // test pins the mount-edge `$effect` but stops at provider
    // load. This test continues through pickAnthropic to confirm
    // the subprocess flow is reachable from the same code path
    // production uses.
    const onAccountAdded = vi.fn();
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER],
      start_claude_login_subprocess: {
        account: 3,
        email: "mount-edge@example.com",
      },
    });

    const { container, rerender } = render(AddAccountModal, {
      props: {
        isOpen: false,
        nextAccountId: 3,
        reauthSlot: null,
        onClose: vi.fn(),
        onAccountAdded,
      },
    });
    await tick();
    expect(mockInvoke).not.toHaveBeenCalled();

    await rerender({
      isOpen: true,
      nextAccountId: 3,
      reauthSlot: null,
      onClose: vi.fn(),
      onAccountAdded,
    });
    for (let i = 0; i < 8; i++) await tick();

    await pickAnthropic(container);

    expect(mockInvoke).toHaveBeenCalledWith("start_claude_login_subprocess", {
      baseDir: "/home/test/.claude/accounts",
      account: 3,
    });
    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("mount-edge@example.com");
  });

  it("running-step renders a liveness spinner", async () => {
    // Round-1 redteam M1 (svelte) — pure-CSS spinner is the only
    // liveness signal during the subprocess wait (no progress
    // events). Pin its presence so a UI refactor doesn't silently
    // drop it.
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    let resolveSub: (v: unknown) => void = () => {};
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return new Promise((resolve) => {
          resolveSub = resolve;
        });
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);

    const spinner = container.querySelector(
      '[data-testid="claude-subprocess-spinner"]',
    );
    expect(
      spinner,
      `spinner must render alongside the running lede; HTML: ${container.innerHTML.slice(0, 400)}`,
    ).not.toBeNull();

    resolveSub({ account: 3, email: "user@example.com" });
    await settleClaude();
  });

  it("client-side redactClientSide strips sk-ant-* and long hex (65+) on error path", async () => {
    // Round-1 redteam M2 (security) — defense-in-depth: even if
    // the backend regresses and emits an un-redacted token, the
    // frontend's redactClientSide() helper sanitizes the string
    // before storing in step.message.
    //
    // Round-2 redteam M1 — assert the threshold (65 chars) keeps
    // git SHA-1 commit hashes (40 chars) AND SHA-256 hex digests
    // (64 chars) readable. Only blobs at or beyond refresh-token
    // length redact.
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    // 80-char hex blob — longer than any debugging hash, well within
    // refresh-token shape.
    const longHex =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const sha1 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"; // 40 chars — must survive
    const sha256 =
      "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"; // 64 chars — must survive
    mockInvoke.mockImplementation((cmd: string) => {
      if (cmd === "start_claude_login_subprocess") {
        return Promise.reject(
          new Error(
            `CC_EXITED_NONZERO: leaked sk-ant-api03-DEADBEEF, sha1=${sha1}, ` +
              `sha256=${sha256}, refresh=${longHex}`,
          ),
        );
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settleClaude();
    await pickAnthropic(container);
    await settleClaude();

    const banner = container.querySelector(".error-banner");
    expect(banner).not.toBeNull();
    const text = banner!.textContent ?? "";
    // sk-ant- prefix replaced with ellipsis; the raw key fragment
    // MUST NOT appear.
    expect(text).not.toContain("DEADBEEF");
    expect(text).toContain("sk-ant-…");
    // Long hex run (80 chars, refresh-token shape) replaced.
    expect(text).not.toContain(longHex);
    expect(text).toContain("[REDACTED]");
    // SHA-1 (40) and SHA-256 (64) survive — they are debugging
    // hashes, not credentials.
    expect(text).toContain(sha1);
    expect(text).toContain(sha256);
  });
});
