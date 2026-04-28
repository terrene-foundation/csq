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

const GEMINI_PROVIDER = {
  id: "gemini",
  name: "Gemini",
  auth_type: "none" as const,
  default_base_url: "https://generativelanguage.googleapis.com",
  default_model: "gemini-2.5-pro",
};

const mockOpenDialog = vi.fn();
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => mockOpenDialog(...args),
}));

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

  // ── PR-G5 Gemini flow ───────────────────────────────────────

  it("shows ToS disclosure when Gemini picked and marker absent", async () => {
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
      | HTMLButtonElement
      | undefined;
    expect(geminiCard).toBeDefined();
    await fireEvent.click(geminiCard!);
    await settle();

    expect(container.textContent).toContain("disclosure");
    // Disclosure text wraps across lines — match the load-bearing
    // phrase (OAuth + subscription) without pinning whitespace.
    expect(container.textContent).toMatch(/OAuth\s+subscription/);
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

  // ── Parallel-race Claude OAuth flow ─────────────────────────
  //
  // The race flow subscribes to seven `claude-login-*` events and
  // transitions the Step union via the payloads it receives. These
  // tests register a per-event dispatch table and capture the
  // listener functions so the suite can simulate the orchestrator's
  // emit sequence deterministically.
  //
  // ROUND-2 contract: every payload now carries `account: number`
  // as its first field. The component guards each handler with
  // `if (e.payload.account !== account) return;` so a stale event
  // for a different slot cannot mutate this modal's state. The
  // `emit()` helper below auto-injects the active account so test
  // bodies don't need to repeat it; tests that explicitly want a
  // wrong-account payload pass the second argument.

  /**
   * Per-event listener captures, keyed by event name. Populated each
   * time the component invokes `listen(name, handler)`. Drives the
   * `emit()` helper below.
   */
  type RaceHandler = (e: { payload: unknown }) => void | Promise<void>;
  let raceHandlers: Map<string, RaceHandler>;

  /// The account every race test runs with. Must match the
  /// `nextAccountId` in `renderModal()` because picking a provider
  /// passes `chosenSlot` (initialised from `nextAccountId`) to
  /// `start_claude_login_race`.
  const RACE_ACCOUNT = 3;

  function installRaceListenMock() {
    raceHandlers = new Map();
    mockListen.mockImplementation(
      async (name: string, handler: RaceHandler) => {
        raceHandlers.set(name, handler);
        return () => {
          // Returning the unregistration matches Tauri's listen contract.
          if (raceHandlers.get(name) === handler) raceHandlers.delete(name);
        };
      },
    );
  }

  /**
   * Emit a race event to the registered handler. Auto-injects
   * `account: RACE_ACCOUNT` into the payload so tests don't have to
   * spell it out everywhere; pass an explicit `account` field in
   * `payload` to override (used by the wrong-account guard tests).
   */
  async function emit(name: string, payload: Record<string, unknown> = {}) {
    const fn = raceHandlers.get(name);
    if (!fn) {
      throw new Error(
        `no race handler registered for ${name}; available: ${Array.from(raceHandlers.keys()).join(", ")}`,
      );
    }
    const merged: Record<string, unknown> = {
      account: RACE_ACCOUNT,
      ...payload,
    };
    await fn({ payload: merged });
    // Allow Svelte to flush state after the handler runs.
    for (let i = 0; i < 4; i++) await tick();
  }

  async function pickAnthropicRace(container: HTMLElement) {
    const cards = container.querySelectorAll(".provider-card");
    const anthropic = Array.from(cards).find((c) =>
      c.textContent?.includes("Anthropic"),
    ) as HTMLButtonElement;
    expect(anthropic).toBeDefined();
    await fireEvent.click(anthropic);
    await settle();
  }

  it("transitions to claude-race-active on browser-opening event", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();

    await pickAnthropicRace(container);

    // After clicking Anthropic, the modal subscribes to all seven
    // `claude-login-*` events before invoking start_claude_login_race.
    expect(raceHandlers.has("claude-login-browser-opening")).toBe(true);
    expect(raceHandlers.has("claude-login-manual-url-ready")).toBe(true);
    expect(raceHandlers.has("claude-login-resolved")).toBe(true);
    expect(raceHandlers.has("claude-login-exchanging")).toBe(true);
    expect(raceHandlers.has("claude-login-success")).toBe(true);
    expect(raceHandlers.has("claude-login-error")).toBe(true);
    expect(raceHandlers.has("claude-login-cancelled")).toBe(true);

    // Initial state: race-init with the spinner-style message.
    expect(container.textContent).toContain("Starting sign-in for account");

    // Backend emits browser-opening with the auth URL.
    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // The modal opens the URL and shows the active panel.
    expect(mockOpenUrl).toHaveBeenCalledWith(
      "https://claude.com/cai/oauth/authorize?x=1",
    );
    expect(container.textContent).toContain("Signing in to account");
    // Manual URL panel hidden until manual-url-ready arrives.
    expect(
      container.querySelector('[data-testid="race-manual-panel"]'),
    ).toBeNull();
  });

  it("expands to manual URL + paste input on manual-url-ready", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // Manual panel now visible.
    const panel = container.querySelector('[data-testid="race-manual-panel"]');
    expect(panel).not.toBeNull();
    const link = container.querySelector(
      '[data-testid="race-manual-url"]',
    ) as HTMLAnchorElement;
    expect(link).not.toBeNull();
    expect(link.getAttribute("href")).toContain("oauth/authorize");
    // Paste input is masked (password type) — auth codes are
    // bearer-equivalent for their lifetime.
    const pasteInput = container.querySelector(
      '[data-testid="race-paste-input"]',
    ) as HTMLInputElement;
    expect(pasteInput).not.toBeNull();
    expect(pasteInput.type).toBe("password");
    // Sign-in button starts disabled.
    const submit = container.querySelector(
      '[data-testid="race-submit-paste"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    // No hint when the backend doesn't send one.
    expect(
      container.querySelector('[data-testid="race-manual-hint"]'),
    ).toBeNull();
  });

  it("invokes submit_paste_code with trimmed value when Sign in clicked", async () => {
    setupMocks({
      list_providers: [ANTHROPIC_PROVIDER],
      submit_paste_code: undefined,
    });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    const pasteInput = container.querySelector(
      '[data-testid="race-paste-input"]',
    ) as HTMLInputElement;
    await fireEvent.input(pasteInput, {
      target: { value: "  AUTH_CODE_xyz123  " },
    });
    await tick();

    const submit = container.querySelector(
      '[data-testid="race-submit-paste"]',
    ) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    await fireEvent.click(submit);
    await settle();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "submit_paste_code",
    );
    expect(call).toBeTruthy();
    expect(call?.[1]).toMatchObject({ account: 3 });
    // Backend trims again, but the modal MUST also trim — the leading
    // whitespace from a clipboard paste is the most common failure
    // mode and we shouldn't ship it across the IPC boundary.
    expect((call?.[1] as { code: string }).code).toBe("AUTH_CODE_xyz123");
  });

  it("disables paste input after loopback resolves the race", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // User starts typing, then loopback wins.
    const pasteInput = container.querySelector(
      '[data-testid="race-paste-input"]',
    ) as HTMLInputElement;
    await fireEvent.input(pasteInput, {
      target: { value: "MID_TYPING" },
    });
    await tick();

    await emit("claude-login-resolved", { via: "loopback" });

    // Paste panel is no longer in the DOM — modal moved to
    // claude-race-resolving with the via-flag overlay.
    expect(
      container.querySelector('[data-testid="race-paste-input"]'),
    ).toBeNull();
    const via = container.querySelector('[data-testid="race-via"]');
    expect(via).not.toBeNull();
    expect(via?.textContent).toContain("Browser sign-in completed");
  });

  it("transitions to exchanging then success on the full happy path", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal({ onAccountAdded });
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-resolved", { via: "loopback" });
    await emit("claude-login-exchanging", {});
    expect(container.textContent).toContain("Exchanging credentials");

    await emit("claude-login-success", {
      email: "user@example.com",
    });
    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("Account 3 added successfully");
    expect(container.textContent).toContain("user@example.com");
  });

  it("shows error banner on claude-login-error", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-error", {
      message: "exchange failed: bad_request",
      kind: "exchange_failed",
    });

    // The success/error rendering reuses the existing .error-banner.
    expect(container.textContent).toContain("exchange failed: bad_request");
    // Try-again button is wired to the error step.
    const tryAgain = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Try again"),
    );
    expect(tryAgain).toBeDefined();
  });

  it("calls cancel_race_login with the active account when the modal is closed mid-race", async () => {
    const onClose = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal({ onClose });
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    await fireEvent.click(closeBtn);
    await settle();

    const call = mockInvoke.mock.calls.find(
      (args) => args[0] === "cancel_race_login",
    );
    expect(call).toBeTruthy();
    // F2: cancel call site MUST pass the active account so a stale
    // cancel from a closed modal cannot abort a sibling modal's
    // race for a different slot.
    expect(call?.[1]).toEqual({ account: RACE_ACCOUNT });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("falls back to picker on claude-login-cancelled (no error banner)", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-cancelled", {});

    // After cancellation, modal returns to picker — provider cards
    // visible again, no error banner. (User-initiated cancel must
    // not look like a failure.)
    expect(container.querySelectorAll(".provider-card").length).toBeGreaterThan(
      0,
    );
    expect(container.querySelector(".error-banner")).toBeNull();
  });

  it("shows manual URL immediately when openUrl rejects", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    mockOpenUrl.mockRejectedValueOnce(new Error("no default browser"));
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // openUrl rejected → manual URL panel surfaces without waiting
    // for the 3 s `manual-url-ready` event. This is the fallback
    // for users on hosts where openUrl fails silently from the
    // OS but Tauri reports success — we don't want them stuck
    // staring at "Browser opening..." for 3 s with no recourse.
    expect(
      container.querySelector('[data-testid="race-manual-panel"]'),
    ).not.toBeNull();
  });

  it("shows submission error when submit_paste_code rejects", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    mockInvoke.mockImplementation((cmd: string, _args?: unknown) => {
      if (cmd === "submit_paste_code") {
        return Promise.reject(new Error("invalid code: paste was empty"));
      }
      if (cmd in mockResponses) return Promise.resolve(mockResponses[cmd]);
      return Promise.resolve(undefined);
    });
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    const pasteInput = container.querySelector(
      '[data-testid="race-paste-input"]',
    ) as HTMLInputElement;
    await fireEvent.input(pasteInput, { target: { value: "BAD_CODE" } });
    await tick();
    await fireEvent.click(
      container.querySelector(
        '[data-testid="race-submit-paste"]',
      ) as HTMLButtonElement,
    );
    await settle();

    const err = container.querySelector('[data-testid="race-error"]');
    expect(err).not.toBeNull();
    expect(err?.textContent).toContain("invalid code");
  });

  // ── Round-2 fixes (F1–F6) ───────────────────────────────────
  //
  // These tests cover the round-2 fix pass: every event handler
  // must guard on payload.account, the cancel command must carry
  // the account, the optional manual-url hint must render, the
  // paste-after-loopback-won kind must render as info not error,
  // and the clipboard write fallback must surface a hint.

  it("F1: ignores claude-login-browser-opening for a different account", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    // Initial state: race-init for account 3.
    expect(container.textContent).toContain("Starting sign-in for account #3");

    // A stale event for a different account (99) MUST be a no-op.
    await emit("claude-login-browser-opening", {
      account: 99,
      auto_url: "https://claude.com/wrong-account",
    });

    // openUrl must NOT have been called — the wrong-account event
    // never reached the browser-open path.
    expect(mockOpenUrl).not.toHaveBeenCalled();
    // State stays on the init step (no transition to active).
    expect(container.textContent).toContain("Starting sign-in for account #3");
    expect(
      container.querySelector('[data-testid="race-active-lede"]'),
    ).toBeNull();
  });

  it("F1: ignores claude-login-manual-url-ready for a different account", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    // Wrong-account manual-url MUST NOT cause the panel to render
    // with the wrong URL.
    await emit("claude-login-manual-url-ready", {
      account: 99,
      manual_url: "https://claude.com/wrong-account",
    });

    expect(
      container.querySelector('[data-testid="race-manual-panel"]'),
    ).toBeNull();
  });

  it("F1: ignores claude-login-resolved for a different account", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-resolved", {
      account: 99,
      via: "loopback",
    });

    // Wrong-account resolved must NOT transition to the resolving
    // step — the modal stays on the active panel for our account.
    expect(container.querySelector('[data-testid="race-via"]')).toBeNull();
    expect(container.textContent).toContain("Signing in to account #3");
  });

  it("F1: ignores claude-login-success for a different account", async () => {
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal({ onAccountAdded });
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-success", {
      account: 99,
      email: "wrong@example.com",
    });

    // onAccountAdded MUST NOT fire for a different account's
    // success — that would refresh the dashboard with stale data
    // attributed to the wrong slot.
    expect(onAccountAdded).not.toHaveBeenCalled();
    expect(container.textContent).not.toContain("wrong@example.com");
  });

  it("F1: ignores claude-login-error for a different account", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-error", {
      account: 99,
      message: "wrong slot's error",
      kind: "exchange_failed",
    });

    // Wrong-account error must NOT swap our modal into the error
    // state. The active panel stays put.
    expect(container.textContent).not.toContain("wrong slot's error");
    expect(container.textContent).toContain("Signing in to account #3");
  });

  it("F1: ignores claude-login-cancelled for a different account", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-cancelled", { account: 99 });

    // Wrong-account cancel must NOT bounce us to picker.
    expect(container.textContent).toContain("Signing in to account #3");
    expect(container.querySelectorAll(".provider-card").length).toBe(0);
  });

  it("F2: skips cancel_race_login invoke when no race is active", async () => {
    // Open the modal, never start a race, then close it. We must
    // NOT call `cancel_race_login` because there's nothing to
    // cancel and the backend's account-scoped cancel rejects junk
    // values.
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();

    const closeBtn = container.querySelector(".close") as HTMLButtonElement;
    await fireEvent.click(closeBtn);
    await settle();

    const cancelCall = mockInvoke.mock.calls.find(
      (args) => args[0] === "cancel_race_login",
    );
    expect(cancelCall).toBeUndefined();
  });

  it("F3: renders the manual-url hint when provided by the backend", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
      hint: "if your browser shows a 'site cannot be reached' error, paste the code below instead",
    });

    const hint = container.querySelector('[data-testid="race-manual-hint"]');
    expect(hint).not.toBeNull();
    expect(hint?.textContent).toContain("site cannot be reached");
  });

  it("F4: renders paste_after_loopback_won as an info banner, not an error", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    // Backend reports the user pasted a code AFTER loopback won.
    await emit("claude-login-error", {
      message:
        "race orchestrator dropped the paste channel — the loopback path completed first",
      kind: "paste_after_loopback_won",
    });

    // The informational banner is present.
    const info = container.querySelector('[data-testid="race-info-banner"]');
    expect(info).not.toBeNull();
    expect(info?.textContent).toContain("already signed in via your browser");

    // The error-styled banner is NOT present — we don't want to
    // alarm a user whose only mistake was being too quick to paste.
    expect(container.querySelector(".error-banner")).toBeNull();
    // No Try-again button either — the flow is still alive and
    // will continue to success on the next event.
    const tryAgain = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Try again"),
    );
    expect(tryAgain).toBeUndefined();
  });

  it("F4: paste_after_loopback_won keeps listeners alive so success still lands", async () => {
    // The orchestrator may emit `success` AFTER the
    // paste_after_loopback_won error because the loopback path
    // already had the code in flight. The component MUST NOT tear
    // down listeners on the info path.
    const onAccountAdded = vi.fn();
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal({ onAccountAdded });
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-error", {
      message: "paste arrived after loopback already won",
      kind: "paste_after_loopback_won",
    });

    // Listeners still registered after the info path.
    expect(raceHandlers.has("claude-login-success")).toBe(true);
    expect(raceHandlers.has("claude-login-exchanging")).toBe(true);

    await emit("claude-login-exchanging", {});
    await emit("claude-login-success", {
      email: "user@example.com",
    });

    expect(onAccountAdded).toHaveBeenCalledOnce();
    expect(container.textContent).toContain("Account 3 added successfully");
  });

  it("F5: disables paste input + shows overlay on loopback win while typing", async () => {
    // Variant of the existing "disables paste input after loopback
    // resolves" test that pins the overlay text. Catches a
    // regression where the resolved handler skips the loopbackWon
    // flag and goes straight to the resolving step (which is fine
    // for users who haven't started typing, but the overlay is the
    // signal that catches mid-typing users).
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // Loopback wins while user is on the active panel.
    await emit("claude-login-resolved", { via: "loopback" });

    // After loopback win, the resolving step's "Browser sign-in
    // completed — finishing up" message is the overlay.
    const via = container.querySelector('[data-testid="race-via"]');
    expect(via).not.toBeNull();
    expect(via?.textContent).toContain("Browser sign-in completed");
  });

  it("F6: renders clipboard fallback hint when navigator.clipboard.writeText rejects", async () => {
    setupMocks({ list_providers: [ANTHROPIC_PROVIDER] });
    installRaceListenMock();
    // Mock the clipboard API to reject — the JSDOM default has no
    // clipboard at all, so we install a minimal stub. The
    // `configurable: true` lets later tests reset it.
    const writeText = vi
      .fn<(text: string) => Promise<void>>()
      .mockRejectedValue(new Error("clipboard blocked"));
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      writable: true,
      configurable: true,
    });

    const { container } = renderModal();
    await settle();
    await pickAnthropicRace(container);

    await emit("claude-login-browser-opening", {
      auto_url: "https://claude.com/cai/oauth/authorize?x=1",
    });
    await emit("claude-login-manual-url-ready", {
      manual_url: "https://claude.com/cai/oauth/authorize?x=1",
    });

    // Click the Copy button — clipboard write rejects.
    const copyBtn = container.querySelector(
      '[data-testid="race-copy-url"]',
    ) as HTMLButtonElement;
    await fireEvent.click(copyBtn);
    await settle();

    expect(writeText).toHaveBeenCalled();
    const hint = container.querySelector('[data-testid="race-copy-hint"]');
    expect(hint).not.toBeNull();
    expect(hint?.textContent).toMatch(/Cmd-C|Ctrl-C/);
    // The "Copied!" confirmation MUST NOT appear when the write
    // actually failed.
    expect(copyBtn.textContent).toContain("Copy");
    expect(copyBtn.textContent).not.toContain("Copied!");
  });
});
