import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// ChangeModelModal calls:
//   invoke('list_ollama_models')    — on mount (+ on submit to re-check)
//   invoke('pull_ollama_model', {model})   — when model missing
//   invoke('set_slot_model', {baseDir, slot, model})  — always
//   invoke('cancel_ollama_pull')    — when user clicks Cancel pull
//   listen('ollama-pull-progress', handler)    — for progress events

const mockInvoke = vi.fn();
let capturedProgressHandler:
  | ((event: { payload: { stream: string; line: string } }) => void)
  | null = null;
const mockListen = vi.fn(
  (event: string, handler: (e: { payload: unknown }) => void) => {
    if (event === "ollama-pull-progress") {
      capturedProgressHandler = handler as typeof capturedProgressHandler;
    }
    return Promise.resolve(() => {});
  },
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) =>
    mockListen(event, handler),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import ChangeModelModal from "./ChangeModelModal.svelte";

function renderModal(propsOverrides: Record<string, unknown> = {}) {
  return render(ChangeModelModal, {
    props: {
      isOpen: true,
      slot: 5,
      onClose: vi.fn(),
      onChanged: vi.fn(),
      ...propsOverrides,
    },
  });
}

describe("ChangeModelModal", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockListen.mockClear();
    capturedProgressHandler = null;
  });

  afterEach(() => {
    cleanup();
  });

  it("loads the installed list on mount and populates the dropdown", async () => {
    mockInvoke.mockResolvedValueOnce(["gemma4:latest", "llama3:8b"]);
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    const select = container.querySelector("select") as HTMLSelectElement;
    expect(select).not.toBeNull();
    const options = Array.from(select.options).map((o) => o.value);
    expect(options).toEqual(["gemma4:latest", "llama3:8b"]);
  });

  // Regression for journal 0061: the modal is rendered by AccountList
  // even when closed, so mount happens with isOpen=false; the user
  // only flips it open later. Earlier code had a $effect guard that
  // skipped the load whenever modalState was already 'loading' — which
  // it always was on first open — so list_ollama_models was never
  // invoked and the spinner hung forever. This test reproduces the
  // real-world open sequence: mount closed, flip open, assert the
  // invoke fired and the picker rendered.
  it("fires list_ollama_models when isOpen flips from false to true after mount", async () => {
    // Use mockResolvedValue (not Once) so the promise still resolves
    // if something else happens to invoke the mock.
    mockInvoke.mockResolvedValue(["qwen3:latest"]);
    const { container, rerender } = render(ChangeModelModal, {
      props: {
        isOpen: false,
        slot: 4,
        onClose: vi.fn(),
        onChanged: vi.fn(),
      },
    });
    await tick();

    // Mount happened with isOpen=false — Tauri must NOT have been
    // called yet. Otherwise we'd be hammering the endpoint on every
    // AccountList render.
    expect(mockInvoke).not.toHaveBeenCalled();

    // User clicks "Change model" on the account card → parent flips
    // isOpen to true.
    await rerender({
      isOpen: true,
      slot: 4,
      onClose: vi.fn(),
      onChanged: vi.fn(),
    });
    // Enough ticks to clear: $effect run → invoke microtask resolve →
    // modalState set → rerender → select rendered.
    for (let i = 0; i < 8; i++) {
      await tick();
    }

    expect(mockInvoke).toHaveBeenCalledWith("list_ollama_models");
    // Debug: dump container state to diagnose what's rendered when
    // the select assertion fails. Vitest prints this automatically
    // on assertion failure via the expect message.
    const select = container.querySelector("select") as HTMLSelectElement;
    expect(
      select,
      `container HTML after open: ${container.innerHTML}`,
    ).not.toBeNull();
    expect(Array.from(select.options).map((o) => o.value)).toEqual([
      "qwen3:latest",
    ]);
  });

  it("shows the pull hint when no models are installed", async () => {
    mockInvoke.mockResolvedValueOnce([]);
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    expect(container.textContent).toContain("No Ollama models found locally");
    expect(container.querySelector("select")).toBeNull();
  });

  it("skips pull when selected model is already installed", async () => {
    mockInvoke.mockResolvedValueOnce(["gemma4:latest"]); // list on mount
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    mockInvoke.mockResolvedValueOnce(["gemma4:latest"]); // re-list on submit
    mockInvoke.mockResolvedValueOnce(undefined); // set_slot_model

    const applyBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Apply"),
    ) as HTMLButtonElement;
    await fireEvent.click(applyBtn);
    await Promise.resolve();
    await Promise.resolve();
    await tick();

    const invoked = mockInvoke.mock.calls.map((c) => c[0]);
    expect(invoked).not.toContain("pull_ollama_model");
    expect(invoked).toContain("set_slot_model");
  });

  it("pulls before setting when the custom model is not installed", async () => {
    mockInvoke.mockResolvedValueOnce(["gemma4:latest"]); // list on mount
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    mockInvoke.mockResolvedValueOnce(["gemma4:latest"]); // re-list on submit
    mockInvoke.mockResolvedValueOnce(undefined); // pull_ollama_model
    mockInvoke.mockResolvedValueOnce(undefined); // set_slot_model

    const customInput = container.querySelector(
      'input[type="text"]',
    ) as HTMLInputElement;
    await fireEvent.input(customInput, { target: { value: "qwen3:latest" } });
    await tick();

    const applyBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Apply"),
    ) as HTMLButtonElement;
    await fireEvent.click(applyBtn);
    // Drain enough microtasks for: re-list → listen → state flip
    // → pull → getBaseDir (homeDir + join) → set_slot_model →
    // final state flip. Each await chains one microtask.
    for (let i = 0; i < 10; i++) {
      await Promise.resolve();
      await tick();
    }

    const invoked = mockInvoke.mock.calls.map((c) => c[0]);
    expect(invoked).toContain("pull_ollama_model");
    expect(invoked).toContain("set_slot_model");
    // pull must come BEFORE set
    const pullIdx = invoked.indexOf("pull_ollama_model");
    const setIdx = invoked.indexOf("set_slot_model");
    expect(pullIdx).toBeLessThan(setIdx);
  });

  it("surfaces an error banner when pull_ollama_model rejects", async () => {
    mockInvoke.mockResolvedValueOnce([]); // list on mount: empty
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    mockInvoke.mockResolvedValueOnce([]); // re-list on submit
    mockInvoke.mockRejectedValueOnce(new Error("ollama not found"));

    const customInput = container.querySelector(
      'input[type="text"]',
    ) as HTMLInputElement;
    await fireEvent.input(customInput, { target: { value: "gemma4" } });
    await tick();

    const applyBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Apply"),
    ) as HTMLButtonElement;
    await fireEvent.click(applyBtn);
    await Promise.resolve();
    await Promise.resolve();
    await tick();

    expect(container.textContent).toContain("ollama not found");
    // set_slot_model must NOT have been called after pull failed.
    const invoked = mockInvoke.mock.calls.map((c) => c[0]);
    expect(invoked).not.toContain("set_slot_model");
  });

  it("appends progress events to the log during pulling state", async () => {
    mockInvoke.mockResolvedValueOnce([]); // list on mount
    const { container } = renderModal();
    await tick();
    await tick();
    await tick();

    // Hold pull_ollama_model pending so the modal stays in
    // `pulling` state long enough for the progress events to
    // appear in the DOM.
    let resolvePull: () => void = () => {};
    const pullPromise = new Promise<void>((resolve) => {
      resolvePull = resolve;
    });
    mockInvoke.mockResolvedValueOnce([]); // re-list on submit
    mockInvoke.mockReturnValueOnce(pullPromise);

    const customInput = container.querySelector(
      'input[type="text"]',
    ) as HTMLInputElement;
    await fireEvent.input(customInput, { target: { value: "gemma4" } });
    await tick();

    const applyBtn = Array.from(container.querySelectorAll("button")).find(
      (b) => b.textContent?.includes("Apply"),
    ) as HTMLButtonElement;
    await fireEvent.click(applyBtn);
    // Let the listen() subscription + state flip land.
    await Promise.resolve();
    await Promise.resolve();
    await tick();
    await tick();

    expect(capturedProgressHandler).not.toBeNull();
    capturedProgressHandler!({
      payload: { stream: "stderr", line: "pulling manifest" },
    });
    capturedProgressHandler!({
      payload: { stream: "stderr", line: "downloading 12345abc 50%" },
    });
    await tick();

    const log = container.querySelector(".log");
    expect(log?.textContent).toContain("pulling manifest");
    expect(log?.textContent).toContain("downloading 12345abc 50%");

    // Unblock the pull promise so the test doesn't hang on cleanup.
    mockInvoke.mockResolvedValueOnce(undefined); // set_slot_model after resolve
    resolvePull();
  });

  // ── PR-G5 — Gemini picker (FR-G-UI-02) ─────────────────────

  it("renders 5 canonical Gemini models with auto first when surface=gemini", async () => {
    const { container } = renderModal({ surface: "gemini", slot: 7 });
    await tick();
    await tick();

    const select = container.querySelector(
      '[data-testid="gemini-model-select"]',
    ) as HTMLSelectElement;
    expect(select).not.toBeNull();
    const ids = Array.from(select.options).map((o) => o.value);
    expect(ids).toEqual([
      "auto",
      "gemini-2.5-pro",
      "gemini-2.5-flash",
      "gemini-2.5-flash-lite",
      "gemini-3-pro-preview",
    ]);
    // Default selection is auto — matches the default the binding
    // marker is provisioned with.
    expect(select.value).toBe("auto");
    // Synchronous load — no IPC fetch for the static list.
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "list_ollama_models",
      expect.anything(),
    );
    expect(mockInvoke).not.toHaveBeenCalledWith(
      "list_codex_models",
      expect.anything(),
    );
  });

  it("shows preview-tier warning when gemini-3-pro-preview is selected", async () => {
    const { container } = renderModal({ surface: "gemini", slot: 7 });
    await tick();
    await tick();

    // No warning by default (auto selected).
    expect(
      container.querySelector('[data-testid="gemini-preview-warning"]'),
    ).toBeNull();

    const select = container.querySelector(
      '[data-testid="gemini-model-select"]',
    ) as HTMLSelectElement;
    await fireEvent.change(select, {
      target: { value: "gemini-3-pro-preview" },
    });
    await tick();

    const warn = container.querySelector(
      '[data-testid="gemini-preview-warning"]',
    );
    expect(warn).not.toBeNull();
    expect(warn?.textContent).toContain("gemini-2.5-pro");
  });

  it("submits gemini_switch_model on Apply click", async () => {
    const onChanged = vi.fn();
    mockInvoke.mockResolvedValueOnce(undefined); // gemini_switch_model
    const { container } = renderModal({
      surface: "gemini",
      slot: 7,
      onChanged,
    });
    await tick();
    await tick();

    const select = container.querySelector(
      '[data-testid="gemini-model-select"]',
    ) as HTMLSelectElement;
    await fireEvent.change(select, { target: { value: "gemini-2.5-pro" } });
    await tick();

    const apply = container.querySelector(
      '[data-testid="gemini-apply"]',
    ) as HTMLButtonElement;
    await fireEvent.click(apply);
    await tick();
    await tick();

    expect(mockInvoke).toHaveBeenCalledWith("gemini_switch_model", {
      baseDir: "/home/test/.claude/accounts",
      slot: 7,
      model: "gemini-2.5-pro",
    });
    expect(onChanged).toHaveBeenCalled();
  });

  it("renders 'Change Gemini model' header for surface=gemini", async () => {
    const { getByText } = renderModal({ surface: "gemini", slot: 7 });
    await tick();
    expect(getByText("Change Gemini model")).toBeTruthy();
  });
});
