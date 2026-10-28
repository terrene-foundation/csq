import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// CorruptPrefsBanner calls:
//   - invoke("consume_prefs_recovery") on mount (HIGH-1 cached-state path)
//   - listen("prefs-reset-to-defaults", ...) on mount (event-listener path)
// All are stubbed so the component runs in jsdom without a Tauri host.

let capturedEventHandler: ((event: { payload: unknown }) => void) | null = null;

// Default mock: consume_prefs_recovery returns null (no cached recovery).
// Tests that need a cached record override this per-test.
let mockInvokeReturnValue: unknown = null;

const mockInvoke = vi.fn((_cmd: string) => {
  return Promise.resolve(mockInvokeReturnValue);
});

const mockListen = vi.fn(
  (_event: string, handler: (e: { payload: unknown }) => void) => {
    capturedEventHandler = handler;
    return Promise.resolve(() => {
      // Unlisten no-op.
    });
  },
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (cmd: string) => mockInvoke(cmd),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) =>
    mockListen(event, handler),
}));

import CorruptPrefsBanner from "./CorruptPrefsBanner.svelte";

const DISMISSAL_KEY = "csq-prefs-recovery-dismissed-at";

// ── localStorage mock ─────────────────────────────────────────────
//
// The jsdom environment used by this test harness does not expose a
// functional localStorage API. We install a minimal in-memory stub so
// tests can exercise the dismissal-persistence logic without any
// native storage dependency.
//
// LOW-1 fix: stub is installed once at module level (existing convention),
// and `beforeEach` clears ALL keys (not just DISMISSAL_KEY) so a test that
// writes a non-DISMISSAL_KEY entry cannot contaminate subsequent tests.
// `afterEach` calls `vi.unstubAllGlobals()` to restore the original
// localStorage binding between test files and after the suite finishes.
const localStorageStore: Record<string, string> = {};
const localStorageMock = {
  getItem: (key: string) => localStorageStore[key] ?? null,
  setItem: (key: string, value: string) => {
    localStorageStore[key] = value;
  },
  removeItem: (key: string) => {
    delete localStorageStore[key];
  },
};
vi.stubGlobal("localStorage", localStorageMock);

describe("CorruptPrefsBanner", () => {
  beforeEach(() => {
    mockInvoke.mockClear();
    mockListen.mockClear();
    capturedEventHandler = null;
    // Reset invoke return to "no cached recovery" default.
    mockInvokeReturnValue = null;
    // LOW-1 fix: clear ALL keys (not only DISMISSAL_KEY) so any test that
    // writes a different key does not contaminate subsequent tests.
    for (const key of Object.keys(localStorageStore)) {
      delete localStorageStore[key];
    }
  });

  afterEach(() => {
    cleanup();
    // LOW-1 fix: restore the original localStorage binding so the stub does
    // not leak across test files or into the global environment after the
    // suite finishes.
    vi.unstubAllGlobals();
    // Re-stub for subsequent tests in this suite (unstubAllGlobals clears it).
    vi.stubGlobal("localStorage", localStorageMock);
  });

  // ── Existing event-listener path tests ────────────────────────────

  it("renders nothing on mount — banner is hidden until event fires", async () => {
    const { container } = render(CorruptPrefsBanner);
    await tick();
    await tick();
    expect(container.querySelector(".banner")).toBeNull();
  });

  it("renders the banner when the prefs-reset-to-defaults event fires", async () => {
    const { container } = render(CorruptPrefsBanner);
    await tick();
    await tick();

    expect(capturedEventHandler).not.toBeNull();
    capturedEventHandler!({
      payload: {
        reason: "desktop_prefs_parse_value",
        occurred_at: new Date().toISOString(),
      },
    });
    await tick();

    const banner = container.querySelector(".banner");
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("Preferences reset");
  });

  it("hides the banner when dismiss is clicked", async () => {
    const { container } = render(CorruptPrefsBanner);
    await tick();
    await tick();

    capturedEventHandler!({
      payload: {
        reason: "desktop_prefs_empty",
        occurred_at: new Date().toISOString(),
      },
    });
    await tick();
    expect(container.querySelector(".banner")).not.toBeNull();

    const dismissBtn = container.querySelector(".dismiss") as HTMLButtonElement;
    await fireEvent.click(dismissBtn);
    await tick();

    expect(container.querySelector(".banner")).toBeNull();
  });

  it("persists dismissal timestamp to localStorage on dismiss", async () => {
    const { container } = render(CorruptPrefsBanner);
    await tick();
    await tick();

    capturedEventHandler!({
      payload: {
        reason: "desktop_prefs_top_level",
        occurred_at: new Date().toISOString(),
      },
    });
    await tick();

    const dismissBtn = container.querySelector(".dismiss") as HTMLButtonElement;
    await fireEvent.click(dismissBtn);
    await tick();

    const stored = localStorage.getItem(DISMISSAL_KEY);
    expect(stored).not.toBeNull();
    // The stored value should be a valid ISO-8601 timestamp.
    expect(new Date(stored!).getTime()).toBeGreaterThan(0);
  });

  it("suppresses the banner when a recovery event fires after a prior dismissal", async () => {
    // Arrange — store a dismissal in the FUTURE to guarantee suppression.
    const futureDismissalAt = new Date(Date.now() + 60_000).toISOString();
    localStorage.setItem(DISMISSAL_KEY, futureDismissalAt);

    const { container } = render(CorruptPrefsBanner);
    await tick();
    await tick();

    capturedEventHandler!({
      payload: {
        reason: "desktop_prefs_parse_typed",
        occurred_at: new Date().toISOString(),
      },
    });
    await tick();

    // Banner must NOT appear because the dismissal timestamp is after
    // the recovery timestamp.
    expect(container.querySelector(".banner")).toBeNull();
  });

  // ── HIGH-1 cached-state path tests ────────────────────────────────
  //
  // These tests verify that the component shows the banner on mount
  // when `invoke("consume_prefs_recovery")` returns a cached record —
  // the defense-in-depth fix for the renderer-mount race where setup()
  // emits before the WebView spawns.

  it("shows banner on mount when consume_prefs_recovery returns a cached record", async () => {
    // Arrange — simulate a cached recovery record from setup().
    const occurredAt = new Date(Date.now() - 1000).toISOString();
    mockInvokeReturnValue = {
      reason: "desktop_prefs_empty",
      occurred_at: occurredAt,
    };

    // Act
    const { container } = render(CorruptPrefsBanner);
    // Allow invoke Promise to resolve and reactivity to settle.
    await tick();
    await new Promise((r) => setTimeout(r, 0));
    await tick();

    // Assert — banner is visible via the cached-state path.
    const banner = container.querySelector(".banner");
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("Preferences reset");
  });

  it("does not show banner on mount when consume_prefs_recovery returns null", async () => {
    // Arrange — no cached recovery (default mockInvokeReturnValue = null).
    const { container } = render(CorruptPrefsBanner);
    await tick();
    await new Promise((r) => setTimeout(r, 0));
    await tick();

    // Assert — banner stays hidden when there is no cached record.
    expect(container.querySelector(".banner")).toBeNull();
  });

  it("suppresses banner from cached path when a prior dismissal covers the recovery time", async () => {
    // Arrange — store a future dismissal so the cached recovery is suppressed.
    const futureDismissalAt = new Date(Date.now() + 60_000).toISOString();
    localStorage.setItem(DISMISSAL_KEY, futureDismissalAt);

    const occurredAt = new Date(Date.now() - 1000).toISOString();
    mockInvokeReturnValue = {
      reason: "desktop_prefs_parse_value",
      occurred_at: occurredAt,
    };

    const { container } = render(CorruptPrefsBanner);
    await tick();
    await new Promise((r) => setTimeout(r, 0));
    await tick();

    // Banner must NOT appear because the cached record is before the
    // stored dismissal timestamp.
    expect(container.querySelector(".banner")).toBeNull();
  });
});
