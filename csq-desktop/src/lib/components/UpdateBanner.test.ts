import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// UpdateBanner calls `invoke("get_update_status")` on mount and
// listens for the `update-available` event. Vitest runs in jsdom
// without a Tauri host, so both APIs must be stubbed. These mocks
// replace the `@tauri-apps/api/core` and `@tauri-apps/api/event`
// modules at resolution time — the component imports them normally
// and receives the mocked exports.
//
// Per-test behaviour is controlled by reassigning `mockInvoke` and
// `mockListen` in `beforeEach`, then returning from `get_update_status`
// the value the test wants. The event listener is captured so tests
// can synthesize a backend-emitted event without starting a Tauri
// runtime.

const mockInvoke = vi.fn();
let capturedEventHandler: ((event: { payload: unknown }) => void) | null = null;
const mockListen = vi.fn(
  (_event: string, handler: (e: { payload: unknown }) => void) => {
    capturedEventHandler = handler;
    return Promise.resolve(() => {
      // Unlisten no-op — we don't need to verify teardown in these tests.
    });
  },
);

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) =>
    mockListen(event, handler),
}));

import UpdateBanner from "./UpdateBanner.svelte";

describe("UpdateBanner", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockListen.mockClear();
    capturedEventHandler = null;
  });

  afterEach(() => {
    cleanup();
  });

  it("renders nothing when no update is cached and no event fires", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const { container } = render(UpdateBanner);
    await tick();
    await tick();
    expect(container.querySelector(".update-banner")).toBeNull();
  });

  it("renders the banner when get_update_status returns a cached update", async () => {
    mockInvoke.mockResolvedValueOnce({
      version: "2.1.0-alpha.14",
      current_version: "2.0.0-alpha.13",
      release_url:
        "https://github.com/terrene-foundation/csq/releases/tag/v2.1.0-alpha.14",
    });
    const { container } = render(UpdateBanner);
    // Two ticks: one for onMount promise resolution, one for the state
    // mutation to flow into the DOM. Keeps the assertion from racing
    // the reactive cycle.
    await tick();
    await tick();
    const banner = container.querySelector(".update-banner");
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("Update available");
    expect(banner?.textContent).toContain("v2.0.0-alpha.13");
    expect(banner?.textContent).toContain("v2.1.0-alpha.14");
  });

  it("renders the banner when the update-available event fires post-mount", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const { container } = render(UpdateBanner);
    await tick();
    await tick();
    expect(container.querySelector(".update-banner")).toBeNull();

    expect(capturedEventHandler).not.toBeNull();
    capturedEventHandler!({
      payload: {
        version: "2.1.0",
        current_version: "2.0.0-alpha.13",
        release_url: "https://example.test/release",
      },
    });
    await tick();
    expect(container.querySelector(".update-banner")).not.toBeNull();
  });

  it("calls open_release_page when Download is clicked", async () => {
    mockInvoke.mockResolvedValueOnce({
      version: "2.1.0",
      current_version: "2.0.0-alpha.13",
      release_url: "https://example.test/release",
    });
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    // After mount, the cached-update path has consumed the first mock
    // resolution. The click handler issues a fresh `invoke` that must
    // succeed so the banner doesn't self-dismiss on error.
    mockInvoke.mockResolvedValueOnce(undefined);
    const downloadBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    expect(downloadBtn).not.toBeNull();
    await fireEvent.click(downloadBtn);

    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
  });

  it("hides the banner when the dismiss button is clicked", async () => {
    mockInvoke.mockResolvedValueOnce({
      version: "2.1.0",
      current_version: "2.0.0-alpha.13",
      release_url: "https://example.test/release",
    });
    const { container } = render(UpdateBanner);
    await tick();
    await tick();
    expect(container.querySelector(".update-banner")).not.toBeNull();

    const dismissBtn = container.querySelector(
      ".update-dismiss",
    ) as HTMLButtonElement;
    await fireEvent.click(dismissBtn);
    await tick();
    expect(container.querySelector(".update-banner")).toBeNull();
  });

  it("self-dismisses if open_release_page fails", async () => {
    mockInvoke.mockResolvedValueOnce({
      version: "2.1.0",
      current_version: "2.0.0-alpha.13",
      release_url: "https://example.test/release",
    });
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    // Simulate a backend error on the download click. The catch path
    // sets `dismissed = true`, so the banner must disappear rather
    // than leave the user staring at a dead button.
    mockInvoke.mockRejectedValueOnce(new Error("no cached update"));
    const downloadBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    // Suppress the console.error the component logs on the rejection;
    // a noisy pass would otherwise look like a real failure in CI.
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await fireEvent.click(downloadBtn);
    await tick();
    await tick();
    expect(container.querySelector(".update-banner")).toBeNull();
    errSpy.mockRestore();
  });
});
