import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// UpdateBanner calls:
//   - invoke("get_update_status") on mount
//   - listen("update-available", ...) on mount
//   - check() from @tauri-apps/plugin-updater on "Install" click
//   - downloadAndInstall(progressFn) on the Update returned by check
//   - relaunch() from @tauri-apps/plugin-process after install
//   - invoke("open_release_page") on "Manual" click (and as a
//     fallback when check() returns null)
//
// All of the above are stubbed so the component runs in jsdom
// without a Tauri host. Per-test behaviour is controlled by the
// mock reassignments in beforeEach.

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

const mockCheck = vi.fn();
const mockRelaunch = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) =>
    mockListen(event, handler),
}));

vi.mock("@tauri-apps/plugin-updater", () => ({
  check: () => mockCheck(),
}));

vi.mock("@tauri-apps/plugin-process", () => ({
  relaunch: () => mockRelaunch(),
}));

import UpdateBanner from "./UpdateBanner.svelte";

function defaultUpdateInfo() {
  return {
    version: "2.1.0",
    current_version: "2.0.0-alpha.14",
    release_url: "https://example.test/release",
  };
}

describe("UpdateBanner", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockListen.mockClear();
    mockCheck.mockReset();
    mockRelaunch.mockReset();
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
      current_version: "2.0.0-alpha.14",
      release_url:
        "https://github.com/terrene-foundation/csq/releases/tag/v2.1.0-alpha.14",
    });
    const { container } = render(UpdateBanner);
    await tick();
    await tick();
    const banner = container.querySelector(".update-banner");
    expect(banner).not.toBeNull();
    expect(banner?.textContent).toContain("Update available");
    expect(banner?.textContent).toContain("v2.0.0-alpha.14");
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
      payload: defaultUpdateInfo(),
    });
    await tick();
    expect(container.querySelector(".update-banner")).not.toBeNull();
  });

  it("runs the in-app install flow when Install is clicked", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    // `check()` returns an Update whose downloadAndInstall accepts
    // a progress callback. The callback drives the banner's state
    // machine: Started → Progress → Finished.
    const downloadAndInstall = vi.fn(async (onEvent?: (e: unknown) => void) => {
      onEvent?.({ event: "Started", data: { contentLength: 1024 } });
      onEvent?.({ event: "Progress", data: { chunkLength: 512 } });
      onEvent?.({ event: "Finished" });
    });
    mockCheck.mockResolvedValueOnce({ downloadAndInstall });
    mockRelaunch.mockResolvedValueOnce(undefined);

    const installBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    expect(installBtn.textContent?.trim()).toBe("Install");
    await fireEvent.click(installBtn);
    // Flush the awaited promise chain: check → downloadAndInstall →
    // state updates → relaunch.
    await Promise.resolve();
    await Promise.resolve();
    await tick();

    expect(mockCheck).toHaveBeenCalledOnce();
    expect(downloadAndInstall).toHaveBeenCalledOnce();
    expect(mockRelaunch).toHaveBeenCalledOnce();
  });

  it("falls back to Manual when check() returns null (no bundle for platform)", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    mockCheck.mockResolvedValueOnce(null);
    // Second invoke call is `open_release_page` from the fallback.
    mockInvoke.mockResolvedValueOnce(undefined);

    const installBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    await fireEvent.click(installBtn);
    await Promise.resolve();
    await Promise.resolve();
    await tick();

    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
    // Banner should stay visible — user just opened the release
    // page, they may still want to dismiss manually.
    expect(container.querySelector(".update-banner")).not.toBeNull();
  });

  it("shows the error state and retry button when downloadAndInstall fails", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    const downloadAndInstall = vi.fn(async () => {
      throw new Error("signature verification failed");
    });
    mockCheck.mockResolvedValueOnce({ downloadAndInstall });

    const installBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    await fireEvent.click(installBtn);
    await Promise.resolve();
    await Promise.resolve();
    await tick();

    const banner = container.querySelector(".update-banner");
    expect(banner?.textContent).toContain("Update failed");
    expect(banner?.textContent).toContain("signature verification failed");
    const retryBtn = container.querySelector(
      ".update-action",
    ) as HTMLButtonElement;
    expect(retryBtn.textContent?.trim()).toBe("Retry");
  });

  it("calls open_release_page when Manual is clicked", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    mockInvoke.mockResolvedValueOnce(undefined);
    const manualBtn = container.querySelector(
      ".update-secondary",
    ) as HTMLButtonElement;
    expect(manualBtn).not.toBeNull();
    await fireEvent.click(manualBtn);

    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
  });

  it("hides the banner when the dismiss button is clicked", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
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

  it("self-dismisses if open_release_page fails from the Manual button", async () => {
    mockInvoke.mockResolvedValueOnce(defaultUpdateInfo());
    const { container } = render(UpdateBanner);
    await tick();
    await tick();

    mockInvoke.mockRejectedValueOnce(new Error("no cached update"));
    const manualBtn = container.querySelector(
      ".update-secondary",
    ) as HTMLButtonElement;
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await fireEvent.click(manualBtn);
    await tick();
    await tick();
    expect(container.querySelector(".update-banner")).toBeNull();
    errSpy.mockRestore();
  });
});
