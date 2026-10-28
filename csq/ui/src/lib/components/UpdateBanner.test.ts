import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";

// Inert custody IPC only: no updater, installer, process, or account host access.
const mockInvoke = vi.fn();
const mockUnlisten = vi.fn();
const mockInstall = vi.fn();
const mockCheck = vi.fn();
const mockRelaunch = vi.fn();
let capturedEventHandler: ((event: { payload: unknown }) => void) | null = null;
const mockListen = vi.fn(
  (_event: string, handler: (e: { payload: unknown }) => void): Promise<() => void> => {
    capturedEventHandler = handler;
    return Promise.resolve(mockUnlisten);
  },
);
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
  Channel: class { onmessage: (event: unknown) => void = () => {}; },
}));
vi.mock("@tauri-apps/api/event", () => ({
  listen: (event: string, handler: (e: { payload: unknown }) => void) => mockListen(event, handler),
}));
vi.mock("@tauri-apps/plugin-updater", () => ({ check: () => mockCheck() }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch: () => mockRelaunch() }));
import UpdateBanner from "./UpdateBanner.svelte";

function defaultUpdateInfo() {
  return { version: "2.1.0-alpha.14", current_version: "2.0.0-alpha.14", release_url: "https://example.test/release" };
}
async function flushUpdate(): Promise<void> {
  for (let i = 0; i < 8; i += 1) { await Promise.resolve(); await tick(); }
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function updateChannel(): { onmessage: (event: Record<string, unknown>) => void } {
  const call = [...mockInvoke.mock.calls].reverse().find((args) => args[0] === "install_update_with_custody");
  expect(call).toBeDefined();
  return call![1].onEvent;
}
async function startInstall() {
  const view = render(UpdateBanner);
  await flushUpdate();
  await fireEvent.click(view.getByRole("button", { name: "Install update in-app" }));
  await flushUpdate();
  return view;
}
describe("UpdateBanner", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
    mockInstall.mockReset().mockImplementation(() => new Promise<boolean>(() => {}));
    mockInvoke.mockImplementation((command: string) => {
      if (command === "get_update_status") return Promise.resolve(defaultUpdateInfo());
      if (command === "get_pending_logins") return Promise.resolve([]);
      if (command === "install_update_with_custody") return mockInstall();
      return Promise.resolve(undefined);
    });
    mockListen.mockClear();
    mockUnlisten.mockReset();
    mockCheck.mockReset();
    mockRelaunch.mockReset();
    capturedEventHandler = null;
  });
  afterEach(() => { cleanup(); });

  it("renders nothing when no update is cached and no event fires", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const view = render(UpdateBanner);
    await flushUpdate();
    expect(view.container.querySelector(".update-banner")).toBeNull();
  });
  it("renders current and available versions from cached status", async () => {
    const view = render(UpdateBanner);
    await flushUpdate();
    expect(view.container.textContent).toContain("Update available");
    expect(view.container.textContent).toContain("v2.0.0-alpha.14");
    expect(view.container.textContent).toContain("v2.1.0-alpha.14");
  });
  it("renders the banner when the update event arrives after mount", async () => {
    mockInvoke.mockResolvedValueOnce(null);
    const view = render(UpdateBanner);
    await flushUpdate();
    expect(view.container.querySelector(".update-banner")).toBeNull();
    capturedEventHandler!({ payload: defaultUpdateInfo() });
    await tick();
    expect(view.getByRole("button", { name: "Install update in-app" })).toBeTruthy();
  });
  it("routes install and restart exclusively through backend custody", async () => {
    const result = deferred<boolean>();
    mockInstall.mockReturnValueOnce(result.promise);
    const view = await startInstall();
    expect(mockInvoke).toHaveBeenCalledWith("install_update_with_custody", { onEvent: expect.any(Object) });
    expect(view.container.textContent).toContain("Preparing update");
    result.resolve(true);
    await flushUpdate();
    expect(view.container.textContent).toContain("Installed — restarting");
    expect(mockCheck).not.toHaveBeenCalled();
    expect(mockRelaunch).not.toHaveBeenCalled();
    expect(mockInvoke.mock.calls.map(([command]) => command)).toEqual(["get_update_status", "install_update_with_custody"]);
  });
  it("opens Manual when the custody owner reports no update", async () => {
    mockInstall.mockResolvedValueOnce(false);
    const view = await startInstall();
    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
    expect(view.getByRole("button", { name: "Install update in-app" })).toBeTruthy();
    expect(mockCheck).not.toHaveBeenCalled();
  });
  it("shows fixed failure text and Retry for an unknown backend rejection", async () => {
    mockInstall.mockRejectedValueOnce(new Error("signature verification failed: private-token-secret"));
    const view = await startInstall();
    expect(view.container.textContent).toContain("Update failed");
    expect(view.container.textContent).toContain("Could not complete the update");
    expect(view.container.textContent).not.toContain("private-token-secret");
    expect(view.getByRole("button", { name: "Retry in-app install" })).toBeTruthy();
  });
  it("opens the release page from Manual", async () => {
    const view = render(UpdateBanner);
    await flushUpdate();
    await fireEvent.click(view.getByRole("button", { name: "Open release page in browser" }));
    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
  });
  it("dismisses the banner for this mount", async () => {
    const view = render(UpdateBanner);
    await flushUpdate();
    await fireEvent.click(view.getByRole("button", { name: "Dismiss update notification" }));
    await tick();
    expect(view.container.querySelector(".update-banner")).toBeNull();
  });
  it("keeps Manual available and shows an actionable browser error", async () => {
    const view = render(UpdateBanner);
    await flushUpdate();
    mockInvoke.mockRejectedValueOnce(new Error("private-token-secret"));
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await fireEvent.click(view.getByRole("button", { name: "Open release page in browser" }));
      await flushUpdate();
      expect(view.container.textContent).toContain("Check your browser and try again");
      expect(view.container.textContent).not.toContain("private-token-secret");
      expect(view.getByRole("button", { name: "Open release page in browser" })).toBeTruthy();
      expect(errSpy).not.toHaveBeenCalled();
    } finally { errSpy.mockRestore(); }
  });
  it("bounds progress and hides a percentage for unknown totals", async () => {
    const view = await startInstall();
    const channel = updateChannel();
    channel.onmessage({ event: "Started", data: { contentLength: 10 } });
    channel.onmessage({ event: "Progress", data: { chunkLength: 5 } });
    await tick();
    expect(view.container.textContent).toContain("50%");
    channel.onmessage({ event: "Progress", data: { chunkLength: 20 } });
    await tick();
    expect(view.container.textContent).toContain("100%");
    for (const contentLength of [null, 0, -1, NaN, Infinity]) {
      channel.onmessage({ event: "Started", data: { contentLength } });
      await tick();
      expect(view.container.textContent).not.toContain("%");
    }
    channel.onmessage({ event: "Finished" });
    await tick();
    expect(view.container.textContent).toContain("Installing v");
    expect(mockRelaunch).not.toHaveBeenCalled();
  });
  it.each([
    ["update_permission_denied", "This window cannot install updates"],
    ["update_check_failed", "Could not check for an update"],
    ["update_download_or_signature_failed", "Could not download or verify the update"],
    ["update_install_failed", "Could not install the update"],
    ["update_custody_release_refused", "Sign-in admission remains closed"],
    ["update_installer_completion_unverified", "sign-in admission remains closed"],
    ["desktop_update_unverified", "Restart the app before signing in"],
    ["update_quiescence_lost", "Update custody could not be verified"],
    ["desktop_quiescence_conflict", "already waiting for sign-ins"],
  ])("maps canonical %s to fixed text", async (tag, message) => {
    mockInstall.mockRejectedValueOnce(tag);
    const view = await startInstall();
    expect(view.container.textContent).toContain(message);
    expect(view.getByRole("button", { name: "Open release page in browser" })).toBeTruthy();
    expect(mockCheck).not.toHaveBeenCalled();
    expect(mockRelaunch).not.toHaveBeenCalled();
  });
  it("blocks signature retries and keeps Manual available even after a browser failure", async () => {
    mockInstall.mockRejectedValueOnce("update_signature_invalid");
    const view = await startInstall();
    expect(view.container.textContent).toContain("signature or signed version is invalid");
    expect(view.container.textContent).toContain("report this release; do not install this download");
    expect(view.queryByRole("button", { name: "Retry in-app install" })).toBeNull();
    expect(mockInstall).toHaveBeenCalledOnce();
    mockInvoke.mockRejectedValueOnce("private-token-secret");
    await fireEvent.click(view.getByRole("button", { name: "Open release page in browser" }));
    await flushUpdate();
    expect(view.container.textContent).toContain("Could not open the release page");
    expect(view.container.textContent).not.toContain("private-token-secret");
    expect(view.queryByRole("button", { name: "Retry in-app install" })).toBeNull();
    await fireEvent.click(view.getByRole("button", { name: "Open release page in browser" }));
    expect(mockInvoke).toHaveBeenCalledWith("open_release_page");
    expect(mockInstall).toHaveBeenCalledOnce();
    expect(mockCheck).not.toHaveBeenCalled();
    expect(mockRelaunch).not.toHaveBeenCalled();
  });
  it("keeps ordinary download failures retryable through custody", async () => {
    mockInstall.mockRejectedValueOnce("update_download_or_signature_failed");
    const view = await startInstall();
    expect(view.container.textContent).toContain("Could not download or verify the update");
    await fireEvent.click(view.getByRole("button", { name: "Retry in-app install" }));
    await flushUpdate();
    expect(mockInstall).toHaveBeenCalledTimes(2);
    expect(view.container.textContent).toContain("Preparing update");
    expect(mockCheck).not.toHaveBeenCalled();
  });
  it.each([undefined, null, { status: "no_update" }])("fails closed for malformed custody result %s", async (outcome) => {
    mockInstall.mockResolvedValueOnce(outcome);
    const view = await startInstall();
    expect(view.container.textContent).toContain("Could not complete the update");
    expect(view.container.textContent).not.toContain("Installed");
    expect(mockInvoke).not.toHaveBeenCalledWith("open_release_page");
  });
  it("prevents overlapping clicks, then detaches the old channel before Retry", async () => {
    const result = deferred<boolean>();
    mockInstall.mockReturnValueOnce(result.promise);
    const view = render(UpdateBanner);
    await flushUpdate();
    const button = view.getByRole("button", { name: "Install update in-app" });
    button.click(); button.click();
    await flushUpdate();
    expect(mockInstall).toHaveBeenCalledOnce();
    const oldCallback = updateChannel().onmessage;
    result.reject("update_check_failed");
    await flushUpdate();
    await fireEvent.click(view.getByRole("button", { name: "Retry in-app install" }));
    await flushUpdate();
    oldCallback({ event: "Finished" });
    await tick();
    expect(view.container.textContent).toContain("Preparing update");
    expect(mockInstall).toHaveBeenCalledTimes(2);
  });
  it("detaches progress after unmount and ignores the owned backend completion", async () => {
    const result = deferred<boolean>();
    mockInstall.mockReturnValueOnce(result.promise);
    const view = await startInstall();
    const channel = updateChannel();
    const callback = channel.onmessage;
    view.unmount();
    expect(channel.onmessage).not.toBe(callback);
    callback({ event: "Finished" });
    result.resolve(false);
    await flushUpdate();
    expect(mockInvoke).not.toHaveBeenCalledWith("open_release_page");
    expect(mockRelaunch).not.toHaveBeenCalled();
    expect(mockUnlisten).toHaveBeenCalledOnce();
  });
  it("unregisters a listener that resolves after unmount", async () => {
    const registration = deferred<() => void>();
    mockListen.mockImplementationOnce(() => registration.promise);
    const view = render(UpdateBanner);
    await flushUpdate();
    view.unmount();
    registration.resolve(mockUnlisten);
    await flushUpdate();
    expect(mockUnlisten).toHaveBeenCalledOnce();
  });
  it("registers once again on remount", async () => {
    const view = render(UpdateBanner);
    await flushUpdate();
    view.unmount();
    expect(mockUnlisten).toHaveBeenCalledOnce();
    render(UpdateBanner);
    await flushUpdate();
    expect(mockListen).toHaveBeenCalledTimes(2);
  });
});
