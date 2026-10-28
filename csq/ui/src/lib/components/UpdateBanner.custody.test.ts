import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent, waitFor } from "@testing-library/svelte";
import { tick } from "svelte";
const { invoke, rawInstall, rawRestart, rawCheck } = vi.hoisted(() => ({
  invoke: vi.fn(), rawInstall: vi.fn(), rawRestart: vi.fn(), rawCheck: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invoke(...args),
  Channel: class { onmessage: (event: unknown) => void = () => {}; },
}));
vi.mock("@tauri-apps/api/event", () => ({ listen: async () => () => {} }));
vi.mock("@tauri-apps/plugin-updater", () => ({ check: () => rawCheck() }));
vi.mock("@tauri-apps/plugin-process", () => ({ relaunch: () => rawRestart() }));
import UpdateBanner from "./UpdateBanner.svelte";
type Pending = { operation_id: string; provider: "claude"|"codex"|"native"; account: number; native_id: string|null };
let pending: Pending[];
let finish: (value: boolean) => void;
let stopped: boolean;
const update = { version: "2.22.0", current_version: "2.21.0", release_url: "https://example.test/release" };
beforeEach(() => {
  vi.clearAllMocks(); pending = []; stopped = false;
  rawInstall.mockResolvedValue(undefined); rawRestart.mockResolvedValue(undefined);
  rawCheck.mockResolvedValue({ downloadAndInstall: rawInstall });
  invoke.mockImplementation(async (cmd: string, args?: { onEvent?: { onmessage: (event: unknown) => void } }) => {
    if (cmd === "get_update_status") return update;
    if (cmd === "get_pending_logins") return [...pending];
    if (cmd === "install_update_with_custody") {
      args?.onEvent?.onmessage({ event: "WaitingForSignIn" });
      return await new Promise<boolean>((resolve) => { finish = resolve; });
    }
    if (cmd.startsWith("cancel_")) { if (stopped) pending = []; return stopped; }
    return null;
  });
});
afterEach(() => { cleanup(); });
async function start() {
  const view = render(UpdateBanner);
  await waitFor(() => expect(view.getByRole("button", { name: "Install update in-app" })).toBeTruthy());
  await fireEvent.click(view.getByRole("button", { name: "Install update in-app" }));
  await tick(); return view;
}
describe("UpdateBanner custody", () => {
  it("uses backend custody command before any raw plugin effect", async () => {
    await start();
    expect(invoke.mock.calls.some(([cmd]) => cmd === "install_update_with_custody"), "UPDATE_UI_MISSED_CUSTODY_WRAPPER").toBe(true);
    expect(rawInstall.mock.calls.length, "UPDATE_UI_RAW_INSTALL_BYPASS").toBe(0);
    expect(rawRestart.mock.calls.length, "UPDATE_UI_RAW_RESTART_BYPASS").toBe(0);
    finish(false);
  });
  it.each([
    ["claude", null, "Claude", "cancel_claude_login"],
    ["codex", null, "Codex", "cancel_codex_login"],
    ["native", "kimi-cli", "Kimi", "cancel_native_login"],
    ["native", "grok", "Grok", "cancel_native_login"],
  ] as const)("offers same confirmed cancellation while waiting for %s %s", async (provider, native_id, label, command) => {
    pending = [{ provider, native_id, account: 3, operation_id: "owned-operation-3" }];
    const view = await start();
    await waitFor(() => expect(view.queryByRole("button", { name: `End ${label} sign-in for slot 3` }), "UPDATE_UI_NO_END_SIGNIN_ACTION").not.toBeNull());
    await fireEvent.click(view.getByRole("button", { name: `End ${label} sign-in for slot 3` }));
    await waitFor(() => expect(invoke.mock.calls.some(([cmd]) => cmd === command)).toBe(true));
    const call = invoke.mock.calls.find(([cmd]) => cmd === command);
    expect(call?.[1]).toMatchObject({ operationId: "owned-operation-3", confirmed: true });
    if (native_id) expect(call?.[1]).toMatchObject({ nativeId: native_id });
    if (provider === "claude") expect(call?.[1]).toMatchObject({ account: 3 });
    await waitFor(() => expect(view.getByText("Sign-in left running. The update will wait.")).toBeTruthy());
    expect(rawInstall).not.toHaveBeenCalled();
    stopped = true;
    await fireEvent.click(view.getByRole("button", { name: `End ${label} sign-in for slot 3` }));
    finish(true);
    await waitFor(() => expect(view.getByText("Installed — restarting…")).toBeTruthy());
  });
  it("preserves download progress received from the custody owner", async () => {
    const view = await start();
    const args = invoke.mock.calls.find(([cmd]) => cmd === "install_update_with_custody")?.[1];
    expect(args?.onEvent, "UPDATE_UI_NO_BACKEND_PROGRESS_CHANNEL").toBeTruthy();
    args.onEvent.onmessage({ event: "Started", data: { contentLength: 100 } });
    args.onEvent.onmessage({ event: "Progress", data: { chunkLength: 50 } });
    await tick(); expect(view.getByText(/Downloading v2.22.0/).textContent).toContain("50%");
    args.onEvent.onmessage({ event: "Finished" });
    await tick(); expect(view.getByText("Installing v2.22.0…")).toBeTruthy();
    finish(true);
  });
});
