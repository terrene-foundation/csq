import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/svelte";
import { tick } from "svelte";

const { mockInvoke } = vi.hoisted(() => ({ mockInvoke: vi.fn() }));

vi.mock("@tauri-apps/api/core", () => ({ invoke: mockInvoke }));
vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/test"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import ArchiveHealthBanner from "./ArchiveHealthBanner.svelte";

const BASE = "/home/test/.claude/accounts";

const WARN = {
  check: "paused",
  state: "warn",
  reason: "archive paused: fix pending",
  hint: "remove ~/.config/csq-archive/PAUSED to resume once the pending fix is installed",
};
const UNKNOWN = {
  check: "upload_jobs",
  state: "unknown",
  reason: "launchctl timed out",
  hint: 'check "launchctl print gui/$UID/com.example.csq-archive.hot" for "$HOME/Library/LaunchAgents/com.example.csq-archive.hot.plist"',
};

async function settle(): Promise<void> {
  for (let i = 0; i < 10; i++) await tick();
}

describe("ArchiveHealthBanner", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });
  afterEach(() => {
    cleanup();
  });

  it("renders nothing when the archive is not configured or healthy", async () => {
    mockInvoke.mockResolvedValue([]);
    const { container } = render(ArchiveHealthBanner);
    await settle();
    expect(mockInvoke).toHaveBeenCalledWith("get_archive_health", {
      baseDir: BASE,
    });
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("shows each failing check with its reason and fix hint", async () => {
    mockInvoke.mockResolvedValue([WARN, UNKNOWN]);
    const { container, getByText } = render(ArchiveHealthBanner);
    await settle();
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    expect(getByText("Backup is not fully active")).toBeTruthy();
    expect(container.querySelector('[data-check="paused"]')!.textContent).toContain(
      "archive paused: fix pending",
    );
    expect(
      container.querySelector('[data-check="upload_jobs"]')!.textContent,
    ).toContain("UNKNOWN");
    expect(container.textContent).toContain("~/.config/csq-archive/PAUSED");
  });

  it("an UNKNOWN-only banner says the status could not be verified", async () => {
    mockInvoke.mockResolvedValue([UNKNOWN]);
    const { getByText } = render(ArchiveHealthBanner);
    await settle();
    expect(getByText("Backup status could not be verified")).toBeTruthy();
  });

  it("is dismissible for the session", async () => {
    mockInvoke.mockResolvedValue([WARN]);
    const { container, getByLabelText } = render(ArchiveHealthBanner);
    await settle();
    await fireEvent.click(
      getByLabelText("Dismiss backup notice for this session"),
    );
    await settle();
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("renders an error state when the command fails and nothing ever loaded", async () => {
    mockInvoke.mockRejectedValue(new Error("boom"));
    const { container, getByText } = render(ArchiveHealthBanner);
    await settle();
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
    expect(getByText("Backup status could not be checked")).toBeTruthy();
  });

  describe("polling", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("re-polls every POLL_MS and keeps the last findings when a refresh fails", async () => {
      mockInvoke
        .mockResolvedValueOnce([WARN])
        .mockRejectedValueOnce(new Error("x"));
      const { container } = render(ArchiveHealthBanner);
      await vi.advanceTimersByTimeAsync(0);
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(container.querySelector('[role="alert"]')).not.toBeNull();
      await vi.advanceTimersByTimeAsync(119_999);
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      // refresh failed after a success: last findings stay, no error banner
      expect(container.querySelector('[data-check="paused"]')).not.toBeNull();
      expect(container.textContent).not.toContain("could not be checked");
    });

    it("reports the check as failed after 3 consecutive failed polls even after an earlier success, and recovers", async () => {
      mockInvoke
        .mockResolvedValueOnce([])
        .mockRejectedValueOnce(new Error("1"))
        .mockRejectedValueOnce(new Error("2"))
        .mockRejectedValueOnce(new Error("3"))
        .mockResolvedValue([]);
      const { container } = render(ArchiveHealthBanner);
      await vi.advanceTimersByTimeAsync(0);
      expect(container.textContent).not.toContain("could not be checked");
      await vi.advanceTimersByTimeAsync(120_000);
      await vi.advanceTimersByTimeAsync(120_000);
      expect(container.textContent).not.toContain("could not be checked");
      await vi.advanceTimersByTimeAsync(120_000);
      expect(container.textContent).toContain("Backup status could not be checked");
      await vi.advanceTimersByTimeAsync(120_000);
      expect(container.textContent).not.toContain("could not be checked");
    });

    it("a dismissal holds for the same findings but a NEW finding re-shows the banner", async () => {
      mockInvoke
        .mockResolvedValueOnce([WARN])
        .mockResolvedValueOnce([WARN])
        .mockResolvedValue([WARN, UNKNOWN]);
      const { container, getByLabelText } = render(ArchiveHealthBanner);
      await vi.advanceTimersByTimeAsync(0);
      await fireEvent.click(
        getByLabelText("Dismiss backup notice for this session"),
      );
      await vi.advanceTimersByTimeAsync(0);
      expect(container.querySelector('[role="alert"]')).toBeNull();
      // same findings on the next poll: stays dismissed
      await vi.advanceTimersByTimeAsync(120_000);
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(container.querySelector('[role="alert"]')).toBeNull();
      // a new check now fails: the banner returns
      await vi.advanceTimersByTimeAsync(120_000);
      expect(mockInvoke).toHaveBeenCalledTimes(3);
      expect(container.querySelector('[role="alert"]')).not.toBeNull();
      expect(
        container.querySelector('[data-check="upload_jobs"]'),
      ).not.toBeNull();
    });
  });
});
