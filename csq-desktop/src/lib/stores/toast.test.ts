import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  toasts,
  showToast,
  dismissToast,
  clearAllToasts,
  DEFAULT_DURATION_MS,
} from "./toast.svelte";

describe("toast store", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    clearAllToasts();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("pushes a toast and returns its id", () => {
    const id = showToast("success", "saved");
    expect(id).toBeGreaterThan(0);
    expect(toasts.length).toBe(1);
    expect(toasts[0].message).toBe("saved");
    expect(toasts[0].kind).toBe("success");
  });

  it("supports multiple live toasts", () => {
    showToast("success", "one");
    showToast("error", "two");
    showToast("info", "three");
    expect(toasts.map((t) => t.message)).toEqual(["one", "two", "three"]);
  });

  it("auto-dismisses after the default duration", () => {
    showToast("info", "bye");
    expect(toasts.length).toBe(1);
    vi.advanceTimersByTime(DEFAULT_DURATION_MS - 1);
    expect(toasts.length).toBe(1);
    vi.advanceTimersByTime(1);
    expect(toasts.length).toBe(0);
  });

  it("dismissToast removes a specific toast by id", () => {
    const a = showToast("success", "a");
    const b = showToast("error", "b");
    dismissToast(a);
    expect(toasts.map((t) => t.message)).toEqual(["b"]);
    expect(toasts[0].id).toBe(b);
  });

  it("manual dismiss cancels the pending auto-dismiss timer", () => {
    const id = showToast("success", "gone early");
    dismissToast(id);
    expect(toasts.length).toBe(0);
    // Advancing past the default duration must not attempt a double
    // removal (which would throw on an empty array in some impls).
    expect(() => vi.advanceTimersByTime(DEFAULT_DURATION_MS * 2)).not.toThrow();
    expect(toasts.length).toBe(0);
  });

  it("durationMs=0 makes a toast sticky", () => {
    showToast("error", "sticky", 0);
    vi.advanceTimersByTime(DEFAULT_DURATION_MS * 10);
    expect(toasts.length).toBe(1);
  });

  it("clearAllToasts drops everything and cancels timers", () => {
    showToast("success", "a");
    showToast("error", "b");
    clearAllToasts();
    expect(toasts.length).toBe(0);
    vi.advanceTimersByTime(DEFAULT_DURATION_MS * 2);
    expect(toasts.length).toBe(0);
  });

  it("dismissing an unknown id is a no-op", () => {
    showToast("info", "live");
    expect(() => dismissToast(99999)).not.toThrow();
    expect(toasts.length).toBe(1);
  });

  it("ids are monotonic across calls", () => {
    const first = showToast("info", "a", 0);
    const second = showToast("info", "b", 0);
    const third = showToast("info", "c", 0);
    expect(second).toBeGreaterThan(first);
    expect(third).toBeGreaterThan(second);
  });
});
