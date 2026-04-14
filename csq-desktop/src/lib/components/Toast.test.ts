import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent } from "@testing-library/svelte";
import { tick } from "svelte";
import {
  showToast,
  dismissToast,
  clearAllToasts,
  toasts,
} from "../stores/toast.svelte";

import Toast from "./Toast.svelte";

async function settle() {
  for (let i = 0; i < 4; i++) await tick();
}

describe("Toast", () => {
  beforeEach(() => {
    clearAllToasts();
  });

  afterEach(() => {
    clearAllToasts();
    cleanup();
  });

  it("renders nothing when no toasts are active", () => {
    const { container } = render(Toast);
    const host = container.querySelector(".toast-host");
    expect(host).not.toBeNull();
    expect(host!.children.length).toBe(0);
  });

  it("renders a success toast", async () => {
    const { container } = render(Toast);
    showToast("success", "Account 3 added", 0);
    await settle();
    const toast = container.querySelector(".toast-success");
    expect(toast).not.toBeNull();
    expect(toast!.textContent).toContain("Account 3 added");
  });

  it("renders an error toast", async () => {
    const { container } = render(Toast);
    showToast("error", "Swap failed", 0);
    await settle();
    const toast = container.querySelector(".toast-error");
    expect(toast).not.toBeNull();
    expect(toast!.textContent).toContain("Swap failed");
  });

  it("renders multiple toasts simultaneously", async () => {
    const { container } = render(Toast);
    showToast("success", "First", 0);
    showToast("error", "Second", 0);
    showToast("info", "Third", 0);
    await settle();
    const items = container.querySelectorAll(".toast");
    expect(items.length).toBe(3);
  });

  it("dismisses a toast when close button is clicked", async () => {
    const { container } = render(Toast);
    showToast("info", "Dismiss me", 0);
    await settle();

    const closeBtn = container.querySelector(".toast-close");
    expect(closeBtn).not.toBeNull();
    await fireEvent.click(closeBtn!);
    await settle();

    const items = container.querySelectorAll(".toast");
    expect(items.length).toBe(0);
  });

  it("has aria-live polite for screen readers", () => {
    const { container } = render(Toast);
    const host = container.querySelector(".toast-host");
    expect(host!.getAttribute("aria-live")).toBe("polite");
  });
});
