import { describe, it, expect } from "vitest";
import { render } from "@testing-library/svelte";
import UsageBar from "./UsageBar.svelte";

describe("UsageBar", () => {
  it("renders label and percentage", () => {
    const { container } = render(UsageBar, { props: { label: "5h", pct: 42 } });
    expect(container.textContent).toContain("5h");
    expect(container.textContent).toContain("42%");
  });

  it("renders 0% for zero usage", () => {
    const { container } = render(UsageBar, { props: { label: "7d", pct: 0 } });
    expect(container.textContent).toContain("0%");
  });

  it("caps bar width at 100%", () => {
    const { container } = render(UsageBar, {
      props: { label: "5h", pct: 150 },
    });
    const fill = container.querySelector(".bar-fill") as HTMLElement;
    expect(fill.style.width).toBe("100%");
  });

  it("uses green color for low usage", () => {
    const { container } = render(UsageBar, { props: { label: "5h", pct: 30 } });
    const fill = container.querySelector(".bar-fill") as HTMLElement;
    expect(fill.style.background).toContain("--green");
  });

  it("uses yellow color for medium usage", () => {
    const { container } = render(UsageBar, { props: { label: "5h", pct: 75 } });
    const fill = container.querySelector(".bar-fill") as HTMLElement;
    expect(fill.style.background).toContain("--yellow");
  });

  it("uses red color for high usage", () => {
    const { container } = render(UsageBar, { props: { label: "5h", pct: 95 } });
    const fill = container.querySelector(".bar-fill") as HTMLElement;
    expect(fill.style.background).toContain("--red");
  });

  // C2 (journal `operator-surfaces`): `pct === null` means the account's
  // quota row carries no window at all for this label — distinct from a
  // measured `0`. Renders the caller's `emptyLabel` and no `.bar-fill`,
  // so an absent window is never indistinguishable from a real 0% reading.
  it("renders emptyLabel and no bar-fill when pct is null", () => {
    const { container } = render(UsageBar, {
      props: { label: "5h", pct: null, emptyLabel: "idle" },
    });
    expect(container.textContent).toContain("5h");
    expect(container.textContent).toContain("idle");
    // The percentage text must NOT read "0%" — that would be the exact
    // fabricated-measurement bug this component exists to prevent.
    expect(container.textContent).not.toContain("0%");
    expect(container.querySelector(".bar-fill")).toBeNull();
    expect(
      container.querySelector('[data-testid="usage-bar-empty"]'),
    ).not.toBeNull();
  });

  it("defaults emptyLabel to an em-dash when the caller does not supply one", () => {
    const { container } = render(UsageBar, {
      props: { label: "7d", pct: null },
    });
    expect(container.textContent).toContain("—");
  });

  it("a null pct that is also stale still renders the stale testid, not the empty one", () => {
    const { container } = render(UsageBar, {
      props: { label: "5h", pct: null, stale: true },
    });
    expect(
      container.querySelector('[data-testid="usage-bar-stale"]'),
    ).not.toBeNull();
  });
});
