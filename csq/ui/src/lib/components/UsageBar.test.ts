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
});
