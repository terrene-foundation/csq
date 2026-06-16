import { describe, it, expect } from "vitest";
import { render } from "@testing-library/svelte";
import TokenBadge from "./TokenBadge.svelte";

describe("TokenBadge", () => {
  it("shows time for healthy status", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 7200 },
    });
    expect(container.textContent).toContain("2h");
  });

  it('shows "Expires" prefix for expiring status', () => {
    const { container } = render(TokenBadge, {
      props: { status: "expiring", expiresSecs: 1800 },
    });
    expect(container.textContent).toContain("Expires");
    expect(container.textContent).toContain("30m");
  });

  it('shows "Expired" for expired status', () => {
    const { container } = render(TokenBadge, {
      props: { status: "expired", expiresSecs: -600 },
    });
    expect(container.textContent).toContain("Expired");
  });

  it('shows "No token" for missing status', () => {
    const { container } = render(TokenBadge, {
      props: { status: "missing", expiresSecs: null },
    });
    expect(container.textContent).toContain("No token");
  });

  it("renders a colored dot", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 3600 },
    });
    const dot = container.querySelector(".dot") as HTMLElement;
    expect(dot).toBeTruthy();
    expect(dot.style.background).toContain("--green");
  });

  it("dot is red for expired", () => {
    const { container } = render(TokenBadge, {
      props: { status: "expired", expiresSecs: -100 },
    });
    const dot = container.querySelector(".dot") as HTMLElement;
    expect(dot.style.background).toContain("--red");
  });

  it("formats days for long durations", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 172800 },
    });
    expect(container.textContent).toContain("2d");
  });

  // journal 0062 Q3: the 1h–2h pending-refresh band must read as a live
  // minute countdown, not a static "1h" that looks stuck.
  it("shows minutes (not 1h) through the final 2h band", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 5400 }, // 90 min
    });
    expect(container.textContent).toContain("90m");
    expect(container.textContent).not.toContain("1h");
  });

  it('shows "60m" not "1h" at exactly one hour', () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 3600 },
    });
    expect(container.textContent).toContain("60m");
    expect(container.textContent).not.toContain("1h");
  });

  it("rolls over to hours at exactly 2h", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 7200 },
    });
    expect(container.textContent).toContain("2h");
    expect(container.textContent).not.toContain("m");
  });

  it("shows 119m just below the 2h rollover", () => {
    const { container } = render(TokenBadge, {
      props: { status: "healthy", expiresSecs: 7140 }, // 119 min
    });
    expect(container.textContent).toContain("119m");
  });
});
