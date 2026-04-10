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
});
