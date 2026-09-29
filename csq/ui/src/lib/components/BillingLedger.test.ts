import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup } from "@testing-library/svelte";
import { tick } from "svelte";

const mockInvoke = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import BillingLedger from "./BillingLedger.svelte";

function usage(cost = 0.276, unestimated = 2, events = 2) {
  return {
    total_input_tokens: 100,
    total_output_tokens: 200,
    total_cost_usd: cost,
    last_30d_input_tokens: 100,
    last_30d_output_tokens: 200,
    last_30d_cost_usd: cost,
    last_7d_input_tokens: 100,
    last_7d_output_tokens: 200,
    last_7d_cost_usd: cost,
    last_5d_input_tokens: 100,
    last_5d_output_tokens: 200,
    last_5d_cost_usd: cost,
    today_input_tokens: 100,
    today_output_tokens: 200,
    today_cost_usd: cost,
    event_count: events,
    unestimated_cost_count: unestimated,
  };
}

// Cache-inclusive payload (an internal ticket). Every dimension of a window is a DISTINCT
// power-of-two multiple, so omitting any single one of the four yields a
// different total — the totals asserted below therefore pin "each dimension
// counted exactly once" rather than merely "some dimensions counted".
function cacheUsage(overrides: Record<string, number> = {}) {
  return {
    ...usage(0.276, 0, 12),
    total_input_tokens: 11_000_000,
    total_output_tokens: 22_000_000,
    total_cache_creation_tokens: 44_000_000,
    total_cache_read_tokens: 808_000_000,
    last_7d_input_tokens: 1_000_000,
    last_7d_output_tokens: 2_000_000,
    last_7d_cache_creation_tokens: 4_000_000,
    last_7d_cache_read_tokens: 8_000_000,
    last_30d_input_tokens: 10_000_000,
    last_30d_output_tokens: 20_000_000,
    last_30d_cache_creation_tokens: 40_000_000,
    last_30d_cache_read_tokens: 800_000_000,
    last_5d_cache_creation_tokens: 2_000_000,
    last_5d_cache_read_tokens: 3_000_000,
    today_cache_creation_tokens: 1_000_000,
    today_cache_read_tokens: 2_000_000,
    request_count: 10_395,
    duplicate_snapshots_collapsed: 7_526,
    finalization_divergent_requests: 7,
    subagent_request_count: 3_204,
    unidentified_request_count: 1_978,
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

async function settle() {
  for (let i = 0; i < 8; i++) await tick();
}

beforeEach(() => {
  vi.useFakeTimers();
  mockInvoke.mockReset();
  mockInvoke.mockResolvedValue(usage());
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("BillingLedger refresh", () => {
  it("describes missing verified pricing without claiming a known model is unrecognized", async () => {
    // The summary only carries the unpriced count, not model identities or the
    // reason. A known model outside its verified historical epoch has this same
    // payload shape; the component must not invent an unknown-model diagnosis.
    mockInvoke.mockResolvedValue(usage(0, 1, 1));
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    const warning = container.querySelector(".ledger-warn");
    expect(warning?.textContent).toContain(
      "1 request(s) without verified pricing — cost partially n/a",
    );
    expect(warning?.getAttribute("title")).toBe(
      "No verified rate for one or more request models/timestamps; token counts remain available and cost is partial.",
    );
    expect(warning?.textContent).not.toContain("unrecognized model");
    expect(warning?.getAttribute("title")).not.toContain("configured model");
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("300 tokens");
  });

  it("refreshes cost and clears the warning on an unchanged mounted slot after five seconds", async () => {
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.276");
    expect(container.querySelector(".ledger-warn")?.textContent).toContain(
      "2 request(s)",
    );
    mockInvoke.mockResolvedValue(usage(0.753, 0));
    await vi.advanceTimersByTimeAsync(4999);
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    await settle();
    expect(mockInvoke).toHaveBeenCalledTimes(2);
    expect(mockInvoke).toHaveBeenLastCalledWith("get_account_usage", {
      account: 15,
      baseDir: "/private/accounts",
    });
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
    expect(
      container.querySelector('[data-testid="ledger-30d"]')?.textContent,
    ).toContain("$0.753");
    expect(container.querySelector(".ledger-warn")).toBeNull();
  });

  it("does not overlap a pending request across poll ticks and resumes after completion", async () => {
    const pending = deferred<ReturnType<typeof usage>>();
    mockInvoke.mockReturnValueOnce(pending.promise);
    render(BillingLedger, { account: 15, baseDir: "/private/accounts" });
    await settle();
    await vi.advanceTimersByTimeAsync(15000);
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    pending.resolve(usage());
    await settle();
    await vi.advanceTimersByTimeAsync(5000);
    expect(mockInvoke).toHaveBeenCalledTimes(2);
  });

  it.each(["slot", "base"] as const)(
    "discards the old reply on %s change without overlapping IPC",
    async (changed) => {
      const old = deferred<ReturnType<typeof usage>>();
      const next = deferred<ReturnType<typeof usage>>();
      mockInvoke
        .mockReturnValueOnce(old.promise)
        .mockReturnValueOnce(next.promise);
      const { container, rerender } = render(BillingLedger, {
        account: 15,
        baseDir: "/private/accounts",
      });
      await settle();
      const props =
        changed === "slot"
          ? { account: 16, baseDir: "/private/accounts" }
          : { account: 15, baseDir: "/private/other" };
      await rerender(props);
      await settle();
      expect(vi.getTimerCount()).toBe(1);
      await vi.advanceTimersByTimeAsync(5000);
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      old.resolve(usage(99, 99));
      await settle();
      expect(mockInvoke).toHaveBeenCalledTimes(2);
      expect(mockInvoke).toHaveBeenLastCalledWith("get_account_usage", props);
      expect(container.querySelector(".ledger-loading")).not.toBeNull();
      expect(container.textContent).not.toContain("$99");
      next.resolve(usage(0.753, 0));
      await settle();
      expect(
        container.querySelector('[data-testid="ledger-7d"]')?.textContent,
      ).toContain("$0.753");
      expect(container.querySelector(".ledger-warn")).toBeNull();
    },
  );

  it("discards a replaced context error and immediately loads the latest of multiple prop changes", async () => {
    const old = deferred<ReturnType<typeof usage>>();
    mockInvoke
      .mockReturnValueOnce(old.promise)
      .mockResolvedValue(usage(0.753, 0));
    const { container, rerender } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    await rerender({ account: 16, baseDir: "/private/accounts" });
    await rerender({ account: 17, baseDir: "/private/other" });
    old.reject(new Error("old request failed"));
    await settle();
    expect(mockInvoke).toHaveBeenCalledTimes(2);
    expect(mockInvoke).toHaveBeenLastCalledWith("get_account_usage", {
      account: 17,
      baseDir: "/private/other",
    });
    expect(container.querySelector(".ledger-error")).toBeNull();
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
  });

  it("clears a loaded old summary while a new slot is loading", async () => {
    const { container, rerender } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(container.querySelector(".ledger-warn")).not.toBeNull();
    const next = deferred<ReturnType<typeof usage>>();
    mockInvoke.mockReturnValueOnce(next.promise);
    await rerender({ account: 16, baseDir: "/private/accounts" });
    await settle();
    expect(container.querySelector(".ledger-loading")).not.toBeNull();
    expect(container.querySelector(".ledger-warn")).toBeNull();
    expect(container.querySelector('[data-testid="ledger-7d"]')).toBeNull();
    next.resolve(usage(0.753, 0));
    await settle();
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
  });

  it("keeps request exclusion instance-local so one pending slot does not block another", async () => {
    const pending = deferred<ReturnType<typeof usage>>();
    mockInvoke
      .mockReturnValueOnce(pending.promise)
      .mockResolvedValue(usage(0.753, 0));
    render(BillingLedger, { account: 15, baseDir: "/private/accounts" });
    await settle();
    const { container } = render(BillingLedger, {
      account: 16,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(mockInvoke).toHaveBeenCalledTimes(2);
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
    await vi.advanceTimersByTimeAsync(5000);
    expect(mockInvoke).toHaveBeenCalledTimes(3);
    expect(mockInvoke).toHaveBeenLastCalledWith("get_account_usage", {
      account: 16,
      baseDir: "/private/accounts",
    });
    pending.resolve(usage());
    await settle();
  });

  it.each(["resolve", "reject"] as const)(
    "cleans up on destroy and ignores a late %s without restarting polling",
    async (completion) => {
      const pending = deferred<ReturnType<typeof usage>>();
      mockInvoke.mockReturnValueOnce(pending.promise);
      const { container, unmount } = render(BillingLedger, {
        account: 15,
        baseDir: "/private/accounts",
      });
      await settle();
      expect(vi.getTimerCount()).toBe(1);
      unmount();
      await settle();
      expect(vi.getTimerCount()).toBe(0);
      if (completion === "resolve") pending.resolve(usage());
      else pending.reject(new Error("late failure"));
      await settle();
      await vi.advanceTimersByTimeAsync(15000);
      expect(mockInvoke).toHaveBeenCalledTimes(1);
      expect(container.textContent).toBe("");
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it("shows a poll error instead of stale costs and recovers on the next successful poll", async () => {
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    mockInvoke.mockRejectedValueOnce(new Error("ledger unavailable"));
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    expect(container.querySelector(".ledger-error")?.textContent).toContain(
      "usage data unavailable",
    );
    expect(
      container.querySelector(".ledger-error")?.getAttribute("title"),
    ).toContain("ledger unavailable");
    expect(container.querySelector('[data-testid="ledger-7d"]')).toBeNull();
    mockInvoke.mockResolvedValue(usage(0.753, 0));
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    expect(container.querySelector(".ledger-error")).toBeNull();
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
  });

  it("keeps hideWhenEmpty but exposes subsequent errors and populated ledger results", async () => {
    mockInvoke.mockResolvedValue(usage(0, 0, 0));
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
      hideWhenEmpty: true,
    });
    await settle();
    expect(container.querySelector(".billing-ledger")).toBeNull();
    mockInvoke.mockRejectedValueOnce(new Error("ledger unavailable"));
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    expect(container.querySelector(".ledger-error")).not.toBeNull();
    mockInvoke.mockResolvedValue(usage(0.753, 0));
    await vi.advanceTimersByTimeAsync(5000);
    await settle();
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("$0.753");
  });
});

describe("BillingLedger cache-inclusive totals", () => {
  it("counts every cache dimension exactly once in each window total", async () => {
    mockInvoke.mockResolvedValue(cacheUsage());
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();

    // 7d: 1,000,000 new input + 2,000,000 replies + 4,000,000 cache written
    //   + 8,000,000 cache reused = 15,000,000 exactly.
    const sevenDay = container.querySelector('[data-testid="ledger-7d"]');
    expect(sevenDay?.getAttribute("data-total-tokens")).toBe("15000000");
    expect(sevenDay?.textContent).toContain("15.00M tokens");

    // 30d: 10,000,000 + 20,000,000 + 40,000,000 + 800,000,000 = 870,000,000.
    const thirtyDay = container.querySelector('[data-testid="ledger-30d"]');
    expect(thirtyDay?.getAttribute("data-total-tokens")).toBe("870000000");
    expect(thirtyDay?.textContent).toContain("870.00M tokens");
  });

  it("omits no dimension and adds none twice when only cache reads are present", async () => {
    // Guards the double-count direction specifically: with input, output and
    // cache-write at zero, the total must equal the cache-read figure itself —
    // not twice it, and not zero.
    mockInvoke.mockResolvedValue(
      cacheUsage({
        last_7d_input_tokens: 0,
        last_7d_output_tokens: 0,
        last_7d_cache_creation_tokens: 0,
        last_7d_cache_read_tokens: 857_000_000,
      }),
    );
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(
      container
        .querySelector('[data-testid="ledger-7d"]')
        ?.getAttribute("data-total-tokens"),
    ).toBe("857000000");
  });

  it("treats absent cache fields as zero rather than NaN on the pre-upgrade payload", async () => {
    mockInvoke.mockResolvedValue(usage(0.276, 0, 2));
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    const sevenDay = container.querySelector('[data-testid="ledger-7d"]');
    expect(sevenDay?.getAttribute("data-total-tokens")).toBe("300");
    expect(sevenDay?.textContent).not.toContain("NaN");
  });

  it("labels the figure as a local rolling-window estimate and not a provider bill", async () => {
    mockInvoke.mockResolvedValue(cacheUsage());
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    const note = container.querySelector(
      '[data-testid="ledger-estimate-note"]',
    );
    expect(note?.textContent).toContain("Estimated here from this computer's");
    expect(note?.textContent).toContain("rolling");
    expect(note?.textContent).toContain("not a bill from your provider");
    expect(note?.textContent).toContain("Covers 10,395 requests");
    expect(
      container.querySelector('[data-testid="ledger-7d"]')?.textContent,
    ).toContain("cached input included");
  });

  it("reveals the non-overlapping breakdown and coverage counts behind the details toggle", async () => {
    mockInvoke.mockResolvedValue(cacheUsage());
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();

    const toggle = container.querySelector<HTMLButtonElement>(
      '[data-testid="ledger-details-toggle"]',
    );
    expect(toggle?.getAttribute("aria-expanded")).toBe("false");
    expect(
      container.querySelector('[data-testid="ledger-details"]'),
    ).toBeNull();

    toggle?.click();
    await settle();
    expect(toggle?.getAttribute("aria-expanded")).toBe("true");

    const breakdown = container.querySelector('[data-testid="breakdown-7d"]');
    expect(breakdown?.textContent).toContain("new input 1.00M");
    expect(breakdown?.textContent).toContain("replies 2.00M");
    expect(breakdown?.textContent).toContain("cache written 4.00M");
    expect(breakdown?.textContent).toContain("cache reused 8.00M");

    expect(
      container.querySelector('[data-testid="coverage-requests"]')?.textContent,
    ).toContain("10,395 requests counted");
    expect(
      container.querySelector('[data-testid="coverage-subagents"]')
        ?.textContent,
    ).toContain("3,204 of them came from helper sessions");
    expect(
      container.querySelector('[data-testid="coverage-duplicates"]')
        ?.textContent,
    ).toContain("7,526 repeated progress readings were merged");
    expect(
      container.querySelector('[data-testid="coverage-divergent"]')
        ?.textContent,
    ).toContain("7 requests ended on readings that disagreed");
    expect(
      container.querySelector('[data-testid="coverage-unidentified"]')
        ?.textContent,
    ).toContain("1,978 records carried no request id");

    toggle?.click();
    await settle();
    expect(
      container.querySelector('[data-testid="ledger-details"]'),
    ).toBeNull();
  });

  it("renders no coverage line for a count the backend did not report", async () => {
    mockInvoke.mockResolvedValue(usage(0.276, 0, 2));
    const { container } = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    container
      .querySelector<HTMLButtonElement>('[data-testid="ledger-details-toggle"]')
      ?.click();
    await settle();
    expect(
      container.querySelector('[data-testid="ledger-details"]'),
    ).not.toBeNull();
    expect(
      container.querySelector('[data-testid="coverage-requests"]'),
    ).toBeNull();
    expect(
      container.querySelector('[data-testid="coverage-divergent"]'),
    ).toBeNull();
    expect(
      container.querySelector('[data-testid="ledger-estimate-note"]')
        ?.textContent,
    ).not.toContain("Covers");
    expect(container.textContent).not.toContain("undefined");
  });

  it("keeps the loading, empty, error and hideWhenEmpty states intact alongside the new rows", async () => {
    const pending = deferred<ReturnType<typeof cacheUsage>>();
    mockInvoke.mockReturnValueOnce(pending.promise);
    const loading = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(loading.container.querySelector(".ledger-loading")).not.toBeNull();
    expect(
      loading.container.querySelector('[data-testid="ledger-estimate-note"]'),
    ).toBeNull();
    pending.resolve(cacheUsage());
    await settle();
    cleanup();

    mockInvoke.mockReset();
    mockInvoke.mockResolvedValue(usage(0, 0, 0));
    const empty = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(empty.container.querySelector(".ledger-empty")).not.toBeNull();
    expect(
      empty.container.querySelector('[data-testid="ledger-estimate-note"]'),
    ).toBeNull();
    cleanup();

    const hidden = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
      hideWhenEmpty: true,
    });
    await settle();
    expect(hidden.container.querySelector(".billing-ledger")).toBeNull();
    expect(hidden.container.textContent).toBe("");
    cleanup();

    mockInvoke.mockReset();
    mockInvoke.mockRejectedValue(new Error("ledger unavailable"));
    const failed = render(BillingLedger, {
      account: 15,
      baseDir: "/private/accounts",
    });
    await settle();
    expect(
      failed.container.querySelector(".ledger-error")?.textContent,
    ).toContain("usage data unavailable");
    expect(
      failed.container.querySelector('[data-testid="ledger-estimate-note"]'),
    ).toBeNull();
  });
});
