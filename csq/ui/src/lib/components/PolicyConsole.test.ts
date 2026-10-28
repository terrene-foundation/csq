import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, cleanup, fireEvent, waitFor } from "@testing-library/svelte";

// ── Tauri IPC mocks ────────────────────────────────────────────────
//
// PolicyConsole calls (all via invoke):
//   policy_preview_active  { baseDir }                                    → PolicyPreview
//   policy_validate_draft  { configJson }                                 → FloorResult
//   policy_create_unsigned { baseDir, schemasJson, configJson, pubkeyHex, bundleVersion, outPath } → void
//   policy_keygen          { baseDir, outDir, force }                     → KeygenResult

const mockInvoke = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

vi.mock("@tauri-apps/api/path", () => ({
  homeDir: () => Promise.resolve("/home/testuser"),
  join: (...parts: string[]) => Promise.resolve(parts.join("/")),
}));

import PolicyConsole from "./PolicyConsole.svelte";
import { buildPublishCommands } from "../utils/policyCommands";

// ── Helpers ──────────────────────────────────────────────────────────
function get(container: HTMLElement, testId: string): HTMLElement | null {
  return container.querySelector(`[data-testid="${testId}"]`);
}

/** Route invoke by command name. Error values cause a rejection. */
function routeByCommand(map: Record<string, unknown>) {
  mockInvoke.mockImplementation((cmd: string) => {
    if (cmd in map) {
      const v = map[cmd];
      return v instanceof Error ? Promise.reject(v) : Promise.resolve(v);
    }
    return Promise.resolve(undefined);
  });
}

// A minimal absent-bundle preview.
const ABSENT_PREVIEW = {
  present: false,
  parseError: null,
  bundleVersion: null,
  formatVersion: null,
  generatedAt: null,
  bundlePubkeyHex: null,
  signatureValid: false,
  floorValid: false,
  floorError: null,
  config: null,
  schemaNames: [],
  schemas: {},
};

// A present bundle with a failing governance floor.
const FLOOR_FAIL_PREVIEW = {
  present: true,
  parseError: null,
  bundleVersion: 3,
  formatVersion: 1,
  generatedAt: "2026-07-15T10:00:00Z",
  bundlePubkeyHex: "aabbcc",
  signatureValid: true,
  floorValid: false,
  floorError: "prohibited_tier",
  config: { risk_tier: "unacceptable", jurisdiction: "DE" },
  schemaNames: ["MySchema"],
  schemas: { MySchema: { type: "object" } },
};

// A fully valid present bundle.
const VALID_PREVIEW = {
  present: true,
  parseError: null,
  bundleVersion: 5,
  formatVersion: 1,
  generatedAt: "2026-07-15T12:00:00Z",
  bundlePubkeyHex: "deadbeef",
  signatureValid: true,
  floorValid: true,
  floorError: null,
  config: { risk_tier: "limited", jurisdiction: "DE", retention_days: 90 },
  schemaNames: ["PromptSchema", "OutputSchema"],
  schemas: {
    PromptSchema: {
      type: "object",
      properties: { prompt: { type: "string" } },
    },
    OutputSchema: {
      type: "object",
      properties: { answer: { type: "string" } },
    },
  },
};

// ── Tests ─────────────────────────────────────────────────────────────
describe("PolicyConsole", () => {
  beforeEach(() => {
    mockInvoke.mockReset();
  });
  afterEach(() => {
    cleanup();
  });

  // ── 1. Absent bundle renders "no bundle" copy ─────────────────────
  it("shows the no-bundle-installed message when present is false", async () => {
    routeByCommand({ policy_preview_active: ABSENT_PREVIEW });

    const { container } = render(PolicyConsole);

    const msg = await waitFor(() => {
      const el = get(container, "no-bundle-message");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(msg.textContent).toContain("No policy bundle is installed yet");
    // Bundle meta must NOT render.
    expect(get(container, "bundle-meta")).toBeNull();
  });

  // ── 2. Floor-fail bundle renders badge + plain-language detail ────
  //    FIX 1: sig-badge-ok must show "Self-consistent (integrity only)",
  //    NOT "Signature intact" / "trusted".
  it("renders integrity-only badge and translated error when floorValid is false", async () => {
    routeByCommand({ policy_preview_active: FLOOR_FAIL_PREVIEW });

    const { container } = render(PolicyConsole);

    // Signature-valid badge must show integrity-only wording (FIX 1).
    const sigOk = await waitFor(() => {
      const el = get(container, "sig-badge-ok");
      expect(el).not.toBeNull();
      return el!;
    });
    // Must use integrity-only wording, NOT the old misleading "Signature intact".
    expect(sigOk.textContent).toContain("Self-consistent (integrity only)");
    expect(sigOk.textContent).not.toContain("Signature intact");
    expect(sigOk.textContent).not.toContain("trusted");

    // The install-time-trust hint must also be rendered (FIX 1).
    const hint = get(container, "sig-integrity-hint");
    expect(hint).not.toBeNull();
    expect(hint!.textContent).toContain("not a trust decision");
    expect(hint!.textContent).toContain("bundle-install");

    // Floor-fail badge.
    const floorBadge = get(container, "floor-badge-fail");
    expect(floorBadge).not.toBeNull();
    expect(floorBadge!.textContent).toContain("Fails governance floor");

    // Plain-language translation of "prohibited_tier".
    const errMsg = get(container, "floor-error-message");
    expect(errMsg).not.toBeNull();
    expect(errMsg!.textContent).toContain("prohibited AI risk tier");
    expect(errMsg!.textContent).toContain("EU AI Act Art. 5");
  });

  // ── 3a. Draft validation: invalid → prohibited_tier message ──────
  it("shows the translated prohibited_tier message on floor check failure", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_validate_draft: {
        valid: false,
        errorTag: "prohibited_tier",
        message: "Risk tier 'unacceptable' is prohibited.",
      },
    });

    const { container } = render(PolicyConsole);

    // Fill in config JSON so the button becomes enabled.
    const configArea = await waitFor(() => {
      const el = get(
        container,
        "draft-config-json",
      ) as HTMLTextAreaElement | null;
      expect(el).not.toBeNull();
      return el!;
    });
    await fireEvent.input(configArea, {
      target: { value: '{"risk_tier":"unacceptable"}' },
    });

    await fireEvent.click(get(container, "check-floor-btn")!);

    const failPanel = await waitFor(() => {
      const el = get(container, "floor-result-fail");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(failPanel.textContent).toContain("Fails the governance floor");

    const detail = get(container, "floor-fail-detail");
    expect(detail).not.toBeNull();
    // Should contain the translated text for prohibited_tier.
    expect(detail!.textContent).toContain("prohibited AI risk tier");
    expect(detail!.textContent).toContain("EU AI Act Art. 5");

    // Pass panel must NOT render.
    expect(get(container, "floor-result-pass")).toBeNull();
  });

  // ── 3b. Draft validation: valid → pass message ───────────────────
  it("shows the governance floor pass message on valid result", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_validate_draft: {
        valid: true,
        errorTag: null,
        message: null,
      },
    });

    const { container } = render(PolicyConsole);

    const configArea = await waitFor(() => {
      const el = get(
        container,
        "draft-config-json",
      ) as HTMLTextAreaElement | null;
      expect(el).not.toBeNull();
      return el!;
    });
    await fireEvent.input(configArea, {
      target: { value: '{"risk_tier":"limited","jurisdiction":"DE"}' },
    });

    await fireEvent.click(get(container, "check-floor-btn")!);

    const passPanel = await waitFor(() => {
      const el = get(container, "floor-result-pass");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(passPanel.textContent).toContain(
      "Passes the EU AI Act / GDPR governance floor",
    );

    // Fail panel must NOT render.
    expect(get(container, "floor-result-fail")).toBeNull();
  });

  // ── 3c. Validate invoke shape: { configJson } with NO formatVersion ─
  //    FIX 3 (AC-2): policy_validate_draft must be invoked with exactly
  //    { configJson } — the formatVersion argument is REMOVED.
  it("invokes policy_validate_draft with { configJson } and no formatVersion key", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_validate_draft: { valid: true, errorTag: null, message: null },
    });

    const { container } = render(PolicyConsole);

    const configArea = await waitFor(() => {
      const el = get(
        container,
        "draft-config-json",
      ) as HTMLTextAreaElement | null;
      expect(el).not.toBeNull();
      return el!;
    });
    const configValue = '{"risk_tier":"limited"}';
    await fireEvent.input(configArea, { target: { value: configValue } });

    await fireEvent.click(get(container, "check-floor-btn")!);

    await waitFor(() => {
      expect(get(container, "floor-result-pass")).not.toBeNull();
    });

    // Find the call to policy_validate_draft.
    const validateCall = mockInvoke.mock.calls.find(
      ([cmd]) => cmd === "policy_validate_draft",
    );
    expect(validateCall).toBeDefined();
    const args = validateCall![1] as Record<string, unknown>;
    // configJson must be present and match.
    expect(args.configJson).toBe(configValue);
    // formatVersion must NOT be present (backend validates internally).
    expect("formatVersion" in args).toBe(false);
  });

  // ── 4. buildPublishCommands unit test ────────────────────────────
  it("buildPublishCommands returns strings containing draftPath and pubkeyHex", () => {
    const opts = {
      draftPath: "/tmp/policy.draft.json",
      signedPath: "/tmp/policy.signed.json",
      pubkeyHex: "deadbeef1234",
      secretKeyPath: "/keys/secret.key",
    };
    const { signCmd, installCmd } = buildPublishCommands(opts);

    // signCmd must contain the draft path.
    expect(signCmd).toContain(opts.draftPath);
    // signCmd must contain the signed output path.
    expect(signCmd).toContain(opts.signedPath);
    // signCmd must contain the secret key path.
    expect(signCmd).toContain(opts.secretKeyPath);

    // installCmd must contain pubkeyHex.
    expect(installCmd).toContain(opts.pubkeyHex);
    // installCmd must contain the signed path.
    expect(installCmd).toContain(opts.signedPath);

    // Both must reference the csq CLI.
    expect(signCmd).toMatch(/^csq /);
    expect(installCmd).toMatch(/^csq /);
  });

  // ── 5a. Export button → success indicator ────────────────────────
  it("shows a success indication after policy_create_unsigned resolves", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_create_unsigned: undefined, // resolves void
    });

    const { container } = render(PolicyConsole);

    // Wait for the export button to appear.
    const exportBtn = await waitFor(() => {
      const el = get(container, "export-draft-btn") as HTMLButtonElement | null;
      expect(el).not.toBeNull();
      return el!;
    });

    // Fill in the output path so the button is enabled.
    const pathInput = get(container, "export-out-path") as HTMLInputElement;
    await fireEvent.input(pathInput, {
      target: { value: "/tmp/test-bundle.draft.json" },
    });

    await fireEvent.click(exportBtn);

    const successMsg = await waitFor(() => {
      const el = get(container, "export-success");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(successMsg.textContent).toContain("/tmp/test-bundle.draft.json");
    // No error should appear.
    expect(get(container, "export-error")).toBeNull();
  });

  // ── 5b. Export button → policy_create_failed → plain-language error ──
  it("renders the plain-language error when policy_create_unsigned rejects with policy_create_failed", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_create_unsigned: new Error("policy_create_failed"),
    });

    const { container } = render(PolicyConsole);

    const exportBtn = await waitFor(() => {
      const el = get(container, "export-draft-btn") as HTMLButtonElement | null;
      expect(el).not.toBeNull();
      return el!;
    });

    const pathInput = get(container, "export-out-path") as HTMLInputElement;
    await fireEvent.input(pathInput, {
      target: { value: "/tmp/test-bundle.draft.json" },
    });

    await fireEvent.click(exportBtn);

    const errMsg = await waitFor(() => {
      const el = get(container, "export-error");
      expect(el).not.toBeNull();
      return el!;
    });
    // Should be the translated message, not the raw tag.
    expect(errMsg!.textContent).toContain("could not be written");
    // No success message.
    expect(get(container, "export-success")).toBeNull();
  });

  // ── 5c. Export with config → configJson is passed (FIX 2, AC-1) ──
  //    The Author panel's configJson must be sent to policy_create_unsigned.
  it("passes the authored configJson to policy_create_unsigned when non-empty", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_create_unsigned: undefined,
    });

    const { container } = render(PolicyConsole);

    // Fill config textarea.
    const configArea = await waitFor(() => {
      const el = get(
        container,
        "draft-config-json",
      ) as HTMLTextAreaElement | null;
      expect(el).not.toBeNull();
      return el!;
    });
    const configValue = '{"risk_tier":"limited","jurisdiction":"DE"}';
    await fireEvent.input(configArea, { target: { value: configValue } });

    // Fill export path and click export.
    const pathInput = get(container, "export-out-path") as HTMLInputElement;
    await fireEvent.input(pathInput, {
      target: { value: "/tmp/test-bundle.draft.json" },
    });

    await fireEvent.click(get(container, "export-draft-btn")!);

    await waitFor(() => {
      expect(get(container, "export-success")).not.toBeNull();
    });

    // Verify policy_create_unsigned was called with the config.
    const createCall = mockInvoke.mock.calls.find(
      ([cmd]) => cmd === "policy_create_unsigned",
    );
    expect(createCall).toBeDefined();
    const args = createCall![1] as Record<string, unknown>;
    // configJson must match the entered text.
    expect(args.configJson).toBe(configValue);
  });

  // ── 5d. Export rejects with floor tag → shows translated message (FIX 4) ──
  //    When policy_create_unsigned rejects with a specific floor tag,
  //    the error message must show the translated governance reason,
  //    NOT a generic create-failed message.
  it("shows the specific floor-tag error message when policy_create_unsigned rejects with prohibited_tier", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_create_unsigned: new Error("prohibited_tier"),
    });

    const { container } = render(PolicyConsole);

    const exportBtn = await waitFor(() => {
      const el = get(container, "export-draft-btn") as HTMLButtonElement | null;
      expect(el).not.toBeNull();
      return el!;
    });

    const pathInput = get(container, "export-out-path") as HTMLInputElement;
    await fireEvent.input(pathInput, {
      target: { value: "/tmp/test-bundle.draft.json" },
    });

    await fireEvent.click(exportBtn);

    const errMsg = await waitFor(() => {
      const el = get(container, "export-error");
      expect(el).not.toBeNull();
      return el!;
    });
    // Must show the translated prohibited_tier text.
    expect(errMsg!.textContent).toContain("prohibited AI risk tier");
    expect(errMsg!.textContent).toContain("EU AI Act Art. 5");
    // Must NOT show the generic create-failed text.
    expect(errMsg!.textContent).not.toContain("could not be written");
    // No success message.
    expect(get(container, "export-success")).toBeNull();
  });

  // ── 5e. Export rejects with policy_path_rejected → translated message ──
  it("shows 'outside the allowed policy directory' when policy_create_unsigned rejects with policy_path_rejected", async () => {
    routeByCommand({
      policy_preview_active: ABSENT_PREVIEW,
      policy_create_unsigned: new Error("policy_path_rejected"),
    });

    const { container } = render(PolicyConsole);

    const exportBtn = await waitFor(() => {
      const el = get(container, "export-draft-btn") as HTMLButtonElement | null;
      expect(el).not.toBeNull();
      return el!;
    });

    const pathInput = get(container, "export-out-path") as HTMLInputElement;
    await fireEvent.input(pathInput, {
      target: { value: "/etc/policy-bundle.draft.json" },
    });

    await fireEvent.click(exportBtn);

    const errMsg = await waitFor(() => {
      const el = get(container, "export-error");
      expect(el).not.toBeNull();
      return el!;
    });
    expect(errMsg!.textContent).toContain(
      "outside the allowed policy directory",
    );
  });

  // ── 6. Valid bundle shows integrity-only badge + floor-pass badge ─
  //    FIX 1: sig-badge-ok must say "Self-consistent (integrity only)",
  //    not "Signature intact". Floor badge stays green / "ok".
  it("renders integrity-only sig badge and floor-pass badge for a fully valid bundle", async () => {
    routeByCommand({ policy_preview_active: VALID_PREVIEW });

    const { container } = render(PolicyConsole);

    await waitFor(() => {
      expect(get(container, "sig-badge-ok")).not.toBeNull();
    });

    // FIX 1: must NOT say "Signature intact" (old misleading text).
    const sigBadge = get(container, "sig-badge-ok")!;
    expect(sigBadge.textContent).toContain("Self-consistent (integrity only)");
    expect(sigBadge.textContent).not.toContain("Signature intact");
    expect(sigBadge.textContent).not.toContain("trusted");

    // The trust hint must be present.
    const hint = get(container, "sig-integrity-hint");
    expect(hint).not.toBeNull();
    expect(hint!.textContent).toContain("not a trust decision");

    // Floor-pass badge should still be styled as ok/green.
    expect(get(container, "floor-badge-ok")).not.toBeNull();
    expect(get(container, "floor-badge-ok")!.textContent).toContain(
      "Passes EU governance floor",
    );

    // Floor error message must NOT render when floor is valid.
    expect(get(container, "floor-error-message")).toBeNull();

    // Schema names should be visible.
    const schemaNames = get(container, "schema-names");
    expect(schemaNames).not.toBeNull();
    expect(schemaNames!.textContent).toContain("PromptSchema");
    expect(schemaNames!.textContent).toContain("OutputSchema");
  });

  // ── 7. preview loading state ─────────────────────────────────────
  it("shows a loading indicator while the preview is fetching", () => {
    // Never resolve — just check the initial loading state.
    mockInvoke.mockImplementation(() => new Promise(() => {}));

    const { container } = render(PolicyConsole);

    expect(get(container, "preview-loading")).not.toBeNull();
  });

  // ── 8. preview error state ───────────────────────────────────────
  it("shows a plain-language error when policy_preview_active rejects", async () => {
    routeByCommand({
      policy_preview_active: new Error("policy_bundle_absent"),
    });

    const { container } = render(PolicyConsole);

    await waitFor(() => {
      expect(get(container, "preview-error")).not.toBeNull();
    });
    // Should translate the tag, not show raw "policy_bundle_absent".
    expect(get(container, "preview-error")!.textContent).toContain(
      "No policy bundle",
    );
  });

  // ── 9. format-version input is gone (FIX 3, AC-2) ───────────────
  it("does not render a format-version input field", async () => {
    routeByCommand({ policy_preview_active: ABSENT_PREVIEW });

    const { container } = render(PolicyConsole);

    // Wait for the component to settle.
    await waitFor(() => {
      expect(get(container, "no-bundle-message")).not.toBeNull();
    });

    // The format-version field must not exist.
    expect(get(container, "draft-format-version")).toBeNull();
  });
});
