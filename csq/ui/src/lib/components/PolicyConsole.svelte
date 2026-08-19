<script lang="ts">
  // ── Policy Bundle Admin Console (an internal ticket AC#3) ──────────────────────────
  //
  // Compliance-admin surface for managing EU AI Act / GDPR policy bundles.
  // Enterprise-only: this component is only mounted when `isEnterprise` is
  // true (App.svelte gating). All invoke calls are Tauri commands stripped
  // from the community build.
  //
  // Responsibilities:
  //   • Show the active policy bundle (version, integrity, governance floor).
  //   • Let the admin author + floor-validate a new draft.
  //   • Export an unsigned draft and generate/display signing keypair info.
  //   • Render copy-ready CLI commands for offline signing + installation.

  import { invoke } from "@tauri-apps/api/core";
  import { untrack } from "svelte";
  import { homeDir, join } from "@tauri-apps/api/path";
  import { buildPublishCommands } from "../utils/policyCommands";

  // ── Types (mirrors Rust command return shapes) ────────────────────────
  interface PolicyPreview {
    present: boolean;
    parseError: string | null;
    bundleVersion: number | null;
    formatVersion: number | null;
    generatedAt: string | null;
    bundlePubkeyHex: string | null;
    signatureValid: boolean;
    floorValid: boolean;
    floorError: string | null;
    config: unknown | null;
    schemaNames: string[];
    schemas: Record<string, unknown>;
  }

  interface FloorResult {
    valid: boolean;
    errorTag: string | null;
    message: string | null;
  }

  interface KeygenResult {
    pubkeyHex: string;
    secretPath: string;
    publicPath: string;
  }

  // ── Fixed-vocabulary error tag → plain-language messages ─────────────
  // (rules/tauri-commands.md MUST Rule 6: every named error maps to
  // actionable UI text; unknown tags fall back to a generic form.)
  // Every tag below is emitted verbatim by the Rust commands in
  // `csq/src/desktop/commands/policy.rs` (`error_tag()` + the command Err
  // arms). Keep this table in lockstep with that source — no invented tags.
  const POLICY_ERROR_TEXT: Record<string, string> = {
    // Command / plumbing errors (thrown as Err by the Tauri commands)
    policy_bundle_absent: "No policy bundle is installed yet.",
    policy_bundle_too_large:
      "The policy bundle file is too large to read (over 16 MiB).",
    policy_bundle_io_error:
      "The policy bundle file could not be read. Check the file and try again.",
    policy_bundle_corrupt:
      "The policy bundle file is not valid — it may be corrupt or was edited by hand.",
    policy_config_parse_error:
      "The governance config JSON is not valid — check the syntax and try again.",
    policy_create_failed:
      "The draft could not be written. Check the schemas JSON and the output path, then try again.",
    policy_path_rejected:
      "The output path is outside the allowed policy directory.",
    policy_keygen_failed:
      "Key generation failed. Ensure the output directory exists and is writable.",
    // Signature / rollback (surfaced on the installed bundle's preview)
    policy_signature_missing:
      "The installed bundle has no signature file — it cannot be trusted.",
    policy_signature_invalid:
      "The installed bundle's signature is invalid — the file may have been tampered with.",
    policy_format_too_new:
      "The installed bundle uses a newer format than this version of csq understands. Update csq.",
    policy_rollback_rejected:
      "The bundle version is older than the currently installed one — rollback is blocked.",
    // Governance-floor violations (EU AI Act / GDPR)
    prohibited_tier:
      "This policy declares a prohibited AI risk tier (EU AI Act Art. 5) — not allowed.",
    no_declared_purpose:
      "No processing purpose is declared (GDPR Art. 5(1)(b)). State at least one purpose.",
    unrecognized_tier:
      "The AI risk tier is not one of the recognised values (prohibited / high / limited / minimal).",
    missing_art9_lawful_basis:
      "Special-category data is processed but no GDPR Art. 9 lawful basis is set.",
    missing_art10_lawful_basis:
      "Criminal-conviction data is processed but no GDPR Art. 10 lawful basis is set.",
  };

  function policyErrorText(tag: string | null | undefined): string {
    if (!tag) return "Something went wrong.";
    return POLICY_ERROR_TEXT[tag] ?? `Something went wrong (${tag}).`;
  }

  function floorErrorText(errorTag: string | null, message: string | null): string {
    if (errorTag && POLICY_ERROR_TEXT[errorTag]) return POLICY_ERROR_TEXT[errorTag];
    if (message) return message;
    if (errorTag) return `Governance check failed (${errorTag}).`;
    return "Governance check failed.";
  }

  function asTag(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  async function getBaseDir(): Promise<string> {
    const home = await homeDir();
    return join(home, ".claude", "accounts");
  }

  function prettyJson(val: unknown): string {
    try {
      return JSON.stringify(val, null, 2);
    } catch {
      return String(val);
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }

  // ── Reactive state: Active policy panel ──────────────────────────────
  let preview = $state<PolicyPreview | null>(null);
  let previewError = $state<string | null>(null);
  let previewBusy = $state(false);
  let expandedSchemas = $state<Set<string>>(new Set());

  // ── Reactive state: Author panel ─────────────────────────────────────
  let draftSchemasJson = $state("");
  let draftConfigJson = $state("");
  let floorResult = $state<FloorResult | null>(null);
  let floorBusy = $state(false);
  let floorError = $state<string | null>(null);

  // ── Reactive state: Export & publish panel ───────────────────────────
  let exportOutPath = $state("");
  let exportBusy = $state(false);
  let exportError = $state<string | null>(null);
  let exportSuccess = $state(false);

  let keygenBusy = $state(false);
  let keygenError = $state<string | null>(null);
  let keygenResult = $state<KeygenResult | null>(null);

  // Publish command state (derived from keygen output + user-entered paths)
  let publishSignedPath = $state("");
  let copiedSign = $state(false);
  let copiedInstall = $state(false);

  // ── Derived: publish commands ─────────────────────────────────────────
  let publishCommands = $derived(
    keygenResult && exportOutPath && publishSignedPath
      ? buildPublishCommands({
          draftPath: exportOutPath,
          signedPath: publishSignedPath,
          pubkeyHex: keygenResult.pubkeyHex,
          secretKeyPath: keygenResult.secretPath,
        })
      : null,
  );

  // ── On mount: load active policy ─────────────────────────────────────
  // svelte-patterns Rule 3 + Rule 5: effect returns cleanup; reads no
  // state that could cause self-invalidation.
  $effect(() => {
    let cancelled = false;
    previewBusy = true;
    previewError = null;
    (async () => {
      try {
        const base = await getBaseDir();
        const result = await invoke<PolicyPreview>("policy_preview_active", {
          baseDir: base,
        });
        if (!cancelled) {
          preview = result;
        }
      } catch (e) {
        if (!cancelled) {
          previewError = policyErrorText(asTag(e));
        }
      } finally {
        if (!cancelled) previewBusy = false;
      }
    })();
    return () => {
      cancelled = true;
    };
  });

  // ── Set default export path once preview resolves ────────────────────
  // Reads `preview` to know when it has populated. Reads+writes
  // exportOutPath/publishSignedPath inside untrack so the effect does NOT
  // self-invalidate (svelte-patterns Rule 5). A cancelled flag guards the
  // async .then() (Rule 3).
  $effect(() => {
    if (preview === null) return;
    let cancelled = false;
    if (untrack(() => exportOutPath) === "") {
      getBaseDir()
        .then((base) => {
          if (!cancelled) {
            untrack(() => {
              if (exportOutPath === "") {
                exportOutPath = `${base}/phase2b/policy-bundle.draft.json`;
                publishSignedPath = `${base}/phase2b/policy-bundle.signed.json`;
              }
            });
          }
        })
        .catch(() => {});
    }
    return () => {
      cancelled = true;
    };
  });

  // ── Actions ───────────────────────────────────────────────────────────
  async function checkFloor() {
    if (floorBusy) return;
    floorBusy = true;
    floorResult = null;
    floorError = null;
    try {
      const result = await invoke<FloorResult>("policy_validate_draft", {
        configJson: draftConfigJson,
      });
      floorResult = result;
    } catch (e) {
      floorError = policyErrorText(asTag(e));
    } finally {
      floorBusy = false;
    }
  }

  async function exportDraft() {
    if (exportBusy) return;
    exportBusy = true;
    exportError = null;
    exportSuccess = false;
    try {
      const base = await getBaseDir();
      await invoke<void>("policy_create_unsigned", {
        baseDir: base,
        schemasJson: draftSchemasJson,
        configJson: draftConfigJson.trim() === "" ? null : draftConfigJson,
        pubkeyHex: keygenResult?.pubkeyHex ?? "",
        bundleVersion: null,
        outPath: exportOutPath,
      });
      exportSuccess = true;
    } catch (e) {
      // Map specific floor tags (e.g. prohibited_tier) and plumbing tags
      // (policy_path_rejected, policy_config_parse_error) through the same
      // lookup used for floor validation results — FIX 4 (FM-1).
      exportError = policyErrorText(asTag(e));
    } finally {
      exportBusy = false;
    }
  }

  async function generateKey() {
    if (keygenBusy) return;
    keygenBusy = true;
    keygenError = null;
    keygenResult = null;
    try {
      const base = await getBaseDir();
      const result = await invoke<KeygenResult>("policy_keygen", {
        baseDir: base,
        outDir: null,
        force: false,
      });
      keygenResult = result;
    } catch (e) {
      keygenError = policyErrorText(asTag(e));
    } finally {
      keygenBusy = false;
    }
  }

  async function copyToClipboard(text: string, which: "sign" | "install") {
    try {
      await navigator.clipboard.writeText(text);
      if (which === "sign") {
        copiedSign = true;
        setTimeout(() => {
          copiedSign = false;
        }, 1800);
      } else {
        copiedInstall = true;
        setTimeout(() => {
          copiedInstall = false;
        }, 1800);
      }
    } catch {
      // clipboard API unavailable in some contexts — silent
    }
  }

  function toggleSchema(name: string) {
    const next = new Set(expandedSchemas);
    if (next.has(name)) {
      next.delete(name);
    } else {
      next.add(name);
    }
    expandedSchemas = next;
  }
</script>

<div class="console" data-testid="policy-console" role="region" aria-label="Policy Bundle Admin Console">
  <div class="head">
    <h2>Policy Bundles</h2>
    <p class="subtitle">
      Manage EU AI Act / GDPR governance policy bundles for this installation.
    </p>
  </div>

  <!-- ── Active policy panel ─────────────────────────────────────── -->
  <section aria-labelledby="active-policy-heading">
    <h3 id="active-policy-heading">Active policy</h3>

    {#if previewBusy}
      <p class="hint" data-testid="preview-loading">Loading…</p>
    {:else if previewError}
      <p class="error" role="alert" data-testid="preview-error">{previewError}</p>
    {:else if preview !== null}
      {#if !preview.present}
        <p class="hint" data-testid="no-bundle-message">
          No policy bundle is installed yet.
        </p>
      {:else}
        <div class="bundle-meta" data-testid="bundle-meta">
          <div class="meta-row">
            <span class="meta-label">Bundle version</span>
            <span class="meta-value">{preview.bundleVersion ?? "—"}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Format version</span>
            <span class="meta-value">{preview.formatVersion ?? "—"}</span>
          </div>
          <div class="meta-row">
            <span class="meta-label">Generated at</span>
            <span class="meta-value">{formatDate(preview.generatedAt)}</span>
          </div>

          <!-- Signature integrity badge -->
          <!-- FIX 1 (SIG-1): policy_preview_active verifies the bundle against
               its OWN embedded pubkey — this is an INTEGRITY check, NOT a
               trust-anchor verdict. A neutral badge with an explicit hint
               prevents a compliance admin from reading "Signature intact" as
               "this bundle is trusted". Trust is established at install time
               via `bundle-install --pubkey <your key>`. -->
          <div class="meta-row sig-meta-row">
            <span class="meta-label">Signature</span>
            {#if preview.signatureValid}
              <span class="badge neutral" data-testid="sig-badge-ok">Self-consistent (integrity only)</span>
            {:else}
              <span class="badge fail" data-testid="sig-badge-fail">Signature INVALID</span>
            {/if}
          </div>
          {#if preview.signatureValid}
            <p class="sig-integrity-hint" data-testid="sig-integrity-hint">
              Confirms the file matches its own embedded key — this is not a trust decision.
              Trust is established at install time via <code>bundle-install --pubkey &lt;your key&gt;</code>.
            </p>
          {/if}

          <!-- Governance floor badge -->
          <div class="meta-row">
            <span class="meta-label">Governance floor</span>
            {#if preview.floorValid}
              <span class="badge ok" data-testid="floor-badge-ok">
                Passes EU governance floor
              </span>
            {:else}
              <span class="badge fail" data-testid="floor-badge-fail">
                Fails governance floor
              </span>
            {/if}
          </div>

          {#if !preview.floorValid && preview.floorError}
            <p class="floor-error" role="alert" data-testid="floor-error-message">
              {floorErrorText(preview.floorError, null)}
            </p>
          {/if}

          <!-- Governance config -->
          {#if preview.config !== null}
            <div class="config-block" data-testid="governance-config">
              <p class="block-label">Governance configuration</p>
              <pre class="code-pre">{prettyJson(preview.config)}</pre>
            </div>
          {/if}

          <!-- Schema names -->
          {#if preview.schemaNames.length > 0}
            <div class="schemas-block" data-testid="schema-names">
              <p class="block-label">
                Enforced schemas ({preview.schemaNames.length})
              </p>
              <ul class="schema-list">
                {#each preview.schemaNames as name (name)}
                  <li>
                    <button
                      class="schema-toggle link"
                      onclick={() => toggleSchema(name)}
                      aria-expanded={expandedSchemas.has(name)}
                      aria-controls="schema-body-{name}"
                    >
                      {name}
                      <span class="toggle-icon"
                        >{expandedSchemas.has(name) ? "▲" : "▼"}</span
                      >
                    </button>
                    {#if expandedSchemas.has(name)}
                      <pre
                        id="schema-body-{name}"
                        class="code-pre schema-body"
                        data-testid="schema-body-{name}"
                      >{prettyJson(preview.schemas[name])}</pre>
                    {/if}
                  </li>
                {/each}
              </ul>
            </div>
          {/if}
        </div>
      {/if}
    {/if}
  </section>

  <!-- ── Author a new version panel ─────────────────────────────── -->
  <section aria-labelledby="author-heading">
    <h3 id="author-heading">Author a new version</h3>
    <p class="hint">
      Paste your schemas and governance config, then check it against the
      EU AI Act / GDPR governance floor before exporting.
    </p>

    <div class="field">
      <label for="draft-schemas-json">
        Schemas JSON
      </label>
      <textarea
        id="draft-schemas-json"
        data-testid="draft-schemas-json"
        bind:value={draftSchemasJson}
        rows="6"
        placeholder="Paste schemas JSON here, e.g. MySchema: type object ..."
      ></textarea>
    </div>

    <div class="field">
      <label for="draft-config-json">
        Governance config JSON
      </label>
      <textarea
        id="draft-config-json"
        data-testid="draft-config-json"
        bind:value={draftConfigJson}
        rows="6"
        placeholder="Paste governance config JSON here, e.g. jurisdiction, risk_tier, retention_days ..."
      ></textarea>
    </div>

    <!-- Governance floor validation — headline feature -->
    <div class="floor-check-area" data-testid="floor-check-area">
      <button
        class="primary"
        data-testid="check-floor-btn"
        onclick={checkFloor}
        disabled={floorBusy || draftConfigJson.trim() === ""}
      >
        {floorBusy ? "Checking…" : "Check against governance floor"}
      </button>

      {#if floorError}
        <p class="error" role="alert" data-testid="floor-call-error">{floorError}</p>
      {/if}

      {#if floorResult !== null}
        {#if floorResult.valid}
          <div class="floor-pass" role="status" data-testid="floor-result-pass">
            <span class="badge ok large">
              Passes the EU AI Act / GDPR governance floor
            </span>
          </div>
        {:else}
          <div class="floor-fail" role="alert" data-testid="floor-result-fail">
            <span class="badge fail large">
              Fails the governance floor
            </span>
            <p class="floor-fail-detail" data-testid="floor-fail-detail">
              {floorErrorText(floorResult.errorTag, floorResult.message)}
            </p>
          </div>
        {/if}
      {/if}
    </div>
  </section>

  <!-- ── Export & publish panel ──────────────────────────────────── -->
  <section aria-labelledby="export-heading">
    <h3 id="export-heading">Export &amp; publish</h3>

    <!-- Export unsigned draft -->
    <div class="field">
      <label for="export-out-path">Draft output path</label>
      <input
        id="export-out-path"
        data-testid="export-out-path"
        type="text"
        bind:value={exportOutPath}
        placeholder="/path/to/policy-bundle.draft.json"
      />
    </div>

    <button
      class="primary"
      data-testid="export-draft-btn"
      onclick={exportDraft}
      disabled={exportBusy || exportOutPath.trim() === ""}
    >
      {exportBusy ? "Exporting…" : "Export unsigned draft"}
    </button>

    {#if exportError}
      <p class="error" role="alert" data-testid="export-error">{exportError}</p>
    {/if}
    {#if exportSuccess}
      <p class="success" role="status" data-testid="export-success">
        Draft exported to <code>{exportOutPath}</code>.
      </p>
    {/if}

    <!-- Generate signing key -->
    <div class="keygen-area" data-testid="keygen-area">
      <button
        class="secondary"
        data-testid="keygen-btn"
        onclick={generateKey}
        disabled={keygenBusy}
      >
        {keygenBusy ? "Generating…" : "Generate signing key"}
      </button>

      {#if keygenError}
        <p class="error" role="alert" data-testid="keygen-error">{keygenError}</p>
      {/if}

      {#if keygenResult !== null}
        <div class="keygen-result" data-testid="keygen-result">
          <div class="meta-row">
            <span class="meta-label">Public key (hex)</span>
            <code class="pubkey" data-testid="keygen-pubkey">{keygenResult.pubkeyHex}</code>
          </div>
          <div class="meta-row">
            <span class="meta-label">Public key file</span>
            <code data-testid="keygen-public-path">{keygenResult.publicPath}</code>
          </div>
          <div class="meta-row">
            <span class="meta-label">Secret key file</span>
            <code data-testid="keygen-secret-path">{keygenResult.secretPath}</code>
          </div>
          <p class="hint">
            Keep your secret key file secure and off shared machines.
            Never share it. The public key hex is safe to share.
          </p>
        </div>
      {/if}
    </div>

    <!-- Publish (run on your secure machine) -->
    <div class="publish-area" data-testid="publish-area">
      <h4>Publish (run on your secure machine)</h4>
      <p class="hint">
        Signing uses your Ed25519 secret key and installing appends an audit
        record — run these on your secure machine via the CLI.
      </p>

      <div class="field">
        <label for="publish-signed-path">Signed bundle output path</label>
        <input
          id="publish-signed-path"
          data-testid="publish-signed-path"
          type="text"
          bind:value={publishSignedPath}
          placeholder="/path/to/policy-bundle.signed.json"
        />
      </div>

      {#if publishCommands !== null}
        <div class="cmd-block" data-testid="sign-cmd-block">
          <p class="cmd-label">1. Sign the draft</p>
          <div class="cmd-row">
            <code class="cmd-text" data-testid="sign-cmd">{publishCommands.signCmd}</code>
            <button
              class="copy-btn"
              data-testid="copy-sign-btn"
              onclick={() => copyToClipboard(publishCommands!.signCmd, "sign")}
              aria-label="Copy sign command"
            >
              {copiedSign ? "Copied!" : "Copy"}
            </button>
          </div>
        </div>

        <div class="cmd-block" data-testid="install-cmd-block">
          <p class="cmd-label">2. Install on the target machine</p>
          <div class="cmd-row">
            <code class="cmd-text" data-testid="install-cmd">{publishCommands.installCmd}</code>
            <button
              class="copy-btn"
              data-testid="copy-install-btn"
              onclick={() => copyToClipboard(publishCommands!.installCmd, "install")}
              aria-label="Copy install command"
            >
              {copiedInstall ? "Copied!" : "Copy"}
            </button>
          </div>
        </div>
      {:else}
        <p class="hint">
          Generate a signing key and fill in the paths above to see the
          copy-ready CLI commands.
        </p>
      {/if}
    </div>
  </section>
</div>

<style>
  .console {
    max-width: 720px;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .head {
    margin-bottom: 1rem;
  }

  h2 {
    font-size: 1rem;
    margin: 0 0 0.25rem;
  }

  h3 {
    font-size: 0.85rem;
    font-weight: 600;
    margin: 0 0 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: var(--text-secondary);
  }

  h4 {
    font-size: 0.8rem;
    font-weight: 600;
    margin: 1rem 0 0.35rem;
  }

  .subtitle {
    margin: 0;
    font-size: 0.8rem;
    color: var(--text-secondary);
  }

  section {
    padding: 1rem 0;
    border-top: 1px solid var(--border);
  }

  .hint {
    color: var(--text-secondary);
    font-size: 0.82rem;
    margin: 0 0 0.75rem;
    line-height: 1.5;
  }

  .error {
    color: var(--danger, #c0392b);
    font-size: 0.85rem;
    margin: 0.5rem 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-left: 3px solid var(--danger, #c0392b);
    border-radius: 3px;
  }

  .success {
    color: var(--success, #27ae60);
    font-size: 0.85rem;
    margin: 0.5rem 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-left: 3px solid var(--success, #27ae60);
    border-radius: 3px;
  }

  /* ── Bundle meta grid ─────────────────────── */
  .bundle-meta {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .meta-row {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    font-size: 0.83rem;
  }

  .meta-label {
    color: var(--text-secondary);
    min-width: 130px;
    flex-shrink: 0;
    font-size: 0.78rem;
  }

  .meta-value {
    color: var(--text-primary);
  }

  /* ── Badges ─────────────────────────────────── */
  .badge {
    display: inline-flex;
    align-items: center;
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    padding: 0.15rem 0.55rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-secondary);
  }

  .badge.ok {
    color: var(--success, #27ae60);
    border-color: var(--success, #27ae60);
    background: transparent;
  }

  /* Neutral badge — used for integrity-only checks that are not trust verdicts */
  .badge.neutral {
    color: var(--text-secondary);
    border-color: var(--border);
    background: var(--bg-secondary);
  }

  .sig-integrity-hint {
    font-size: 0.78rem;
    color: var(--text-secondary);
    margin: 0.2rem 0 0.4rem 130px; /* align under the badge, past the label column */
    line-height: 1.5;
  }

  .sig-meta-row {
    align-items: flex-start;
  }

  .badge.fail {
    color: var(--danger, #c0392b);
    border-color: var(--danger, #c0392b);
    background: transparent;
  }

  .badge.large {
    font-size: 0.82rem;
    padding: 0.3rem 0.8rem;
  }

  /* ── Code blocks ─────────────────────────────── */
  .code-pre {
    font-size: 0.78rem;
    margin: 0.3rem 0 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    overflow-x: auto;
    max-height: 200px;
    white-space: pre;
    word-break: break-all;
  }

  .config-block,
  .schemas-block {
    margin-top: 0.75rem;
  }

  .block-label {
    font-size: 0.78rem;
    color: var(--text-secondary);
    font-weight: 600;
    margin: 0 0 0.2rem;
  }

  .schema-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }

  .schema-toggle {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    font: inherit;
    font-size: 0.82rem;
    background: transparent;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    padding: 0.1rem 0;
    text-align: left;
  }

  .schema-toggle:hover {
    color: var(--accent, #2d7dd2);
  }

  .toggle-icon {
    font-size: 0.65rem;
    color: var(--text-secondary);
  }

  .schema-body {
    margin-top: 0.2rem;
  }

  .floor-error {
    margin: 0.4rem 0 0;
    font-size: 0.82rem;
    color: var(--danger, #c0392b);
  }

  /* ── Author panel ─────────────────────────────── */
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 0.65rem;
  }

  label {
    font-size: 0.8rem;
    color: var(--text-secondary);
    font-weight: 500;
  }

  textarea {
    width: 100%;
    box-sizing: border-box;
    font: inherit;
    font-size: 0.82rem;
    font-family: monospace;
    padding: 0.45rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
    resize: vertical;
  }

  input[type="text"] {
    font: inherit;
    font-size: 0.82rem;
    padding: 0.4rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg-primary);
    color: var(--text-primary);
  }

  input[type="text"] {
    width: 100%;
    box-sizing: border-box;
  }

  .floor-check-area {
    margin-top: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .floor-pass,
  .floor-fail {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    margin-top: 0.35rem;
  }

  .floor-fail-detail {
    font-size: 0.83rem;
    color: var(--danger, #c0392b);
    margin: 0;
    padding: 0.4rem 0.6rem;
    background: var(--bg-secondary);
    border-left: 3px solid var(--danger, #c0392b);
    border-radius: 3px;
  }

  /* ── Export panel ─────────────────────────────── */
  .keygen-area {
    margin-top: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .keygen-result {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    margin-top: 0.35rem;
    padding: 0.6rem;
    background: var(--bg-secondary);
    border-radius: 4px;
    border: 1px solid var(--border);
  }

  .pubkey {
    font-size: 0.75rem;
    word-break: break-all;
  }

  .publish-area {
    margin-top: 1rem;
  }

  .cmd-block {
    margin-bottom: 0.75rem;
  }

  .cmd-label {
    font-size: 0.78rem;
    color: var(--text-secondary);
    font-weight: 600;
    margin: 0 0 0.25rem;
  }

  .cmd-row {
    display: flex;
    align-items: stretch;
    gap: 0.4rem;
  }

  .cmd-text {
    flex: 1;
    font-size: 0.78rem;
    padding: 0.4rem 0.55rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 4px;
    word-break: break-all;
    white-space: pre-wrap;
    font-family: monospace;
  }

  .copy-btn {
    font: inherit;
    font-size: 0.78rem;
    padding: 0.3rem 0.7rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .copy-btn:hover {
    background: var(--bg-tertiary, rgba(255, 255, 255, 0.06));
  }

  /* ── Shared button styles ──────────────────────── */
  button {
    font: inherit;
    font-size: 0.85rem;
    padding: 0.4rem 0.85rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button.primary {
    background: var(--accent);
    border-color: var(--accent);
    /* i-audit sweep — white-on-accent measured 2.21:1 in the default
       dark theme (WCAG AA needs 4.5:1). var(--bg-primary) flips per
       theme and clears AA on both (dark 7.93:1, light 6.20:1) — same
       fix as an internal ticket's AddAccountModal .actions button.primary. */
    color: var(--bg-primary);
  }

  button.secondary {
    background: transparent;
    border-color: var(--border);
    color: var(--text-primary);
  }

  button.link {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    padding: 0;
    font-size: 0.82rem;
    text-decoration: underline;
    cursor: pointer;
  }

  code {
    font-family: monospace;
    font-size: 0.8rem;
  }
</style>
