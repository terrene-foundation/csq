---
name: svelte-patterns
description: Svelte 5 runes, component composition, and desktop UI patterns. Applies to all Svelte 5 component files and SvelteKit route files.
triggers:
  - "writing or reviewing Svelte 5 component code"
  - "using $state, $derived, or $effect runes"
  - "creating reactive stores or component props"
  - "Svelte component file touched in editor"
paths:
  - "**/*.svelte"
  - "**/*.ts" (in svelte context)
---

# Svelte 5 Patterns

Applies to all Svelte components and TypeScript in `src/`. Covers runes, composition, stores, and desktop-specific UI.

## Runes

```typescript
let count = $state(0);                // owns and mutates
let doubled = $derived(count * 2);    // pure transformation
$effect(() => {                       // side effect with cleanup
  const id = setInterval(tick, 1000);
  return () => clearInterval(id);
});
```

When `$effect` and `$derived` could both apply, prefer `$derived` — effects are harder to reason about and easier to get wrong.

## MUST Rules

### 1. $state is plain data, not class instances

Classes carry methods and prototype chains that `$state` cannot track reliably.

```
BAD:  class Counter { value = 0; increment() { this.value++; } }
GOOD: let counter = $state({ value: 0 })
```

**Why:** Svelte's reactivity relies on proxy-wrapping; class instances with prototype methods break the proxy path and produce inconsistent updates.

### 2. $derived must not mutate $state

Derived values are computed, not stored. Mutations belong in `$effect` or event handlers.

**Why:** A derived expression that mutates its source creates an infinite reactive loop at best, and silently corrupted state at worst.

### 3. $effect must return a cleanup function

Every effect that sets up subscriptions, timers, or event listeners MUST return a teardown function.

```svelte
$effect(() => {
  window.addEventListener('resize', handleResize);
  return () => window.removeEventListener('resize', handleResize);
});
```

**Why:** Missing cleanup leaks listeners and timers across component remounts; in a long-running desktop app, the leak accumulates until the process is visibly slow to restart.

### 4. Props use `$props()`

```typescript
let { name, onSubmit } = $props<{ name: string; onSubmit: () => void }>();
```

**Why:** `$props()` is the Svelte 5 contract; `export let` is legacy and breaks with typed prop destructuring.

## Component Composition

Prefer snippets over slots — they compose more cleanly and avoid wrapper divs.

```svelte
{#snippet list(items: Item[])}
  {#each items as item}<li>{item.name}</li>{/each}
{/snippet}

<List>
  {#snippet children()}{@render list(items)}{/snippet}
</List>
```

Keep props flat. Nested prop objects make testing and reuse brittle.

## Stores

| Scope | Use |
|---|---|
| Component-local | `$state` |
| Cross-component shared | Svelte store (`writable`, `readable`) |
| Shared computed | `$derived` at module level or derived store |

```typescript
import { writable } from 'svelte/store';
export const currentWindow = writable<WindowState | null>(null);
```

## TypeScript

Annotate all props, state, and function signatures. Avoid `any`. Complex types go in `src/lib/types.ts`.

Use `CustomEvent` with typed generics for component events:

```typescript
<ListItem onresult={(e: CustomEvent<QueryResult>) => handle(e.detail)} />
```

## Desktop UI

**Sizing:** Use CSS relative units and Tauri window constraints. Never hardcode pixels.

**Fonts:** System font stack for native feel.

```css
font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
```

**Dialogs:** Use Tauri `window.dialog` for file dialogs and confirmations — not custom modals. Custom modals bypass accessibility and OS expectations.

**Tray:** 16x16 and 32x32 PNG with transparency. Never block the main thread during tray menu construction.

## Anti-Patterns

- **`$:` reactive statements** — deprecated in Svelte 5; use `$derived` or `$effect`.
- **Empty `$effect` with no cleanup** — listener leak; always return cleanup.
- **Calling Rust commands without loading state** — silent failures leave users with no feedback.

## Cross-References

- `tauri-patterns.md` — Tauri command handlers and IPC
- `tauri-commands.md` — command API design
- `security.md` — no secrets in frontend state
