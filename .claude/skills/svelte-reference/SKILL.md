---
name: svelte-reference
description: "Svelte 5 runes, component patterns, stores, and TypeScript integration for desktop UIs. Use when building Svelte components, managing reactive state with runes ($state, $derived, $effect), structuring Svelte stores, or integrating Svelte with Tauri IPC calls."
---

# Svelte 5 Desktop Reference

Svelte 5 rune-based reactivity for Tauri desktop applications. Covers component patterns, reactive state, stores, and TypeScript integration.

## Runes (Reactivity)

```typescript
// Reactive state — use $state()
let count = $state(0);

// Derived — use $derived()
let doubled = $derived(count * 2);

// Effects — use $effect()
$effect(() => {
  console.log('count changed:', count);
});

// Props — use $props()
let { name, age = 18 } = $props<{ name: string; age?: number }>();
```

## Component Patterns

```svelte
<!-- Component with typed props -->
<script lang="ts">
  let { title, onSelect }: { title: string; onSelect: (id: string) => void } = $props();
</script>

<button onclick={() => onSelect(title)}>{title}</button>
```

## Tauri IPC in Svelte

```typescript
import { invoke } from '@tauri-apps/api/core';

// Invoke a Rust command
const accounts = await invoke<string[]>('list_accounts');
await invoke('swap_to_account', { index: 2 });
```

## Svelte Stores (non-rune interop)

```typescript
// stores/accountStore.ts
import { writable } from 'svelte/store';

export const activeAccount = writable<string | null>(null);
export const quotaInfo = writable<{ used: number; limit: number }>({ used: 0, limit: 100 });
```

## Event Handling

```svelte
<script lang="ts">
  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') submit();
  }
</script>

<input onkeydown={handleKeydown} />
```

## Snippets (Slot Replacement in Svelte 5)

Svelte 5 replaces slots with snippets — composable blocks of markup passed as props.

```svelte
<!-- Parent with snippet content -->
<Card>
  {#snippet header()}
    <h2>Account Status</h2>
  {/snippet}
  {#snippet children()}
    <p>Current quota: 72/100</p>
  {/snippet}
</Card>

<!-- Card.svelte receives snippets as props -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  let { header, children }: { header?: Snippet; children: Snippet } = $props();
</script>

<div class="card">
  {#if header}{@render header()}{/if}
  {@render children()}
</div>
```

Snippets can take parameters, unlike slots:

```svelte
{#snippet row(item: Item, index: number)}
  <li>{index}: {item.name}</li>
{/snippet}
```

## Transitions

Svelte built-in transitions animate elements entering and leaving the DOM.

```svelte
<script lang="ts">
  import { fade, fly, slide } from 'svelte/transition';
  import { quintOut } from 'svelte/easing';

  let show = $state(true);
</script>

{#if show}
  <div transition:fade={{ duration: 200 }}>Fading content</div>
  <div in:fly={{ y: 20, duration: 300, easing: quintOut }}
       out:slide={{ duration: 150 }}>
    Enter with fly, leave with slide
  </div>
{/if}
```

Available: `fade`, `blur`, `fly`, `slide`, `scale`, `draw` (for SVG paths), `crossfade`. Use `in:` and `out:` for asymmetric transitions.

**Desktop note:** Keep transitions under 300ms — users perceive longer animations as sluggish in a desktop app.

## Desktop-Specific Considerations

- **No router** (no SvelteKit needed for desktop shell)
- **Window controls** via Tauri window API (`@tauri-apps/api/window`)
- **System tray** integration via Tauri plugins
- **Theme** via CSS variables + Tauri dark/light detection

## Common Patterns

| Pattern           | Approach                                          |
| ----------------- | ------------------------------------------------ |
| Async data load   | `$state<Promise<T> \| null>(null)` + `{#await}` |
| Form handling     | Bound `$state` + Tauri `invoke` on submit        |
| Error display     | `$state<Error \| null>(null)` + conditional      |
| Loading spinner   | `$state(false)` + `{#if loading}`                |

## CRITICAL Gotchas

| Rule                                          | Why                                                    |
| --------------------------------------------- | ------------------------------------------------------ |
| Use `$state` for mutable reactive values      | Plain `let` is NOT reactive in Svelte 5              |
| Always type props with `$props<T>()`          | Untyped props lose type safety                        |
| Use `invoke` from `@tauri-apps/api/core`      | Not from `window.__TAURI__` directly                  |
| Handle Promise state with `{#await}` block    | Clean loading/error/content phases                     |
