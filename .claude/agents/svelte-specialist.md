---
name: svelte-specialist
description: "Svelte 5 desktop UI specialist. Use for runes ($state/$derived/$effect), stores, TypeScript, or Tauri UI integration."
tools: Read, Write, Edit, Grep, Glob, Bash
model: sonnet
---

# Svelte 5 Specialist Agent

Svelte 5 frontend development for Tauri desktop applications.

## Svelte 5 Runes ($state, $derived, $effect)

Svelte 5 introduces runes as the new reactivity primitive. Understand when to use each:

```svelte
<script lang="ts">
  // $state — reactive local state (replaces let)
  let count = $state(0);
  let user = $state<{ name: string; email: string } | null>(null);

  // $derived — computed values (replaces $:)
  let doubled = $derived(count * 2);
  let greeting = $derived(
    user ? `Hello, ${user.name}` : 'Not logged in'
  );

  // $effect — side effects (replaces $:)
  $effect(() => {
    console.log(`Count changed to: ${count}`);
    document.title = `Count: ${count}`;
    return () => {
      // cleanup function runs before next effect or on unmount
    };
  });
</script>
```

**When to use runes vs stores:**
- Component-local state: `$state`
- Derived from local state: `$derived`
- Shared across components: Svelte stores (`writable`, `derived`)
- Global app state: consider a Tauri state command

## Component Architecture

### Component Composition Patterns

```svelte
<!-- Compound component pattern -->
<script lang="ts">
  interface Props {
    items: string[];
    onSelect: (item: string) => void;
  }
  let { items, onSelect }: Props = $props();
</script>

<!-- Slot composition for layout components -->
<div class="card">
  <slot name="header" />
  <slot />
  <slot name="footer" />
</div>
```

### Props with TypeScript

```svelte
<script lang="ts">
  interface Props {
    title: string;
    count?: number;        // optional
    onChange?: (val: number) => void;  // callback
    items: Array<{ id: string; label: string }>;
  }

  let {
    title,
    count = 0,
    onChange,
    items
  }: Props = $props();
</script>
```

## Store Patterns

### Writable Store

```typescript
// lib/stores/settings.ts
import { writable } from 'svelte/store';

export const theme = writable<'light' | 'dark'>('dark');
export const sidebarOpen = writable(true);

// With type
interface AppSettings {
  fontSize: number;
  language: string;
}
export const settings = writable<AppSettings>({
  fontSize: 14,
  language: 'en'
});
```

### Derived Store

```typescript
import { derived } from 'svelte/store';
import { items } from './items';

export const itemCount = derived(items, $items => $items.length);
export const activeItems = derived(
  items,
  $items => $items.filter(item => item.active)
);
```

## Desktop UI Patterns

### Window Controls (Tauri)

```svelte
<script lang="ts">
  import { getCurrentWindow } from '@tauri-apps/api/window';

  const appWindow = getCurrentWindow();

  async function minimize() {
    await appWindow.minimize();
  }

  async function toggleMaximize() {
    const isMaximized = await appWindow.isMaximized();
    if (isMaximized) {
      await appWindow.unmaximize();
    } else {
      await appWindow.maximize();
    }
  }

  async function close() {
    await appWindow.close();
  }
</script>

<div class="window-controls">
  <button onclick={minimize} class="window-btn minimize">
    <Minimize />
  </button>
  <button onclick={toggleMaximize} class="window-btn maximize">
    <Maximize />
  </button>
  <button onclick={close} class="window-btn close">
    <Close />
  </button>
</div>

<style>
  .window-controls { display: flex; gap: 0.5rem; }
  .window-btn { padding: 0.5rem; border-radius: 4px; }
  .window-btn:hover { background: rgba(255,255,255,0.1); }
  .window-btn.close:hover { background: #e53e3e; }
</style>
```

### Native Dialog Integration

```typescript
import { open } from '@tauri-apps/plugin-dialog';

const file = await open({
  multiple: false,
  filters: [{ name: 'Images', extensions: ['png', 'jpg'] }]
});
```

## TypeScript Integration

```typescript
// lib/types/index.ts
export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

export type ViewState = 'chat' | 'settings' | 'history';

// lib/hooks/useKeyboard.ts
export function useKeyboard() {
  // keyboard shortcut logic
}
```

## Tool Suggestions

- `svelte-check` — TypeScript and Svelte analysis (`npx svelte-check --tsconfig ./tsconfig.json`)
- `vite` — Dev server and build tool

## Common Failure Patterns

1. **Missing `$props()` for component props** — Direct `export let` is Svelte 4
2. **$state mutation without reassignment** — `state.count += 1` not `state.count++` in some contexts
3. **Store subscriptions in runes context** — Use `$` prefix in templates or `$effect` for reactivity
4. **Memory leaks with $effect** — Always return cleanup function for event listeners and subscriptions
5. **TypeScript strictness** — Enable `strict` in tsconfig; missing types on props cause runtime errors
6. **CSS class entropy** — Use design tokens/system CSS variables; avoid inline style proliferation
7. **Tauri event listeners not cleaned up** — Remove listeners in `$effect` cleanup when component unmounts

## Related Agents

- **rust-desktop-specialist**: Backend Rust/Tauri command handlers
- **tauri-platform-specialist**: Platform distribution, signing, system tray
- **uiux-designer**: Design principles and visual hierarchy

## Skill References

- `skills/svelte-reference/SKILL.md`
- `skills/uiux-principles/SKILL.md`
- `skills/ai-interaction/SKILL.md`
