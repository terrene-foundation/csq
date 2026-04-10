---
name: uiux-principles
description: "Framework-agnostic UI/UX design principles for desktop applications. Use when designing layouts, information hierarchy, component hierarchies, accessibility, motion, or typography for the Svelte desktop app."
---

# UI/UX Principles (Desktop)

Framework-agnostic design principles adapted for Svelte + Tauri desktop applications. Covers layout, visual hierarchy, component design, accessibility, and motion.

## Top-Down Design Order

```
LEVEL 1: FRAME/LAYOUT     — Space division, window structure, information architecture
LEVEL 2: FEATURE          — Discoverability, action hierarchy, navigation
LEVEL 3: COMPONENT        — Widget appropriateness, interaction patterns, feedback
LEVEL 4: VISUAL DETAILS   — Colors, shadows, typography refinements
```

## Layout Principles

- **70/30 rule**: 70% content area, 30% chrome/navigation
- **F-pattern**: Primary content top-left; users scan left-to-right first
- **Inverted pyramid**: Most important information first, supporting detail later
- **Single-window model**: Desktop app with panel-based layout (sidebar + main + optional detail pane)

## Component Hierarchy (Desktop)

| Type      | Size   | Style    | Position       | Use                        |
| --------- | ------ | -------- | -------------- | -------------------------- |
| Primary   | 44px+  | Filled   | Top-right      | 1 per view (Save, Apply)   |
| Secondary | 36px   | Outlined | Near primary   | 2-3 per view (Cancel)     |
| Tertiary  | 28px   | Text     | Contextual     | Unlimited (Edit, View)    |

## Typography

- **Font stack**: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`
- **Scale**: 12px (caption) / 14px (body) / 16px (subheading) / 20px (heading) / 28px (title)
- **Line height**: 1.4 for body, 1.2 for headings
- **Max line length**: 80 characters (~600px at 14px) — beyond this readability drops

## Color (Desktop Light/Dark)

```css
/* Light mode */
--bg-primary: #ffffff;
--bg-secondary: #f5f5f5;
--text-primary: #1a1a1a;
--text-secondary: #666666;
--accent: #0066cc;
--border: #e0e0e0;

/* Dark mode — via @media (prefers-color-scheme: dark) */
--bg-primary: #1a1a1a;
--bg-secondary: #2a2a2a;
--text-primary: #f5f5f5;
--text-secondary: #999999;
--accent: #4da6ff;
--border: #404040;
```

## Accessibility (WCAG 2.1 AA)

- All interactive elements keyboard-accessible (Tab + Enter/Space)
- Minimum contrast ratio 4.5:1 for body text, 3:1 for large text
- Focus indicators visible (`outline: 2px solid var(--accent)`)
- ARIA labels on icon-only buttons
- No color as sole indicator (always pair with icon or text)

## Motion

| Type             | Duration | Easing              | Use                          |
| ---------------- | -------- | ------------------- | ---------------------------- |
| Micro-interaction | 50-150ms | ease-out            | Hover, button press          |
| Panel transition  | 200-300ms | ease-in-out        | Sidebar open/close           |
| Page transition   | 300-400ms | ease-in-out        | Modal open/close             |
| Loading spinner  | 800ms+   | linear              | Async operations             |

- `prefers-reduced-motion`: disable all animations when set
- Animate only `transform` and `opacity` (GPU-accelerated)

## Desktop Gestures

Desktop gestures are limited compared to mobile — users expect precision, not swipe-to-dismiss. Support these:

| Gesture | Context | Expected behavior |
|---|---|---|
| Left click | All interactive elements | Primary action |
| Double click | List items, icons | Open / activate |
| Right click | Anywhere contextual | Context menu |
| Middle click | Links, tabs | Open in new window or close tab |
| Scroll | Scrollable panes | Vertical scroll; horizontal only if content exceeds viewport |
| Pinch-zoom (trackpad) | Content panes | Zoom content, not chrome |
| Two-finger swipe (trackpad) | Pane backgrounds | Horizontal scroll or back/forward navigation |
| Drag | List items, files | Reorder or drag-out to external apps |
| Keyboard shortcut | All primary actions | Every mouse action should have a keyboard equivalent |

**Platform conventions:**

- **macOS:** Cmd+W closes window, Cmd+Q quits app, Cmd+, opens preferences.
- **Windows:** Alt+F4 closes, Ctrl+Shift+Esc opens Task Manager, F10 activates menu bar.
- **Linux:** Follow GNOME HIG or KDE HIG depending on target DE.

**Never** override OS-level shortcuts (Cmd+Tab, Win+D) — users rely on them across apps.

## Window Management

Desktop apps run inside windows that users resize, move, minimize, and maximize. Design for every state.

### Window States

| State | Design requirement |
|---|---|
| Minimized | Preserve state; restoring returns to exact layout |
| Maximized | Content expands; navigation remains accessible |
| Resizing (drag) | Layout reflows smoothly — no layout thrashing |
| Small viewport | Sidebar collapses or hides; primary content stays usable |
| Multi-monitor | Window remembers position per monitor |
| Full-screen | Menu bar auto-hides on macOS; panels adapt |

### Minimum Size

Every window MUST declare a minimum size small enough for cramped setups but large enough to stay usable:

```rust
WebviewWindowBuilder::new(&app, "main", url)
    .min_inner_size(600.0, 400.0)
    .inner_size(1024.0, 768.0)
    .build()?;
```

### Multi-Window Patterns

- **Main + secondary**: one persistent window (main app) plus disposable helper windows (settings, logs, previews).
- **Document windows**: each open project or file gets its own window, common in editors.
- **Palette windows**: small always-on-top windows for commands or inspectors.

Store window positions per display ID; restoring a window on a monitor that was disconnected confuses users.

### Window Chrome

- **Native chrome** (title bar, traffic lights) is the default — users recognize it.
- **Custom chrome** only when the design needs edge-to-edge content; still provide drag regions and OS controls.
- **Transparent/vibrancy** (macOS) is fine for chrome but never for body content — text on blur is unreadable.

## Empty & Error States

```
EMPTY STATE: Icon + Headline + Body text + CTA button
ERROR STATE: Warning icon + What happened + How to fix + Retry button
LOADING: Spinner or skeleton — never blank screen
```

## CRITICAL Gotchas

| Rule                               | Why                                                    |
| ---------------------------------- | ------------------------------------------------------ |
| Never hide primary actions         | Desktop users expect visible CTAs                      |
| Always use native window controls  | Users rely on OS window management                    |
| No color as sole indicator         | Colorblind users need text/icons                       |
| Keyboard navigation required       | Power users navigate without mouse                     |
| Test on both light + dark themes   | Contrast issues are easy to miss in one mode           |
