# /design - UI/UX Design Principles Quick Reference

## Purpose

Load the UI/UX Design Principles skill for framework-agnostic design patterns, layout principles, and desktop UX guidelines.

**CRITICAL**: This skill should be invoked PROACTIVELY for ALL frontend work, regardless of whether it's Svelte components, CSS layout, or Tauri window configuration.

## Quick Reference

| Command              | Action                                            |
| -------------------- | ------------------------------------------------- |
| `/design`            | Load comprehensive design principles              |
| `/design layout`     | Show layout and information architecture patterns |
| `/design hierarchy`  | Show visual hierarchy principles                  |
| `/design components` | Show component design guidelines                  |

## What You Get

- Top-Down Design Methodology (layout -> features -> components -> details)
- Layout & Information Architecture (70/30 rule, grid systems)
- Visual Hierarchy Principles (F-pattern, Z-pattern, inverted pyramid)
- Desktop UX Patterns (action hierarchy, system tray, window management)
- Component Design Guidelines (cards, buttons, empty states, loading states)
- Accessibility Standards (WCAG 2.1 AA compliance)
- Design System Principles (tokens, naming conventions)

## Quick Principles

### Top-Down Design Order (ALWAYS Follow)

```
LEVEL 1: FRAME/LAYOUT (Highest Priority)
  -> Space division, visual hierarchy, information architecture

LEVEL 2: FEATURE COMMUNICATION
  -> Discoverability, action hierarchy, navigation

LEVEL 3: COMPONENT EFFECTIVENESS
  -> Widget appropriateness, interaction patterns, feedback

LEVEL 4: VISUAL DETAILS (Lowest Priority)
  -> Colors, shadows, animations, typography refinements
```

### The 70/30 Rule

- 70% of space = primary content (what user came to see/do)
- 30% of space = secondary UI (navigation, filters, chrome)

### Action Hierarchy

- **Primary**: 1 per page, large filled button, brand color
- **Secondary**: 2-3 per page, medium outlined button
- **Tertiary**: Unlimited, small text buttons, contextual

## Critical Rules

1. **ALWAYS** design top-down (layout before details)
2. **NEVER** perfect visual details before fixing layout
3. **ALWAYS** have visible primary CTA (not just keyboard shortcut)
4. **ALWAYS** provide loading and empty states
5. **NEVER** use color as sole indicator (accessibility)
6. **ALWAYS** use system font stack for native desktop feel

## Agent Teams

Deploy these agents when doing design work:

- **uiux-designer** -- Design analysis, layout critique, visual hierarchy recommendations
- **svelte-specialist** -- Svelte 5 implementation of design patterns

## Skill Reference

This command loads: `.claude/skills/uiux-principles/SKILL.md`
