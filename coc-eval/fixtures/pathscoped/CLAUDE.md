# Pathscoped fixture — CC baseline

MARKER_CC_ROOT=cc-pathscoped-root-PCC0J

This fixture is used to verify that Claude Code honors `.claude/rules/*.md` with `paths:` YAML frontmatter (inject the rule content into context when the session's working set matches the glob).
