# Sample Python file — matches the path-scoped rule's `paths: ["**/*.py"]`.
# Asking the CLI to reason about this file should trigger the path-scoped
# rule's injection on Claude Code (only).
def hello():
    return "world"
