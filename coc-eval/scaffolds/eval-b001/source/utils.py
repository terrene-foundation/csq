"""Utility functions v1 -- identical in source and target."""

import json
from pathlib import Path


def load_config(config_path):
    """Load JSON config file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")
    return json.loads(path.read_text())


def ensure_directory(dir_path):
    """Create directory if it doesn't exist."""
    Path(dir_path).mkdir(parents=True, exist_ok=True)


def sanitize_path(base_dir, user_path):
    """Sanitize a user-provided path to prevent traversal."""
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError(f"Path traversal blocked: {user_path}")
    return target
