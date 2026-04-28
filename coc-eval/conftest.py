"""pytest configuration for coc-eval.

Adds `coc-eval/` to sys.path so tests can import `from lib.validators import ...`
without needing the parent dir to be a Python package (it has a hyphen, which
isn't a valid Python module name).
"""

import sys
from pathlib import Path

EVAL_DIR = Path(__file__).parent.resolve()
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))
