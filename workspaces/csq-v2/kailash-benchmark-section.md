# Draft: Benchmark Section for kailash-coc-claude-py README

> WITHDRAWN — COC vs bare eval results are invalid. See red team findings below.

## Red Team Findings (2026-04-10)

The COC vs bare implementation eval (coc-eval/) produced a +20 delta (COC 50/50 vs bare 30/50).
This result is **invalid** due to contaminated scaffolds:

- **EVAL-A006**: Scaffold `access_control.py` already contains the bug fix AND the negative tests.
  The prompt asks the model to "write negative tests" and "fix the bug" — but both are already done.
  Bare Opus correctly reports no bug. Score: 0. COC Opus writes a response in the expected format. Score: 10.
  
- **EVAL-P003**: Scaffold `rbac.py` already has vacancy guards in all three bridge methods AND
  cross-feature tests. The prompt asks the model to find a missing guard — but it's already there.
  Same dynamic: bare reports truth (0), COC follows the prompt pattern (10).

The +20 delta measures "willingness to follow a prompt that contradicts the code" not "COC value-add."

### Action items

1. Fix scaffolds: restore the actual bugs (remove fixes, remove pre-written tests)
2. Re-run eval with clean scaffolds
3. Only then publish results to kailash-coc-claude-py
4. Expand from 5 to 20+ tests before claiming statistical significance
