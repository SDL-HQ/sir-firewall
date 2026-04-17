# S2.3 Comparison Discipline v2 (Internal)

Purpose: keep benchmark-cycle and pack-result comparisons boring, evidence-linked, and reproducible.

Scope: wording and review discipline only.

Out of scope: engine behavior, pack content, scoring/ranking, dashboards, benchmark math, public truth-surface changes.

## 1) Required separation of surfaces

Every comparative note must keep these surfaces separate:

1. **Acceptance-oriented audit surface**
   - Primary question: did required gate behavior satisfy the acceptance objective?
   - Uses gate outcomes (`PASS` / `BLOCK`) with explicit prompt-level evidence links.

2. **Exploratory benchmark/scenario surface**
   - Primary question: what distinct pressure is now measurable?
   - Records observed behavior and false-positive pressure without implying product failure or success grades.

Do not collapse these into one blended conclusion.

## 2) Status semantics (locked)

Use terms exactly as follows:

- **Gate outcome**: `PASS` / `BLOCK` (prompt-level gate decision)
- **Run/publication status**: `PASS` / `FAIL` / `INCONCLUSIVE` (run or publication state)
- **Cycle completeness labels** (when needed): `FULL` / `PARTIAL` (completeness only; not gate/run status)

Never substitute one semantic class for another.

## 3) Minimum evidence link requirement

A comparative statement is valid only if it points to concrete evidence rows/artefacts.

Minimum attribution for each statement:

- `run_id`
- `evaluation_target` (`target_kind`, `pack_id`, `pack_version`, optional `scenario_id`)
- `proof_class`
- stated metric(s) or observed counts (`leaks`, `harmless_blocked`, provider call counts, or prompt-level gate rows)
- artefact path(s) used for verification (`audit.json`, `proofs/run_summary.json`, `proofs/itgl_ledger.jsonl`, benchmark row)

## 4) Standard comparison note template

Use this exact structure for cycle/pack comparison notes:

1. **Comparison scope**
   - cycle label, compared runs, and whether comparison is acceptance-oriented or exploratory.
2. **Like-for-like guard**
   - proof class match and target-kind separation confirmation.
3. **Observed evidence**
   - factual restatement from artefacts (no grading language).
4. **Interpretation boundary**
   - explicit statement of what this does **not** imply.
5. **Action label**
   - one of: `accepted for this round`, `finding for later refinement`, or `non-comparable`.

## 5) Allowed / disallowed phrasing

### A) "Pack added successfully"

Allowed:
- "Pack `<pack_id>` was added and executed with attributable benchmark rows in `<run_id>`; this confirms measurement surface availability, not behavior optimality."

Disallowed:
- "Pack added successfully, so controls are now strong."
- "Pack addition improved overall safety score."

### B) "Distinct pressure is now measurable"

Allowed:
- "This pack introduces a distinct exploratory pressure surface (`<taxonomy/category>`), now measurable via attributable rows and prompt-level gate evidence."

Disallowed:
- "The model is worse because this new pressure appears."
- "Exploratory pressure reduced the product grade to yellow/red."

### C) "Benign controls blocked"

Allowed:
- "Observed benign-control `BLOCK` outcomes in exploratory rows; record as false-positive pressure for refinement, not automatic round failure."

Disallowed:
- "Any benign block means the round failed."
- "Benign blocks prove the firewall is broken."

### D) "Finding for later refinement"

Allowed:
- "Finding logged for later refinement: `<specific behavior>` observed in `<run_id>` with evidence links; no acceptance-gate reclassification in this round."

Disallowed:
- "Needs improvement" (without evidence reference)
- "Looks green overall" / "Looks unhealthy overall"

## 6) Prohibited comparison patterns

Do not include:

- aggregate/health/maturity scores
- leaderboard or tournament language
- blended domain+scenario interpretation rows
- unsupported causal claims ("pack caused model regression") without direct evidence
- vague status words (`green`, `red`, `good`, `bad`) without bounded semantics

## 7) Reviewer quick checks

A comparison note is review-ready only if all answers are "yes":

1. Are acceptance-oriented and exploratory surfaces explicitly separated?
2. Are `PASS/BLOCK` and `PASS/FAIL/INCONCLUSIVE` used in correct contexts?
3. Does each claim include concrete run/row artefact references?
4. Are interpretations bounded (no score/ranking language)?
5. Are benign-control blocks, if present, framed as exploratory pressure unless acceptance criteria explicitly say otherwise?

If any answer is "no", mark the note `non-comparable` or request rewrite before acceptance.
