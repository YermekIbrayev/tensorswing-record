# tensorswing-record

**RECORD STATUS: INTACT**

## What this repo is

This is the tamper-evident record of TensorSwing's weekly stock predictions.
Every week, before the model set makes its calls, TensorSwing commits a
cryptographic hash of each prediction here — before anyone, including us,
knows how the week will turn out. When the week's outcomes are known, the
labels are published alongside the original commitments so anyone can line
up what was promised against what happened.

Predictions themselves are a paid product (see `SUBSCRIBER-LICENSE.md`).
What's public here is the proof structure around them: hashes, labels,
audit results, and the incident log — not the forecasts.

## What this proves / what it does not

Each week's prediction set is:

- **cryptographically committed before Monday's market open** — the hash of
  every prediction is fixed and recorded before the week's trading begins,
  so the prediction cannot be edited after the fact to look better.
- **publicly timestamped** — the commitment is anchored to the Bitcoin
  blockchain via OpenTimestamps — anyone can verify the timestamp without
  trusting us.
- **spot-checked weekly by a public randomness beacon we cannot influence** —
  a subset of that week's leaves is selected for disclosure by a source of
  randomness outside TensorSwing's control, and the disclosed leaves are
  checked against their commitments.
- **fully checkable by any subscriber** — a subscriber holding the week's
  raw archive can recompute every hash in this repo from the underlying
  predictions and confirm they match.

What this does not prove: the blockchain timestamp establishes *when* a
commitment was made, not whether the underlying prediction was any good.
Nothing here certifies model accuracy, and nothing here is investment
advice. Outcome quality lives in the published labels and aggregate
statistics, which anyone can read — the cryptography only closes the door
on after-the-fact editing.

## The models

TensorSwing runs three model families against the same universe each week:

- **N-HITS** (`n-hits`) — in-house neural forecaster, MC-dropout uncertainty.
- **PATCHTST** (`patchtst`) — in-house neural forecaster, MC-dropout
  uncertainty.
- **CHRONOS** (`chronos`) — Amazon Chronos (third-party foundation model),
  native quantiles.

Each model's numeric forecast is paired with an LLM-generated thesis — a
natural-language explanation of the call. The thesis is descriptive, not a
fourth model output with its own accuracy claim.

The full roster and change-notice rule live in `roster.json`.

## Bootstrap week: 2026-W34

The full protocol document (`PROTOCOL.md`) — covering the manifest format,
the Merkle construction, the randomness-beacon audit procedure, and the
grading rules in detail — lands before week 2026-W35.

**2026-W34 is a reduced-schema bootstrap week**, run to prove the pipeline
end-to-end before the full protocol is documented. Its manifests and hashes
follow a simplified schema; treat 2026-W34 as a shakedown week, not a
template for the steady-state format that begins in 2026-W35.

## Repo layout

As weeks are sealed, this repo fills in:

```
manifests/                                weekly commitment manifests
hashes/<model>/<week>/<TICKER>.sha256     per-leaf commitment hashes
labels/                                   published outcome labels
audits/                                   weekly randomness-beacon spot-check results
proofs/                                   Merkle proofs for disclosed/spot-checked leaves
incidents/                                incident log (hash-chained, genesis at 000.json)
<week>.manifest.ots                       OpenTimestamps proof for that week's manifest, at repo root
```

`roster.json` and `universe.json` (this repo's root) record which models and
which tradable universe were in force, with a one-cycle change-notice rule
for both.

Each week's full archive is also published here encrypted, and opens
automatically 24 months after its seal.

## Trust model

GitHub is hygiene here, not the trust anchor — the OpenTimestamps chain is.
GitHub gives you a convenient, versioned place to read the record; the
actual claim that a commitment predates the outcome it describes rests on
the Bitcoin-anchored OpenTimestamps proof, which does not depend on GitHub,
TensorSwing, or anyone else staying honest or staying online.

## Licensing

- Code in `scripts/` and `tests/` is MIT-licensed — see `LICENSE`.
- Record data (`manifests/`, `hashes/`, `labels/`, `audits/`, `incidents/`,
  `proofs/`, `roster.json`, `universe.json`) is CC BY 4.0 — see
  `LICENSE-DATA.md`.
- The paid weekly-archive license subscribers operate under is published in
  `SUBSCRIBER-LICENSE.md`.
