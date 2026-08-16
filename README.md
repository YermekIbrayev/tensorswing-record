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
audits/<week>/                            beacon audit record + reveal files
                                          (each reveal carries its own Merkle proof)
incidents/                                incident log (hash-chained, genesis at 000.json)
stamps/<week>/                            RFC 3161 timestamp tokens (Sectigo + DigiCert)
tsa/                                      vendored TSA CA chains for offline token checks
release/<week>.seed.tle                   timelock-encrypted week seed (opens at embargo)
scripts/                                  verify.py + the pinned derive_indices.py
protocol/                                 versioned protocol texts + test vectors
<week>.manifest.ots                       OpenTimestamps proof for that week's manifest, at repo root
```

`roster.json` and `universe.json` (this repo's root) record which models and
which tradable universe were in force, with a one-cycle change-notice rule
for both.

Each week's full archive is also published here encrypted, and opens
automatically 24 months after its seal.

## Verify it yourself

The record is designed so a skeptical stranger can check it without
trusting us. `PROTOCOL.md` §13 defines the procedure; `scripts/verify.py`
is one implementation of it, written against the protocol text and
runnable with nothing but Python (≥ 3.9) and this repo:

```
git clone https://github.com/YermekIbrayev/tensorswing-record
cd tensorswing-record
python scripts/verify.py                # every sealed week
python scripts/verify.py 2026-W35      # one week
python scripts/verify.py --all         # also fetch + check the release archive
python scripts/verify.py --verify-beacon  # cross-check the drand beacon mirrors
```

It prints one PASS/FAIL/PENDING/SKIPPED row per check and exits non-zero
only on FAIL. **PENDING** means the week is younger than that artifact's
own deadline (labels land Friday, the audit lands Saturday, the Bitcoin
attestation lands within 7 days of seal) — absence before a deadline is
expected, not a failure. **2026-W34 reports BOOTSTRAP**: a reduced-schema
shakedown week checked only for presence and its OpenTimestamps stamp.

Two checks are stronger run with dedicated tools, and verify.py prints
the exact commands:

```
# Bitcoin anchoring (OpenTimestamps; needs: pip install opentimestamps-client)
ots verify 2026-W35.manifest.ots -f manifests/2026-W35.manifest.json

# RFC 3161 timestamp tokens, offline, against the vendored CA chains
openssl ts -verify -queryfile stamps/2026-W35/manifest.sectigo.tsq \
  -in stamps/2026-W35/manifest.sectigo.tsr -CAfile tsa/sectigo-chain.pem
```

**What verify.py does not do:** it does not check the drand beacon's BLS
signature (that needs pairing cryptography outside Python's standard
library). `--verify-beacon` instead fetches the round from independent
drand mirrors and byte-compares them, which defends against a fabricated
beacon value unless every queried mirror colludes; for full assurance run
a drand client against the pinned round. It also leaves price
plausibility to you: compare the published `reference`/`final_close`
values against any independent daily-close source (§13 suggests a 1%
informative tolerance for adjusted-close differences).

Per the honesty template this record is built on, the timestamp "removes
exactly one trust assumption — that we could have backdated our own
record — and that is all it removes."

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
