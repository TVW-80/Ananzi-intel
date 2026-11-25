# F.A.N.G.S ATT&CK evaluation harness

A **measurable, reproducible outside judge** for F.A.N.G.S's MITRE ATT&CK
detection — so the project's cyber claims are scored against ground truth, not
asserted. Built to answer a skeptical SOC lead: *"is your ATT&CK mapping real,
and how much do you actually detect?"*

Everything here scores F.A.N.G.S against **public, authoritative data**:

| Dataset | Role |
| --- | --- |
| `mitre/cti` (Enterprise ATT&CK STIX) | the official technique/tactic universe + revoked→replacement map |
| `redcanaryco/atomic-red-team` | labeled adversary commands (ground-truth technique per test) |
| `SigmaHQ/sigma` | the detection rules (process_creation), each tagged with its ATT&CK technique |

## What it measures

**1. Coverage** — `coverage.mjs`
Extracts every ATT&CK technique F.A.N.G.S works with (straight from the code) and
scores it against the live Enterprise matrix, on three honest surfaces:

- **Active attribution** — techniques F.A.N.G.S *derives itself* from raw signals
  (the `attackTtp.js` KIND map: ddos→T1498, c2→T1071, scanning→T1595…).
- **Explains** — techniques it can render when a feed supplies the ID.
- **Sigma detection** — techniques the new detection engine *actually detected*
  against ground truth (written by `sigma-eval.mjs`).

It also reports **ATT&CK drift**: F.A.N.G.S IDs that MITRE has since revoked,
resolved to their replacement.

**2. Detection scoring** — `sigma-eval.mjs` + `sigma-engine.mjs`
Builds a labeled corpus from Atomic Red Team (each command line → ground-truth
technique), runs the SigmaHQ `process_creation` corpus over it with a real Sigma
evaluation engine, and scores Sigma→ATT&CK attribution:

- **alert precision** — when the detector fires, how often the right technique is named;
- **recall** — of all known-bad events, how many it named correctly;
- **F1** — the judged metric;
- **detection breadth** — of the techniques a process_creation rule can see, how
  many the engine catches at least once (the ATT&CK-coverage read).

## Results (ATT&CK Enterprise v20.1, Atomic Red Team + SigmaHQ, Nov 2026)

ATT&CK Enterprise universe: **227 techniques, 479 sub-techniques, 15 tactics.**

| Surface | Techniques | % of Enterprise | Tactics |
| --- | --- | --- | --- |
| Active attribution (F.A.N.G.S today) | 12 | 5.3% | 9 / 15 |
| Explains (feed-supplied id) | 55 | 24.2% | 15 / 15 |
| **Sigma detection (new, verified vs ground truth)** | **72** | **31.7%** | **13 / 15** |

> The new Sigma detection engine **more than 5×'s** F.A.N.G.S's verified
> attribution surface (12 → 72 techniques) and every one of those 72 is a
> technique the engine *actually detected* on a labeled Atomic Red Team command.

**ATT&CK drift found** (F.A.N.G.S references IDs retired in v20.1):
`T1562 → T1685`, `T1562.001 → T1685`, `T1574.002 → T1574.001`.

**Detection scoring** (2,460 labeled command events · 1,249 scored Sigma rules):

| Metric | Value |
| --- | --- |
| detector per-event **F1** | **26.8%** (alert-P 29.3% · R 24.7%) |
| detection **breadth** | **72 / 119 = 60.5%** of rule-visible techniques caught ≥ once |

### Judge: F1 ≥ 0.80 → **BELOW BAR, reported honestly**

The per-event attribution F1 is **0.268**, under the 0.80 target. That is a real,
informative result, and the *why* is the finding a SOC lead cares about:

1. **Single sensor ceiling.** `process_creation` is one of Sigma's many log
   sources. Registry, network, image-load and PowerShell-script-block techniques
   can't be seen from a process event, so recall is capped by sensor overlap.
2. **Label-granularity disagreement.** Atomic Red Team and SigmaHQ sometimes map
   the *same* behavior to different techniques (e.g. `net user /add`: Atomic
   labels it T1098, Sigma tags T1136) — both defensible, counted as a miss here.
3. **Synthetic command corpus.** We score command lines, not decoded EVTX host
   telemetry; evasion-variant atomics that a rule intentionally doesn't match
   still count against per-event recall.

The honest coverage read — **60.5% of rule-visible techniques detected, 72/227
of Enterprise, 13/15 tactics** — is strong. The gap to 0.80 F1 is the roadmap:
add registry / network / script-block log sources and a technique-equivalence
map. This is exactly the measured, defensible footing the harness exists to give.

## Reproduce

```bash
# 1. datasets (public, GitHub)
mkdir -p ~/attack-data && cd ~/attack-data
git clone --depth 1 https://github.com/mitre/cti.git mitre-cti
git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git
git clone --depth 1 https://github.com/SigmaHQ/sigma.git

# 2. from the repo root (ATTACK_DATA defaults to /home/claude/attack-data)
export ATTACK_DATA=~/attack-data
node tools/attack-eval/sigma-eval.mjs --json tools/attack-eval/results-detection.json
node tools/attack-eval/coverage.mjs  --json tools/attack-eval/results-coverage.json \
     --layer tools/attack-eval/fangs-attack-layer.json
```

`fangs-attack-layer.json` imports into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
(active = red, explains = gold, Sigma detection = blue).

## Tests

`attack-eval.test.mjs` is **hermetic** — it exercises the Sigma engine (field
modifiers, condition grammar, technique-tag parsing) and the scorer math with
inline fixtures, so it runs in CI with no dataset clones. It runs under
`npm test` (the `tools/` root was added to the unit runner).

## Honesty notes

- Every F.A.N.G.S technique is validated against the live STIX matrix; revoked
  IDs are surfaced, never silently counted.
- The Sigma engine is a pragmatic subset of the spec (documented in
  `sigma-engine.mjs`); unknown event fields are treated as absent, which is
  conservative (a filter on a field we don't carry can't suppress a detection).
- Numbers above are reproducible from the pinned public datasets; re-running on a
  newer ATT&CK / Atomic / Sigma snapshot will move them, by design.
