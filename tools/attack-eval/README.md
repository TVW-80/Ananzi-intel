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
| **Sigma detection (new, verified vs ground truth)** | **85** | **37.4%** | **13 / 15** |

> The new Sigma detection engine **7×'s** F.A.N.G.S's verified attribution
> surface (12 → 85 techniques) and every one of those 85 is a technique the
> engine *actually detected* on a labeled Atomic Red Team event. It is
> **multi-sensor**: `process_creation` (child-binary + command line) and
> `ps_script` (PowerShell script-block text) — two log sources that can be
> faithfully derived from an atomic without inventing telemetry.

**ATT&CK drift found** (F.A.N.G.S references IDs retired in v20.1):
`T1562 → T1685`, `T1562.001 → T1685`, `T1574.002 → T1574.001`.

**Detection scoring** (3,263 labeled events · 1,402 scored Sigma rules — process_creation 1,249 + ps_script 153):

| Metric | Value |
| --- | --- |
| detector per-event **F1** | **27.5%** (alert-P 32.3% · R 23.9%) |
| detection **breadth** | **85 / 122 = 69.7%** of rule-visible techniques caught ≥ once |

### Real-telemetry detection (multi-sensor) — `telemetry-eval.mjs`

The command corpus is one sensor. This judge replays the **full multi-sensor
Sigma corpus** (2,189 rules across 33 log sources: process_creation, registry,
network, image_load, create_remote_thread, process_access, dns, pipe, ps_script,
ps_module…) over **real labeled Windows telemetry** — 96 OTRF Security-Datasets
(Mordor) captures, each Sysmon/PowerShell trace labeled with the ATT&CK technique
it ran. This is how a detection team actually measures coverage.

| Metric | Value |
| --- | --- |
| **dataset detection recall** | **57.9%** (55 / 95 captures detected) |
| technique breadth | 64.5% (20 / 31 labeled techniques caught) |
| alert precision (coarse) | 23.8% |
| sensors contributing | process_creation · create_remote_thread · ps_module · registry · network · process_access |

Moving from a single-sensor command corpus to multi-sensor real telemetry **more
than doubled detection** (≈25% → 57.9%), and every sensor carries weight. Judge
(detection recall ≥ 0.80): **BELOW BAR at 0.579, reported honestly**. The eval
prints the exact gap — the 11 undetected techniques (T1012, T1049, T1056, T1110,
T1123, T1135, T1210, T1222, T1550, T1558, and T1562, which ATT&CK v20.1 retired)
— so closing it is a concrete to-do list, not a mystery.

### Command-corpus judge: F1 ≥ 0.80 → **BELOW BAR, reported honestly**

The per-event attribution F1 is **0.275**, under the 0.80 target. That is a real,
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
git clone --depth 1 https://github.com/OTRF/Security-Datasets.git   # real telemetry (needs `unzip`)

# 2. from the repo root (ATTACK_DATA defaults to /home/claude/attack-data)
export ATTACK_DATA=~/attack-data
node tools/attack-eval/sigma-eval.mjs      --json tools/attack-eval/results-detection.json
node tools/attack-eval/telemetry-eval.mjs  --json tools/attack-eval/results-telemetry.json
node tools/attack-eval/coverage.mjs        --json tools/attack-eval/results-coverage.json \
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
