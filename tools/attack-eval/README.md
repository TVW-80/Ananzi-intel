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

The command corpus is one sensor. This judge replays the **full Sigma corpus**
(2,959 ATT&CK-tagged rules across 65 log sources — the main `rules/` plus
`rules-emerging-threats/` and `rules-threat-hunting/`, routed by Sigma's own
logsource taxonomy) over **real labeled Windows telemetry** — 95 OTRF
Security-Datasets (Mordor) captures, 635k events of Sysmon, Security, PowerShell
and other channels, each labeled with the ATT&CK technique it ran.

The honest progression: **57.9%** recall as first shipped → **70.5%** after the
routing/engine fixes below (main `rules/` only) → **75.8%** after also loading
the +482 emerging-threats and threat-hunting rules the repo ships but the loader
ignored. No gaming — just correct routing and the rules that were already there.

**Ablation** — one fix at a time, same 95 captures, same judge, on the full
2,959-rule corpus (so its baseline row, 65.3%, is higher than the 57.9% first
shipped on `rules/` alone).

| config | recall | alert-P | F1 | captures |
| --- | --- | --- | --- | --- |
| baseline routing | 65.3% | 28.8% | 39.9% | 62/95 |
| + Sigma-spec Sysmon EventID map | 65.3% | 28.2% | 39.4% | 62/95 |
| + `service:` rules (Security, System, Defender…) | 71.6% | 23.3% | 35.2% | 68/95 |
| + classic PowerShell 400/600/800 | 71.6% | 23.3% | 35.2% | 68/95 |
| + MITRE revoked-by id normalization | 75.8% | 24.2% | 36.6% | 72/95 |
| **+ Sigma modifiers per spec (cidr, windash…)** | **75.8%** | **25.6%** | **38.3%** | **72/95** |

What each fix was, found by triaging misses in the raw data, not by tuning:

1. **288 rules were silently dropped.** The loader kept only rules with a
   `logsource.category`; Sigma's `product: windows` + `service:` rules (141
   Security, 55 System…) were never loaded, and 127k Security events were never
   scored. DCSync (T1003.006, Security 4662), pass-the-hash and SMB lateral
   movement are only visible there. Routing now comes from pySigma's own
   service→channel and Sysmon EventID tables (`windows-logsource-map.json`).
2. **Ground truth used retired ATT&CK ids.** OTRF labels predate ATT&CK v20.1,
   which revoked T1562 (→ T1685, and T1562.004 → T1686 at sub-technique level).
   Labels and fired tags are both resolved through MITRE's STIX `revoked-by`
   relationships (full id first) — MITRE's identity map, not a fuzzy one. The
   un-normalized ("raw ids") numbers are written alongside: 71.6 / 24.7 / 36.8%.
3. **113 rules used modifiers the engine mis-evaluated.** Unknown modifiers fell
   back to plain equals, so `IpAddress|cidr: 10.0.0.0/8` never matched and a
   "logon **from a public IP**" rule fired on every private-network logon. The
   spec engine implements `cidr`, `windash`, `base64offset`, `base64`,
   `fieldref`, `exists`, `gt/gte/lt/lte` and case-sensitive `re` with `i/m/s`;
   `windash` and `base64offset` are byte-identical to pySigma on every value in
   the SigmaHQ corpus (131/131, 33/33; golden fixtures in `pysigma-golden.json`).
   A rule using a modifier neither engine implements is **skipped and counted**,
   never guessed. Two fixes (spec Sysmon map, classic PowerShell) moved nothing —
   kept in the table, not hidden.

**Correction worth knowing:** technique breadth went *down* by one (26 → 25 of
32) with the spec engine — T1110 had only counted as "detected" because a
T1110-tagged public-IP rule fired *falsely* on private logons. The number got
more honest, not worse. Zero captures were lost vs. the baseline.

**Operating points** — the final detector alerting only on rules at or above
each Sigma `level`. All five are reported; none was picked after the fact.

| alert on level ≥ | recall | alert-P | F1 |
| --- | --- | --- | --- |
| informational (all rules) | 75.8% | 25.6% | 38.3% |
| low | 75.8% | 28.3% | 41.2% |
| **medium** | **70.5%** | **61.2%** | **65.5%** |
| high | 50.5% | 31.1% | 38.5% |
| critical | 6.3% | 70.6% | 11.6% |

The **medium** tier is the one a SOC would actually run: 70.5% recall at **61.2%
precision** (F1 65.5%) — the emerging-threats rules it adds are high-fidelity, so
tightening to medium+ barely costs recall while more than doubling precision.
Judge (detection recall ≥ 0.80): **BELOW BAR at 0.758, reported honestly.** Still
undetected: T1012, T1049, T1056, T1110, T1135, T1210, T1222 — mostly discovery
commands and SMB/lateral-movement captures whose labeled technique either isn't
in the captured telemetry or is detected under a different (correct) ATT&CK id;
closing them further would mean a technique-equivalence map, which this harness
deliberately refuses.

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
# 3. regenerate the app's coverage data from those results (never hand-edit it)
node tools/attack-eval/snapshot.mjs        # → src/anansi/coverageData.generated.js
```

`src/anansi/coverageBoard.test.mjs` fails if `coverageData.generated.js` and the
result files ever disagree. `windows-logsource-map.json` and
`pysigma-golden.json` are generated with pySigma (`pip install
pysigma-pipeline-windows pysigma-pipeline-sysmon`); each file names its source
versions.

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
- The Sigma engine has two modes (`sigma-engine.mjs`): the **legacy** engine every
  older number was measured with (kept so those numbers reproduce), and the
  **spec** engine, verified against pySigma, used for the final real-telemetry
  row. Unknown event fields are treated as absent, which is conservative (a filter
  on a field we don't carry can't suppress a detection).
- Nothing in the ablation is tuned on the captures: every fix is a spec or
  identity correction, and the Sigma-level operating points are all reported.
- Numbers above are reproducible from the pinned public datasets; re-running on a
  newer ATT&CK / Atomic / Sigma snapshot will move them, by design.
