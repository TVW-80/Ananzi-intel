#!/usr/bin/env node
/**
 * F.A.N.G.S detection rate on EVTX-ATTACK-SAMPLES — a complementary measurement
 * to the OTRF technique-recall judge.
 *
 * EVTX-ATTACK-SAMPLES (sbousseaden) is 278 curated, real Windows event-log
 * captures of attacker behaviour, organised by ATT&CK TACTIC (no per-file
 * technique label). Because every capture IS malicious, the honest question is
 * capture-level DETECTION RATE: of these real attacks, on how many does the
 * detector fire at least one rule? And where (which tactic) is it silent?
 *
 * This is NOT technique recall — a fire here is "the detector made noise on a
 * known-bad capture", a true-positive-rate at the capture level. Reported at two
 * tiers: all rules, and the realistic SOC tier (rules at Sigma level ≥ medium).
 *
 * Convert first:  python3 tools/attack-eval/evtx_to_json.py <evtx-dir> <cache>
 * Then:           node tools/attack-eval/evtx-eval.mjs [--cache DIR] [--json OUT]
 */
import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ruleFires } from './sigma-engine.mjs';
import { loadAllRules, routes, LEVEL_RANK } from './telemetry-eval.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (name, fb) => { const i = process.argv.indexOf(name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fb; };
const DATA = arg('--data', process.env.ATTACK_DATA || '/home/claude/attack-data');
const CACHE = arg('--cache', join(DATA, 'evtx-json'));

/** Load the converted captures: [{ id, tactic, events[] }]. */
export function loadEvtxCaptures(cacheDir) {
  const indexPath = join(cacheDir, 'index.json');
  if (!existsSync(indexPath)) return [];
  const index = JSON.parse(readFileSync(indexPath, 'utf8')).captures || [];
  const files = new Set(readdirSync(cacheDir));
  return index
    .filter((c) => files.has(`${c.id}.ndjson`))
    .map((c) => ({
      id: c.id,
      tactic: c.tactic,
      events: readFileSync(join(cacheDir, `${c.id}.ndjson`), 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean),
    }));
}

/**
 * Pure: did any rule fire on this capture, and the highest Sigma level that did.
 * Rule engine selection matches telemetry-eval (legacy unless a rule needs the
 * spec engine and the spec engine supports it).
 * @returns {{ fired: boolean, maxRank: number }}
 */
export function scoreCaptureDetection(events, byCat) {
  let fired = false;
  let maxRank = -1;
  for (const raw of events) {
    const r = routes(raw);
    if (!r) continue;
    for (const b of r.buckets) {
      for (const rule of byCat.get(b.bucket) || []) {
        const hit = !rule.needsSpec ? ruleFires(rule, r.ev) : (rule.specSupported !== false && ruleFires(rule, r.ev, { spec: true }));
        if (hit) { fired = true; if ((rule.rank ?? 0) > maxRank) maxRank = rule.rank ?? 0; }
      }
    }
  }
  return { fired, maxRank };
}

/** Pure: tally detection over all captures → report object (no I/O). */
export function evaluate(caps, byCat) {
  const MED = LEVEL_RANK.medium;
  const tally = new Map(); // tactic -> { total, any, medium }
  const silent = [];
  for (const c of caps) {
    const { fired, maxRank } = scoreCaptureDetection(c.events, byCat);
    const t = tally.get(c.tactic) || { total: 0, any: 0, medium: 0 };
    t.total += 1;
    if (fired) t.any += 1; else silent.push({ id: c.id, tactic: c.tactic });
    if (maxRank >= MED) t.medium += 1;
    tally.set(c.tactic, t);
  }
  const any = [...tally.values()].reduce((s, t) => s + t.any, 0);
  const medium = [...tally.values()].reduce((s, t) => s + t.medium, 0);
  const r4 = (x) => Number(x.toFixed(4));
  return {
    generatedAt: new Date().toISOString(),
    source: 'EVTX-ATTACK-SAMPLES (github.com/sbousseaden)',
    captures: caps.length,
    detectionRateAny: r4(caps.length ? any / caps.length : 0),
    detectionRateMedium: r4(caps.length ? medium / caps.length : 0),
    detectedAny: any,
    detectedMedium: medium,
    byTactic: Object.fromEntries(
      [...tally.entries()]
        .sort((a, b) => b[1].any / b[1].total - a[1].any / a[1].total)
        .map(([k, t]) => [k, { total: t.total, any: t.any, medium: t.medium, rateAny: r4(t.any / t.total) }]),
    ),
    silent,
  };
}

function main() {
  const byCat = loadAllRules(join(DATA, 'sigma'));
  const caps = loadEvtxCaptures(CACHE);
  if (!caps.length) { console.error(`No converted captures in ${CACHE}. Run evtx_to_json.py first.`); process.exit(1); }
  const totalRules = [...byCat.values()].reduce((n, a) => n + a.length, 0);
  const rep = evaluate(caps, byCat);
  const pct = (x) => `${(100 * x).toFixed(1)}%`;

  console.log('── F.A.N.G.S DETECTION RATE ON EVTX-ATTACK-SAMPLES ─────────────────');
  console.log(`captures: ${rep.captures} curated malicious EVTX captures (tactic-labeled)`);
  console.log(`detector: ${totalRules} Sigma rules\n`);
  console.log('DETECTION RATE BY TACTIC   (any rule · medium+ rule)');
  for (const [tactic, t] of Object.entries(rep.byTactic)) {
    console.log(`  ${tactic.padEnd(22)} ${pct(t.rateAny).padStart(6)} (${t.any}/${t.total})   medium+ ${pct(t.total ? t.medium / t.total : 0).padStart(6)}`);
  }
  console.log(`\nOVERALL  ${pct(rep.detectionRateAny)} of ${rep.captures} captures fire a rule   ·   medium+ ${pct(rep.detectionRateMedium)}`);
  console.log(`\nSILENT captures (blind spots — no rule fired): ${rep.silent.length}`);
  for (const c of rep.silent.slice(0, 15)) console.log(`   [${c.tactic}] ${c.id}`);

  const out = arg('--json');
  if (out) { writeFileSync(out, JSON.stringify(rep, null, 2)); console.log(`\nreport → ${out}`); }
}

if (process.argv[1] && process.argv[1].endsWith('evtx-eval.mjs')) main();
