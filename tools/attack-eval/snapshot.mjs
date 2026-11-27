#!/usr/bin/env node
/**
 * F.A.N.G.S — generate the app's ATT&CK coverage data from the judges' output.
 *
 * The SITREP coverage board and the ATT&CK matrix heatmap used to read a
 * hand-typed snapshot. This builds it from tools/attack-eval/results-*.json
 * (plus the ATT&CK STIX matrix for technique names / tactic columns), so the
 * numbers the UI shows are the numbers the judges produced — never retyped.
 * src/anansi/coverageBoard.test.mjs fails if the generated file and the result
 * files ever disagree.
 *
 * Usage: node tools/attack-eval/snapshot.mjs [--data DIR] [--results DIR] [--out FILE]
 *   (run after sigma-eval.mjs, telemetry-eval.mjs and coverage.mjs)
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..', '..');
export const OUT_PATH = join(ROOT, 'src', 'anansi', 'coverageData.generated.js');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const parent = (id) => String(id).split('.')[0].toUpperCase();

/**
 * Evidence level per ATT&CK technique, strongest first. Real telemetry beats the
 * lab corpus: a technique the command corpus catches but a real trace misses is
 * shown as MISSED, because that is what a SOC would actually see.
 *   T — detected on real labeled telemetry (OTRF)
 *   M — exercised in real telemetry, NOT detected (a measured gap)
 *   C — Sigma rule verified on the Atomic Red Team command corpus
 *   E — F.A.N.G.S explains it when a feed supplies the id (no detection)
 *   - — no coverage
 */
export const EVIDENCE = Object.freeze({
  T: 'detected on real telemetry',
  M: 'missed on real telemetry',
  C: 'verified on command corpus',
  E: 'explained only',
  '-': 'no coverage',
});

export function evidenceFor(id, sets) {
  if (sets.telemetryDetected.has(id)) return 'T';
  if (sets.telemetryMissed.has(id)) return 'M';
  if (sets.corpus.has(id)) return 'C';
  if (sets.explains.has(id)) return 'E';
  return '-';
}

/** Evidence sets from the result files (parent-level technique ids). */
export function evidenceSets({ coverage, detection, telemetry }) {
  const P = (arr) => new Set((arr || []).map(parent));
  return {
    telemetryDetected: P(telemetry.detectedTechniques),
    telemetryMissed: P(telemetry.undetectedTechniques),
    corpus: P(detection.detectionBreadth?.techniques),
    explains: P(coverage.surfaces?.explains?.validIds),
    active: P(coverage.surfaces?.activeAttribution?.validIds),
  };
}

/** "T1562 → T1685 (Disable or Modify Tools)" → { from, to, name } */
export function parseDrift(s) {
  const m = /^(T\d{4}(?:\.\d{3})?)\s*→\s*(T\d{4}(?:\.\d{3})?)\s*\((.*)\)\s*$/.exec(String(s));
  return m ? { from: m[1], to: m[2], name: m[3] } : null;
}

/** ATT&CK Enterprise matrix skeleton from STIX: tactic columns (matrix order) → live parent techniques. */
export function matrixSkeleton(bundle) {
  const ext = (o) => (o.external_references || []).find((r) => r.source_name === 'mitre-attack')?.external_id;
  const tacticsByStix = new Map();
  let order = [];
  for (const o of bundle.objects) {
    if (o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated) tacticsByStix.set(o.id, { id: ext(o), short: o.x_mitre_shortname, name: o.name });
    if (o.type === 'x-mitre-matrix' && /enterprise/i.test(o.name || '') && Array.isArray(o.tactic_refs)) order = o.tactic_refs;
  }
  const tactics = (order.length ? order.map((r) => tacticsByStix.get(r)).filter(Boolean) : [...tacticsByStix.values()])
    .map((t) => ({ ...t, techniques: [] }));
  const byShort = new Map(tactics.map((t) => [t.short, t]));
  for (const o of bundle.objects) {
    if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated || o.x_mitre_is_subtechnique) continue;
    const id = ext(o);
    if (!id) continue;
    for (const p of o.kill_chain_phases || []) {
      if (p.kill_chain_name === 'mitre-attack' && byShort.has(p.phase_name)) byShort.get(p.phase_name).techniques.push([id, o.name]);
    }
  }
  for (const t of tactics) t.techniques.sort((a, b) => a[1].localeCompare(b[1]));
  return tactics;
}

/** Pure: the app's coverage data from the three result files + the matrix skeleton. */
export function buildSnapshot({ coverage, detection, telemetry, skeleton }) {
  const sets = evidenceSets({ coverage, detection, telemetry });
  const s = coverage.surfaces || {};
  const surf = (x) => ({ techniques: x.techniqueCount, pct: Number(x.techniquePct.toFixed(1)), tactics: x.tacticCount });
  const d = detection.detector;
  const version = coverage.attackVersion ? `v${coverage.attackVersion}` : 'unknown';
  const matrix = skeleton.map((t) => ({
    id: t.id, short: t.short, name: t.name,
    techniques: t.techniques.map(([id, name]) => [id, name, evidenceFor(id, sets), sets.active.has(id) ? 1 : 0]),
  }));
  return {
    attack: version,
    enterprise: { techniques: coverage.enterprise.techniques, tactics: coverage.enterprise.tactics },
    surfaces: { active: surf(s.activeAttribution), explains: surf(s.explains), detection: surf(s.sigmaDetection) },
    // The command-corpus scorecard is the DETECTOR scope — the scope its judge line reports.
    scorecard: {
      f1: d.f1, alertPrecision: d.alertPrecision, recall: d.recall,
      breadthDetected: detection.detectionBreadth.detected, breadthCovered: detection.detectionBreadth.ruleCovered,
      bar: detection.judge?.bar ?? 0.8, events: detection.corpusEvents, rules: detection.rules,
    },
    telemetry: {
      captureRecall: telemetry.datasetDetectionRecall, detected: telemetry.detectedDatasets, captures: telemetry.datasets,
      techDetected: telemetry.techniquesDetected, techLabeled: telemetry.techniquesLabeled,
      alertPrecision: telemetry.alertPrecision, f1: telemetry.f1,
      sensors: Object.keys(telemetry.sensorHits || {}).length, rules: telemetry.rules,
      undetected: [...(telemetry.undetectedTechniques || [])].sort(),
      raw: telemetry.raw || null,
      ablation: telemetry.ablation || [],
      operatingPoints: telemetry.operatingPoints || [],
      bar: telemetry.judge?.bar ?? 0.8,
    },
    drift: (coverage.drift || []).map(parseDrift).filter(Boolean),
    source: `ATT&CK ${version} · Atomic Red Team · SigmaHQ · OTRF Security-Datasets`,
    generatedFrom: {
      coverage: coverage.generatedAt || null, detection: detection.generatedAt || null, telemetry: telemetry.generatedAt || null,
    },
    matrix,
  };
}

export function renderModule(snapshot) {
  return [
    '// GENERATED by tools/attack-eval/snapshot.mjs from tools/attack-eval/results-*.json.',
    '// Do not edit by hand — re-run the judges, then `node tools/attack-eval/snapshot.mjs`.',
    '// src/anansi/coverageBoard.test.mjs fails if this file and the result files disagree.',
    `export const COVERAGE_DATA = Object.freeze(${JSON.stringify(snapshot, null, 1)});`,
    '',
  ].join('\n');
}

export function loadResults(dir = HERE) {
  const j = (f) => JSON.parse(readFileSync(join(dir, f), 'utf8'));
  return { coverage: j('results-coverage.json'), detection: j('results-detection.json'), telemetry: j('results-telemetry.json') };
}

function main() {
  const DATA = arg('--data', process.env.ATTACK_DATA || '/home/claude/attack-data');
  const bundle = JSON.parse(readFileSync(join(DATA, 'mitre-cti', 'enterprise-attack', 'enterprise-attack.json'), 'utf8'));
  const out = arg('--out', OUT_PATH);
  const snap = buildSnapshot({ ...loadResults(arg('--results', HERE)), skeleton: matrixSkeleton(bundle) });
  writeFileSync(out, renderModule(snap));
  const cells = snap.matrix.reduce((n, t) => n + t.techniques.length, 0);
  const tally = {};
  for (const t of snap.matrix) for (const [, , e] of t.techniques) tally[e] = (tally[e] || 0) + 1;
  console.log(`wrote ${out}`);
  console.log(`ATT&CK ${snap.attack}: ${snap.matrix.length} tactics · ${cells} matrix cells · evidence ${JSON.stringify(tally)}`);
}

if (process.argv[1] && process.argv[1].endsWith('snapshot.mjs')) main();
