#!/usr/bin/env node
/**
 * F.A.N.G.S — MITRE ATT&CK coverage analyzer (the Rung-1 outside judge).
 *
 * Measures, against the OFFICIAL Enterprise ATT&CK matrix (mitre/cti STIX),
 * which techniques F.A.N.G.S can work with, split into two honest surfaces:
 *
 *   ACTIVE ATTRIBUTION  techniques F.A.N.G.S derives itself from raw signals
 *                       (the attackTtp.js KIND map: ddos→T1498, c2→T1071, …)
 *   EXPLAINS            techniques it can render/explain when a feed supplies
 *                       the ID (glossary + incident timeline references)
 *   SIGMA DETECTION     techniques covered by the new Sigma engine (if its
 *                       coverage file exists), so the before/after is visible
 *
 * Nothing here is invented: every F.A.N.G.S technique is validated against the
 * STIX matrix, unknown/revoked IDs are reported, and the % is reproducible.
 *
 * Usage:  node tools/attack-eval/coverage.mjs [--data DIR] [--json OUT] [--layer OUT]
 *   --data   dataset dir holding mitre-cti/ (default $ATTACK_DATA or /home/claude/attack-data)
 *   --json   write the full report as JSON
 *   --layer  write an ATT&CK Navigator layer JSON
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const DATA = arg('--data', process.env.ATTACK_DATA || '/home/claude/attack-data');

// ── 1. Official Enterprise ATT&CK universe (from STIX) ───────────────────────
export function loadEnterprise(stixPath) {
  const bundle = JSON.parse(readFileSync(stixPath, 'utf8'));
  const techniques = new Map(); // id -> { id, name, isSub, parent, tactics[] }  (LIVE only)
  const tacticNames = new Map();
  const byStix = new Map(); // stix id -> { extId, name }  (all attack-patterns, incl. revoked)
  let version = null;
  for (const o of bundle.objects) {
    if (o.type === 'x-mitre-collection') version = (o.x_mitre_version || version);
    if (o.type !== 'attack-pattern') continue;
    const ref = (o.external_references || []).find((r) => r.source_name === 'mitre-attack');
    if (!ref?.external_id) continue;
    byStix.set(o.id, { extId: ref.external_id, name: o.name });
    if (o.revoked || o.x_mitre_deprecated) continue; // live universe excludes these
    const id = ref.external_id;
    const isSub = Boolean(o.x_mitre_is_subtechnique);
    const tactics = (o.kill_chain_phases || [])
      .filter((p) => p.kill_chain_name === 'mitre-attack')
      .map((p) => p.phase_name);
    techniques.set(id, { id, name: o.name, isSub, parent: isSub ? id.split('.')[0] : id, tactics });
    for (const t of tactics) tacticNames.set(t, t);
  }
  // revoked-by relationships → map a retired external_id to its replacement.
  const revokedBy = new Map(); // oldExtId -> { id, name }
  for (const o of bundle.objects) {
    if (o.type !== 'relationship' || o.relationship_type !== 'revoked-by') continue;
    const from = byStix.get(o.source_ref);
    const to = byStix.get(o.target_ref);
    if (from && to) revokedBy.set(from.extId, { id: to.extId, name: to.name });
  }
  return { techniques, tactics: [...tacticNames.keys()].sort(), revokedBy, version };
}

// ── 2. F.A.N.G.S technique surfaces (extracted from the codebase) ────────────
const TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;

function readIds(relPath) {
  try {
    return new Set(String(readFileSync(join(REPO, relPath), 'utf8')).match(TECH_RE) || []);
  } catch {
    return new Set();
  }
}

/** Techniques F.A.N.G.S ACTIVELY attributes: the attackTtp.js TECHNIQUES table. */
export function fangsActiveIds() {
  const src = readFileSync(join(REPO, 'src/data/attackTtp.js'), 'utf8');
  // Parse the `export const TECHNIQUES = Object.freeze({ ... })` block only, so
  // this counts what F.A.N.G.S derives, not every ID mentioned in a comment.
  const block = src.slice(src.indexOf('TECHNIQUES = Object.freeze({'));
  const end = block.indexOf('});');
  return new Set((block.slice(0, end).match(TECH_RE) || []));
}

/** Techniques F.A.N.G.S can EXPLAIN when a feed supplies the id. */
export function fangsExplainsIds() {
  const ids = new Set();
  for (const f of [
    'server/providers/anansi/attack-glossary.js',
    'server/providers/anansi/incident-timeline.js',
    'src/data/attackTtp.js',
  ]) {
    for (const id of readIds(f)) ids.add(id);
  }
  return ids;
}

const parentOf = (id) => String(id).split('.')[0];

function coverageOf(ids, ent) {
  const valid = [...ids].filter((id) => ent.techniques.has(id));
  const unknown = [...ids].filter((id) => !ent.techniques.has(id));
  const parents = new Set(valid.map(parentOf).filter((p) => ent.techniques.has(p) && !ent.techniques.get(p).isSub));
  const tactics = new Set(valid.flatMap((id) => ent.techniques.get(id).tactics));
  return { ids: [...ids].sort(), valid, unknown, parents, tactics };
}

function main() {
  const stix = join(DATA, 'mitre-cti', 'enterprise-attack', 'enterprise-attack.json');
  const ent = loadEnterprise(stix);
  const allParents = [...ent.techniques.values()].filter((t) => !t.isSub);
  const allSubs = [...ent.techniques.values()].filter((t) => t.isSub);

  const active = coverageOf(fangsActiveIds(), ent);
  const explains = coverageOf(fangsExplainsIds(), ent);
  // Optional: Sigma engine coverage, written by sigma-eval.mjs.
  let sigma = null;
  try {
    const sc = JSON.parse(readFileSync(join(HERE, 'sigma-coverage.json'), 'utf8'));
    sigma = coverageOf(new Set(sc.techniques || []), ent);
  } catch { /* not built yet */ }

  const pct = (n, d) => (d ? ((100 * n) / d).toFixed(1) : '0.0');
  const line = (label, c) =>
    `${label.padEnd(20)} ${String(c.parents.size).padStart(3)} / ${allParents.length} techniques ` +
    `(${pct(c.parents.size, allParents.length).padStart(5)}%)  ·  ${c.tactics.size}/${ent.tactics.length} tactics` +
    (c.unknown.length ? `  ·  ${c.unknown.length} unknown id(s): ${c.unknown.join(', ')}` : '');

  console.log('── F.A.N.G.S ATT&CK COVERAGE (Enterprise) ──────────────────────────');
  console.log(`ATT&CK Enterprise${ent.version ? ` v${ent.version}` : ''}: ${allParents.length} techniques, ${allSubs.length} sub-techniques, ${ent.tactics.length} tactics\n`);
  console.log(line('ACTIVE ATTRIBUTION', active));
  console.log(line('EXPLAINS (feed id)', explains));
  if (sigma) console.log(line('SIGMA DETECTION', sigma));
  console.log('\ntactics touched (active):', [...active.tactics].sort().join(', ') || '(none)');

  // ATT&CK drift: F.A.N.G.S ids that MITRE has since revoked, with replacements.
  const drift = [...new Set([...active.unknown, ...explains.unknown])].sort().map((id) => {
    const r = ent.revokedBy.get(id);
    return r ? `${id} → ${r.id} (${r.name})` : `${id} (retired, no direct replacement)`;
  });
  if (drift.length) {
    console.log('\n⚠ ATT&CK DRIFT — F.A.N.G.S references ids retired in this ATT&CK version:');
    for (const d of drift) console.log('   ' + d);
  }

  const report = {
    generatedAt: new Date().toISOString(),
    attackVersion: ent.version || null,
    enterprise: { techniques: allParents.length, subtechniques: allSubs.length, tactics: ent.tactics.length },
    drift: drift,
    surfaces: {
      activeAttribution: summarize(active, allParents.length, ent.tactics.length),
      explains: summarize(explains, allParents.length, ent.tactics.length),
      ...(sigma ? { sigmaDetection: summarize(sigma, allParents.length, ent.tactics.length) } : {}),
    },
  };

  const jsonOut = arg('--json');
  if (jsonOut) { writeFileSync(jsonOut, JSON.stringify(report, null, 2)); console.log(`\nreport → ${jsonOut}`); }

  const layerOut = arg('--layer');
  if (layerOut) {
    const navTech = (c, color) => c.valid.map((id) => ({ techniqueID: id, score: 1, color, enabled: true }));
    const layer = {
      name: 'F.A.N.G.S coverage',
      versions: { layer: '4.5', navigator: '4.9.1', attack: '15' },
      domain: 'enterprise-attack',
      description: 'F.A.N.G.S ATT&CK coverage: active attribution (red), explains (gold), Sigma detection (blue).',
      techniques: [
        ...navTech(explains, '#d4af37'),
        ...(sigma ? navTech(sigma, '#3fa7ff') : []),
        ...navTech(active, '#ff2b2b'),
      ],
      gradient: { colors: ['#060606', '#ff2b2b'], minValue: 0, maxValue: 1 },
      legendItems: [
        { label: 'active attribution', color: '#ff2b2b' },
        { label: 'explains (feed id)', color: '#d4af37' },
        ...(sigma ? [{ label: 'Sigma detection', color: '#3fa7ff' }] : []),
      ],
    };
    writeFileSync(layerOut, JSON.stringify(layer, null, 2));
    console.log(`navigator layer → ${layerOut}`);
  }
  return report;
}

function summarize(c, totalParents, totalTactics) {
  return {
    techniqueCount: c.parents.size,
    techniquePct: Number(((100 * c.parents.size) / totalParents).toFixed(2)),
    tacticCount: c.tactics.size,
    tacticPct: Number(((100 * c.tactics.size) / totalTactics).toFixed(2)),
    validIds: c.valid.sort(),
    unknownIds: c.unknown.sort(),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
