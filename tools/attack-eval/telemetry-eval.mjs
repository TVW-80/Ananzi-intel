#!/usr/bin/env node
/**
 * F.A.N.G.S — multi-sensor detection on REAL labeled telemetry (Rung-3 judge).
 *
 * The command-corpus judge (sigma-eval.mjs) is bounded to one sensor. This one
 * runs the FULL Sigma rule corpus — process_creation, registry, network,
 * image_load, dns, pipe, ps_script — over genuine Windows Sysmon/PowerShell
 * telemetry from OTRF Security-Datasets (Mordor), where each capture is labeled
 * with the ATT&CK technique it exercised. That is how a detection team actually
 * measures coverage: replay a real attack trace, ask which rules fire, and check
 * they name the right technique.
 *
 * Metrics (telemetry-standard):
 *   dataset detection recall — of the labeled captures, how many did we detect
 *                              (≥1 fired rule naming the capture's technique);
 *   technique breadth        — distinct labeled techniques detected ≥ once;
 *   alert precision          — of all rule-fires, how many named a technique the
 *                              source capture actually exercised.
 *
 * Honest by construction: ground truth is the dataset's own ATT&CK mapping; a
 * capture also contains benign OS noise, so event-level precision is coarse (a
 * fired rule is "wrong" only if its technique isn't one the capture ran) — the
 * headline is dataset-level detection, the standard for trace-based evals.
 *
 * Needs `unzip` on PATH. Usage:
 *   node tools/attack-eval/telemetry-eval.mjs [--data DIR] [--json OUT] [--limit N]
 */
import { readFileSync, readdirSync, existsSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { ruleFires, ruleTechniques } from './sigma-engine.mjs';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');
const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const DATA = arg('--data', process.env.ATTACK_DATA || '/home/claude/attack-data');
const parent = (id) => String(id).split('.')[0].toUpperCase();

// Sysmon EventID → candidate Sigma logsource categories (an event is tested
// against rules in any of its categories; generic registry_event catches rules
// that don't pin the specific add/set/rename).
const SYSMON_CATS = {
  1: ['process_creation'], 3: ['network_connection'], 7: ['image_load'],
  8: ['create_remote_thread'], 9: ['raw_access_thread'], 10: ['process_access'],
  11: ['file_event'], 12: ['registry_add', 'registry_event'], 13: ['registry_set', 'registry_event'],
  14: ['registry_rename', 'registry_event'], 15: ['create_stream_hash', 'file_event'],
  17: ['pipe_created'], 18: ['pipe_created'], 22: ['dns_query'], 23: ['file_delete'],
  25: ['process_tampering'], 26: ['file_delete'],
};

/** Map a raw telemetry event → { categories[], ...fields } or null to skip. */
export function categorize(e) {
  if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
  const ch = String(e.Channel || '');
  const id = Number(e.EventID);
  if (ch.includes('Sysmon')) {
    const cats = SYSMON_CATS[id];
    return cats ? { categories: cats, ev: e } : null;
  }
  if (id === 4104) return { categories: ['ps_script'], ev: e }; // PS script-block
  if (id === 4103) return { categories: ['ps_module'], ev: e }; // PS module logging (Payload/ContextInfo)
  if (id === 4688) { // Security process creation → Sysmon field names
    return { categories: ['process_creation'], ev: { ...e, Image: e.NewProcessName || e.Image, ParentImage: e.ParentProcessName || e.ParentImage } };
  }
  return null;
}

/** Load every Sigma rule carrying a technique, bucketed by logsource category. */
export function loadAllRules(sigmaDir) {
  const byCat = new Map();
  const root = join(sigmaDir, 'rules');
  const walk = (dir) => {
    for (const n of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, n.name);
      if (n.isDirectory()) walk(p);
      else if (n.name.endsWith('.yml')) {
        let doc; try { doc = yaml.load(readFileSync(p, 'utf8')); } catch { continue; }
        const cat = (doc?.logsource || {}).category;
        if (!cat) continue;
        const techs = ruleTechniques(doc);
        if (!techs.length) continue;
        if (!byCat.has(cat)) byCat.set(cat, []);
        byCat.get(cat).push({ detection: doc.detection, techniques: techs, level: doc.level });
      }
    }
  };
  if (existsSync(root)) walk(root);
  return byCat;
}

/** Load Windows datasets: technique labels + local event-zip path. */
export function loadDatasets(secDir) {
  const metaDir = join(secDir, 'datasets', 'atomic', '_metadata');
  const out = [];
  if (!existsSync(metaDir)) return out;
  for (const f of readdirSync(metaDir)) {
    if (!f.endsWith('.yaml')) continue;
    let m; try { m = yaml.load(readFileSync(join(metaDir, f), 'utf8')); } catch { continue; }
    const platform = [].concat(m?.platform || []).map(String);
    if (!platform.some((p) => /windows/i.test(p))) continue;
    // Valid Enterprise technique ids only — T0000 is a placeholder some datasets
    // carry; scoring against a non-existent technique would just be noise.
    const techs = [...new Set((m.attack_mappings || []).map((a) => parent(a.technique)).filter((t) => /^T\d{4}$/.test(t) && t !== 'T0000'))];
    if (!techs.length) continue;
    // files[].link → local path under the repo
    const link = (m.files || []).map((x) => x.link).find((l) => /\/windows\/.*\/host\/.*\.zip$/.test(String(l)));
    if (!link) continue;
    const rel = String(link).replace(/^https?:\/\/[^/]+\/[^/]+\/[^/]+\/[^/]+\//, ''); // strip raw.githubusercontent.com/OTRF/Security-Datasets/<branch>/
    const zip = join(secDir, rel);
    if (existsSync(zip)) out.push({ id: m.id, techniques: techs, zip });
  }
  return out;
}

/** Pure: run one capture's events through the category-gated rules. */
export function scoreCapture(events, byCat, G) {
  const predicted = new Set();
  let totalEvents = 0, firedEvents = 0, correctFires = 0;
  const catHits = new Map();
  for (const raw of events) {
    const c = categorize(raw);
    if (!c) continue;
    totalEvents += 1;
    const pe = new Set();
    for (const cat of c.categories) {
      for (const r of byCat.get(cat) || []) {
        if (ruleFires(r, c.ev)) for (const t of r.techniques) { pe.add(t); if (G.has(t)) catHits.set(cat, (catHits.get(cat) || 0) + 1); }
      }
    }
    if (pe.size) firedEvents += 1;
    let ok = false;
    for (const t of pe) { predicted.add(t); if (G.has(t)) ok = true; }
    if (ok) correctFires += 1;
  }
  return { predicted, totalEvents, firedEvents, correctFires, catHits };
}

function readEvents(zip) {
  let text;
  try { text = execFileSync('unzip', ['-p', zip], { maxBuffer: 512 * 1024 * 1024 }).toString('utf8'); }
  catch { return []; }
  const events = [];
  for (const line of text.split('\n')) {
    const s = line.trim();
    if (!s) continue;
    try { events.push(JSON.parse(s)); } catch { /* skip */ }
  }
  return events;
}

function main() {
  const sigmaDir = join(DATA, 'sigma');
  const secDir = join(DATA, 'Security-Datasets');
  const byCat = loadAllRules(sigmaDir);
  let datasets = loadDatasets(secDir);
  const limit = Number(arg('--limit', '0'));
  if (limit) datasets = datasets.slice(0, limit);

  const totalRules = [...byCat.values()].reduce((n, a) => n + a.length, 0);
  console.log('── F.A.N.G.S MULTI-SENSOR DETECTION ON REAL TELEMETRY ──────────────');
  console.log(`datasets: ${datasets.length} labeled Windows captures (OTRF Security-Datasets)`);
  console.log(`detector: ${totalRules} Sigma rules across ${byCat.size} log sources ` +
    `(${[...byCat.entries()].sort((a, b) => b[1].length - a[1].length).slice(0, 6).map(([c, a]) => `${c} ${a.length}`).join(', ')}…)\n`);

  let detectedDatasets = 0, firedEvents = 0, correctFires = 0, totalEvents = 0;
  const techDetected = new Set(), techAll = new Set();
  const catHits = new Map(); // category → datasets where it produced a correct hit
  const undetected = []; // the actionable gaps: captures we missed + what fired instead

  for (const ds of datasets) {
    const G = new Set(ds.techniques);
    for (const t of G) techAll.add(t);
    const s = scoreCapture(readEvents(ds.zip), byCat, G);
    totalEvents += s.totalEvents; firedEvents += s.firedEvents; correctFires += s.correctFires;
    for (const [c, n] of s.catHits) catHits.set(c, (catHits.get(c) || 0) + n);
    const hit = [...G].some((t) => s.predicted.has(t));
    if (hit) { detectedDatasets += 1; for (const t of G) if (s.predicted.has(t)) techDetected.add(t); }
    else undetected.push({ id: ds.id, techniques: [...G], fired: [...s.predicted].slice(0, 6) });
    process.stdout.write(`\r  scored ${detectedDatasets} detected / running…`);
  }
  process.stdout.write('\r');

  const datasetRecall = datasets.length ? detectedDatasets / datasets.length : 0;
  const breadth = techAll.size ? techDetected.size / techAll.size : 0;
  const alertPrecision = firedEvents ? correctFires / firedEvents : 0;
  const f1 = alertPrecision + datasetRecall ? (2 * alertPrecision * datasetRecall) / (alertPrecision + datasetRecall) : 0;
  const pct = (x) => (100 * x).toFixed(1) + '%';

  console.log(`events scored: ${totalEvents.toLocaleString('en-US')} (benign OS noise included, as in a real trace)\n`);
  console.log(`DATASET DETECTION RECALL   ${pct(datasetRecall).padStart(6)}  (${detectedDatasets}/${datasets.length} captures detected)`);
  console.log(`TECHNIQUE BREADTH          ${pct(breadth).padStart(6)}  (${techDetected.size}/${techAll.size} labeled techniques caught)`);
  console.log(`ALERT PRECISION            ${pct(alertPrecision).padStart(6)}  (fired events naming a technique the capture ran)`);
  console.log(`COMBINED F1 (recall×prec)  ${pct(f1).padStart(6)}`);
  console.log('\ntop sensors by correct hits:', [...catHits.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([c, n]) => `${c} ${n}`).join(' · '));

  // Actionable gaps — not metric-chasing, the detection-engineering to-do list.
  const missTechs = [...techAll].filter((t) => !techDetected.has(t)).sort();
  console.log('\nDETECTION GAPS — undetected captures (labeled technique → what fired instead):');
  for (const u of undetected.slice(0, 10)) console.log(`   ${u.id}  [${u.techniques.join(',')}]  fired: ${u.fired.join(',') || '(nothing)'}`);
  console.log(`undetected techniques (${missTechs.length}): ${missTechs.join(', ') || '(none)'}`);

  const PASS = 0.8;
  console.log(`\nJUDGE: dataset detection recall ${pct(datasetRecall)} vs bar ${pct(PASS)} → ${datasetRecall >= PASS ? 'PASS' : 'BELOW BAR — reported honestly'}`);

  const out = arg('--json');
  if (out) {
    writeFileSync(out, JSON.stringify({
      generatedAt: new Date().toISOString(),
      datasets: datasets.length, rules: totalRules, logSources: byCat.size, eventsScored: totalEvents,
      datasetDetectionRecall: Number(datasetRecall.toFixed(4)), detectedDatasets,
      techniqueBreadth: Number(breadth.toFixed(4)), techniquesDetected: techDetected.size, techniquesLabeled: techAll.size,
      alertPrecision: Number(alertPrecision.toFixed(4)), f1: Number(f1.toFixed(4)),
      detectedTechniques: [...techDetected].sort(),
      undetectedTechniques: missTechs,
      undetectedCaptures: undetected,
      judge: { bar: PASS, metric: 'dataset detection recall', value: Number(datasetRecall.toFixed(4)), pass: datasetRecall >= PASS },
    }, null, 2));
    console.log(`\nreport → ${out}`);
  }
}

if (process.argv[1] && process.argv[1].endsWith('telemetry-eval.mjs')) main();
