#!/usr/bin/env node
/**
 * F.A.N.G.S — Sigma detection scoring harness (the Rung-2 outside judge).
 *
 * Builds a LABELED corpus from Atomic Red Team (each atomic test's command line,
 * ground-truth technique = its ATT&CK id), runs the SigmaHQ process_creation
 * rule corpus over it with a real Sigma engine, and scores how well Sigma →
 * ATT&CK technique attribution matches the ground truth: precision / recall / F1.
 *
 * Honest scope: this measures "given the command line of a known-malicious
 * action, does a Sigma rule fire and name the correct ATT&CK technique." It is a
 * detection-engineering eval over synthetic command events, not full host
 * telemetry (no EVTX decode) — stated plainly in the output. Also emits
 * sigma-coverage.json so coverage.mjs can show the before/after ATT&CK surface.
 *
 * Usage: node tools/attack-eval/sigma-eval.mjs [--data DIR] [--json OUT] [--limit N]
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
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

// Shell (parent) image per Atomic executor.
const SHELL_IMAGE = {
  command_prompt: 'C:\\Windows\\System32\\cmd.exe',
  powershell: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  sh: '/bin/sh',
  bash: '/bin/bash',
};
// cmd/sh builtins that aren't their own process — skip when picking the child binary.
const BUILTINS = new Set(['set', 'echo', '@echo', 'rem', '::', 'if', 'for', 'exit', 'cls', 'cd', 'pushd',
  'popd', 'call', 'goto', 'pause', 'timeout', 'title', 'color', 'ver', 'type', 'else', 'do', 'then', 'fi',
  'done', 'export', 'source', 'alias', 'unset', 'read', 'test', 'true', 'false', 'sleep', 'wait']);

/** Derive the child process Image + CommandLine for one shell command line. */
function childProcess(line, windows) {
  let s = line.trim().replace(/^@/, '');
  if (!s || s.startsWith('::') || s.startsWith('#') || s.startsWith('rem ')) return null;
  s = s.replace(/^(?:cmd(?:\.exe)?\s+)?\/c\s+/i, '').replace(/^(?:sh|bash)\s+-c\s+["']?/i, '');
  const tok = (s.match(/^"([^"]+)"|^(\S+)/) || [])[0]?.replace(/"/g, '');
  if (!tok) return null;
  const base = tok.split(/[\\/]/).pop().toLowerCase();
  const nameNoExt = base.replace(/\.(exe|com|bat|cmd|ps1|sh)$/i, '');
  if (BUILTINS.has(nameNoExt) || BUILTINS.has(base)) return null;
  let image;
  if (tok.includes('\\') || tok.includes('/')) image = tok; // explicit path
  else if (windows) image = `C:\\Windows\\System32\\${nameNoExt}.exe`;
  else image = `/usr/bin/${nameNoExt}`;
  return { Image: image, OriginalFileName: image.split(/[\\/]/).pop(), CommandLine: s.slice(0, 4000) };
}

function walkYaml(dir) {
  const out = [];
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, name.name);
    if (name.isDirectory()) out.push(...walkYaml(p));
    else if (name.name.endsWith('.yml') || name.name.endsWith('.yaml')) out.push(p);
  }
  return out;
}

/** Substitute #{arg} with its default value (or the arg name if none). */
function fillArgs(command, inputs = {}) {
  return String(command).replace(/#\{(\w+)\}/g, (_, k) => {
    const d = inputs[k]?.default;
    return d === undefined || d === null ? k : String(d);
  });
}

const MAX_LINES = 8; // cap command lines per test so one script can't flood the corpus

export function buildCorpus(atomicsDir) {
  const events = [];
  const seen = new Set();
  for (const f of readdirSync(atomicsDir)) {
    if (!/^T\d{4}/.test(f)) continue;
    const file = join(atomicsDir, f, `${f}.yaml`);
    if (!existsSync(file)) continue;
    let doc;
    try { doc = yaml.load(readFileSync(file, 'utf8')); } catch { continue; }
    const technique = parent(doc.attack_technique || f);
    for (const test of doc.atomic_tests || []) {
      const ex = test.executor || {};
      const shell = SHELL_IMAGE[ex.name];
      if (!shell || !ex.command) continue; // manual tests / no command → skip
      const command = fillArgs(ex.command, test.input_arguments);
      const windows = !shell.startsWith('/');
      const add = (ev) => {
        const key = `${technique}|${ev.category}|${ev.CommandLine || ev.ScriptBlockText}`;
        if (ev && !seen.has(key)) { seen.add(key); events.push({ technique, name: test.name, platform: (test.supported_platforms || [])[0] || 'windows', ParentImage: shell, ...ev }); }
      };
      if (ex.name === 'powershell') {
        const cmd = command.replace(/\s+/g, ' ').trim().slice(0, 4000);
        if (cmd) {
          // Two sensors see one PowerShell atomic: the process (powershell.exe
          // invocation) and the script-block log (the script text itself).
          add({ category: 'process_creation', Image: shell, OriginalFileName: 'powershell.exe', CommandLine: `powershell.exe ${cmd}` });
          add({ category: 'ps_script', Image: shell, OriginalFileName: 'powershell.exe', ScriptBlockText: cmd, CommandLine: cmd });
        }
        continue;
      }
      // cmd/sh/bash: each command line spawns its own child process.
      const lines = command.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).slice(0, MAX_LINES);
      for (const line of lines) {
        const child = childProcess(line, windows);
        if (child) add({ category: 'process_creation', ...child });
      }
    }
  }
  return events;
}

// Sigma logsource category → rule dirs. Each category is a distinct sensor; a
// rule only runs against events of its own category (gated in score()).
const RULE_ROOTS = {
  process_creation: ['rules/windows/process_creation', 'rules/linux/process_creation', 'rules/macos/process_creation'],
  ps_script: ['rules/windows/powershell/powershell_script'], // ScriptBlockText == the atomic's script body
};

export function loadRules(sigmaDir, categories = ['process_creation', 'ps_script']) {
  const rules = [];
  for (const cat of categories) {
    for (const rel of RULE_ROOTS[cat] || []) {
      const root = join(sigmaDir, rel);
      if (!existsSync(root)) continue;
      for (const file of walkYaml(root)) {
        let doc;
        try { doc = yaml.load(readFileSync(file, 'utf8')); } catch { continue; }
        if (!doc || (doc.logsource || {}).category !== cat) continue;
        const techs = ruleTechniques(doc);
        if (!techs.length) continue; // only rules that name an ATT&CK technique can be scored
        rules.push({ id: doc.id, title: doc.title, detection: doc.detection, tags: doc.tags, level: doc.level, category: cat, techniques: techs });
      }
    }
  }
  return rules;
}

export function score(corpus, rules, { onlyCovered = false } = {}) {
  const coveredTechs = new Set(rules.flatMap((r) => r.techniques));
  const rows = onlyCovered ? corpus.filter((e) => coveredTechs.has(e.technique)) : corpus;
  // A rule only sees events from its own log source (sensor).
  const byCat = new Map();
  for (const r of rules) { if (!byCat.has(r.category)) byCat.set(r.category, []); byCat.get(r.category).push(r); }
  let correct = 0, fired = 0; // event-level: alerted at all / alerted with the right technique
  let tpStrict = 0, fpStrict = 0, fnStrict = 0; // strict multi-label (co-labels counted as FP)
  const perTech = new Map(); // tech -> {events, detected}
  for (const e of rows) {
    const predicted = new Set();
    for (const r of byCat.get(e.category) || []) if (ruleFires(r, e)) for (const t of r.techniques) predicted.add(t);
    const hit = predicted.has(e.technique);
    if (predicted.size) fired += 1;
    correct += hit ? 1 : 0;
    tpStrict += hit ? 1 : 0;
    fnStrict += hit ? 0 : 1;
    fpStrict += [...predicted].filter((t) => t !== e.technique).length;
    const pt = perTech.get(e.technique) || { events: 0, detected: 0 };
    pt.events += 1; pt.detected += hit ? 1 : 0;
    perTech.set(e.technique, pt);
  }
  // Alert precision: when the detector fires, how often is the right technique named.
  const precision = fired ? correct / fired : 0;
  // Detection recall: of all known-bad events, how many did we name correctly.
  const recall = rows.length ? correct / rows.length : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const strict = {
    precision: tpStrict + fpStrict ? tpStrict / (tpStrict + fpStrict) : 0,
    recall: tpStrict + fnStrict ? tpStrict / (tpStrict + fnStrict) : 0,
  };
  strict.f1 = strict.precision + strict.recall ? (2 * strict.precision * strict.recall) / (strict.precision + strict.recall) : 0;
  return { events: rows.length, fired, correct, precision, recall, f1, strict, perTech, coveredTechs };
}

function pct(x) { return (100 * x).toFixed(1) + '%'; }

function main() {
  const atomicsDir = join(DATA, 'atomic-red-team', 'atomics');
  const sigmaDir = join(DATA, 'sigma');
  const corpus = buildCorpus(atomicsDir);
  const rules = loadRules(sigmaDir, ['process_creation', 'ps_script']);
  const limit = Number(arg('--limit', '0'));
  const rows = limit ? corpus.slice(0, limit) : corpus;

  console.log('── F.A.N.G.S SIGMA DETECTION SCORING ───────────────────────────────');
  console.log(`corpus: ${rows.length} labeled command events (Atomic Red Team)`);
  const byCat = rules.reduce((m, r) => (m[r.category] = (m[r.category] || 0) + 1, m), {});
  console.log(`detector: ${rules.length} Sigma rules carrying an ATT&CK technique (${Object.entries(byCat).map(([c, n]) => `${c} ${n}`).join(', ')})`);
  console.log(`distinct techniques — in corpus: ${new Set(rows.map((e) => e.technique)).size}, covered by a rule: ${new Set(rules.flatMap((r) => r.techniques)).size}\n`);

  const full = score(rows, rules, { onlyCovered: false });
  const covered = score(rows, rules, { onlyCovered: true });
  // High-confidence detector: how a SOC tunes out noisy rules (level high/critical only).
  const hiRules = rules.filter((r) => ['high', 'critical'].includes(r.level));
  const hi = score(rows, hiRules, { onlyCovered: true });

  const show = (label, s) =>
    console.log(
      `${label.padEnd(26)} events ${String(s.events).padStart(4)} · fired ${String(s.fired).padStart(4)} · ` +
      `alert-P ${pct(s.precision).padStart(6)} · R ${pct(s.recall).padStart(6)} · F1 ${pct(s.f1).padStart(6)}`,
    );
  show('END-TO-END (all techs)', full);
  show('DETECTOR (covered techs)', covered);
  show(`HIGH-CONF (${hiRules.length} hi/crit)`, hi);
  console.log(`   strict multi-label F1 (co-labels=FP): end-to-end ${pct(full.strict.f1)}, detector ${pct(covered.strict.f1)}`);

  // Per-technique detection recall, worst first — the gaps a detection engineer fixes.
  const gaps = [...covered.perTech.entries()]
    .map(([t, v]) => ({ t, rate: v.detected / v.events, v }))
    .sort((a, b) => a.rate - b.rate)
    .slice(0, 12);
  console.log('\nlowest detection-recall techniques (covered by a rule but often missed):');
  for (const g of gaps) console.log(`   ${g.t}  ${pct(g.rate).padStart(6)}  (${g.v.detected}/${g.v.events})`);

  // Detection breadth — the ATT&CK-coverage lens a SOC lead reads: of the
  // techniques a process_creation rule can see, how many did the engine actually
  // catch at least once across the corpus (vs per-event recall over evasion variants).
  const detectedTechs = [...covered.perTech.entries()].filter(([, v]) => v.detected > 0).map(([t]) => t).sort();
  const coveredCount = covered.perTech.size;
  console.log(`\ndetection breadth: ${detectedTechs.length}/${coveredCount} rule-covered techniques caught at least once ` +
    `(${pct(detectedTechs.length / coveredCount)})`);

  const PASS = 0.8;
  console.log(`\nJUDGE (per-event attribution): detector F1 ${pct(covered.f1)} vs bar ${pct(PASS)} → ${covered.f1 >= PASS ? 'PASS' : 'BELOW BAR — reported honestly'}`);
  console.log('  (per-event F1 scores every red-team variant incl. evasion; detection breadth above is the ATT&CK-coverage read.)');

  // Emit the techniques the engine ACTUALLY detected, so coverage.mjs shows the
  // honest before/after ATT&CK surface (not merely what a rule is tagged with).
  writeFileSync(join(HERE, 'sigma-coverage.json'), JSON.stringify({ generatedAt: new Date().toISOString(), techniques: detectedTechs }, null, 2));

  const out = arg('--json');
  if (out) {
    const report = {
      generatedAt: new Date().toISOString(),
      corpusEvents: rows.length,
      rules: rules.length,
      techniquesInCorpus: new Set(rows.map((e) => e.technique)).size,
      techniquesCovered: covered.coveredTechs.size,
      endToEnd: metrics(full),
      detector: metrics(covered),
      highConfidence: metrics(hi),
      detectionBreadth: { detected: detectedTechs.length, ruleCovered: coveredCount, pct: round(detectedTechs.length / coveredCount), techniques: detectedTechs },
      judge: { bar: PASS, metric: 'per-event detector F1', value: round(covered.f1), pass: covered.f1 >= PASS },
    };
    writeFileSync(out, JSON.stringify(report, null, 2));
    console.log(`\nreport → ${out}`);
  }
  return { full, covered };
}

const metrics = (s) => ({ events: s.events, fired: s.fired, correct: s.correct, alertPrecision: round(s.precision), recall: round(s.recall), f1: round(s.f1), strictF1: round(s.strict.f1) });
const round = (x) => Number(x.toFixed(4));

if (process.argv[1] && process.argv[1].endsWith('sigma-eval.mjs')) main();
