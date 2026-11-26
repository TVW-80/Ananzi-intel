import test from 'node:test';
import assert from 'node:assert/strict';
import { matchSelection, evalCondition, ruleFires, ruleTechniques } from './sigma-engine.mjs';
import { score } from './sigma-eval.mjs';
import { categorize, scoreCapture } from './telemetry-eval.mjs';

// ── Sigma engine (pure, dependency-free) ─────────────────────────────────────
test('field modifiers: contains / endswith / startswith / re / |all', () => {
  const ev = { Image: 'C:\\Windows\\System32\\whoami.exe', CommandLine: 'whoami.exe /all /fo list' };
  assert.equal(matchSelection({ 'Image|endswith': '\\whoami.exe' }, ev), true);
  assert.equal(matchSelection({ 'Image|endswith': '\\reg.exe' }, ev), false);
  assert.equal(matchSelection({ 'CommandLine|contains': '/all' }, ev), true);
  assert.equal(matchSelection({ 'CommandLine|startswith': 'whoami' }, ev), true);
  assert.equal(matchSelection({ 'CommandLine|re': '\\/fo\\s+list' }, ev), true);
  // |all → every listed value must be present
  assert.equal(matchSelection({ 'CommandLine|contains|all': ['/all', '/fo'] }, ev), true);
  assert.equal(matchSelection({ 'CommandLine|contains|all': ['/all', '/nope'] }, ev), false);
  // a referenced field we don't carry can't match (conservative)
  assert.equal(matchSelection({ 'IntegrityLevel': 'High' }, ev), false);
});

test('selections: list OR, map AND, keyword full-text, list-of-maps', () => {
  const ev = { Image: 'C:\\Windows\\System32\\reg.exe', CommandLine: 'reg.exe save HKLM\\SAM out.hiv' };
  assert.equal(matchSelection({ 'CommandLine|contains': ['save', 'export'] }, ev), true); // OR
  assert.equal(matchSelection({ 'Image|endswith': '\\reg.exe', 'CommandLine|contains': 'save' }, ev), true); // AND
  assert.equal(matchSelection({ 'Image|endswith': '\\reg.exe', 'CommandLine|contains': 'nope' }, ev), false);
  assert.equal(matchSelection(['sam', 'lsass'], ev), true); // keyword full-text (SAM)
  assert.equal(matchSelection([{ 'CommandLine|contains': 'nope' }, { 'Image|endswith': '\\reg.exe' }], ev), true); // list-of-maps OR
});

test('condition grammar: selection / not filter / 1 of / all of / parentheses', () => {
  const T = { selection: true, selection_a: true, selection_b: false, filter: false };
  assert.equal(evalCondition('selection', T), true);
  assert.equal(evalCondition('selection and not filter', T), true);
  assert.equal(evalCondition('selection and not filter', { ...T, filter: true }), false);
  assert.equal(evalCondition('1 of selection_*', T), true);
  assert.equal(evalCondition('all of selection_*', T), false);
  assert.equal(evalCondition('all of selection_*', { ...T, selection_b: true }), true);
  assert.equal(evalCondition('(selection_a or selection_b) and not filter', T), true);
  assert.equal(evalCondition('all of them', { a: true, b: true }), true);
  assert.equal(evalCondition('1 of them', { a: false, b: false }), false);
});

test('ruleTechniques parses parent ATT&CK ids from tags', () => {
  assert.deepEqual(ruleTechniques({ tags: ['attack.execution', 'attack.t1059.001', 'attack.t1105'] }).sort(), ['T1059', 'T1105']);
  assert.deepEqual(ruleTechniques({ tags: ['attack.ta0002'] }), []); // tactics aren't techniques
});

test('ruleFires end-to-end on a realistic rule', () => {
  const rule = {
    detection: {
      selection_img: { 'Image|endswith': '\\schtasks.exe' },
      selection_cli: { 'CommandLine|contains': '/create' },
      filter: { 'CommandLine|contains': '/ru SYSTEMBACKUP' },
      condition: 'selection_img and selection_cli and not filter',
    },
    tags: ['attack.t1053.005'],
  };
  assert.equal(ruleFires(rule, { Image: 'C:\\Windows\\System32\\schtasks.exe', CommandLine: 'schtasks.exe /create /tn evil /tr calc' }), true);
  assert.equal(ruleFires(rule, { Image: 'C:\\Windows\\System32\\schtasks.exe', CommandLine: 'schtasks.exe /query' }), false); // no /create
  assert.equal(ruleFires(rule, { Image: 'C:\\Windows\\System32\\cmd.exe', CommandLine: 'schtasks.exe /create' }), false); // wrong Image
});

// ── scorer math (alert precision / recall / F1 / breadth) ────────────────────
test('score computes alert-precision, recall, F1 and respects onlyCovered', () => {
  const rules = [
    { detection: { s: { 'Image|endswith': '\\whoami.exe' }, condition: 's' }, techniques: ['T1033'], level: 'low' },
    { detection: { s: { 'CommandLine|contains': '/create' }, condition: 's' }, techniques: ['T1053'], level: 'high' },
  ];
  const corpus = [
    { technique: 'T1033', Image: 'C:\\x\\whoami.exe', CommandLine: 'whoami.exe /all' },   // R1 hits
    { technique: 'T1053', Image: 'C:\\x\\schtasks.exe', CommandLine: 'schtasks.exe /create /tn z' }, // R2 hits
    { technique: 'T1055', Image: 'C:\\x\\rundll32.exe', CommandLine: 'rundll32.exe foo' }, // no rule
  ];
  const covered = score(corpus, rules, { onlyCovered: true }); // drops the T1055 event (no rule covers it)
  assert.equal(covered.events, 2);
  assert.equal(covered.correct, 2);
  assert.equal(covered.precision, 1); // every fired alert named the right technique
  assert.equal(covered.recall, 1);
  assert.equal(covered.f1, 1);

  const full = score(corpus, rules, { onlyCovered: false });
  assert.equal(full.events, 3);
  assert.equal(full.fired, 2);
  assert.equal(full.correct, 2);
  assert.equal(full.precision, 1); // correct / fired
  assert.ok(Math.abs(full.recall - 2 / 3) < 1e-9); // correct / events
  assert.ok(Math.abs(full.f1 - 0.8) < 1e-9); // harmonic(1, 0.667)
  // per-technique breadth: both covered techniques detected at least once
  assert.equal([...covered.perTech.values()].every((v) => v.detected > 0), true);
});

// ── telemetry eval: event→sensor mapping + capture scoring ───────────────────
test('categorize maps telemetry events to the right Sigma log sources', () => {
  const sys = (id, extra = {}) => ({ Channel: 'Microsoft-Windows-Sysmon/Operational', EventID: id, ...extra });
  assert.deepEqual(categorize(sys(1)).categories, ['process_creation']);
  assert.deepEqual(categorize(sys(3)).categories, ['network_connection']);
  assert.deepEqual(categorize(sys(13)).categories, ['registry_set', 'registry_event']);
  assert.deepEqual(categorize(sys(7)).categories, ['image_load']);
  assert.deepEqual(categorize({ Channel: 'Microsoft-Windows-PowerShell/Operational', EventID: 4104 }).categories, ['ps_script']);
  assert.deepEqual(categorize({ Channel: 'Microsoft-Windows-PowerShell/Operational', EventID: 4103 }).categories, ['ps_module']);
  // Security 4688 → process_creation with Sysmon field names
  const sec = categorize({ Channel: 'Security', EventID: 4688, NewProcessName: 'C:\\x\\m.exe', ParentProcessName: 'C:\\x\\cmd.exe' });
  assert.deepEqual(sec.categories, ['process_creation']);
  assert.equal(sec.ev.Image, 'C:\\x\\m.exe');
  assert.equal(categorize(sys(5)), null); // process-terminated → not scored
  assert.equal(categorize({ Channel: 'Application', EventID: 1000 }), null);
});

test('scoreCapture gates rules by sensor and credits only the capture technique', () => {
  const byCat = new Map([
    ['process_creation', [{ detection: { s: { 'Image|endswith': '\\mimikatz.exe' }, condition: 's' }, techniques: ['T1003'] }]],
    ['registry_set', [{ detection: { s: { 'TargetObject|contains': '\\CurrentVersion\\Run' }, condition: 's' }, techniques: ['T1547'] }]],
  ]);
  const sysmon = (id, fields) => ({ Channel: 'Microsoft-Windows-Sysmon/Operational', EventID: id, ...fields });
  const events = [
    sysmon(1, { Image: 'C:\\tmp\\mimikatz.exe', CommandLine: 'mimikatz.exe sekurlsa::logonpasswords' }), // → T1003 (in G)
    sysmon(13, { TargetObject: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil' }),        // → T1547 (not in G)
    sysmon(1, { Image: 'C:\\Windows\\notepad.exe', CommandLine: 'notepad.exe' }),                         // benign → no rule
  ];
  const G = new Set(['T1003']); // the capture is labeled Credential Access
  const r = scoreCapture(events, byCat, G);
  assert.equal(r.totalEvents, 3);
  assert.equal(r.firedEvents, 2);       // mimikatz + run-key both fired a rule
  assert.equal(r.correctFires, 1);      // only the mimikatz event named the capture's technique
  assert.ok(r.predicted.has('T1003') && r.predicted.has('T1547'));
  assert.equal(r.catHits.get('process_creation'), 1); // the correct-technique hit came from process_creation
});
