import test from 'node:test';
import assert from 'node:assert/strict';
import { matchSelection, evalCondition, ruleFires, ruleTechniques, ruleTechniqueIds } from './sigma-engine.mjs';
import { score } from './sigma-eval.mjs';
import {
  categorize, scoreCapture, routes, buildNormalizer, scoreCaptureConfigs,
  CHANNEL_SERVICES, SYSMON_CATS, BASELINE_ORIGINS, ABLATION,
} from './telemetry-eval.mjs';

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
  // category routes (service routes checked separately — every Sysmon event is also service:sysmon)
  const cats = (e) => categorize(e).categories.filter((c) => !c.startsWith('service:'));
  assert.deepEqual(cats(sys(1)), ['process_creation']);
  assert.deepEqual(cats(sys(3)), ['network_connection']);
  assert.deepEqual(cats(sys(13)), ['registry_set', 'registry_event']);
  assert.deepEqual(cats(sys(7)), ['image_load']);
  assert.ok(categorize(sys(1)).categories.includes('service:sysmon'));
  const ps = (id) => ({ Channel: 'Microsoft-Windows-PowerShell/Operational', EventID: id });
  assert.deepEqual(categorize(ps(4104)).categories, ['ps_script', 'service:powershell']);
  assert.deepEqual(categorize(ps(4103)).categories, ['ps_module', 'service:powershell']);
  // Security 4688 → process_creation with Sysmon field names
  const sec = categorize({ Channel: 'Security', EventID: 4688, NewProcessName: 'C:\\x\\m.exe', ParentProcessName: 'C:\\x\\cmd.exe' });
  // …and, per the Sigma spec, also the Security service rules (4624/4662/4769… live there)
  assert.deepEqual(sec.categories, ['process_creation', 'service:security']);
  assert.equal(sec.ev.Image, 'C:\\x\\m.exe');
  // Spec Sysmon map: 5 is process_termination, 19-21 are wmi_event (the old hand map skipped them)
  assert.deepEqual(categorize(sys(5)).categories.filter((c) => !c.startsWith('service:')), ['process_termination']);
  assert.ok(categorize(sys(19)).categories.includes('wmi_event'));
  assert.deepEqual(categorize({ Channel: 'Application', EventID: 1000 }).categories, ['service:application']);
});

test('the ablation baseline reproduces the old hand-made routing exactly', () => {
  const sys = (id) => ({ Channel: 'Microsoft-Windows-Sysmon/Operational', EventID: id });
  const base = (e) => categorize(e, BASELINE_ORIGINS);
  assert.equal(base(sys(5)), null); // old map never scored process termination
  assert.equal(base({ Channel: 'Application', EventID: 1000 }), null); // old loader dropped service rules
  assert.deepEqual(base({ Channel: 'Security', EventID: 4688, NewProcessName: 'x' }).categories, ['process_creation']);
  assert.deepEqual(base(sys(15)).categories, ['create_stream_hash', 'file_event']); // old approximation kept for the "before" column
  assert.deepEqual(base(sys(13)).categories, ['registry_set', 'registry_event']);
  assert.equal(ABLATION[0].id, 'baseline');
  assert.equal(ABLATION.at(-1).normalize, true);
});

test('service routing follows the Sigma spec and ignores channel case (OTRF has "security")', () => {
  assert.deepEqual(CHANNEL_SERVICES.get('security'), ['security']);
  const lower = routes({ Channel: 'security', EventID: 4662 });
  assert.deepEqual(lower.buckets, [{ bucket: 'service:security', origin: 'service' }]);
  assert.deepEqual(routes({ Channel: 'Microsoft-Windows-Windows Defender/Operational', EventID: 1116 }).buckets.map((b) => b.bucket), ['service:windefend']);
  // classic PowerShell: Sigma defines ps_classic_start as Windows PowerShell EventID 400
  const classic = routes({ Channel: 'Windows PowerShell', EventID: 400 });
  assert.deepEqual(classic.buckets.map((b) => `${b.bucket}/${b.origin}`), ['ps_classic_start/classic', 'service:powershell-classic/service']);
  assert.equal(routes({ Channel: 'Some-Unknown/Operational', EventID: 1 }), null);
  assert.deepEqual(SYSMON_CATS[6], ['driver_load']);
});

test('MITRE revoked-by normalizer: full id first, parent fallback, chains followed', () => {
  const revokedBy = new Map([
    ['T1562', { id: 'T1685' }], ['T1562.004', { id: 'T1686' }], ['T1562.002', { id: 'T1685.001' }],
    ['T9001', { id: 'T9002' }], ['T9002', { id: 'T9003' }], // chain
  ]);
  const norm = buildNormalizer(revokedBy);
  assert.equal(norm('T1562.004'), 'T1686'); // sub-technique retired on its own
  assert.equal(norm('T1562.002'), 'T1685'); // → T1685.001 → scored at parent level
  assert.equal(norm('T1562.009'), 'T1685'); // sub not listed → parent's replacement
  assert.equal(norm('T9001'), 'T9003');
  assert.equal(norm('T1003.006'), 'T1003'); // live ids pass through, parent-level
  assert.deepEqual(ruleTechniqueIds({ tags: ['attack.t1562.004', 'attack.t1003', 'attack.defense-evasion'] }), ['T1562.004', 'T1003']);
});

test('scoreCaptureConfigs attributes a detection to the fix that enables it', () => {
  const byCat = new Map([
    ['service:security', [{ detection: { s: { EventID: 4662, 'Properties|contains': '1131f6aa' }, condition: 's' }, ids: ['T1003.006'], techniques: ['T1003'] }]],
    ['process_creation', [{ detection: { s: { 'Image|endswith': '\\netsh.exe' }, condition: 's' }, ids: ['T1686'], techniques: ['T1686'] }]],
  ]);
  const events = [
    { Channel: 'Security', EventID: 4662, Properties: '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}' }, // DCSync
    { Channel: 'Microsoft-Windows-Sysmon/Operational', EventID: 1, Image: 'C:\\Windows\\System32\\netsh.exe' },
  ];
  const norm = buildNormalizer(new Map([['T1562.004', { id: 'T1686' }]]));
  const cfg = (id) => ABLATION.find((c) => c.id === id);
  const [base, svc, full] = scoreCaptureConfigs(events, byCat, ['T1003.006', 'T1562.004'], [cfg('baseline'), cfg('services'), cfg('full')], norm);
  assert.equal(base.predicted.has('T1003'), false); // Security events were invisible
  assert.equal(svc.predicted.has('T1003'), true); // service rules see the DCSync 4662
  assert.equal(svc.G.has('T1686'), false); // raw label is the retired T1562 …
  assert.equal(full.G.has('T1686') && full.predicted.has('T1686'), true); // … normalized, the netsh fire counts
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

// ── Sigma spec engine (|cidr, |windash, |base64offset, |re flags, |fieldref…) ──
import { windashVariants, base64offsetVariants, inCidr, ruleSupported, ruleModifiers } from './sigma-engine.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const GOLDEN = JSON.parse(readFileSync(fileURLToPath(new URL('./pysigma-golden.json', import.meta.url)), 'utf8'));

test('windash and base64offset expansions are identical to pySigma (golden fixtures from the real corpus)', () => {
  assert.ok(Object.keys(GOLDEN.windash).length >= 5 && Object.keys(GOLDEN.base64offset).length >= 5);
  for (const [v, want] of Object.entries(GOLDEN.windash)) assert.deepEqual([...new Set(windashVariants(v))].sort(), [...want].sort(), `windash ${JSON.stringify(v)}`);
  for (const [v, want] of Object.entries(GOLDEN.base64offset)) assert.deepEqual([...new Set(base64offsetVariants(v))].sort(), [...want].sort(), `base64offset ${JSON.stringify(v)}`);
});

test('|cidr matches v4, v6 and v4-mapped v6 — and the "public IP logon" filter now works', () => {
  assert.equal(inCidr('10.0.0.5', '10.0.0.0/8'), true);
  assert.equal(inCidr('8.8.8.8', '10.0.0.0/8'), false);
  assert.equal(inCidr('::ffff:192.168.1.4', '192.168.0.0/16'), true);
  assert.equal(inCidr('fe80::1', 'fe80::/10'), true);
  assert.equal(inCidr('-', '10.0.0.0/8'), false);
  // the SigmaHQ rule that fired on every lab trace: 4624 type 3, filter = private ranges
  const rule = { detection: {
    selection: { EventID: 4624, LogonType: 3 },
    filter_main_local_ranges: { 'IpAddress|cidr': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] },
    condition: 'selection and not 1 of filter_main_*',
  } };
  const internal = { EventID: 4624, LogonType: 3, IpAddress: '172.18.39.5' };
  const external = { EventID: 4624, LogonType: 3, IpAddress: '203.0.113.9' };
  assert.equal(ruleFires(rule, internal), true); // legacy: |cidr fell back to equals → false positive
  assert.equal(ruleFires(rule, internal, { spec: true }), false); // spec: private logon filtered out
  assert.equal(ruleFires(rule, external, { spec: true }), true); // a real public-IP logon still fires
});

test('|re is case-sensitive per spec unless |i; |fieldref compares two fields; unknown modifiers are refused', () => {
  const ev = { CommandLine: 'POWERSHELL -enc AAAA', SubjectUserName: 'bob', TargetUserName: 'bob' };
  const re = (k) => ({ detection: { s: { [k]: 'powershell' }, condition: 's' } });
  assert.equal(ruleFires(re('CommandLine|re'), ev), true); // legacy: always case-insensitive
  assert.equal(ruleFires(re('CommandLine|re'), ev, { spec: true }), false);
  assert.equal(ruleFires(re('CommandLine|re|i'), ev, { spec: true }), true);
  const fr = { detection: { s: { 'TargetUserName|fieldref': 'SubjectUserName' }, condition: 's' } };
  assert.equal(ruleFires(fr, ev, { spec: true }), true);
  assert.equal(ruleFires(fr, { ...ev, TargetUserName: 'alice' }, { spec: true }), false);
  const wd = { detection: { s: { 'CommandLine|windash|contains': ' -enc ' }, condition: 's' } };
  assert.equal(ruleFires(wd, { CommandLine: 'powershell /enc AAAA' }, { spec: true }), true);
  assert.equal(ruleFires(wd, { CommandLine: 'powershell /enc AAAA' }), false);
  assert.deepEqual([...ruleModifiers({ detection: { s: { 'A|utf16le|base64offset|contains': 'x' }, condition: 's' } })].sort(), ['base64offset', 'contains', 'utf16le']);
  assert.equal(ruleSupported({ detection: { s: { 'A|utf16le|base64offset|contains': 'x' }, condition: 's' } }), false);
  assert.equal(ruleSupported(wd), true);
});
