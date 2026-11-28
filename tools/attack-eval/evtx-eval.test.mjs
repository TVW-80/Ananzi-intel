import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ruleFires } from './sigma-engine.mjs';
import { LEVEL_RANK } from './telemetry-eval.mjs';
import { scoreCaptureDetection, evaluate } from './evtx-eval.mjs';

// A minimal detector: one process_creation rule that fires on mimikatz.exe.
const mimikatzRule = {
  detection: { selection: { 'Image|endswith': '\\mimikatz.exe' }, condition: 'selection' },
  rank: LEVEL_RANK.high, needsSpec: false, specSupported: true, id: 'test-mimikatz', level: 'high',
};
const byCat = new Map([['process_creation', [mimikatzRule]]]);

// Security 4688 process creation → routes maps NewProcessName onto Image.
const malicious = { Channel: 'Security', EventID: 4688, NewProcessName: 'C:\\temp\\mimikatz.exe' };
const benign = { Channel: 'Security', EventID: 4688, NewProcessName: 'C:\\windows\\notepad.exe' };

test('scoreCaptureDetection fires on a malicious event and records its level', () => {
  const r = scoreCaptureDetection([benign, malicious], byCat);
  assert.equal(r.fired, true);
  assert.equal(r.maxRank, LEVEL_RANK.high);
});

test('scoreCaptureDetection stays silent when no rule matches', () => {
  const r = scoreCaptureDetection([benign, benign], byCat);
  assert.equal(r.fired, false);
  assert.equal(r.maxRank, -1);
});

test('scoreCaptureDetection ignores unroutable events without throwing', () => {
  const r = scoreCaptureDetection([null, 42, { Channel: 'Application', EventID: 9999 }], byCat);
  assert.equal(r.fired, false);
});

test('a high-level fire counts toward medium+ but a low-level fire does not', () => {
  const low = { ...mimikatzRule, rank: LEVEL_RANK.low, level: 'low' };
  const lowCat = new Map([['process_creation', [low]]]);
  assert.equal(scoreCaptureDetection([malicious], byCat).maxRank >= LEVEL_RANK.medium, true);
  assert.equal(scoreCaptureDetection([malicious], lowCat).maxRank >= LEVEL_RANK.medium, false);
});

test('evaluate tallies detection rate overall and per tactic, and lists blind spots', () => {
  const caps = [
    { id: 'a', tactic: 'execution', events: [malicious] },
    { id: 'b', tactic: 'execution', events: [benign] },
    { id: 'c', tactic: 'discovery', events: [benign] },
  ];
  const rep = evaluate(caps, byCat);
  assert.equal(rep.captures, 3);
  assert.equal(rep.detectedAny, 1);
  assert.equal(rep.detectionRateAny, 0.3333);
  assert.equal(rep.byTactic.execution.any, 1);
  assert.equal(rep.byTactic.execution.total, 2);
  assert.equal(rep.byTactic.discovery.any, 0);
  // blind spots = the two benign-only captures, never the detected one
  assert.deepEqual(rep.silent.map((s) => s.id).sort(), ['b', 'c']);
});

test('evaluate on no captures yields a zero report, not NaN', () => {
  const rep = evaluate([], byCat);
  assert.equal(rep.captures, 0);
  assert.equal(rep.detectionRateAny, 0);
  assert.equal(rep.detectionRateMedium, 0);
  assert.deepEqual(rep.silent, []);
});

// Guard the routing assumption the eval leans on.
test('routes-dependent: the mimikatz rule only fires through the Image mapping', () => {
  // Without the 4688→Image mapping the rule would never match NewProcessName.
  assert.equal(ruleFires(mimikatzRule, { Image: 'C:\\temp\\mimikatz.exe' }), true);
  assert.equal(ruleFires(mimikatzRule, { NewProcessName: 'C:\\temp\\mimikatz.exe' }), false);
});
