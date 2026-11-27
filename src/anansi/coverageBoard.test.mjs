import test from 'node:test';
import assert from 'node:assert/strict';
import { COVERAGE_SNAPSHOT, coverageGap } from './coverageBoard.js';

const S = COVERAGE_SNAPSHOT;
const round1 = (x) => Number(x.toFixed(1));

test('coverage snapshot describes a valid slice of the ATT&CK matrix', () => {
  assert.ok(S.enterprise.techniques > 100 && S.enterprise.techniques < 1000);
  assert.ok(S.enterprise.tactics >= 14 && S.enterprise.tactics <= 15);
  const ids = S.surfaces.map((s) => s.id).sort();
  assert.deepEqual(ids, ['active', 'detection', 'explains']);
  for (const s of S.surfaces) {
    assert.ok(s.techniques >= 0 && s.techniques <= S.enterprise.techniques, `${s.id} techniques in range`);
    assert.ok(s.tactics >= 0 && s.tactics <= S.enterprise.tactics, `${s.id} tactics in range`);
    // the printed % must match techniques / enterprise (no fudged coverage)
    assert.equal(round1((100 * s.techniques) / S.enterprise.techniques), round1(s.pct), `${s.id} pct matches count`);
  }
});

test('surfaces grow in the expected order: active ⊂ explains, detection is the new reach', () => {
  const by = Object.fromEntries(S.surfaces.map((s) => [s.id, s]));
  assert.ok(by.active.techniques <= by.explains.techniques, 'active is the narrowest surface');
  assert.ok(by.detection.techniques > by.active.techniques, 'the Sigma detector widens coverage');
});

test('detection scorecard is internally consistent and honestly reported', () => {
  const sc = S.scorecard;
  for (const k of ['f1', 'alertPrecision', 'recall', 'bar']) {
    assert.ok(sc[k] >= 0 && sc[k] <= 1, `${k} is a ratio`);
  }
  assert.ok(sc.breadthDetected <= sc.breadthCovered, 'cannot detect more than the rules cover');
  assert.ok(sc.events > 0 && sc.rules > 0, 'corpus + rule counts present');
  // the detection surface count is exactly the techniques detected ≥ once
  const detection = S.surfaces.find((s) => s.id === 'detection');
  assert.equal(detection.techniques, sc.breadthDetected, 'detection surface == breadth detected');
  // F1 is the harmonic mean of alert precision and recall (± rounding)
  const f1 = (2 * sc.alertPrecision * sc.recall) / (sc.alertPrecision + sc.recall);
  assert.ok(Math.abs(f1 - sc.f1) < 0.01, 'F1 is the harmonic mean of P and R');
});

test('real-telemetry scorecard is internally consistent', () => {
  const tm = S.telemetry;
  assert.ok(tm.captureRecall >= 0 && tm.captureRecall <= 1);
  assert.ok(tm.detected <= tm.captures, 'cannot detect more captures than exist');
  assert.ok(tm.techDetected <= tm.techLabeled, 'cannot detect more techniques than labeled');
  assert.ok(Math.abs(tm.captureRecall - tm.detected / tm.captures) < 0.005, 'recall == detected / captures');
  assert.ok(tm.sensors >= 2, 'multi-sensor');
});

test('coverageGap is a bounded, faithful copilot focus drawn from the snapshot', () => {
  const g = coverageGap();
  assert.equal(g.kind, 'coverage'); // routes the copilot to the gaps prompt
  assert.equal(g.detectionF1, S.scorecard.f1);
  assert.equal(g.bar, S.scorecard.bar);
  assert.deepEqual(g.undetectedTechniques, S.telemetry.undetected);
  assert.equal(g.realTelemetryRecall, S.telemetry.captureRecall);
  // every undetected id is a real ATT&CK technique id (the detection to-do list)
  for (const id of g.undetectedTechniques) assert.match(id, /^T\d{4}(\.\d{3})?$/);
  // drift is flattened to from→to strings, one per snapshot drift entry
  assert.equal(g.drift.length, S.drift.length);
});

test('ATT&CK drift entries resolve a retired id to a live replacement', () => {
  assert.ok(S.drift.length >= 1);
  for (const d of S.drift) {
    assert.match(d.from, /^T\d{4}(\.\d{3})?$/);
    assert.match(d.to, /^T\d{4}(\.\d{3})?$/);
    assert.notEqual(d.from, d.to);
    assert.ok(typeof d.name === 'string' && d.name.length);
  }
});
