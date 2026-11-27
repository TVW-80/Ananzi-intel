import test from 'node:test';
import assert from 'node:assert/strict';
import { COVERAGE_DATA } from './coverageData.generated.js';
import { deltaPts, niceCeil, scale, matrixStats, mitreUrl, pct, EVIDENCE_ORDER, EVIDENCE_UI } from './coverageLab.js';

test('formatting helpers say exactly what changed', () => {
  assert.equal(deltaPts(0.705, 0.579), '▲ 12.6 pts');
  assert.equal(deltaPts(0.182, 0.238), '▼ 5.6 pts');
  assert.equal(deltaPts(0.1815, 0.238), '▼ 5.6 pts'); // 18.2% vs 23.8% as displayed — never 5.7
  assert.equal(deltaPts(0.5, 0.5), '± 0 pts');
  assert.equal(pct(0.7053), '70.5%');
  assert.equal(niceCeil(31.1), 40);
  assert.equal(niceCeil(0.2), 10);
  assert.equal(scale(0, 1, 38, 346)(0.5), 192);
  assert.equal(mitreUrl('T1003.006'), 'https://attack.mitre.org/techniques/T1003/006/');
});

test('matrixStats tallies each technique once and agrees with the real-telemetry judge', () => {
  const s = matrixStats(COVERAGE_DATA.matrix);
  const total = Object.values(s.byEvidence).reduce((a, b) => a + b, 0);
  assert.equal(total, s.techniques.size);
  assert.equal(s.perTactic.length, COVERAGE_DATA.matrix.length);
  const tm = COVERAGE_DATA.telemetry;
  // every technique the matrix marks detected / missed is one the judge reported as such
  for (const r of s.techniques.values()) {
    if (r.ev === 'T') assert.ok(!tm.undetected.includes(r.id), `${r.id} marked detected but judge says undetected`);
    if (r.ev === 'M') assert.ok(tm.undetected.includes(r.id), `${r.id} marked missed but judge did not report it`);
  }
  assert.ok(s.byEvidence.T > 0 && s.byEvidence.T <= tm.techDetected);
  // every evidence level has a label; only the two real-trace outcomes carry a glyph
  assert.deepEqual(EVIDENCE_ORDER.filter((e) => EVIDENCE_UI[e].glyph), ['T', 'M']);
});
