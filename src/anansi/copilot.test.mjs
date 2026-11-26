import test from 'node:test';
import assert from 'node:assert/strict';
import { groundingContext } from './copilot.js';

test('groundingContext is safe on empty input and always carries the coverage', () => {
  const g = groundingContext(null);
  assert.deepEqual(g.topSources, []);
  assert.deepEqual(g.alerts, []);
  assert.ok(g.attackCoverage && Array.isArray(g.attackCoverage.surfaces));
  assert.deepEqual(g.attackCoverage.surfaces.map((s) => s.id).sort(), ['active', 'detection', 'explains']);
  assert.match(g.note, /hypothesis/);
});

test('groundingContext bounds the live snapshot it forwards', () => {
  const attack = {
    updatedAt: '2026-11-26T00:00:00Z',
    rate: { perMinute: 5 },
    sources: Array.from({ length: 40 }, (_, i) => ({ name: `src${i}`, weight: 0.5, dominantService: 'ssh' })),
    alerts: Array.from({ length: 40 }, (_, i) => ({ source: 'X', title: `t${i}`, plain: 'p', time: null })),
    attackTypes: [{ label: 'SSH', count: 9 }],
    ddos: { targets: [{ name: 'US', value: 1.4 }] },
    exposure: [{ label: 'RDP', total: 10 }],
  };
  const g = groundingContext(attack);
  assert.equal(g.topSources.length, 10); // capped
  assert.equal(g.alerts.length, 12);     // capped
  assert.equal(g.rate, 5);
  assert.equal(g.topSources[0].place, 'src0');
  assert.equal(g.ddosTargets[0].country, 'US');
});
