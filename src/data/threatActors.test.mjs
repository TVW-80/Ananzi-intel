import test from 'node:test';
import assert from 'node:assert/strict';
import { actorsForTechniques, actorLeadLabel, actorLeadsForIncident } from './threatActors.js';
import { THREAT_ACTORS } from './threatActors.generated.js';

test('generated actor data is well-formed (ATT&CK groups + MISP country)', () => {
  assert.ok(THREAT_ACTORS.length > 100, 'has the ATT&CK group set');
  const apt29 = THREAT_ACTORS.find((a) => a.id === 'G0016');
  assert.ok(apt29, 'APT29 present');
  assert.equal(apt29.country, 'RU'); // from MISP galaxy
  assert.ok(apt29.techniques.length > 10 && apt29.techniques.every((t) => /^T\d{4}$/.test(t)));
  assert.ok(Array.isArray(apt29.aliases) && apt29.aliases.length && apt29.aliases.every((a) => typeof a === 'string' && a));
});

test('actorsForTechniques ranks by overlap, needs a real overlap, folds sub-techniques', () => {
  const apt29 = THREAT_ACTORS.find((a) => a.id === 'G0016');
  // feed six of APT29's own techniques (one as a sub-technique id) → APT29 is a lead
  const ids = [...apt29.techniques.slice(0, 6)];
  ids[0] = `${ids[0]}.001`; // sub-technique must fold to its parent
  const hits = actorsForTechniques(ids, { limit: 20 });
  const a = hits.find((x) => x.id === 'G0016');
  assert.ok(a, 'APT29 is among the leads for its own techniques');
  assert.equal(a.overlap, 6);
  assert.equal(a.of, 6);
  // results are sorted by overlap, strongest first
  assert.ok(hits.every((x, k) => k === 0 || hits[k - 1].overlap >= x.overlap));

  // below the minimum overlap → nothing (a single shared technique is not a lead)
  assert.deepEqual(actorsForTechniques(['T1059'], { minOverlap: 2 }), []);
  assert.deepEqual(actorsForTechniques([]), []);
  assert.equal(actorsForTechniques(apt29.techniques, { limit: 3 }).length, 3, 'honours the limit');
});

test('actorLeadLabel reads as a lead, and incident helper pulls technique ids', () => {
  const label = actorLeadLabel({ name: 'APT29', aliases: ['Cozy Bear', 'NOBELIUM'], country: 'RU', overlap: 4, of: 6 });
  assert.match(label, /APT29 \(aka Cozy Bear, NOBELIUM · RU\) — 4 of 6 techniques/);
  const apt29 = THREAT_ACTORS.find((a) => a.id === 'G0016');
  const leads = actorLeadsForIncident({ techniques: apt29.techniques.slice(0, 8).map((id) => ({ id })) }, { limit: 30 });
  assert.ok(leads.some((a) => a.id === 'G0016'));
});
