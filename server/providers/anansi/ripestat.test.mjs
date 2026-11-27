import test from 'node:test';
import assert from 'node:assert/strict';
import { parseRpkiValidation, parseAsHolder, enrichHijacksWithRipe, RPKI_UI } from './ripestat.js';

// Payloads below are the real RIPEstat Data API shapes, captured live 2026-11-27.
const rpkiInvalidAsn = { data: { status: 'invalid_asn', validating_roas: [{ origin: '3333', prefix: '193.0.0.0/21', validity: 'invalid_asn', max_length: 21 }] } };
const rpkiInvalidLength = { data: { status: 'invalid_length', validating_roas: [{ origin: '3333', prefix: '193.0.0.0/21', validity: 'invalid_length', max_length: 21 }] } };
const rpkiValid = { data: { status: 'valid', validating_roas: [{ origin: '3333', prefix: '193.0.0.0/21', validity: 'valid', max_length: 21 }] } };
const rpkiUnknown = { data: { status: 'unknown', validating_roas: [] } };
const asOverview = { data: { holder: 'RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre (RIPE NCC)', announced: true, resource: '3333', type: 'as' } };

test('parseRpkiValidation names the authorized AS and flags the hijack-supporting states', () => {
  const inv = parseRpkiValidation(rpkiInvalidAsn, 64500);
  assert.equal(inv.status, 'invalid_asn');
  assert.equal(inv.invalid, true);
  assert.equal(inv.hijackEvidence, true);
  assert.equal(inv.roaOrigin, 3333);
  assert.match(inv.technical, /authorizes origin AS3333/);
  assert.match(inv.plain, /only AS3333 may announce/);
  assert.match(inv.plain, /AS64500/); // the suspected hijacker

  const len = parseRpkiValidation(rpkiInvalidLength, 64500);
  assert.equal(len.status, 'invalid_length');
  assert.equal(len.hijackEvidence, true);
  assert.equal(len.roaMaxLength, 21);
  assert.match(len.technical, /max length \/21/);

  // A VALID status weakens the hijack claim — surfaced, not hidden.
  const ok = parseRpkiValidation(rpkiValid, 3333);
  assert.equal(ok.invalid, false);
  assert.equal(ok.hijackEvidence, false);
  assert.match(ok.plain, /may be a false alarm/);

  const unk = parseRpkiValidation(rpkiUnknown, 64500);
  assert.equal(unk.status, 'unknown');
  assert.equal(unk.hijackEvidence, false);
  assert.equal(unk.roaOrigin, null);

  // Garbage in → a safe "unknown" finding, never a throw.
  const empty = parseRpkiValidation(null, 1);
  assert.equal(empty.status, 'unknown');
  assert.equal(empty.label, RPKI_UI.unknown.label);
});

test('parseAsHolder pulls the holder name, null when absent', () => {
  assert.match(parseAsHolder(asOverview), /RIPE NCC/);
  assert.equal(parseAsHolder({ data: {} }), null);
  assert.equal(parseAsHolder(null), null);
});

/** A fetch stub that answers RIPEstat URLs from a fixture map and counts calls. */
function stubFetch(routes) {
  const calls = [];
  const impl = async (url) => {
    calls.push(url);
    for (const [needle, payload] of routes) {
      if (url.includes(needle)) {
        if (payload instanceof Error) throw payload;
        return { ok: true, status: 200, json: async () => payload };
      }
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return { impl, calls };
}

test('enrichHijacksWithRipe attaches RPKI, fills a missing holder, and bounds its work', async () => {
  const { impl, calls } = stubFetch([
    ['rpki-validation/data.json?resource=AS64500', rpkiInvalidAsn],
    ['as-overview/data.json?resource=AS64500', asOverview],
  ]);
  const events = [
    { id: 'a', hijackerAsn: 64500, hijackerOrg: '', prefixes: ['193.0.0.0/24'], victimCountries: ['NL'] },
    { id: 'b', hijackerAsn: null, prefixes: ['10.0.0.0/8'] }, // no ASN → skipped
    { id: 'c', hijackerAsn: 64500, hijackerOrg: 'Known Org', prefixes: [] }, // no prefix → skipped
  ];
  const out = await enrichHijacksWithRipe(events, { fetchImpl: impl, now: () => 1000 });
  assert.equal(out, events);
  assert.equal(events[0].rpki.status, 'invalid_asn');
  assert.equal(events[0].hijackerOrg, asOverview.data.holder); // empty org filled from RIPEstat
  assert.equal(events[1].rpki, undefined); // skipped, untouched
  assert.equal(events[2].rpki, undefined);
  assert.equal(calls.length, 2); // one rpki + one holder, only for the eligible event
});

test('enrichHijacksWithRipe is best-effort: a RIPEstat failure leaves the hijack unchanged', async () => {
  const { impl } = stubFetch([['rpki-validation', new Error('network down')]]);
  const events = [{ id: 'a', hijackerAsn: 64500, hijackerOrg: 'Org', prefixes: ['1.2.3.0/24'] }];
  const out = await enrichHijacksWithRipe(events, { fetchImpl: impl, now: () => 1 });
  assert.equal(out[0].rpki, undefined); // no crash, no field
});

test('enrichHijacksWithRipe caches by AS+prefix, so a refresh makes no new calls', async () => {
  const { impl, calls } = stubFetch([['rpki-validation', rpkiValid]]);
  const cache = new Map();
  const mk = () => [{ id: 'a', hijackerAsn: 3333, hijackerOrg: 'RIPE', prefixes: ['193.0.0.0/21'] }];
  await enrichHijacksWithRipe(mk(), { fetchImpl: impl, cache, now: () => 1000 });
  await enrichHijacksWithRipe(mk(), { fetchImpl: impl, cache, now: () => 2000 });
  assert.equal(calls.length, 1); // second run served from cache (org present → no holder call)
});

test('enrichHijacksWithRipe handles an empty list without calling out', async () => {
  const { impl, calls } = stubFetch([]);
  assert.deepEqual(await enrichHijacksWithRipe([], { fetchImpl: impl }), []);
  assert.deepEqual(await enrichHijacksWithRipe(null, { fetchImpl: impl }), []);
  assert.equal(calls.length, 0);
});
