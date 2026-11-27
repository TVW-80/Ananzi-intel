import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseWatchConfig, crtShUrl, parseCrtShResults, extractLookalikes, classifyDomain, isHostname,
  mergeFindings, buildCertWatchAlerts, DEFAULT_WATCH,
} from './cert-transparency.js';

const paypal = DEFAULT_WATCH.find((w) => w.brand === 'PayPal');

test('classifyDomain uses the Public Suffix List, so brand ccTLD sites are never flagged', () => {
  // official — the registered name's own label IS the brand, under any suffix
  for (const legit of ['paypal.com', 'www.paypal.com', 'paypal.de', 'paypal.com.au', 'paypal.co.id', 'imzala.paypal.com.tr']) {
    assert.equal(classifyDomain(legit, paypal).verdict, 'legit', `${legit} must be legit (PSL ccTLD)`);
  }
  // allowlisted embedded-brand infrastructure
  assert.equal(classifyDomain('obsnessie.paypalinc.com', paypal).verdict, 'legit');
  assert.equal(classifyDomain('login.paypalcorp.com', paypal).verdict, 'legit');
  // squat — brand word embedded in a registered name that isn't the brand
  const squat = classifyDomain('paypal-login-secure.com', paypal);
  assert.deepEqual(squat, { verdict: 'lookalike', pattern: 'squat' });
  assert.equal(classifyDomain('paypal-techsupport.com', paypal).pattern, 'squat');
  assert.equal(classifyDomain('paypal--checkout.pages.dev', paypal).pattern, 'squat');
  // deception — the real domain used as a sub-label of an unrelated registrable domain
  assert.deepEqual(classifyDomain('signin.paypal.com.account-verify.ru', paypal), { verdict: 'lookalike', pattern: 'deception' });
  // unrelated — brand word only inside someone else's domain (e.g. Xoom infra)
  assert.equal(classifyDomain('paypal-services.xoom.com', paypal).verdict, 'ignore');
  assert.equal(classifyDomain('not-a-host', paypal).verdict, 'ignore');
});

test('isHostname rejects the org-name lines crt.sh mixes into name_value', () => {
  assert.equal(isHostname('paypal-login-secure.com'), true);
  assert.equal(isHostname('paypal, inc.'), false); // the trap
  assert.equal(isHostname('PayPal'), false);
});

// Real crt.sh rows captured live 2026-11-27 (legit PayPal infra + the "PayPal, Inc." org line).
const realLegitRows = [
  { id: 30083090858, issuer_name: 'C=US, O=DigiCert Inc, CN=DigiCert Global', not_before: '2026-10-01T00:00:00', common_name: 'obsnessie.paypalinc.com', name_value: 'nessieotel-vip.ccg01.phx.paypalinc.com\nobsnessie.paypalinc.com\nPayPal, Inc.' },
  { id: 29352335165, issuer_name: 'C=US, O=DigiCert Inc, CN=DigiCert Global', not_before: '2026-09-11T00:00:00', common_name: 'c3osmosis.paypalinc.com', name_value: 'osmosis-vip.ccg01.paypalc3.com\nc3osmosis.paypalinc.com\nPayPal, Inc.' },
  { id: 111, issuer_name: 'CN=x', not_before: '2026-01-01T00:00:00', common_name: 'www.paypal.com.au', name_value: 'www.paypal.com.au\npaypal.com.au' },
];
const lookalikeRows = [
  { id: 900001, issuer_name: "C=US, O=Let's Encrypt, CN=R3", not_before: '2026-11-27T00:00:00', common_name: 'paypal-login-secure.com', name_value: 'paypal-login-secure.com\nwww.paypal-login-secure.com' },
  { id: 900002, issuer_name: "C=US, O=Let's Encrypt, CN=R3", not_before: '2026-11-26T00:00:00', common_name: 'signin.paypal.com.account-verify.ru', name_value: 'signin.paypal.com.account-verify.ru' },
];

test('extractLookalikes leaves real brand infra (incl. ccTLD) alone and flags impostors', () => {
  assert.deepEqual(extractLookalikes(parseCrtShResults(realLegitRows), paypal), [], 'legit paypalinc/paypalc3/paypal.com.au must not flag');
  assert.equal(parseCrtShResults(realLegitRows).some((r) => r.domain.includes(',')), false, 'the org-name line is never a domain');
  const bad = extractLookalikes(parseCrtShResults(lookalikeRows), paypal);
  assert.deepEqual(bad.map((f) => f.domain).sort(), ['paypal-login-secure.com', 'signin.paypal.com.account-verify.ru', 'www.paypal-login-secure.com']);
  assert.ok(bad.every((f) => f.brand === 'PayPal' && f.certId && f.pattern));
});

test('parseWatchConfig falls back to defaults, and parses a custom watchlist', () => {
  assert.equal(parseWatchConfig(''), DEFAULT_WATCH);
  const custom = parseWatchConfig('Acme:acme:acme.io,acme-corp.com ; Globex:globex');
  assert.equal(custom.length, 2);
  assert.deepEqual(custom[0], { brand: 'Acme', label: 'acme', allow: ['acme.io', 'acme-corp.com'] });
  assert.deepEqual(custom[1], { brand: 'Globex', label: 'globex', allow: [] });
});

test('crtShUrl encodes the token and carries the JSON/limit params', () => {
  const u = crtShUrl('pay pal', { limit: 50 });
  assert.match(u, /q=pay%20pal/);
  assert.match(u, /output=json/);
  assert.match(u, /limit=50/);
});

test('mergeFindings dedupes, stamps firstSeen, prunes old, caps, newest first', () => {
  const store = [];
  let t = 1000;
  mergeFindings(store, [{ certId: 1, domain: 'a.com', brand: 'X' }], { now: () => t });
  mergeFindings(store, [{ certId: 1, domain: 'a.com', brand: 'X' }, { certId: 2, domain: 'b.com', brand: 'X' }], { now: () => (t = 2000) });
  assert.equal(store.length, 2);
  assert.equal(store[0].domain, 'b.com'); // newest first
  assert.equal(store.find((f) => f.certId === 1).firstSeen, 1000); // kept from first sight
  mergeFindings(store, [], { now: () => 1000 + 4 * 24 * 60 * 60 * 1000, maxAgeMs: 3 * 24 * 60 * 60 * 1000 });
  assert.equal(store.length, 0); // pruned
  mergeFindings(store, Array.from({ length: 80 }, (_, i) => ({ certId: i, domain: `d${i}.com`, brand: 'X' })), { now: () => 5000, cap: 60 });
  assert.equal(store.length, 60);
});

test('buildCertWatchAlerts defangs, labels a lead not a verdict, links the cert', () => {
  const [a] = buildCertWatchAlerts([{ certId: 900001, domain: 'paypal-login-secure.com', brand: 'PayPal', pattern: 'squat', issuer: 'R3', notBefore: '2026-11-27T00:00:00', firstSeen: 1 }]);
  assert.equal(a.source, 'Cert watch');
  assert.match(a.title, /impersonating PayPal/);
  assert.match(a.plain, /paypal-login-secure\[\.\]com/); // defanged
  assert.match(a.plain, /lead to investigate, not a confirmed attack/);
  assert.equal(a.link, 'https://crt.sh/?id=900001');
  const [d] = buildCertWatchAlerts([{ certId: 2, domain: 'signin.paypal.com.evil.ru', brand: 'PayPal', pattern: 'deception', firstSeen: 1 }]);
  assert.match(d.plain, /real domain as a sub-label/);
});
