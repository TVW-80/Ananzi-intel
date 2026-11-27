/**
 * Certificate Transparency lookalike watch — keyless brand-impersonation intel.
 *
 * Every TLS certificate issued on the public web is logged to Certificate
 * Transparency. crt.sh exposes those logs as JSON. For a defender the valuable
 * signal is: "a certificate was just minted for a domain that impersonates a
 * brand" — caught the moment the attacker provisions HTTPS, often before the
 * first phishing email goes out.
 *
 * Done properly with the Public Suffix List (via tldts), so the registrable
 * domain is computed correctly and the brand's own country sites are NOT
 * mislabelled. The classifier is deliberately precision-first:
 *   • legit   — the registered name's own label IS the brand (`paypal.com`,
 *               `paypal.de`, `paypal.com.au` — any ccTLD, for free), or the
 *               registrable domain is on the brand's allowlist;
 *   • lookalike/squat      — the brand word is embedded in a registered name
 *               that isn't the brand (`paypal-login.com`, `paypal-techsupport.com`);
 *   • lookalike/deception  — the brand's real domain is used as a subdomain of
 *               an unrelated registrable domain (`signin.paypal.com.evil.ru`);
 *   • ignore  — the brand word only appears inside someone else's unrelated name.
 *
 * Honest by construction: a lookalike is a LABELED HYPOTHESIS, never a verdict.
 * A legitimate reseller, a researcher, or a brand's niche domain can trip it, so
 * every alert says "a lead, not a confirmed attack". Keyless (crt.sh, no token);
 * crt.sh is slow and flaky, so the Attack Map queries ONE brand per refresh,
 * accumulates findings, and never fails the snapshot if crt.sh is down.
 */

import { parse } from 'tldts';

/**
 * Default brands to watch. `label` is the brand's official registered-name
 * label (any public suffix on it is treated as the brand); `allow` lists the
 * brand's OTHER registrable domains whose name also embeds the brand word, so
 * they aren't flagged as squats (e.g. paypalinc.com). Domains that don't embed
 * the brand word at all — icloud.com, amazonaws.com — never need listing.
 */
export const DEFAULT_WATCH = Object.freeze([
  Object.freeze({ brand: 'Microsoft', label: 'microsoft', allow: Object.freeze(['microsoftonline.com', 'microsoftstore.com', 'microsoft365.com', 'microsoft.net', 'microsoftonline-p.com']) }),
  Object.freeze({ brand: 'PayPal', label: 'paypal', allow: Object.freeze(['paypalinc.com', 'paypalcorp.com', 'paypalobjects.com', 'paypalcredit.com', 'paypal-communication.com', 'paypalc3.com', 'paypal-mktg.com']) }),
  Object.freeze({ brand: 'Apple', label: 'apple', allow: Object.freeze(['apple-cloudkit.com', 'apple.news']) }),
  Object.freeze({ brand: 'Coinbase', label: 'coinbase', allow: Object.freeze(['coinbasecloud.com', 'coinbase-corp.com']) }),
]);

const MAX_AGE_MS = 3 * 24 * 60 * 60 * 1000; // forget a finding after 3 days
const STORE_CAP = 60;

/**
 * Parse CT_WATCH: "Brand:label:allow1,allow2; Brand2:label2" → watch list.
 * Falls back to DEFAULT_WATCH when unset or unparseable.
 */
export function parseWatchConfig(raw) {
  const text = String(raw || '').trim();
  if (!text) return DEFAULT_WATCH;
  const out = [];
  for (const entry of text.split(';')) {
    const [brand, label, allow] = entry.split(':').map((s) => String(s || '').trim());
    if (!brand || !label) continue;
    out.push({
      brand,
      label: label.toLowerCase(),
      allow: String(allow || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
    });
  }
  return out.length ? out : DEFAULT_WATCH;
}

/** crt.sh JSON query URL for one brand label. */
export function crtShUrl(token, { base = 'https://crt.sh', limit = 150 } = {}) {
  return `${base}/?q=${encodeURIComponent(token)}&output=json&exclude=expired&limit=${limit}`;
}

const cleanName = (n) => String(n || '').trim().toLowerCase().replace(/^\*\./, '');
// A real DNS hostname — rejects the org-name lines crt.sh mixes into name_value
// (e.g. "PayPal, Inc." has a space and comma and is not a host).
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9_-]{1,63}\.)+[a-z]{2,63}$/;
export const isHostname = (s) => HOSTNAME.test(String(s || ''));

/**
 * Pure (PSL-backed): classify one hostname against a watched brand.
 * @returns {{ verdict: 'legit'|'ignore'|'lookalike', pattern?: 'squat'|'deception' }}
 */
export function classifyDomain(host, item) {
  // allowPrivateDomains treats hosting platforms (pages.dev, github.io, …) as
  // registrable boundaries, so `paypal--checkout.pages.dev` reads as a squat on
  // the attacker's own space rather than a subdomain of "pages.dev".
  const info = parse(String(host || ''), { allowPrivateDomains: true });
  const reg = info.domain; // registrable domain (eTLD+1), null for a bare suffix
  if (!reg) return { verdict: 'ignore' };
  const label = String(item.label || '').toLowerCase();
  const nameLabel = String(info.domainWithoutSuffix || '').toLowerCase(); // the registered name's own label
  const subLabels = String(info.subdomain || '').toLowerCase().split('.').filter(Boolean);

  if (nameLabel === label) return { verdict: 'legit' }; // paypal.com, paypal.de, paypal.com.au …
  if ((item.allow || []).includes(reg)) return { verdict: 'legit' }; // brand's other embedded-brand domains
  if (nameLabel.includes(label)) return { verdict: 'lookalike', pattern: 'squat' }; // paypal-login.com
  if (subLabels.includes(label)) return { verdict: 'lookalike', pattern: 'deception' }; // signin.paypal.com.evil.ru
  return { verdict: 'ignore' };
}

/** Pure: crt.sh JSON payload → flat list of { certId, domain, issuer, notBefore }. */
export function parseCrtShResults(payload) {
  const rows = Array.isArray(payload) ? payload : [];
  const out = [];
  for (const r of rows) {
    const certId = Number(r?.id) || null;
    const issuer = String(r?.issuer_name || '').replace(/^.*\bCN=/, '').trim() || String(r?.issuer_name || '').trim();
    const notBefore = String(r?.not_before || '') || null;
    const names = new Set();
    for (const part of String(r?.name_value || '').split(/\s*\n\s*/)) { const c = cleanName(part); if (isHostname(c)) names.add(c); }
    const cn = cleanName(r?.common_name);
    if (isHostname(cn)) names.add(cn);
    for (const domain of names) out.push({ certId, domain, issuer, notBefore });
  }
  return out;
}

/** Pure: keep only the rows that impersonate the watched brand (squat or deception). */
export function extractLookalikes(rows, item) {
  const seen = new Set();
  const out = [];
  for (const row of rows) {
    const { verdict, pattern } = classifyDomain(row.domain, item);
    if (verdict !== 'lookalike') continue;
    const key = `${row.certId}|${row.domain}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ certId: row.certId, domain: row.domain, brand: item.brand, pattern, issuer: row.issuer, notBefore: row.notBefore });
  }
  return out;
}

/**
 * Merge new findings into a rolling store (mutates + returns it): dedup by
 * cert+domain, stamp firstSeen on first sight, prune old, cap, newest first.
 */
export function mergeFindings(store, found, { now = Date.now, maxAgeMs = MAX_AGE_MS, cap = STORE_CAP } = {}) {
  const at = now();
  const index = new Map(store.map((f) => [`${f.certId}|${f.domain}`, f]));
  for (const f of found) {
    const key = `${f.certId}|${f.domain}`;
    if (!index.has(key)) { const rec = { ...f, firstSeen: at }; index.set(key, rec); store.push(rec); }
  }
  const kept = store
    .filter((f) => at - f.firstSeen < maxAgeMs)
    .sort((a, b) => b.firstSeen - a.firstSeen)
    .slice(0, cap);
  store.length = 0;
  store.push(...kept);
  return store;
}

const defang = (d) => String(d).replace(/\./g, '[.]');

/** Findings → Attack Map alert items ({ source, title, plain, technical, link, time }). */
export function buildCertWatchAlerts(findings, { limit = 6 } = {}) {
  return (findings || []).slice(0, limit).map((f) => {
    const how = f.pattern === 'deception'
      ? `uses ${f.brand}’s real domain as a sub-label of an unrelated domain`
      : `embeds “${f.brand}” in a domain that isn’t ${f.brand}’s`;
    return {
      source: 'Cert watch',
      title: `New certificate impersonating ${f.brand}: ${defang(f.domain)}`,
      plain: `A TLS certificate was just issued for ${defang(f.domain)}, which ${how} — a common phishing setup. Treat it as a lead to investigate, not a confirmed attack.`,
      technical: `crt.sh CT log: cert ${f.certId} for ${f.domain} (issuer ${f.issuer || 'n/a'}; not_before ${f.notBefore || 'n/a'}); PSL-classified ${f.pattern} impersonation of ${f.brand}.`,
      link: f.certId ? `https://crt.sh/?id=${f.certId}` : 'https://crt.sh/',
      time: f.notBefore ? `${f.notBefore}Z`.replace(/Z+$/, 'Z') : null,
    };
  });
}
