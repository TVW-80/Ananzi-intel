/**
 * RIPEstat (RIPE NCC) BGP enrichment — keyless corroboration for the Attack
 * Map's hijack arcs.
 *
 * Cloudflare Radar tells us a hijack is SUSPECTED. RIPEstat's RPKI validation
 * is the independent, authoritative second opinion: a Route Origin Authorization
 * (ROA) is the real address-holder's cryptographically signed statement of which
 * AS may announce a prefix. If the suspected hijacker's AS is not the authorized
 * origin, the announcement is RPKI-invalid — the single strongest public signal
 * that the route really is a hijack. Conversely, an RPKI-valid status is a
 * reason to doubt the alert, which we surface honestly rather than hide.
 *
 * Keyless (stat.ripe.net Data API — no token, CORS-open, generous). Best-effort
 * and polite: one prefix per hijack, a small cache, bounded concurrency, a short
 * timeout; ANY failure leaves the hijack exactly as it was. Correlation stays a
 * hypothesis — this adds evidence, it does not manufacture certainty.
 *
 * Response shapes verified live against the RIPEstat Data API (2026-11-27):
 *   rpki-validation  data.status ∈ valid | invalid_asn | invalid_length | unknown
 *                    data.validating_roas[] = { origin, prefix, max_length, validity }
 *   as-overview      data = { holder, announced, resource, type }
 */

export const RIPESTAT_BASE = 'https://stat.ripe.net/data';
const USER_AGENT = 'Ananzi/1.0 (personal threat-intel research dashboard)';
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // ROAs change slowly; 6h is plenty.

/** Display metadata per RPKI status. `hijackEvidence` = this status supports the hijack claim. */
export const RPKI_UI = Object.freeze({
  invalid_asn: Object.freeze({ label: 'RPKI INVALID · wrong AS', hijackEvidence: true }),
  invalid_length: Object.freeze({ label: 'RPKI INVALID · too specific', hijackEvidence: true }),
  valid: Object.freeze({ label: 'RPKI valid', hijackEvidence: false }),
  unknown: Object.freeze({ label: 'RPKI unknown · no ROA', hijackEvidence: false }),
});

/** Pure: an rpki-validation payload → a compact, display-ready finding. */
export function parseRpkiValidation(payload, hijackerAsn) {
  const d = (payload && payload.data) || {};
  const status = String(d.status || 'unknown');
  const roa = (d.validating_roas || [])[0] || null;
  const ui = RPKI_UI[status] || RPKI_UI.unknown;
  const roaOrigin = roa && roa.origin != null ? Number(roa.origin) : null;
  const roaMaxLength = roa && roa.max_length != null ? Number(roa.max_length) : null;
  let plain;
  let technical;
  if (status === 'invalid_asn') {
    plain = `The address owner's signed records say only AS${roaOrigin} may announce this block — not AS${hijackerAsn}. A strong sign this really is a hijack.`;
    technical = `RPKI invalid_asn: a ROA authorizes origin AS${roaOrigin} for this prefix; the announcing AS${hijackerAsn} is not authorized.`;
  } else if (status === 'invalid_length') {
    plain = 'The announcement carves out a smaller slice of addresses than the owner authorized — the classic way to quietly steal a route.';
    technical = `RPKI invalid_length: the announced prefix is more specific than the ROA max length /${roaMaxLength} (origin AS${roaOrigin}).`;
  } else if (status === 'valid') {
    plain = "The owner's signed records DO authorize this announcement, so this alert may be a false alarm rather than a hijack.";
    technical = `RPKI valid: a ROA authorizes AS${roaOrigin} for this prefix, consistent with the announcement.`;
  } else {
    plain = "The address owner hasn't published signed routing records, so RPKI can't confirm or rule out this one.";
    technical = 'RPKI unknown: no ROA covers this prefix/AS pair.';
  }
  return {
    status,
    label: ui.label,
    hijackEvidence: Boolean(ui.hijackEvidence),
    invalid: status.startsWith('invalid'),
    roaOrigin,
    roaMaxLength,
    plain,
    technical,
  };
}

/** Pure: an as-overview payload → the AS holder name, or null. */
export function parseAsHolder(payload) {
  const holder = String(((payload && payload.data) || {}).holder || '').trim();
  return holder || null;
}

/** Run `fn` over `items` with at most `n` in flight; never rejects (best-effort). */
async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try { await fn(items[idx], idx); } catch { /* best-effort: skip this one */ }
    }
  });
  await Promise.all(workers);
}

/**
 * Enrich suspected hijacks (normalized Cloudflare events) in place with RIPEstat
 * RPKI validation and, when the org name is missing, the AS holder. Returns the
 * same array. Only the first `limit` events that carry an ASN + prefix are
 * queried, so the cost is bounded regardless of how many hijacks are live.
 */
export async function enrichHijacksWithRipe(events, {
  fetchImpl = (...a) => fetch(...a),
  cache = new Map(),
  now = Date.now,
  base = RIPESTAT_BASE,
  limit = 6,
  concurrency = 3,
  timeoutMs = 4000,
} = {}) {
  if (!Array.isArray(events) || !events.length) return events || [];

  const fetchJson = async (url) => {
    const res = await fetchImpl(url, {
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) throw new Error(`ripestat HTTP ${res.status}`);
    return res.json();
  };
  const cached = async (key, url, parse) => {
    const hit = cache.get(key);
    if (hit && now() - hit.at < CACHE_TTL_MS) return hit.value;
    const value = parse(await fetchJson(url));
    cache.set(key, { at: now(), value });
    return value;
  };

  const targets = events
    .filter((e) => e && e.hijackerAsn && (e.prefixes || [])[0])
    .slice(0, limit);

  await pool(targets, concurrency, async (e) => {
    const asn = e.hijackerAsn;
    const prefix = e.prefixes[0];
    e.rpki = await cached(
      `rpki:${asn}:${prefix}`,
      `${base}/rpki-validation/data.json?resource=AS${asn}&prefix=${encodeURIComponent(prefix)}`,
      (payload) => parseRpkiValidation(payload, asn),
    );
    if (!e.hijackerOrg) {
      const holder = await cached(
        `holder:${asn}`,
        `${base}/as-overview/data.json?resource=AS${asn}`,
        parseAsHolder,
      );
      if (holder) e.hijackerOrg = holder;
    }
  });

  return events;
}
