/**
 * Threat-actor naming for RECON — "which known adversaries are associated with
 * the techniques in this incident?"
 *
 * This is a LEAD, never attribution. Many actors share a technique (everyone
 * runs PowerShell), so a technique overlap is weak evidence. The matcher is
 * deliberately conservative — it requires a real overlap, ranks more-specific
 * actors ahead of broad ones, and every surface that shows a lead labels it as
 * a hypothesis (RECON_DISCLAIMER). Data: MITRE ATT&CK groups + MISP Galaxy
 * country/sponsor, baked into threatActors.generated.js by tools/gen-threat-actors.mjs.
 */
import { THREAT_ACTORS } from './threatActors.generated.js';

const parent = (id) => String(id).split('.')[0].toUpperCase();

/**
 * Known actors associated with a set of ATT&CK techniques, strongest first.
 * @param {string[]} techIds technique ids (sub-techniques allowed; folded to parents)
 * @returns {{id,name,aliases,country,sponsor,overlap,of,matched}[]}
 */
export function actorsForTechniques(techIds, { limit = 3, minOverlap = 2 } = {}) {
  const want = new Set((techIds || []).map(parent).filter(Boolean));
  if (want.size < minOverlap) return [];
  const scored = [];
  for (const a of THREAT_ACTORS) {
    const matched = a.techniques.filter((t) => want.has(t));
    if (matched.length < minOverlap) continue;
    scored.push({
      id: a.id, name: a.name, aliases: a.aliases, country: a.country, sponsor: a.sponsor,
      overlap: matched.length, of: want.size, matched,
      // specificity: an actor with a narrower technique set is a stronger lead
      _spec: matched.length / a.techniques.length,
    });
  }
  scored.sort((x, y) => y.overlap - x.overlap || y._spec - x._spec || x.id.localeCompare(y.id));
  return scored.slice(0, limit).map(({ _spec, ...a }) => a);
}

/** One-line label for an actor lead, e.g. "APT29 (aka Cozy Bear · RU) — 4 of 6 techniques". */
export function actorLeadLabel(a) {
  const akas = (a.aliases || []).slice(0, 2);
  const tail = [akas.length ? `aka ${akas.join(', ')}` : null, a.country].filter(Boolean).join(' · ');
  return `${a.name}${tail ? ` (${tail})` : ''} — ${a.overlap} of ${a.of} techniques`;
}

/** Compact actor leads for an incident's techniques (for grounding / case files). */
export function actorLeadsForIncident(incident, opts) {
  const ids = (incident?.techniques || []).map((t) => (typeof t === 'string' ? t : t?.id)).filter(Boolean);
  return actorsForTechniques(ids, opts);
}
