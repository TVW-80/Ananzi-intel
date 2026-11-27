/**
 * A pragmatic Sigma detection engine — enough of the spec to evaluate the
 * `process_creation` rule corpus against synthetic process events. Pure and
 * dependency-free so the unit test can exercise it with inline fixtures.
 *
 * Supported: field modifiers contains/startswith/endswith/re/all/cased (+ plain
 * equals, case-insensitive by default); list values (OR, or AND with |all);
 * map selections (AND across fields); keyword lists (full-text OR); list-of-maps
 * (OR); null value (field absent). Conditions: and/or/not, parentheses,
 * `1 of x*`, `all of x*`, `1 of them`, `all of them`. Unknown event fields are
 * treated as absent (conservative — a filter on a field we don't carry can't
 * suppress a detection), which is the honest behavior for synthetic events.
 *
 * Two engines, one code path. The LEGACY engine (default) is what every
 * published number was measured with: unknown modifiers fall back to plain
 * equals and |re is case-insensitive. The SPEC engine ({ spec: true }) follows
 * the Sigma specification as pySigma implements it — |cidr, |windash,
 * |base64offset, |base64, |fieldref, |exists, |gt/gte/lt/lte, and |re is
 * case-sensitive unless |i (|m, |s flags too). A rule that uses a modifier the
 * spec engine does not implement is reported by ruleSupported() so callers skip
 * it instead of mis-evaluating it (a silent fallback inside a filter turns a
 * "logon from a PUBLIC IP" rule into "every network logon").
 */
import { BlockList, isIP } from 'node:net';

const lc = (v) => String(v ?? '').toLowerCase();

/** Event field → array of string values we can match against. */
function fieldValues(event, field) {
  const v = event[field];
  if (v === undefined || v === null) return null; // absent
  return Array.isArray(v) ? v.map(String) : [String(v)];
}

// ── Sigma spec modifiers (verified against pySigma in attack-eval.test.mjs) ──
const memo = (fn) => { const c = new Map(); return (k) => { let v = c.get(k); if (v === undefined) { v = fn(k); c.set(k, v); } return v; }; };

/** |windash: a "-" or "/" starting a word may be any of - / – — ― (pySigma SigmaWindowsDashModifier). */
const WINDASH = ['-', '/', '–', '—', '―'];
export const windashVariants = memo((s) => {
  const str = String(s);
  const idx = [];
  const re = /\B[-/]\b/g;
  let m;
  while ((m = re.exec(str))) idx.push(m.index);
  let out = [str];
  for (const i of idx) out = out.flatMap((v) => WINDASH.map((c) => v.slice(0, i) + c + v.slice(i + 1)));
  return out;
});

/** |base64offset: the value base64-encoded at all three byte offsets (pySigma SigmaBase64OffsetModifier). */
export const base64offsetVariants = memo((s) => {
  const str = String(s);
  const b = Buffer.from(str, 'utf8');
  const start = [0, 2, 3];
  const end = [undefined, -3, -2];
  return [0, 1, 2].map((i) => Buffer.concat([Buffer.alloc(i, 0x20), b]).toString('base64').slice(start[i], end[([...str].length + i) % 3]));
});

const cidrList = memo((cidr) => {
  const [net, bits] = String(cidr).split('/');
  const t = isIP(net);
  if (!t) return null;
  const bl = new BlockList();
  bl.addSubnet(net, Number(bits ?? (t === 4 ? 32 : 128)), t === 4 ? 'ipv4' : 'ipv6');
  return { bl, t };
});
/** |cidr: is an IP (v4, v6, or v4-mapped v6) inside a network. */
export function inCidr(value, cidr) {
  const c = cidrList(cidr);
  if (!c) return false;
  const v = String(value ?? '').trim();
  const t = isIP(v);
  if (!t) return false;
  if (t === 6 && c.t === 4) {
    const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(v);
    return mapped ? c.bl.check(mapped[1], 'ipv4') : false;
  }
  return t === c.t && c.bl.check(v, t === 4 ? 'ipv4' : 'ipv6');
}

/** Modifiers the spec engine implements. Anything else → ruleSupported() is false. */
export const SPEC_MODIFIERS = new Set(['contains', 'startswith', 'endswith', 'all', 'cased', 're', 'i', 'm', 's',
  'windash', 'base64offset', 'base64', 'cidr', 'fieldref', 'exists', 'gt', 'gte', 'lt', 'lte']);
/** Modifiers whose meaning differs between the legacy and spec engines. */
export const SPEC_SENSITIVE = new Set(['re', 'i', 'm', 's', 'windash', 'base64offset', 'base64', 'cidr', 'fieldref', 'exists', 'gt', 'gte', 'lt', 'lte']);

function cmpOne(eventVal, want, mods, spec) {
  const cased = mods.includes('cased');
  const e = cased ? String(eventVal) : lc(eventVal);
  if (mods.includes('re')) {
    const flags = spec ? ['i', 'm', 's'].filter((f) => mods.includes(f)).join('') : (cased ? '' : 'i');
    try { return new RegExp(String(want), flags).test(String(eventVal)); } catch { return false; }
  }
  if (spec) {
    const num = (x) => (String(x).trim() === '' ? NaN : Number(x));
    if (mods.includes('gt')) return num(eventVal) > num(want);
    if (mods.includes('gte')) return num(eventVal) >= num(want);
    if (mods.includes('lt')) return num(eventVal) < num(want);
    if (mods.includes('lte')) return num(eventVal) <= num(want);
  }
  const w = cased ? String(want) : lc(want);
  if (mods.includes('contains')) return e.includes(w);
  if (mods.includes('startswith')) return e.startsWith(w);
  if (mods.includes('endswith')) return e.endsWith(w);
  return e === w; // plain equals
}

function matchField(rawKey, want, event, spec = false) {
  const [field, ...mods] = rawKey.split('|');
  const values = fieldValues(event, field);
  if (spec && mods.includes('exists')) return (values !== null) === (want === true || String(want).toLowerCase() === 'true');
  if (want === null) return values === null || values.every((v) => v === ''); // field: null → absent
  if (values === null) return false; // referenced field we don't carry
  const wants = Array.isArray(want) ? want : [want];
  const all = mods.includes('all');
  let test;
  if (spec && mods.includes('cidr')) {
    test = (w) => values.some((ev) => inCidr(ev, w));
  } else if (spec && mods.includes('fieldref')) {
    const rest = mods.filter((m) => m !== 'fieldref');
    test = (w) => { const ref = fieldValues(event, String(w)); return !!ref && values.some((ev) => ref.some((r) => cmpOne(ev, r, rest, spec))); };
  } else {
    const expand = (w) => {
      let vs = [String(w)];
      if (spec) {
        for (const m of mods) {
          if (m === 'windash') vs = vs.flatMap(windashVariants);
          else if (m === 'base64offset') vs = vs.flatMap(base64offsetVariants);
          else if (m === 'base64') vs = vs.map((v) => Buffer.from(v, 'utf8').toString('base64'));
        }
      }
      return vs;
    };
    test = (w) => expand(w).some((v) => values.some((ev) => cmpOne(ev, v, mods, spec)));
  }
  return all ? wants.every(test) : wants.some(test);
}

function matchMap(map, event, spec) {
  return Object.entries(map).every(([k, v]) => matchField(k, v, event, spec));
}

const TEXT_FIELDS = ['CommandLine', 'Image', 'ParentImage', 'OriginalFileName', 'ScriptBlockText',
  'Payload', 'ContextInfo', 'Details', 'TargetObject', 'TargetFilename', 'ImageLoaded',
  'DestinationHostname', 'QueryName', 'PipeName', 'Signature'];
function matchKeyword(str, event) {
  const needle = lc(str);
  return TEXT_FIELDS.some((f) => lc(event[f]).includes(needle));
}

/** Evaluate one named selection block against an event. */
export function matchSelection(value, event, { spec = false } = {}) {
  if (Array.isArray(value)) {
    return value.some((item) =>
      item && typeof item === 'object' ? matchMap(item, event, spec) : matchKeyword(item, event),
    );
  }
  if (value && typeof value === 'object') return matchMap(value, event, spec);
  return matchKeyword(value, event);
}

// ── condition expression ─────────────────────────────────────────────────────
function tokenize(cond) {
  return String(cond)
    .replace(/[()]/g, (m) => ` ${m} `)
    .trim()
    .split(/\s+/);
}

/** Evaluate the condition string given a map of selectionName → boolean. */
export function evalCondition(cond, sel) {
  const names = Object.keys(sel);
  const toks = tokenize(cond);
  let i = 0;
  const peek = () => toks[i];
  const glob = (pat) => {
    const re = new RegExp('^' + pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    return names.filter((n) => re.test(n));
  };
  function quant(kind, pat) {
    const set = pat === 'them' ? names : glob(pat);
    if (!set.length) return false;
    return kind === 'all' ? set.every((n) => sel[n]) : set.some((n) => sel[n]);
  }
  function atom() {
    const t = peek();
    if (t === '(') { i++; const v = orExpr(); if (peek() === ')') i++; return v; }
    if (t === '1' || t === 'all' || t === 'any') {
      // "1 of x" / "all of x" / "any of x"
      if (toks[i + 1] === 'of') { const pat = toks[i + 2]; i += 3; return quant(t === 'all' ? 'all' : '1', pat); }
    }
    i++;
    return Boolean(sel[t]); // unknown name → false
  }
  function notExpr() {
    if (peek() === 'not') { i++; return !notExpr(); }
    return atom();
  }
  function andExpr() {
    let v = notExpr();
    while (peek() === 'and') { i++; v = notExpr() && v; }
    return v;
  }
  function orExpr() {
    let v = andExpr();
    while (peek() === 'or') { i++; v = andExpr() || v; }
    return v;
  }
  return orExpr();
}

/** Every field modifier a rule's detection uses. */
export function ruleModifiers(rule) {
  const out = new Set();
  const walk = (v) => {
    if (!v || typeof v !== 'object') return;
    for (const [k, x] of Object.entries(v)) {
      if (k.includes('|')) for (const m of k.split('|').slice(1)) out.add(m);
      walk(x);
    }
  };
  for (const [name, value] of Object.entries(rule.detection || {})) if (name !== 'condition') walk(Array.isArray(value) ? value : { [name]: value });
  return out;
}

/** Can the spec engine evaluate this rule faithfully? (false → skip it, never guess) */
export function ruleSupported(rule) {
  for (const m of ruleModifiers(rule)) if (!SPEC_MODIFIERS.has(m)) return false;
  return true;
}

/** Does a parsed Sigma rule fire on an event? opts.spec selects the spec engine. */
export function ruleFires(rule, event, opts = {}) {
  const det = rule.detection || {};
  const sel = {};
  for (const [name, value] of Object.entries(det)) {
    if (name === 'condition') continue;
    sel[name] = matchSelection(value, event, opts);
  }
  const cond = det.condition;
  if (Array.isArray(cond)) return cond.some((c) => evalCondition(c, sel)); // rare multi-condition
  return evalCondition(cond || Object.keys(sel).join(' and '), sel);
}

/** Full ATT&CK ids from a rule's tags, sub-techniques kept (T1562.004). Needed
 *  for MITRE revoked-by resolution, which can retire a sub-technique alone. */
export function ruleTechniqueIds(rule) {
  const out = new Set();
  for (const tag of rule.tags || []) {
    const m = /^attack[._]t(\d{4})(?:\.(\d{3}))?$/i.exec(String(tag));
    if (m) out.add(m[2] ? `T${m[1]}.${m[2]}` : `T${m[1]}`);
  }
  return [...out];
}

/** Parent ATT&CK technique ids from a rule's tags (attack.t1059.001 → T1059). */
export function ruleTechniques(rule) {
  const out = new Set();
  for (const tag of rule.tags || []) {
    const m = /^attack[._]t(\d{4})(?:\.\d{3})?$/i.exec(String(tag));
    if (m) out.add('T' + m[1]);
  }
  return [...out];
}
