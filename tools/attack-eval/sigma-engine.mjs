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
 */

const lc = (v) => String(v ?? '').toLowerCase();

/** Event field → array of string values we can match against. */
function fieldValues(event, field) {
  const v = event[field];
  if (v === undefined || v === null) return null; // absent
  return Array.isArray(v) ? v.map(String) : [String(v)];
}

function cmpOne(eventVal, want, mods) {
  const cased = mods.includes('cased');
  const e = cased ? String(eventVal) : lc(eventVal);
  if (mods.includes('re')) {
    try { return new RegExp(String(want), cased ? '' : 'i').test(String(eventVal)); } catch { return false; }
  }
  const w = cased ? String(want) : lc(want);
  if (mods.includes('contains')) return e.includes(w);
  if (mods.includes('startswith')) return e.startsWith(w);
  if (mods.includes('endswith')) return e.endsWith(w);
  return e === w; // plain equals
}

function matchField(rawKey, want, event) {
  const [field, ...mods] = rawKey.split('|');
  const values = fieldValues(event, field);
  if (want === null) return values === null || values.every((v) => v === ''); // field: null → absent
  if (values === null) return false; // referenced field we don't carry
  const wants = Array.isArray(want) ? want : [want];
  const all = mods.includes('all');
  const test = (w) => values.some((ev) => cmpOne(ev, w, mods));
  return all ? wants.every(test) : wants.some(test);
}

function matchMap(map, event) {
  return Object.entries(map).every(([k, v]) => matchField(k, v, event));
}

const TEXT_FIELDS = ['CommandLine', 'Image', 'ParentImage', 'OriginalFileName', 'ScriptBlockText'];
function matchKeyword(str, event) {
  const needle = lc(str);
  return TEXT_FIELDS.some((f) => lc(event[f]).includes(needle));
}

/** Evaluate one named selection block against an event. */
export function matchSelection(value, event) {
  if (Array.isArray(value)) {
    return value.some((item) =>
      item && typeof item === 'object' ? matchMap(item, event) : matchKeyword(item, event),
    );
  }
  if (value && typeof value === 'object') return matchMap(value, event);
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

/** Does a parsed Sigma rule fire on an event? */
export function ruleFires(rule, event) {
  const det = rule.detection || {};
  const sel = {};
  for (const [name, value] of Object.entries(det)) {
    if (name === 'condition') continue;
    sel[name] = matchSelection(value, event);
  }
  const cond = det.condition;
  if (Array.isArray(cond)) return cond.some((c) => evalCondition(c, sel)); // rare multi-condition
  return evalCondition(cond || Object.keys(sel).join(' and '), sel);
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
