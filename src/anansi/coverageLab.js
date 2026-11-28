/**
 * Ananzi FANGS — ATT&CK COVERAGE LAB: the visual drill-down behind SITREP's
 * coverage board.
 *
 *   • KPI tiles — detection on real attack traces, alert precision, techniques
 *     caught, each with its change vs the detector as first shipped;
 *   • the ATT&CK Enterprise matrix, one cell per technique, coloured by the
 *     strongest EVIDENCE the judges produced (real trace > lab corpus > claim);
 *   • "how each fix moved detection" — the ablation as a meter list;
 *   • precision vs recall at every Sigma alert level — the SOC trade-off curve.
 *
 * Every number and every cell comes from coverageData.generated.js, which
 * tools/attack-eval/snapshot.mjs builds from the judges' result files — nothing
 * is typed by hand. Colour never carries meaning alone: cells also carry ✓ / ✕
 * glyphs, every visual has a legend or direct labels, and one "table view"
 * switch turns the whole lab into plain tables. Palette validated with the
 * dataviz validator on the app's #0a0908 surface (blue ordinal evidence ramp +
 * reserved critical red for misses; CVD ΔE ≥ 24 between red and every blue).
 *
 * English-only (src/anansi/**). Rendering + small pure helpers.
 */
import { COVERAGE_DATA } from './coverageData.generated.js';

const SVG = 'http://www.w3.org/2000/svg';

/** Evidence levels, strongest first (see tools/attack-eval/snapshot.mjs). */
export const EVIDENCE_UI = Object.freeze({
  T: { label: 'Detected on real attack telemetry', short: 'detected', glyph: '✓' },
  M: { label: 'Missed on real attack telemetry', short: 'missed', glyph: '✕' },
  C: { label: 'Verified on the Atomic command corpus', short: 'lab-verified', glyph: '' },
  E: { label: 'Explained only (when a feed names it)', short: 'explained', glyph: '' },
  '-': { label: 'No coverage yet', short: 'none', glyph: '' },
});
export const EVIDENCE_ORDER = Object.freeze(['T', 'M', 'C', 'E', '-']);

// Half-up, so a stored 0.1815 reads 18.2% exactly as the judge printed it (binary floats would round it down).
export const pct = (x, d = 1) => `${(Math.round((100 * (Number(x) || 0) + 1e-9) * 10 ** d) / 10 ** d).toFixed(d)}%`;
/** Signed change in percentage points, e.g. "▲ 12.6 pts" / "▼ 8.4 pts" / "± 0 pts". */
export function deltaPts(now, before) {
  // The difference of the DISPLAYED (one-decimal) values, so it always matches what a reader subtracts.
  const r1 = (v) => Math.round((100 * (Number(v) || 0) + 1e-9) * 10);
  const d = (r1(now) - r1(before)) / 10;
  if (Math.abs(d) < 0.05) return '± 0 pts';
  return `${d > 0 ? '▲' : '▼'} ${Math.abs(d).toFixed(1)} pts`;
}
/** Round up to the next multiple of step (≥ step). */
export const niceCeil = (x, step = 10) => Math.max(step, Math.ceil((Number(x) || 0) / step) * step);
/** Linear scale. */
export const scale = (d0, d1, r0, r1) => (v) => r0 + ((v - d0) / (d1 - d0 || 1)) * (r1 - r0);

/** Per-technique index + per-tactic tallies from the generated matrix. */
export function matrixStats(matrix = COVERAGE_DATA.matrix) {
  const techniques = new Map();
  const perTactic = matrix.map((t) => {
    let detected = 0, missed = 0;
    for (const [id, name, ev, active] of t.techniques) {
      if (ev === 'T') detected += 1;
      if (ev === 'M') missed += 1;
      const rec = techniques.get(id) || { id, name, ev, active: Boolean(active), tactics: [] };
      rec.tactics.push(t.name);
      techniques.set(id, rec);
    }
    return { id: t.id, short: t.short, name: t.name, total: t.techniques.length, detected, missed };
  });
  const byEvidence = Object.fromEntries(EVIDENCE_ORDER.map((e) => [e, 0]));
  for (const r of techniques.values()) byEvidence[r.ev] += 1;
  return { techniques, perTactic, byEvidence };
}

export const mitreUrl = (id) => `https://attack.mitre.org/techniques/${String(id).replace('.', '/')}/`;

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}
function svg(doc, tag, attrs = {}) {
  const n = doc.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  return n;
}

/** One shared tooltip; tooltips enhance, never gate (every value is also in table view). */
function createTip(doc) {
  const tip = el(doc, 'div', 'covlab-tip');
  tip.setAttribute('role', 'tooltip');
  tip.hidden = true;
  const show = (text, x, y) => {
    tip.textContent = text;
    tip.hidden = false;
    const w = tip.offsetWidth || 220;
    const vw = doc.defaultView?.innerWidth || 1200;
    tip.style.left = `${Math.max(8, Math.min(vw - w - 8, x + 12))}px`;
    tip.style.top = `${Math.max(8, y + 14)}px`;
  };
  const near = (node, text) => { const r = node.getBoundingClientRect(); show(text, r.left, r.bottom - 8); };
  return { tip, show, near, hide: () => { tip.hidden = true; } };
}
const bindTip = (node, tipApi, text) => {
  node.addEventListener('pointerenter', (e) => tipApi.show(typeof text === 'function' ? text() : text, e.clientX, e.clientY));
  node.addEventListener('pointermove', (e) => tipApi.show(typeof text === 'function' ? text() : text, e.clientX, e.clientY));
  node.addEventListener('pointerleave', tipApi.hide);
  node.addEventListener('focus', () => tipApi.near(node, typeof text === 'function' ? text() : text));
  node.addEventListener('blur', tipApi.hide);
};

/** Rendered text width in SVG user units (canvas text metrics when available, else a safe estimate). */
let measureCtx;
function textWidth(doc, text, px = 9.5) {
  try {
    measureCtx ||= doc.createElement('canvas').getContext('2d');
    if (measureCtx) {
      const family = doc.defaultView?.getComputedStyle?.(doc.body).getPropertyValue('--font-sans') || 'sans-serif';
      measureCtx.font = `${px}px ${family.trim() || 'sans-serif'}`;
      const w = measureCtx.measureText(text).width;
      if (w > 0) return w + 2;
    }
  } catch { /* no canvas (tests) */ }
  return text.length * px * 0.62;
}

// ── pieces ───────────────────────────────────────────────────────────────────
/** KPI tiles: the three numbers a SOC lead asks for, each vs the detector as shipped. */
export function kpiTiles(doc, D = COVERAGE_DATA, { compact = false } = {}) {
  const tm = D.telemetry;
  const base = (tm.ablation || [])[0];
  const wrap = el(doc, 'div', `covlab-kpis${compact ? ' compact' : ''}`);
  const tile = (label, value, sub, delta) => {
    const t = el(doc, 'div', 'covlab-kpi');
    t.append(el(doc, 'div', 'covlab-kpi-label', label), el(doc, 'div', 'covlab-kpi-value', value));
    if (delta) t.append(el(doc, 'div', 'covlab-kpi-delta', delta));
    if (sub) t.append(el(doc, 'div', 'covlab-kpi-sub', sub));
    return t;
  };
  const recall = tile('Detection on real attack traces', pct(tm.captureRecall), `${tm.detected} of ${tm.captures} labeled captures · bar ${pct(tm.bar, 0)}`,
    base ? `${deltaPts(tm.captureRecall, base.recall)} vs as shipped` : null);
  // meter: one ratio against its limit (same-ramp track, bar marker at the judge's pass line)
  const meter = el(doc, 'div', 'covlab-meter');
  meter.setAttribute('role', 'img');
  meter.setAttribute('aria-label', `${pct(tm.captureRecall)} of ${pct(tm.bar, 0)} bar`);
  const fill = el(doc, 'span', 'covlab-meter-fill');
  fill.style.width = `${Math.min(100, 100 * tm.captureRecall)}%`;
  const mark = el(doc, 'span', 'covlab-meter-bar');
  mark.style.left = `${100 * tm.bar}%`;
  meter.append(fill, mark);
  recall.insertBefore(meter, recall.querySelector('.covlab-kpi-sub'));
  wrap.append(recall,
    tile('Alert precision', pct(tm.alertPrecision), 'firing events that named a technique the trace really ran',
      base ? `${deltaPts(tm.alertPrecision, base.alertPrecision)} vs as shipped` : null),
    tile('Techniques caught on real traces', `${tm.techDetected}/${tm.techLabeled}`, 'labeled ATT&CK techniques in the OTRF captures', null));
  return wrap;
}

export function legend(doc, { active = true } = {}) {
  const lg = el(doc, 'div', 'covlab-legend');
  lg.setAttribute('aria-label', 'Matrix legend');
  for (const e of EVIDENCE_ORDER) {
    const item = el(doc, 'span', 'covlab-legend-item');
    const sw = el(doc, 'span', 'covlab-swatch', EVIDENCE_UI[e].glyph);
    sw.dataset.ev = e;
    item.append(sw, doc.createTextNode(EVIDENCE_UI[e].short));
    item.title = EVIDENCE_UI[e].label;
    lg.append(item);
  }
  if (active) {
    const item = el(doc, 'span', 'covlab-legend-item');
    item.append(el(doc, 'span', 'covlab-active-dot'), doc.createTextNode('live attribution'));
    item.title = 'F.A.N.G.S attributes this technique from raw live signals';
    lg.append(item);
  }
  return lg;
}

/** Thumbnail matrix for the SITREP board (one click opens the lab). */
export function miniMatrix(doc, D = COVERAGE_DATA) {
  const grid = el(doc, 'div', 'covlab-mini');
  grid.setAttribute('aria-hidden', 'true');
  for (const t of D.matrix) {
    const col = el(doc, 'div', 'covlab-mini-col');
    for (const [, , ev] of t.techniques) { const c = el(doc, 'span', 'covlab-mini-cell'); c.dataset.ev = ev; col.append(c); }
    grid.append(col);
  }
  return grid;
}

/** Full ATT&CK matrix with roving-tabindex keyboard navigation. */
function fullMatrix(doc, D, tipApi, onSelect) {
  const stats = matrixStats(D.matrix);
  const grid = el(doc, 'div', 'covlab-matrix');
  grid.style.gridTemplateColumns = `repeat(${D.matrix.length}, minmax(68px, 1fr))`;
  grid.setAttribute('role', 'grid');
  grid.setAttribute('aria-label', `MITRE ATT&CK ${D.attack} Enterprise matrix — evidence per technique`);
  const cols = [];
  D.matrix.forEach((t, ci) => {
    const s = stats.perTactic[ci];
    const col = el(doc, 'div', 'covlab-col');
    col.setAttribute('role', 'rowgroup');
    const head = el(doc, 'div', 'covlab-col-head');
    head.append(el(doc, 'span', 'covlab-col-name', t.name), el(doc, 'span', 'covlab-col-count', `${s.detected}✓ ${s.missed ? `${s.missed}✕ ` : ''}/ ${s.total}`));
    head.title = `${t.name}: ${s.detected} detected on real telemetry, ${s.missed} missed, ${s.total} techniques`;
    col.append(head);
    const cells = t.techniques.map(([id, name, ev, active], ri) => {
      const b = el(doc, 'button', 'covlab-cell');
      b.type = 'button';
      b.dataset.ev = ev;
      b.dataset.id = id;
      b.tabIndex = ci === 0 && ri === 0 ? 0 : -1;
      b.setAttribute('role', 'gridcell');
      b.setAttribute('aria-label', `${id} ${name}: ${EVIDENCE_UI[ev].label}${active ? '; live attribution' : ''}`);
      b.append(el(doc, 'span', 'covlab-cell-id', id));
      if (EVIDENCE_UI[ev].glyph) b.append(el(doc, 'span', 'covlab-cell-glyph', EVIDENCE_UI[ev].glyph));
      if (active) b.append(el(doc, 'span', 'covlab-active-dot'));
      bindTip(b, tipApi, `${id} · ${name}\n${EVIDENCE_UI[ev].label}${active ? '\n● live attribution' : ''}`);
      b.addEventListener('click', () => onSelect(id));
      col.append(b);
      return b;
    });
    cols.push(cells);
    grid.append(col);
  });
  grid.addEventListener('keydown', (e) => {
    const cur = doc.activeElement;
    if (!cur?.classList?.contains('covlab-cell')) return;
    let ci = cols.findIndex((c) => c.includes(cur));
    let ri = cols[ci].indexOf(cur);
    if (e.key === 'ArrowDown') ri = Math.min(cols[ci].length - 1, ri + 1);
    else if (e.key === 'ArrowUp') ri = Math.max(0, ri - 1);
    else if (e.key === 'ArrowRight') { ci = Math.min(cols.length - 1, ci + 1); ri = Math.min(ri, cols[ci].length - 1); }
    else if (e.key === 'ArrowLeft') { ci = Math.max(0, ci - 1); ri = Math.min(ri, cols[ci].length - 1); }
    else return;
    e.preventDefault();
    cur.tabIndex = -1;
    const next = cols[ci][ri];
    next.tabIndex = 0;
    next.focus();
  });
  return grid;
}

/** "How each fix moved detection": the ablation as a meter list (one hue, final step emphasised). */
function ablationMeters(doc, D, tipApi) {
  const rows = D.telemetry.ablation || [];
  const bar = D.telemetry.bar ?? 0.8;
  const list = el(doc, 'div', 'covlab-meters');
  rows.forEach((r, i) => {
    const row = el(doc, 'div', `covlab-meter-row${i === rows.length - 1 ? ' final' : ''}`);
    row.tabIndex = 0;
    const track = el(doc, 'span', 'covlab-track');
    const fill = el(doc, 'span', 'covlab-track-fill');
    fill.style.width = `${Math.min(100, 100 * r.recall)}%`;
    const mark = el(doc, 'span', 'covlab-track-bar');
    mark.style.left = `${100 * bar}%`;
    track.append(fill, mark);
    const prev = rows[i - 1];
    row.append(el(doc, 'span', 'covlab-meter-name', r.label), track, el(doc, 'span', 'covlab-meter-val', pct(r.recall)));
    row.setAttribute('aria-label', `${r.label}: recall ${pct(r.recall)}, alert precision ${pct(r.alertPrecision)}, F1 ${pct(r.f1)}`);
    bindTip(row, tipApi, `${r.label}\nrecall ${pct(r.recall)} (${r.detected}/${D.telemetry.captures})${prev ? ` · ${deltaPts(r.recall, prev.recall)}` : ''}\nalert precision ${pct(r.alertPrecision)} · F1 ${pct(r.f1)}`);
    list.append(row);
  });
  const axis = el(doc, 'div', 'covlab-meter-axis');
  axis.append(el(doc, 'span', null, ''), el(doc, 'span', 'covlab-meter-axis-note', `recall on ${D.telemetry.captures} real traces · marker = ${pct(bar, 0)} bar`), el(doc, 'span', null, ''));
  list.append(axis);
  return list;
}

/** Precision vs recall at each Sigma alert level — a connected dot plot, one axis per measure. */
function operatingChart(doc, D, tipApi) {
  const ops = D.telemetry.operatingPoints || [];
  const W = 360, H = 220, m = { l: 38, r: 14, t: 12, b: 32 };
  const yMax = niceCeil(100 * Math.max(0.1, ...ops.map((o) => o.alertPrecision)), 10) / 100;
  const x = scale(0, 1, m.l, W - m.r);
  const y = scale(0, yMax, H - m.b, m.t);
  const s = svg(doc, 'svg', { viewBox: `0 0 ${W} ${H}`, class: 'covlab-ops', role: 'img', 'aria-label': 'Alert precision versus detection recall at each Sigma level' });
  const grid = svg(doc, 'g', { class: 'covlab-ops-grid' });
  for (let v = 0; v <= yMax + 1e-9; v += yMax / 4) {
    grid.append(svg(doc, 'line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v) }));
    const tl = svg(doc, 'text', { x: m.l - 6, y: y(v) + 3, 'text-anchor': 'end', class: 'covlab-ops-tick' });
    tl.textContent = `${Math.round(100 * v)}%`;
    grid.append(tl);
  }
  for (let v = 0; v <= 1.0001; v += 0.2) {
    const tl = svg(doc, 'text', { x: x(v), y: H - m.b + 14, 'text-anchor': 'middle', class: 'covlab-ops-tick' });
    tl.textContent = `${Math.round(100 * v)}%`;
    grid.append(tl);
  }
  grid.append(svg(doc, 'line', { x1: m.l, x2: W - m.r, y1: H - m.b, y2: H - m.b, class: 'covlab-ops-axis' }));
  s.append(grid);
  // recall pass line (solid hairline, labelled — a threshold, not a grid)
  const bar = D.telemetry.bar ?? 0.8;
  s.append(svg(doc, 'line', { x1: x(bar), x2: x(bar), y1: m.t, y2: H - m.b, class: 'covlab-ops-bar' }));
  const bl = svg(doc, 'text', { x: x(bar) - 4, y: m.t + 9, 'text-anchor': 'end', class: 'covlab-ops-barlabel' });
  bl.textContent = `recall bar ${pct(bar, 0)}`;
  s.append(bl);
  const barLabelW = textWidth(doc, bl.textContent, 8.5);
  const placed = [{ x0: x(bar) - 4 - barLabelW, x1: x(bar) - 4, y0: m.t, y1: m.t + 11 }];
  const xl = svg(doc, 'text', { x: (m.l + W - m.r) / 2, y: H - 4, 'text-anchor': 'middle', class: 'covlab-ops-title' });
  xl.textContent = 'detection recall on real traces →';
  s.append(xl);
  const yl = svg(doc, 'text', { x: 10, y: (m.t + H - m.b) / 2, 'text-anchor': 'middle', class: 'covlab-ops-title', transform: `rotate(-90 10 ${(m.t + H - m.b) / 2})` });
  yl.textContent = 'alert precision →';
  s.append(yl);
  if (ops.length) {
    s.append(svg(doc, 'polyline', { points: ops.map((o) => `${x(o.recall)},${y(o.alertPrecision)}`).join(' '), class: 'covlab-ops-line' }));
    const pts = ops.map((o) => ({ x: x(o.recall), y: y(o.alertPrecision) }));
    // Obstacles, sampled every 3px. HARD: the connecting line (sitting on it blurs which point a
    // label belongs to). SOFT: the recall pass line — a label may cross it, drawn with a halo.
    const hard = [];
    for (let k = 1; k < pts.length; k++) {
      const a = pts[k - 1], b = pts[k], n = Math.max(1, Math.ceil(Math.hypot(b.x - a.x, b.y - a.y) / 3));
      for (let j = 0; j <= n; j++) hard.push({ x: a.x + ((b.x - a.x) * j) / n, y: a.y + ((b.y - a.y) * j) / n });
    }
    const soft = [];
    for (let yy = m.t; yy <= H - m.b; yy += 3) soft.push({ x: x(bar), y: yy });
    const hits = (list, b) => list.some((o) => o.x > b.x0 - 3 && o.x < b.x1 + 3 && o.y > b.y0 - 3 && o.y < b.y1 + 3);
    ops.forEach((o, i) => {
      const cx = pts[i].x, cy = pts[i].y;
      s.append(svg(doc, 'circle', { cx, cy, r: i === 0 ? 6 : 4.5, class: `covlab-ops-pt${i === 0 ? ' head' : ''}` }));
      // Direct label at a spot around ITS OWN point that hits no other label,
      // no other point and stays in the plot — so a label can never drift onto
      // a neighbour (a mislabelled operating point would misreport the trade-off).
      const text = i === 0 ? 'all rules' : `≥ ${o.level}`;
      const w = textWidth(doc, text), h = 10;
      // anchor: start = text begins at x0, end = text ends at x1, middle = centred — so the gap to the point is exact
      const cands = [
        { x0: cx + 9, y0: cy - h / 2, a: 'start' }, { x0: cx - w / 2, y0: cy - 9 - h, a: 'middle' },
        { x0: cx - 9 - w, y0: cy - h / 2, a: 'end' }, { x0: cx - w / 2, y0: cy + 9, a: 'middle' },
        { x0: cx + 7, y0: cy - 7 - h, a: 'start' }, { x0: cx + 7, y0: cy + 7, a: 'start' }, { x0: cx - 7 - w, y0: cy - 7 - h, a: 'end' }, { x0: cx - 7 - w, y0: cy + 7, a: 'end' },
      ].map((c) => ({ ...c, x1: c.x0 + w, y1: c.y0 + h }));
      const clearHard = (b) => b.x0 >= m.l && b.x1 <= W - m.r && b.y0 >= m.t && b.y1 <= H - m.b
        && !placed.some((p) => b.x0 < p.x1 && b.x1 > p.x0 && b.y0 < p.y1 && b.y1 > p.y0)
        && !pts.some((p, j) => j !== i && p.x > b.x0 - 6 && p.x < b.x1 + 6 && p.y > b.y0 - 6 && p.y < b.y1 + 6)
        && !hits(hard, b);
      // 1st: clear of everything · 2nd: may cross the pass line (halo keeps it legible) · last resort: right of own point
      const box = cands.find((b) => clearHard(b) && !hits(soft, b)) || cands.find(clearHard) || cands[0];
      placed.push(box);
      const t = svg(doc, 'text', { x: box.a === 'end' ? box.x1 : box.a === 'middle' ? (box.x0 + box.x1) / 2 : box.x0, y: box.y1 - 1.5, 'text-anchor': box.a, class: 'covlab-ops-label' });
      t.textContent = text;
      s.append(t);
      const hit = svg(doc, 'circle', { cx, cy, r: 13, class: 'covlab-ops-hit', tabindex: 0, 'aria-label': `level ≥ ${o.level}: recall ${pct(o.recall)}, precision ${pct(o.alertPrecision)}, F1 ${pct(o.f1)}` });
      bindTip(hit, tipApi, `alert on Sigma level ≥ ${o.level}${i === 0 ? ' (all rules)' : ''}\nrecall ${pct(o.recall)} (${o.detected}/${D.telemetry.captures}) · precision ${pct(o.alertPrecision)} · F1 ${pct(o.f1)}`);
      s.append(hit);
    });
  }
  return s;
}

/** Prettify a kebab-case ATT&CK tactic id → "Privilege escalation". */
const tacticLabel = (s) => String(s).replace(/-/g, ' ').replace(/^./, (c) => c.toUpperCase());

/**
 * Detection rate on real malicious EVTX captures, by tactic — a horizontal meter
 * list. Bar = any rule fired; marker = the medium+ tier a SOC alerts on (always a
 * subset, so it sits inside the bar). Same track visual as the ablation meters.
 */
function realAttackStrip(doc, D, tipApi) {
  const e = D.evtx;
  const rows = [...(e.byTactic || [])]; // already sorted desc by rateAny in the snapshot
  const list = el(doc, 'div', 'covlab-meters');
  for (const r of rows) {
    const medRate = r.total ? r.medium / r.total : 0;
    const row = el(doc, 'div', 'covlab-meter-row');
    row.tabIndex = 0;
    const track = el(doc, 'span', 'covlab-track');
    const fill = el(doc, 'span', 'covlab-track-fill');
    fill.style.width = `${Math.min(100, 100 * r.rateAny)}%`;
    const mark = el(doc, 'span', 'covlab-track-bar');
    mark.style.left = `${Math.min(100, 100 * medRate)}%`;
    track.append(fill, mark);
    row.append(el(doc, 'span', 'covlab-meter-name', tacticLabel(r.tactic)), track, el(doc, 'span', 'covlab-meter-val', pct(r.rateAny)));
    row.setAttribute('aria-label', `${tacticLabel(r.tactic)}: ${pct(r.rateAny)} of ${r.total} captures fire a rule, ${pct(medRate)} at the medium+ tier`);
    bindTip(row, tipApi, `${tacticLabel(r.tactic)}\nfires a rule: ${pct(r.rateAny)} (${r.any}/${r.total})\nmedium+ tier: ${pct(medRate)} (${r.medium}/${r.total})`);
    list.append(row);
  }
  const axis = el(doc, 'div', 'covlab-meter-axis');
  axis.append(el(doc, 'span', null, ''), el(doc, 'span', 'covlab-meter-axis-note', `bar = any rule · marker = medium+ tier · ${e.silent} captures silent`), el(doc, 'span', null, ''));
  list.append(axis);
  return list;
}

// ── table view (the WCAG-clean twin of every visual) ─────────────────────────
function table(doc, caption, head, rows) {
  const t = el(doc, 'table', 'covlab-table');
  t.append(el(doc, 'caption', null, caption));
  const thead = el(doc, 'thead');
  const hr = el(doc, 'tr');
  for (const h of head) hr.append(el(doc, 'th', null, h));
  thead.append(hr);
  const tb = el(doc, 'tbody');
  for (const r of rows) { const tr = el(doc, 'tr'); for (const c of r) tr.append(el(doc, 'td', null, String(c))); tb.append(tr); }
  t.append(thead, tb);
  return t;
}

/** The lab panel: { element, open(techniqueId?), close(), isOpen() }. */
export function createCoverageLab(doc = document, { data = COVERAGE_DATA, onExplain = null } = {}) {
  const D = data;
  const stats = matrixStats(D.matrix);
  const tipApi = createTip(doc);
  const panel = el(doc, 'aside', 'covlab-panel');
  panel.hidden = true;
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', 'ATT&CK coverage lab');
  panel.lang = 'en'; // lets the browser hyphenate long tactic names
  const head = el(doc, 'div', 'recon-panel-head covlab-head');
  const title = el(doc, 'span', null, `ATT&CK COVERAGE LAB · measured · ${D.attack}`);
  const tools = el(doc, 'span', 'covlab-headtools');
  const tableBtn = el(doc, 'button', 'covlab-tablebtn', 'table view');
  tableBtn.type = 'button';
  tableBtn.setAttribute('aria-pressed', 'false');
  const close = el(doc, 'button', 'recon-panel-close', '×');
  close.type = 'button';
  close.setAttribute('aria-label', 'Close ATT&CK coverage lab');
  tools.append(tableBtn, close);
  head.append(title, tools);
  const body = el(doc, 'div', 'recon-panel-body covlab-body');
  panel.append(head, body, tipApi.tip);

  let tableView = false;
  let selected = null;
  const detail = el(doc, 'div', 'covlab-detail');
  detail.setAttribute('aria-live', 'polite');

  function renderDetail() {
    detail.replaceChildren();
    const r = selected && stats.techniques.get(selected);
    if (!r) { detail.append(el(doc, 'span', 'covlab-detail-hint', 'Select a technique to see its evidence.')); return; }
    const top = el(doc, 'div', 'covlab-detail-top');
    const sw = el(doc, 'span', 'covlab-swatch', EVIDENCE_UI[r.ev].glyph);
    sw.dataset.ev = r.ev;
    top.append(sw, el(doc, 'b', null, `${r.id} · ${r.name}`));
    detail.append(top, el(doc, 'div', 'covlab-detail-ev', `${EVIDENCE_UI[r.ev].label}${r.active ? ' · live attribution from raw signals' : ''}`),
      el(doc, 'div', 'covlab-detail-tac', r.tactics.join(' · ')));
    const acts = el(doc, 'div', 'covlab-detail-acts');
    if (onExplain) {
      const ex = el(doc, 'button', 'atk-cov-explain', 'explain ▸');
      ex.type = 'button';
      ex.addEventListener('click', () => { try { onExplain({ kind: 'technique', title: `${r.id} ${r.name}`, id: r.id, name: r.name, evidence: EVIDENCE_UI[r.ev].label, tactics: r.tactics, liveAttribution: r.active }); } catch { /* copilot not ready */ } });
      acts.append(ex);
    }
    const a = el(doc, 'a', 'covlab-mitre', 'MITRE ATT&CK ▸');
    a.href = mitreUrl(r.id);
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    acts.append(a);
    detail.append(acts);
  }

  const section = (h, sub, ...nodes) => {
    const sec = el(doc, 'section', 'covlab-section');
    sec.append(el(doc, 'h4', null, h));
    if (sub) sec.append(el(doc, 'p', 'covlab-sub', sub));
    sec.append(...nodes);
    return sec;
  };

  function render() {
    tipApi.hide();
    const tm = D.telemetry;
    const evCounts = EVIDENCE_ORDER.map((e) => `${stats.byEvidence[e]} ${EVIDENCE_UI[e].short}`).join(' · ');
    const nodes = [kpiTiles(doc, D)];
    if (!tableView) {
      nodes.push(
        section('ATT&CK MATRIX · strongest evidence per technique', `${stats.techniques.size} techniques in ${D.matrix.length} tactics — ${evCounts}. Real traces outrank the lab: a technique the corpus catches but a real trace misses shows as missed.`,
          legend(doc), fullMatrix(doc, D, tipApi, (id) => { selected = id; renderDetail(); }), detail),
        el(doc, 'div', 'covlab-pair'),
      );
      const pair = nodes[nodes.length - 1];
      pair.append(
        section('HOW EACH FIX MOVED DETECTION', 'One fix at a time, same captures, same judge (tools/attack-eval).', ablationMeters(doc, D, tipApi)),
        section('PRECISION vs RECALL BY SIGMA LEVEL', 'Alerting only on rules at or above each level. Every point is reported; none was picked after the fact.', operatingChart(doc, D, tipApi)),
      );
      if (D.evtx) {
        nodes.push(section('REAL-ATTACK DETECTION RATE BY TACTIC',
          `${D.evtx.detectedAny} of ${D.evtx.captures} curated malicious EVTX captures fire a rule — ${pct(D.evtx.rateAny)} (${pct(D.evtx.rateMedium)} at the medium+ tier). A capture-level true-positive rate, distinct from recall above.`,
          realAttackStrip(doc, D, tipApi)));
      }
    } else {
      const byEv = EVIDENCE_ORDER.flatMap((e) => [...stats.techniques.values()].filter((r) => r.ev === e).sort((a, b) => a.id.localeCompare(b.id)).map((r) => [EVIDENCE_UI[e].short, r.id, r.name, r.tactics.join(', '), r.active ? 'yes' : '']));
      nodes.push(
        table(doc, 'Detection fixes, one at a time', ['fix', 'recall', 'alert precision', 'F1', 'captures'], (tm.ablation || []).map((r) => [r.label, pct(r.recall), pct(r.alertPrecision), pct(r.f1), `${r.detected}/${tm.captures}`])),
        table(doc, 'Operating points by Sigma level', ['alert on level ≥', 'recall', 'alert precision', 'F1', 'captures'], (tm.operatingPoints || []).map((o) => [o.level, pct(o.recall), pct(o.alertPrecision), pct(o.f1), `${o.detected}/${tm.captures}`])),
        table(doc, `ATT&CK ${D.attack} techniques by evidence`, ['evidence', 'id', 'technique', 'tactics', 'live attribution'], byEv),
      );
      if (D.evtx) {
        nodes.push(table(doc, `Real-attack detection rate by tactic (EVTX-ATTACK-SAMPLES, ${D.evtx.captures} captures)`,
          ['tactic', 'fires a rule', 'medium+ tier', 'captures'],
          D.evtx.byTactic.map((r) => [tacticLabel(r.tactic), pct(r.rateAny), pct(r.total ? r.medium / r.total : 0), `${r.any}/${r.total}`])));
      }
    }
    const drift = (D.drift || []).map((d) => `${d.from}→${d.to}`).join(', ');
    nodes.push(el(doc, 'p', 'covlab-foot', `Scored against ${D.source}. ATT&CK drift handled via MITRE revoked-by (${drift || 'none'}). Generated from the judges' result files${D.generatedFrom?.telemetry ? ` · telemetry run ${String(D.generatedFrom.telemetry).slice(0, 10)}` : ''}.`));
    body.replaceChildren(...nodes);
    if (!tableView) renderDetail();
  }

  const onKey = (e) => { if (e.key === 'Escape' && !panel.hidden) api.close(); };
  tableBtn.addEventListener('click', () => { tableView = !tableView; tableBtn.setAttribute('aria-pressed', String(tableView)); tableBtn.classList.toggle('active', tableView); render(); });
  close.addEventListener('click', () => api.close());
  for (const type of ['pointerdown', 'dblclick', 'wheel']) panel.addEventListener(type, (e) => e.stopPropagation());

  const api = {
    element: panel,
    isOpen: () => !panel.hidden,
    open(techniqueId = null) {
      if (techniqueId) selected = techniqueId;
      if (panel.hidden) { panel.hidden = false; doc.addEventListener('keydown', onKey); }
      render();
      (techniqueId ? panel.querySelector(`.covlab-cell[data-id="${techniqueId}"]`) : close)?.focus?.();
      tipApi.hide(); // programmatic focus: no uninvited tooltip over the matrix
    },
    close() { panel.hidden = true; tipApi.hide(); doc.removeEventListener('keydown', onKey); },
  };
  return api;
}
