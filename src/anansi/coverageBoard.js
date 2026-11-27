/**
 * Ananzi FANGS — ATT&CK DETECTION COVERAGE board (the SITREP summary card).
 *
 * A compact read of F.A.N.G.S's own measured MITRE ATT&CK coverage: KPI tiles
 * (detection on real attack traces, alert precision, techniques caught), a
 * thumbnail of the ATT&CK matrix, the three coverage surfaces, the command-
 * corpus scorecard and ATT&CK drift. "open lab ▸" (or the thumbnail) opens the
 * full ATT&CK COVERAGE LAB (coverageLab.js) — the visuals live there, so the
 * SITREP stays uncluttered.
 *
 * Honest by construction: every number comes from coverageData.generated.js,
 * which tools/attack-eval/snapshot.mjs builds from the judges' result files.
 * Only labels, colours and notes are written here. English-only (src/anansi/**).
 */
import { COVERAGE_DATA } from './coverageData.generated.js';
import { kpiTiles, miniMatrix, legend } from './coverageLab.js';

const D = COVERAGE_DATA;

/** UI-only text per coverage surface; the numbers are merged in from the generated data. */
const SURFACE_UI = Object.freeze({
  active: { label: 'Active attribution', color: '#ff2b2b', note: 'derived from raw live signals (ddos→T1498, c2→T1071…)' },
  explains: { label: 'Explains (feed id)', color: '#d4af37', note: 'rendered when a feed supplies the technique id' },
  detection: { label: 'Sigma detection', color: '#3fa7ff', note: 'Sigma rules verified against the Atomic Red Team command corpus' },
});

/** The measured snapshot (generated numbers + UI labels). Regenerate, never retype. */
export const COVERAGE_SNAPSHOT = Object.freeze({
  attack: D.attack,
  enterprise: D.enterprise,
  surfaces: ['active', 'explains', 'detection'].map((id) => Object.freeze({ id, ...SURFACE_UI[id], ...D.surfaces[id] })),
  scorecard: D.scorecard,
  telemetry: D.telemetry,
  drift: D.drift,
  source: D.source,
});

const pct1 = (x) => `${(100 * x).toFixed(1)}%`;

/** Compact, bounded coverage-gap payload for grounding the copilot's "explain". */
export function coverageGap(snapshot = COVERAGE_SNAPSHOT) {
  const sc = snapshot.scorecard;
  const tm = snapshot.telemetry || {};
  const tiers = (tm.operatingPoints || []).map((o) => `≥${o.level}: recall ${pct1(o.recall)} / precision ${pct1(o.alertPrecision)}`);
  return {
    kind: 'coverage',
    title: 'ATT&CK detection coverage',
    attack: snapshot.attack,
    detectionF1: sc.f1,
    bar: sc.bar,
    alertPrecision: sc.alertPrecision,
    recall: sc.recall,
    breadth: `${sc.breadthDetected}/${sc.breadthCovered}`,
    realTelemetryRecall: tm.captureRecall ?? null,
    realTelemetryPrecision: tm.alertPrecision ?? null,
    techniquesDetected: tm.techDetected ?? null,
    techniquesLabeled: tm.techLabeled ?? null,
    undetectedTechniques: tm.undetected || [],
    alertTiers: tiers,
    drift: (snapshot.drift || []).map((d) => `${d.from}→${d.to}`),
  };
}

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** The ATT&CK coverage board: { element, update() }. update is a no-op (static, generated snapshot). */
export function createCoverageBoard(doc = document, snapshot = COVERAGE_SNAPSHOT, { onExplain = null, onOpenLab = null } = {}) {
  const wrap = el(doc, 'section', 'atk-cov collapsed');
  wrap.setAttribute('aria-label', 'ATT&CK detection coverage');
  const head = el(doc, 'div', 'atk-cov-head');
  const headL = el(doc, 'div', 'atk-cov-headL');
  const toggle = el(doc, 'button', 'atk-cov-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'atk-cov-title', '◆ ATT&CK COVERAGE · measured');
  const tm = snapshot.telemetry || {};
  const tally = el(doc, 'span', 'atk-cov-tally', tm.captureRecall != null ? `${pct1(tm.captureRecall)} on real traces` : '');
  headL.append(toggle, title);
  head.append(headL, tally);

  const body = el(doc, 'div', 'atk-cov-body');
  body.append(kpiTiles(doc, D, { compact: true }));

  // Thumbnail of the matrix — one click opens the lab.
  const thumb = el(doc, 'button', 'atk-cov-thumb');
  thumb.type = 'button';
  thumb.setAttribute('aria-label', `Open the ATT&CK coverage lab — ${D.matrix.length} tactics, evidence per technique`);
  thumb.append(miniMatrix(doc, D), el(doc, 'span', 'atk-cov-thumb-cta', 'ATT&CK matrix · open lab ▸'));
  if (onOpenLab) thumb.addEventListener('click', () => { try { onOpenLab(); } catch { /* lab not ready */ } });
  else thumb.disabled = true;
  body.append(thumb, legend(doc, { active: false }));

  const actions = el(doc, 'div', 'atk-cov-actions');
  if (onOpenLab) {
    const open = el(doc, 'button', 'atk-cov-explain', 'open lab ▸');
    open.type = 'button';
    open.addEventListener('click', () => { try { onOpenLab(); } catch { /* lab not ready */ } });
    actions.append(open);
  }
  if (onExplain) {
    const btn = el(doc, 'button', 'atk-cov-explain', 'explain gaps ▸');
    btn.type = 'button';
    btn.title = 'Ask the grounded copilot to explain these detection gaps and what to fix first';
    btn.addEventListener('click', () => { try { onExplain(coverageGap(snapshot)); } catch { /* copilot not ready */ } });
    actions.append(btn);
  }
  if (actions.childElementCount) body.append(actions);

  const sub = el(doc, 'div', 'atk-cov-sub', `coverage surfaces vs MITRE ATT&CK ${snapshot.attack} — ${snapshot.enterprise.techniques} techniques · ${snapshot.enterprise.tactics} tactics`);
  body.append(sub);
  // Coverage meter list — one row per surface (name · bar · figure).
  for (const s of snapshot.surfaces) {
    const row = el(doc, 'div', 'atk-cov-row');
    const name = el(doc, 'span', 'atk-cov-name', s.label);
    const barWrap = el(doc, 'span', 'atk-cov-bar');
    const fill = el(doc, 'span', 'atk-cov-fill');
    fill.style.width = `${Math.max(2, s.pct)}%`;
    fill.style.background = s.color;
    barWrap.append(fill);
    const val = el(doc, 'span', 'atk-cov-val', `${s.techniques} · ${s.pct}% · ${s.tactics}/${snapshot.enterprise.tactics} tac`);
    row.append(name, barWrap, val);
    row.title = s.note;
    body.append(row);
  }

  // Command-corpus scorecard (detector scope — the scope its judge reports).
  const sc = snapshot.scorecard;
  const card = el(doc, 'div', 'atk-cov-score');
  const pass = sc.f1 >= sc.bar;
  card.append(
    el(doc, 'span', 'atk-cov-score-h', 'COMMAND-CORPUS SCORECARD'),
    el(doc, 'span', `atk-cov-badge ${pass ? 'ok' : 'below'}`, `F1 ${pct1(sc.f1)} / bar ${pct1(sc.bar)}`),
  );
  card.append(el(doc, 'div', 'atk-cov-score-detail',
    `alert-P ${pct1(sc.alertPrecision)} · recall ${pct1(sc.recall)} · breadth ${sc.breadthDetected}/${sc.breadthCovered} (${pct1(sc.breadthDetected / sc.breadthCovered)}) · ${sc.events.toLocaleString('en-US')} events / ${sc.rules.toLocaleString('en-US')} rules`));
  if (tm.captureRecall != null) {
    card.append(el(doc, 'div', 'atk-cov-score-detail',
      `real telemetry: ${pct1(tm.captureRecall)} capture detection (${tm.detected}/${tm.captures}) · ${tm.techDetected}/${tm.techLabeled} techniques · ${tm.sensors} log sources contributing · ${tm.rules.toLocaleString('en-US')} rules`));
  }
  body.append(card);

  if (snapshot.drift.length) {
    const drift = el(doc, 'div', 'atk-cov-drift');
    drift.append(el(doc, 'span', 'atk-cov-drift-h', `⚠ ATT&CK DRIFT · ${snapshot.drift.length}`));
    for (const d of snapshot.drift) drift.append(el(doc, 'span', 'atk-cov-drift-item', `${d.from} → ${d.to} (${d.name})`));
    body.append(drift);
  }
  body.append(el(doc, 'div', 'atk-cov-src', `scored against ${snapshot.source} · tools/attack-eval`));
  wrap.append(head, body);

  // Collapse, remembered per viewer (best-effort; never throws).
  const STORE_KEY = 'ananzi.fangs.attackCoverage.collapsed';
  let collapsed = true;
  try { const v = globalThis.localStorage?.getItem(STORE_KEY); if (v != null) collapsed = v === '1'; } catch { /* private mode */ }
  const apply = () => {
    wrap.classList.toggle('collapsed', collapsed);
    toggle.textContent = collapsed ? '▸' : '▾';
    toggle.setAttribute('aria-expanded', String(!collapsed));
    toggle.title = collapsed ? 'Expand coverage' : 'Collapse coverage';
  };
  const set = (n) => { collapsed = n; try { globalThis.localStorage?.setItem(STORE_KEY, n ? '1' : '0'); } catch { /* ignore */ } apply(); };
  toggle.addEventListener('click', () => set(!collapsed));
  title.style.cursor = 'pointer';
  title.addEventListener('click', () => set(!collapsed));
  apply();

  return { element: wrap, update() { /* static generated snapshot — nothing to refresh */ } };
}
