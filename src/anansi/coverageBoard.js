/**
 * Ananzi FANGS — ATT&CK DETECTION COVERAGE board.
 *
 * Surfaces F.A.N.G.S's own, measured MITRE ATT&CK coverage in the SITREP: how
 * much of the Enterprise matrix it attributes and detects, the detection
 * scorecard (precision / recall / F1 vs ground truth), and any ATT&CK drift —
 * the output of the offline judge in tools/attack-eval, scored against the live
 * ATT&CK STIX matrix, Atomic Red Team and SigmaHQ.
 *
 * Honest by construction: this is a dated SNAPSHOT of a reproducible evaluation,
 * not a live claim. Regenerate with `node tools/attack-eval/sigma-eval.mjs` +
 * `coverage.mjs` and paste the numbers below. English-only (src/anansi/**).
 *
 * Rendering only.
 */

/** Dated snapshot of tools/attack-eval (keep in sync with its results-*.json). */
export const COVERAGE_SNAPSHOT = Object.freeze({
  attack: 'v20.1',
  enterprise: { techniques: 227, tactics: 15 },
  surfaces: [
    { id: 'active', label: 'Active attribution', techniques: 12, pct: 5.3, tactics: 9, color: '#ff2b2b', note: 'derived from raw signals (ddos→T1498, c2→T1071…)' },
    { id: 'explains', label: 'Explains (feed id)', techniques: 55, pct: 24.2, tactics: 15, color: '#d4af37', note: 'rendered when a feed supplies the technique id' },
    { id: 'detection', label: 'Sigma detection', techniques: 85, pct: 37.4, tactics: 13, color: '#3fa7ff', note: 'process_creation + PowerShell script-block, verified vs ground truth' },
  ],
  scorecard: { f1: 0.275, alertPrecision: 0.323, recall: 0.239, breadthDetected: 85, breadthCovered: 122, bar: 0.8, events: 3263, rules: 1402 },
  // Higher-fidelity read: full multi-sensor Sigma corpus replayed over real
  // labeled Windows telemetry (OTRF Security-Datasets). See tools/attack-eval.
  telemetry: {
    captureRecall: 0.579, detected: 55, captures: 95, techDetected: 20, techLabeled: 31, sensors: 6, rules: 2189,
    // ATT&CK techniques present in the labeled telemetry that F.A.N.G.S does not
    // yet detect — the real detection to-do list (grounds the copilot's gaps).
    undetected: ['T1012', 'T1049', 'T1056', 'T1110', 'T1123', 'T1135', 'T1210', 'T1222', 'T1550', 'T1558', 'T1562'],
  },
  drift: [
    { from: 'T1562', to: 'T1685', name: 'Disable or Modify Tools' },
    { from: 'T1574.002', to: 'T1574.001', name: 'DLL' },
  ],
  source: 'ATT&CK v20.1 · Atomic Red Team · SigmaHQ · OTRF Security-Datasets',
});

const pct1 = (x) => `${(100 * x).toFixed(1)}%`;

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** Compact, bounded coverage-gap payload for grounding the copilot's "explain". */
export function coverageGap(snapshot = COVERAGE_SNAPSHOT) {
  const sc = snapshot.scorecard;
  const tm = snapshot.telemetry || {};
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
    techniquesDetected: tm.techDetected ?? null,
    techniquesLabeled: tm.techLabeled ?? null,
    undetectedTechniques: tm.undetected || [],
    drift: (snapshot.drift || []).map((d) => `${d.from}→${d.to}`),
  };
}

/** The ATT&CK coverage board: { element, update() }. update is a no-op (static snapshot). */
export function createCoverageBoard(doc = document, snapshot = COVERAGE_SNAPSHOT, { onExplain = null } = {}) {
  const wrap = el(doc, 'section', 'atk-cov collapsed');
  wrap.setAttribute('aria-label', 'ATT&CK detection coverage');
  const head = el(doc, 'div', 'atk-cov-head');
  const headL = el(doc, 'div', 'atk-cov-headL');
  const toggle = el(doc, 'button', 'atk-cov-toggle', '▾');
  toggle.type = 'button';
  const title = el(doc, 'span', 'atk-cov-title', '◆ ATT&CK COVERAGE · measured');
  const tally = el(doc, 'span', 'atk-cov-tally', `${snapshot.surfaces.find((s) => s.id === 'detection').techniques}/${snapshot.enterprise.techniques}`);
  headL.append(toggle, title);
  head.append(headL, tally);

  const body = el(doc, 'div', 'atk-cov-body');
  const sub = el(doc, 'div', 'atk-cov-sub', `vs MITRE ATT&CK ${snapshot.attack} — ${snapshot.enterprise.techniques} techniques · ${snapshot.enterprise.tactics} tactics`);
  body.append(sub);

  // Coverage bars — one row per surface.
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

  // Detection scorecard.
  const sc = snapshot.scorecard;
  const card = el(doc, 'div', 'atk-cov-score');
  const pass = sc.f1 >= sc.bar;
  card.append(
    el(doc, 'span', 'atk-cov-score-h', 'DETECTION SCORECARD'),
    el(doc, 'span', `atk-cov-badge ${pass ? 'ok' : 'below'}`, `F1 ${pct1(sc.f1)} / bar ${pct1(sc.bar)}`),
  );
  const detail = el(doc, 'div', 'atk-cov-score-detail',
    `command corpus: alert-P ${pct1(sc.alertPrecision)} · recall ${pct1(sc.recall)} · breadth ${sc.breadthDetected}/${sc.breadthCovered} (${pct1(sc.breadthDetected / sc.breadthCovered)}) · ${sc.events.toLocaleString('en-US')} events / ${sc.rules.toLocaleString('en-US')} rules`);
  card.append(detail);
  const tm = snapshot.telemetry;
  if (tm) {
    card.append(el(doc, 'div', 'atk-cov-score-detail',
      `real telemetry: ${pct1(tm.captureRecall)} capture detection (${tm.detected}/${tm.captures}) · ${tm.techDetected}/${tm.techLabeled} techniques · ${tm.sensors} sensors · ${tm.rules.toLocaleString('en-US')} rules`));
  }
  // "explain ▸" — ask the grounded copilot to read these gaps in plain English.
  if (onExplain) {
    const btn = el(doc, 'button', 'atk-cov-explain', 'explain gaps ▸');
    btn.type = 'button';
    btn.title = 'Ask the grounded copilot to explain these detection gaps and what to fix first';
    btn.addEventListener('click', () => { try { onExplain(coverageGap(snapshot)); } catch { /* copilot not ready */ } });
    card.append(btn);
  }
  body.append(card);

  // ATT&CK drift — retired ids F.A.N.G.S still references, with replacements.
  if (snapshot.drift.length) {
    const drift = el(doc, 'div', 'atk-cov-drift');
    drift.append(el(doc, 'span', 'atk-cov-drift-h', `⚠ ATT&CK DRIFT · ${snapshot.drift.length}`));
    for (const d of snapshot.drift) {
      drift.append(el(doc, 'span', 'atk-cov-drift-item', `${d.from} → ${d.to} (${d.name})`));
    }
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

  return { element: wrap, update() { /* static snapshot — nothing to refresh */ } };
}
