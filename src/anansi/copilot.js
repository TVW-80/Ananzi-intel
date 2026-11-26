/**
 * Ananzi FANGS — analyst copilot panel (the "ASK" surface).
 *
 * A small grounded chat: it gathers the current F.A.N.G.S picture (attack map
 * snapshot + measured ATT&CK coverage), sends it with the question to
 * /api/copilot, and shows the answer. Off unless the operator configured a model
 * (ANTHROPIC_API_KEY / OPENAI_API_KEY / OLLAMA_URL) — the server keeps the key
 * and does the grounding; this is just the UI. English-only (src/anansi/**).
 *
 * Rendering only; the grounding + honesty rules live server-side in copilot.js.
 */
import { COVERAGE_SNAPSHOT } from './coverageBoard.js';

function el(doc, tag, cls, text) {
  const n = doc.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/** Compact, bounded grounding context from the live attack snapshot + coverage. */
export function groundingContext(attack) {
  const a = attack || {};
  const trim = (arr, n, f) => (Array.isArray(arr) ? arr.slice(0, n).map(f) : []);
  return {
    updatedAt: a.updatedAt || null,
    rate: a.rate?.perMinute ?? null,
    topSources: trim(a.sources, 10, (s) => ({ place: s.name, weight: s.weight, mostly: s.dominantService || null })),
    attackTypes: trim(a.attackTypes, 6, (t) => ({ type: t.label, count: t.count })),
    ddosTargets: trim(a.ddos?.targets, 6, (t) => ({ country: t.name, pct: t.value })),
    alerts: trim(a.alerts, 12, (x) => ({ source: x.source, title: x.title, plain: x.plain || null, time: x.time || null })),
    exposure: trim(a.exposure, 5, (e) => ({ what: e.label, total: e.total })),
    attackCoverage: {
      attack: COVERAGE_SNAPSHOT.attack,
      surfaces: COVERAGE_SNAPSHOT.surfaces.map((s) => ({ id: s.id, techniques: s.techniques, pct: s.pct })),
      detectionScorecard: COVERAGE_SNAPSHOT.scorecard,
      realTelemetry: COVERAGE_SNAPSHOT.telemetry,
      drift: COVERAGE_SNAPSHOT.drift,
    },
    note: 'This is the only data to answer from. Correlation is a hypothesis; the timeline is as-reported.',
  };
}

export function createCopilot(doc = document, { getContext = () => ({}), fetchImpl = (...a) => globalThis.fetch(...a) } = {}) {
  const wrap = el(doc, 'div', 'copilot');
  const note = el(doc, 'p', 'copilot-note', 'Grounded in the current F.A.N.G.S data — attack map + measured ATT&CK coverage. It won’t invent anything; correlation is a hypothesis.');
  const log = el(doc, 'div', 'copilot-log');
  const off = el(doc, 'div', 'copilot-off');
  off.hidden = true;
  const form = el(doc, 'form', 'copilot-form');
  const input = el(doc, 'input', 'copilot-input');
  input.type = 'text';
  input.placeholder = 'Ask about the current picture…';
  input.setAttribute('aria-label', 'Ask the copilot');
  const ask = el(doc, 'button', 'copilot-send', 'ASK');
  ask.type = 'submit';
  form.append(input, ask);
  wrap.append(note, off, log, form);

  let busy = false;
  const bubble = (who, text, cls) => {
    const b = el(doc, 'div', `copilot-msg copilot-${who}${cls ? ` ${cls}` : ''}`, text);
    log.append(b);
    log.scrollTop = log.scrollHeight;
    return b;
  };

  async function refreshEnabled() {
    try {
      const res = await fetchImpl('/api/copilot', { cache: 'no-store' });
      const body = await res.json();
      const enabled = body.enabled === true;
      off.hidden = enabled;
      input.disabled = ask.disabled = !enabled;
      if (!enabled) off.textContent = 'Copilot is off. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_URL (a local model — no data leaves your machine) to turn it on.';
      else if (body.provider) note.dataset.provider = body.provider;
    } catch {
      off.hidden = false; input.disabled = ask.disabled = true;
      off.textContent = 'Copilot backend not reachable.';
    }
  }

  async function submit(question) {
    if (busy || !question) return;
    busy = true; input.disabled = ask.disabled = true;
    bubble('user', question);
    const pending = bubble('bot', '…', 'pending');
    try {
      const res = await fetchImpl('/api/copilot', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, context: getContext() }),
      });
      const body = await res.json();
      if (body.status === 'ok') { pending.textContent = body.answer; pending.classList.remove('pending'); }
      else if (body.status === 'key-required') { pending.textContent = body.message || 'Copilot is off.'; pending.classList.add('copilot-err'); refreshEnabled(); }
      else { pending.textContent = `Couldn’t answer: ${body.error || 'unknown error'}`; pending.classList.add('copilot-err'); }
    } catch (e) {
      pending.textContent = `Couldn’t reach the copilot: ${e?.message || e}`;
      pending.classList.add('copilot-err');
    } finally {
      pending.classList.remove('pending');
      busy = false; input.disabled = ask.disabled = false; input.focus();
    }
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q) return;
    input.value = '';
    submit(q);
  });

  return { element: wrap, open() { refreshEnabled(); } };
}
