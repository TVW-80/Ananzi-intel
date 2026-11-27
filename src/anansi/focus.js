/**
 * Ananzi focus: WORLD or 757.
 *
 * WORLD (the default) shows everything everywhere. 757 is a Hampton Roads
 * filter — the country-level Cyber layers keep only US entries and the Shodan
 * layers search around Norfolk. There is no on-screen switch: the WORLD / 757
 * toggle was removed, so the app always runs on WORLD and setFocus() is only a
 * programmatic entry point (no persistence — a stored 757 could otherwise trap
 * a viewer in a focus they can no longer leave).
 */
export const FOCUS_WORLD = 'world';
export const FOCUS_757 = '757';
const listeners = new Set();

let current = FOCUS_WORLD;

export function getFocus() {
  return current;
}

export function setFocus(next) {
  const value = next === FOCUS_757 ? FOCUS_757 : FOCUS_WORLD;
  if (value === current) return;
  current = value;
  for (const fn of [...listeners]) {
    try {
      fn(value);
    } catch (err) {
      console.warn('[Ananzi focus] listener failed', err);
    }
  }
}

/** @returns {() => void} unsubscribe */
export function onFocusChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * Country-level points in 757 focus: keep only the United States (and US
 * states). Points with exact coordinates are kept if they are within the
 * Hampton Roads box.
 */
export function inFocus(point, focus = current) {
  if (focus !== FOCUS_757) return true;
  const id = String(point?.id || '');
  if (point?.approximate === false && Number.isFinite(point.lat) && Number.isFinite(point.lon)) {
    return point.lat > 35.9 && point.lat < 38.0 && point.lon > -77.9 && point.lon < -75.3;
  }
  return /:US$/.test(id) || /:us-state:/.test(id);
}
