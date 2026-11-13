/* Core helpers shared by every page: DOM access, auto-escaping HTML templates,
   the JSON API client, number/time formatting and animation utilities. */

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

export const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ESCAPES[ch]);

class SafeHtml {
  constructor(value) { this.value = value; }
  toString() { return this.value; }
}

/** Mark markup as trusted. Only use for strings built by `html` or `icon`. */
export const raw = (value) => new SafeHtml(String(value));

function renderValue(value) {
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(renderValue).join('');
  if (value === null || value === undefined || value === false) return '';
  return escapeHtml(value);
}

/** Tagged template: every interpolated value is HTML-escaped unless it is SafeHtml. */
export function html(strings, ...values) {
  return new SafeHtml(strings.reduce((out, part, i) => out + part + (i < values.length ? renderValue(values[i]) : ''), ''));
}

const contextNode = document.getElementById('app-context');
export const ctx = Object.freeze(contextNode ? JSON.parse(contextNode.textContent) : {});
export const isAdmin = ctx.role === 'admin';
const SPRITE = ctx.icons || 'static/img/icons.svg';

export const icon = (name, cls = '') =>
  raw(`<svg class="icon ${escapeHtml(cls)}" aria-hidden="true" focusable="false"><use href="${escapeHtml(SPRITE)}#${escapeHtml(name)}"></use></svg>`);

export const iconHref = (name) => `${SPRITE}#${name}`;

/* ---------- API client ---------- */

export class ApiError extends Error {
  constructor(message, status, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details || null;
  }
}

const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content ?? '';

/** Call the JSON API. Resolves to { data, meta }; rejects with ApiError. */

/* Static demo: answer API calls from saved sample data (scripts/build_static_demo.py). */
async function mockApi(path, method, body) {
  await new Promise((r) => setTimeout(r, 120));
  const M = window.__MOCK__ || {};
  const url = new URL(path, 'http://x');
  if (method === 'GET') {
    let key = url.pathname;
    if (url.searchParams.has('range')) key += `?range=${url.searchParams.get('range')}`;
    if (url.pathname === '/api/threats') key += `?page=${url.searchParams.get('page') || 1}`;
    const hit = M[key] || M[url.pathname] || M[`/api/threats?page=1`];
    if (!hit) throw new ApiError('Not available in the static demo.', 404);
    return { data: hit.data, meta: hit.meta || {} };
  }
  if (url.pathname === '/api/query') {
    const samples = M['POST /api/query'] || [];
    const name = (body?.domain || '').toLowerCase();
    const hit = samples.find((s) => s.data?.domain === name) || samples[1] || samples[0];
    if (!hit) throw new ApiError('Not available in the static demo.', 404);
    return { data: { ...hit.data, domain: body?.domain || hit.data.domain }, meta: hit.meta || {} };
  }
  return { data: { ...(body || {}), id: Date.now() }, meta: { demo: true } };
}
export async function api(path, { method = 'GET', body } = {}) {
  if (window.__MOCK__) return mockApi(path, method, body);
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken();
  let response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Cannot reach the server - check that Sentinel is running.', 0);
  }
  if (response.status === 401) {
    window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname)}`);
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  const payload = await response.json().catch(() => null);
  if (!response.ok || !payload || payload.success !== true) {
    throw new ApiError(payload?.error || `Request failed (${response.status})`, response.status, payload?.details);
  }
  return { data: payload.data, meta: payload.meta || {} };
}

/* ---------- Formatting ---------- */

const integer = new Intl.NumberFormat('en-US');

export const fmt = {
  int: (value) => integer.format(Math.round(Number(value) || 0)),
  dec: (value, digits = 1) => (Number(value) || 0).toFixed(digits),
  // null = not measured (e.g. bind mode: BIND's log has no latency / cache data)
  pct: (value, digits = 1) => (value === null || value === undefined ? '—' : `${(Number(value) || 0).toFixed(digits)}%`),
  ms: (value) => `${(Number(value) || 0).toFixed(Number(value) >= 100 ? 0 : 1)}ms`,
  bytes(value) {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = Number(value) || 0;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return `${size.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  },
  time: (ts) => new Date(ts * 1000).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' }),
  dateTime: (ts) => (ts ? new Date(ts * 1000).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—'),
};

export function timeAgo(ts, now = Date.now() / 1000) {
  if (!ts) return 'never';
  const seconds = Math.max(0, Math.round(now - ts));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds} secs ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

export const SEVERITY_LABEL = Object.freeze({ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' });
export const sevBadge = (severity) => (severity ? html`<span class="badge sev-${severity}">${SEVERITY_LABEL[severity] || severity}</span>` : '');

/* ---------- Motion ---------- */

export const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const running = new WeakMap();
const easeOutQuart = (t) => 1 - (1 - t) ** 4;

/** Animate a number from its previous value to `target`. */
export function countUp(el, target, { decimals = 0, prefix = '', suffix = '', duration = 1100 } = {}) {
  if (!el) return;
  if (target === null || target === undefined) {  // not measured: show a dash, restart from 0 next time
    cancelAnimationFrame(running.get(el));
    el.classList.remove('skeleton');
    delete el.dataset.value;
    el.textContent = '—';
    return;
  }
  const to = Number(target) || 0;
  const from = Number(el.dataset.value ?? 0);
  el.dataset.value = String(to);
  el.classList.remove('skeleton');
  const render = (value) => prefix + (decimals ? value.toFixed(decimals) : fmt.int(value)) + suffix;
  cancelAnimationFrame(running.get(el));
  if (reducedMotion() || from === to) { el.textContent = render(to); return; }
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    el.textContent = render(from + (to - from) * easeOutQuart(t));
    if (t < 1) running.set(el, requestAnimationFrame(step));
  };
  running.set(el, requestAnimationFrame(step));
}

/** Grow [data-scale] bars (0-100) once they are painted, using transform for smooth motion. */
export function animateBars(root = document) {
  requestAnimationFrame(() => requestAnimationFrame(() => {
    $$('[data-scale]', root).forEach((bar) => {
      const pct = Math.max(0, Math.min(100, Number(bar.dataset.scale) || 0));
      bar.style.transform = `scaleX(${pct / 100})`;
    });
  }));
}

export function setText(el, text) {
  if (!el) return;
  el.textContent = text;
  el.classList.remove('skeleton');
}

/* ---------- Timing ---------- */

export function debounce(fn, wait = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

/** Run `task` now and then every `interval` ms while the tab is visible. Returns stop(). */
export function poll(task, interval, onError) {
  let timer = null;
  let busy = false;
  let stopped = false;
  const schedule = () => {
    if (!stopped && !document.hidden) timer = setTimeout(run, interval);
  };
  async function run() {
    timer = null;
    if (stopped || busy) return;
    busy = true;
    try {
      await task();
    } catch (error) {
      onError?.(error);
    } finally {
      busy = false;
    }
    schedule();
  }
  const onVisibility = () => {
    if (document.hidden) {
      clearTimeout(timer);
      timer = null;
    } else if (!timer && !busy) {
      run();
    }
  };
  document.addEventListener('visibilitychange', onVisibility);
  run();
  return () => {
    stopped = true;
    clearTimeout(timer);
    document.removeEventListener('visibilitychange', onVisibility);
  };
}

/* ---------- Browser storage (best effort: may be unavailable) ---------- */

export const storage = {
  get(key, fallback = null) {
    try {
      const value = localStorage.getItem(key);
      return value === null ? fallback : JSON.parse(value);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      /* Storage blocked (private mode): the preference simply is not remembered. */
    }
  },
};
