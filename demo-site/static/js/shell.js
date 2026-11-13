/* Application shell: sidebar collapse / mobile drawer, live clock, status indicator,
   "last update" footer, keyboard shortcuts and card hover glow. */
import { $, api, iconHref, poll, storage } from './core.js';

const COLLAPSE_KEY = 'sentinel.sidebar.collapsed';
const MOBILE = window.matchMedia('(max-width: 760px)');
const NARROW = window.matchMedia('(max-width: 1100px)');
const STATUS_INTERVAL = 15000;

function setToggleIcon(collapsed) {
  $('#sidebar-toggle use')?.setAttribute('href', iconHref(collapsed ? 'panel-left-open' : 'panel-left-close'));
}

function setupSidebar() {
  const app = $('#app');
  const toggle = $('#sidebar-toggle');
  const scrim = $('#sidebar-scrim');
  if (!app || !toggle) return;

  const closeDrawer = () => {
    app.classList.remove('is-drawer-open');
    if (scrim) scrim.hidden = true;
  };
  const apply = () => {
    if (MOBILE.matches) {
      app.classList.remove('is-collapsed');
      setToggleIcon(true);
      return;
    }
    closeDrawer();
    const preference = storage.get(COLLAPSE_KEY, null);
    const collapsed = preference === null ? NARROW.matches : Boolean(preference);
    app.classList.toggle('is-collapsed', collapsed);
    setToggleIcon(collapsed);
  };

  apply();
  requestAnimationFrame(() => requestAnimationFrame(() => app.classList.add('is-ready')));

  toggle.addEventListener('click', () => {
    if (MOBILE.matches) {
      const open = !app.classList.contains('is-drawer-open');
      app.classList.toggle('is-drawer-open', open);
      if (scrim) scrim.hidden = !open;
      return;
    }
    const collapsed = !app.classList.contains('is-collapsed');
    app.classList.toggle('is-collapsed', collapsed);
    setToggleIcon(collapsed);
    storage.set(COLLAPSE_KEY, collapsed);
  });
  scrim?.addEventListener('click', closeDrawer);
  MOBILE.addEventListener('change', apply);
  NARROW.addEventListener('change', apply);
}

function setupClock() {
  const el = $('#clock');
  if (!el) return;
  const tick = () => {
    el.textContent = new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', second: '2-digit' });
  };
  tick();
  setInterval(tick, 1000);
}

function setupShortcuts() {
  document.addEventListener('keydown', (event) => {
    if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.altKey) return;
    const target = event.target;
    if (target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
    if (event.key === '[') {
      $('#sidebar-toggle')?.click();
    } else if (event.key === '/') {
      const search = $('[data-search]');
      if (search) {
        event.preventDefault();
        search.focus();
      }
    }
  });
}

function setupGlow() {
  document.addEventListener('pointermove', (event) => {
    const card = event.target.closest?.('.stat-card, .kpi');
    if (!card) return;
    const rect = card.getBoundingClientRect();
    card.style.setProperty('--mx', `${event.clientX - rect.left}px`);
    card.style.setProperty('--my', `${event.clientY - rect.top}px`);
  }, { passive: true });
}

/** Reflect server health in the top bar ("● ACTIVE" / "● OFFLINE"). */
export function applyStatus(status) {
  const pill = $('#status-pill');
  if (!pill) return;
  const active = status?.overall === 'active';
  pill.classList.toggle('is-offline', !active);
  const text = $('#status-text');
  if (text) text.textContent = active ? 'ACTIVE' : 'OFFLINE';
}

export function markUpdated(date = new Date()) {
  const el = $('#last-update');
  if (el) el.textContent = date.toLocaleString('en-US');
}

export function initShell({ pollStatus = true } = {}) {
  setupSidebar();
  setupClock();
  setupShortcuts();
  setupGlow();
  if (pollStatus) {
    poll(async () => {
      const { data } = await api('/api/status');
      applyStatus(data);
      markUpdated();
    }, STATUS_INTERVAL, () => applyStatus({ overall: 'offline' }));
  }
}
