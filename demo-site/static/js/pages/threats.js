/* Threat log: filterable, paginated list of blocked queries with live refresh and unblock. */
import { $, $$, api, countUp, debounce, fmt, html, icon, isAdmin, poll, sevBadge } from '../core.js';
import { confirmDialog, toast } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';

const PER_PAGE = 25;
const LIVE_MS = 5000;

initShell();
const form = $('#filters');
const body = $('#threat-body');
const liveButton = $('#live-toggle');
let page = 1;
let pages = 1;
let live = true;
let stopLive = null;
let requestSeq = 0;  // discard responses to superseded filters/pages

function query() {
  const params = new URLSearchParams();
  new FormData(form).forEach((value, key) => { if (value) params.set(key, value); });
  params.set('page', String(page));
  params.set('per_page', String(PER_PAGE));
  return params.toString();
}

function scoreCell(confidence) {
  if (confidence === null || confidence === undefined) return html`<span class="cell-dim">—</span>`;
  return html`<span class="score"><span class="score-bar"><span style="width:${Math.round(confidence * 100)}%"></span></span>${confidence.toFixed(2)}</span>`;
}

function row(threat, fresh) {
  return html`
    <tr class="${fresh ? 'row-enter' : ''}" data-id="${threat.id}">
      <td class="cell-dim" title="${new Date(threat.ts * 1000).toLocaleString('en-US')}">${fmt.dateTime(threat.ts)}</td>
      <td>${threat.client_ip}</td>
      <td class="cell-strong cell-wrap" title="${threat.domain}">${threat.domain}</td>
      <td><span style="color:${threat.category.color}">${threat.category.name}</span></td>
      <td class="cell-dim">${threat.source_label}</td>
      <td>${sevBadge(threat.severity)}</td>
      <td>${scoreCell(threat.confidence)}</td>
      <td class="actions">${isAdmin ? html`
        <button class="btn btn-ghost" type="button" data-unblock="${threat.domain}">${icon('shield-off')}<span>Unblock</span></button>` : ''}</td>
    </tr>`;
}

function renderSeverity(counts) {
  Object.entries(counts).forEach(([key, value]) => countUp($(`#sev-${key}`), value, { duration: 800 }));
  const active = form.elements.severity.value;
  $$('.sev-card').forEach((card) => card.classList.toggle('is-active', card.dataset.severity === active));
}

function renderPager(meta) {
  pages = meta.pages;
  const first = (meta.page - 1) * meta.per_page + 1;
  const last = Math.min(meta.total, meta.page * meta.per_page);
  $('#pager-info').textContent = meta.total ? `Showing ${fmt.int(first)}–${fmt.int(last)} of ${fmt.int(meta.total)}` : 'No results';
  $('#prev-page').disabled = page <= 1;
  $('#next-page').disabled = page >= pages;
}

async function load({ quiet = false } = {}) {
  const seq = ++requestSeq;
  const { data, meta } = await api(`/api/threats?${query()}`);
  if (seq !== requestSeq) return;
  const known = new Set($$('tr[data-id]', body).map((tr) => tr.dataset.id));
  body.innerHTML = data.length
    ? html`${data.map((t) => row(t, quiet && known.size > 0 && !known.has(String(t.id))))}`
    : html`<tr><td colspan="8"><div class="empty-state">${icon('shield-check', 'empty-icon')}<p>No blocked queries match these filters.</p></div></td></tr>`;
  renderSeverity(meta.severity_counts);
  renderPager(meta);
  markUpdated();
}

const reportError = (error) => toast(error.message, 'error');

function syncLive() {
  stopLive?.();
  stopLive = null;
  const on = live && page === 1;
  liveButton.classList.toggle('is-on', on);
  liveButton.setAttribute('aria-pressed', String(on));
  if (on) stopLive = poll(() => load({ quiet: true }), LIVE_MS, reportError);
  else load().catch(reportError);
}

function reload() {
  page = 1;
  syncLive();
}

form.addEventListener('change', reload);
form.elements.q.addEventListener('input', debounce(reload, 300));
form.addEventListener('submit', (event) => {
  event.preventDefault();
  reload();
});
form.addEventListener('reset', () => setTimeout(reload, 0));

$('#sev-grid').addEventListener('click', (event) => {
  const card = event.target.closest('[data-severity]');
  if (!card) return;
  const select = form.elements.severity;
  select.value = select.value === card.dataset.severity ? '' : card.dataset.severity;
  reload();
});

liveButton.addEventListener('click', () => {
  live = !live;
  syncLive();
});

$('#prev-page').addEventListener('click', () => {
  if (page > 1) {
    page -= 1;
    syncLive();
  }
});
$('#next-page').addEventListener('click', () => {
  if (page < pages) {
    page += 1;
    syncLive();
  }
});

body.addEventListener('click', async (event) => {
  const button = event.target.closest('[data-unblock]');
  if (!button) return;
  const domain = button.dataset.unblock;
  const confirmed = await confirmDialog({
    title: 'Unblock domain',
    message: html`Create an <strong>allow</strong> rule for <strong>${domain}</strong>? Future lookups of this name and its subdomains will be answered normally.`,
    confirmLabel: 'Allow domain',
  });
  if (!confirmed) return;
  try {
    // replace: an exact-match custom block rule for this domain becomes the allow rule
    await api('/api/policies/rules', {
      method: 'POST',
      body: { domain, action: 'allow', note: 'Unblocked from the threat log', replace: true },
    });
    toast(`${domain} is now allowed`, 'success');
    load().catch(reportError);
  } catch (error) {
    reportError(error);
  }
});

async function loadCategories() {
  const { data } = await api('/api/policies');
  $('#filter-category').insertAdjacentHTML('beforeend', String(html`${data.categories.map((c) => html`<option value="${c.key}">${c.name}</option>`)}`));
}

loadCategories().catch(reportError);
syncLive();
