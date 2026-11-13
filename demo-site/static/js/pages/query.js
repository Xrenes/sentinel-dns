/* Query tester: resolve a name and explain the answer (zone, policy, upstream, DNSSEC, ML). */
import { $, api, fmt, html, icon, sevBadge, storage, timeAgo } from '../core.js';
import { clearFieldErrors, showFieldErrors, toast, withBusy } from '../ui.js';
import { initShell } from '../shell.js';

const HISTORY_KEY = 'sentinel.query.history';
const HISTORY_SIZE = 10;
const STATUS_VIEW = {
  resolved: { word: 'RESOLVED', tone: 'green', icon: 'circle-check' },
  blocked: { word: 'BLOCKED', tone: 'red', icon: 'shield-alert' },
  nxdomain: { word: 'NXDOMAIN', tone: 'amber', icon: 'circle-x' },
  nodata: { word: 'NO DATA', tone: 'amber', icon: 'circle-alert' },
  timeout: { word: 'TIMEOUT', tone: 'red', icon: 'timer' },
  error: { word: 'ERROR', tone: 'red', icon: 'circle-alert' },
};
const SERVED_BY = { 'local-zone': 'Local zone', upstream: 'Upstream', rpz: 'Policy zone (RPZ)', bind: 'BIND' };

initShell();
const form = $('#query-form');
const result = $('#result');
let history = storage.get(HISTORY_KEY, []);
let latestQuery = 0;  // answers to superseded queries are dropped, so a late older answer cannot replace a newer one

const metric = (label, value, tone = '') => html`
  <div class="metric"><div class="metric-label">${label}</div><div class="metric-value ${tone}" title="${value}">${value}</div></div>`;

function dnssecLabel(dnssec) {
  if (dnssec.ad) return ['VALIDATED (AD)', 'tone-green'];
  if (dnssec.signed) return ['SIGNED ZONE', 'tone-green'];
  return ['NOT SIGNED', 'tone-muted'];
}

function policyCallout(policy) {
  if (policy.action === 'blocked') {
    const category = policy.category || { name: 'Other', color: '#d1d5db' };
    const enforced = policy.enforced !== false;  // bind mode: Sentinel's policies do not reach named yet
    return html`
      <div class="callout" style="--accent:${category.color}">${icon('shield-alert')}
        <div><strong>${enforced ? 'Blocked' : 'Would be blocked'} by ${policy.source_label}.</strong> Matched <code>${policy.matched}</code> in
          <span style="color:${category.color}">${category.name}</span> ${sevBadge(policy.severity)}
          ${policy.confidence ? ` · ML confidence ${policy.confidence.toFixed(2)}` : ''}.
          ${enforced ? 'The resolver answered NXDOMAIN through the response policy zone.'
            : 'Not blocked yet: once Sentinel sees this lookup in BIND\'s log it adds the name to the response-policy zone, so the next lookup is blocked. Clients get the answer below until then.'}</div>
      </div>`;
  }
  if (policy.source === 'policy') {
    return html`<div class="callout" style="--accent:#22c55e">${icon('shield-check')}
      <div><strong>Allowed by rule.</strong> <code>${policy.matched}</code> is on the allow list, so feeds and the ML detector are skipped.</div></div>`;
  }
  return '';
}

function answersTable(answers) {
  if (!answers.length) return html`<p class="muted-note">No answer records returned.</p>`;
  return html`
    <div class="table-wrap"><table class="table">
      <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Value</th></tr></thead>
      <tbody>${answers.map((a, i) => html`
        <tr class="fade-in" style="animation-delay:${i * 70}ms">
          <td>${a.name}</td><td><span class="rtype rtype-${a.type}">${a.type}</span></td>
          <td class="cell-dim">${fmt.int(a.ttl)}</td><td class="cell-strong cell-wrap" title="${a.value}">${a.value}</td>
        </tr>`)}</tbody>
    </table></div>`;
}

function mlBox(ml) {
  const tone = { malicious: 'tone-red', suspicious: 'tone-amber' }[ml.label] || 'tone-green';
  return html`
    <div class="field">
      <div class="range-head"><span class="field-label">ML risk · ${ml.model}</span>
        <span class="${tone}">${ml.score.toFixed(2)} · ${ml.label.toUpperCase()}</span></div>
      <div class="gauge" role="meter" aria-valuemin="0" aria-valuemax="1" aria-valuenow="${ml.score}" aria-label="ML risk score"><span class="gauge-mask"></span></div>
      <div class="gauge-scale"><span>benign</span><span>suspicious</span><span>malicious</span></div>
      ${ml.reasons.length
        ? html`<ul class="reason-list">${ml.reasons.map((reason) => html`<li>${reason}</li>`)}</ul>`
        : html`<p class="muted-note">No risk signals in this name.</p>`}
    </div>`;
}

function renderResult(data) {
  const view = STATUS_VIEW[data.status] || STATUS_VIEW.error;
  const [dnssecText, dnssecTone] = dnssecLabel(data.dnssec);
  result.innerHTML = html`
    <div class="result fade-in">
      <div class="result-status">
        <span class="result-word tone-${view.tone}">${view.word}</span>
        <span class="result-domain">${icon(view.icon, 'icon-sm')} ${data.domain} · ${data.type}</span>
      </div>
      <div class="metrics">
        ${metric('Response time', fmt.ms(data.response_ms))}
        ${metric('RCODE', data.rcode, data.rcode === 'NOERROR' ? 'tone-green' : 'tone-amber')}
        ${metric('Answered by', `${SERVED_BY[data.served_by] || data.served_by}${['upstream', 'bind'].includes(data.served_by) ? ` ${data.server}` : ''}`)}
        ${metric('DNSSEC', dnssecText, dnssecTone)}
      </div>
      ${data.error ? html`<div class="callout" style="--accent:#ef4444">${icon('circle-alert')}<div>${data.error}</div></div>` : ''}
      ${policyCallout(data.policy)}
      ${answersTable(data.answers)}
      ${mlBox(data.ml)}
    </div>`;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const mask = $('.gauge-mask', result);
    if (mask) mask.style.transform = `scaleX(${1 - data.ml.score})`;
  }));
}

function renderHistory() {
  const list = $('#history');
  list.innerHTML = history.length
    ? html`${history.map((item, i) => html`
      <li><button class="history-item" type="button" data-index="${i}">
        <span class="dot dot-${(STATUS_VIEW[item.status] || STATUS_VIEW.error).tone}"></span>
        <span class="name">${item.domain}</span><span class="meta">${item.type} · ${timeAgo(item.ts)}</span>
      </button></li>`)}`
    : html`<li class="muted-note">No queries yet in this session.</li>`;
}

function remember(data) {
  const entry = { domain: data.domain, type: data.type, status: data.status, ts: Date.now() / 1000 };
  history = [entry, ...history.filter((h) => h.domain !== entry.domain || h.type !== entry.type)].slice(0, HISTORY_SIZE);
  storage.set(HISTORY_KEY, history);
  renderHistory();
}

function run(domain, type) {
  form.elements.domain.value = domain;
  form.elements.type.value = type;
  form.requestSubmit();
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const body = Object.fromEntries(new FormData(form));
  const query = ++latestQuery;
  withBusy($('#query-submit'), async () => {
    try {
      const { data } = await api('/api/query', { method: 'POST', body });
      if (query !== latestQuery) return;
      clearFieldErrors(form);
      renderResult(data);
      remember(data);
    } catch (error) {
      if (query !== latestQuery) return;
      if (!showFieldErrors(form, error)) toast(error.message, 'error');
    }
  });
});

$('#examples').addEventListener('click', (event) => {
  const chip = event.target.closest('[data-domain]');
  if (chip) run(chip.dataset.domain, chip.dataset.type);
});

$('#history').addEventListener('click', (event) => {
  const item = event.target.closest('[data-index]');
  const entry = item && history[Number(item.dataset.index)];
  if (entry) run(entry.domain, entry.type);
});

renderHistory();
