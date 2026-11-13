/* Dashboard: live stat cards, recent threats, top categories, system status and 24h traffic. */
import { $, $$, animateBars, api, countUp, fmt, html, icon, poll, sevBadge, setText, timeAgo } from '../core.js';
import { toast } from '../ui.js';
import { applyStatus, initShell, markUpdated } from '../shell.js';
import { setSeries, trafficChart } from '../charts.js';

const REFRESH_MS = 5000;
const els = {
  queries: $('#stat-queries'),
  queriesSub: $('#stat-queries-sub'),
  blocked: $('#stat-blocked'),
  critical: $('#stat-critical'),
  allowed: $('#stat-allowed'),
  allowRate: $('#stat-allow-rate'),
  latency: $('#stat-latency'),
  cache: $('#stat-cache'),
  threats: $('#threat-list'),
  categories: $('#category-list'),
  status: $('#status-grid'),
};

initShell({ pollStatus: false });
const chart = trafficChart($('#traffic-chart'));
let firstLoad = true;
let threatKeys = null;  // null = nothing rendered yet (an empty result must still draw the empty state)
let failures = 0;

function renderSummary(summary) {
  const duration = firstLoad ? 1500 : 700;
  countUp(els.queries, summary.queries_today, { duration });
  countUp(els.blocked, summary.blocked_today, { duration });
  countUp(els.allowed, summary.allowed_today, { duration });
  countUp(els.latency, summary.avg_response_ms, { decimals: 1, suffix: 'ms', duration });

  const change = summary.change_pct;
  const rising = change !== null && change >= 0;
  els.queriesSub.className = `stat-sub ${change === null ? 'tone-muted' : rising ? 'tone-green' : 'tone-red'}`;
  els.queriesSub.innerHTML = change === null
    ? html`${icon('activity', 'icon-sm')}<span>No data from yesterday yet</span>`
    : html`${icon(rising ? 'trending-up' : 'trending-down', 'icon-sm')}<span>${rising ? '+' : ''}${fmt.dec(change, 0)}% from yesterday</span>`;
  setText(els.critical, `${fmt.int(summary.critical_today)} critical threats`);
  setText(els.allowRate, `${fmt.pct(summary.allow_rate)} allow rate`);
  setText(els.cache, `${fmt.pct(summary.cache_hit_rate)} cache hit rate`);
}

const threatKey = (threat) => `${threat.domain}|${threat.last_seen}`;

function threatRow(threat, index, fresh) {
  const classes = ['threat-row', firstLoad ? 'reveal' : '', fresh ? 'flash' : ''].filter(Boolean).join(' ');
  return html`
    <div class="${classes}" style="--i:${index}" title="${fmt.int(threat.hits)} blocked lookups in the last 24h">
      <div class="threat-main">
        <div class="threat-domain">${threat.domain}</div>
        <div class="threat-meta"><span class="cat" style="--cat:${threat.category.color}">${threat.category.name}</span> • ${threat.source_label}</div>
      </div>
      <div class="threat-side">${sevBadge(threat.severity)}<span class="time-ago" data-ts="${threat.last_seen}">${timeAgo(threat.last_seen)}</span></div>
    </div>`;
}

function renderThreats(threats) {
  const keys = threats.map(threatKey);
  if (threatKeys !== null && keys.join() === threatKeys.join()) return;
  const previous = new Set(threatKeys || []);
  threatKeys = keys;
  els.threats.innerHTML = threats.length
    ? html`${threats.map((t, i) => threatRow(t, i, !firstLoad && !previous.has(threatKey(t))))}`
    : html`<div class="empty-state">${icon('shield-check', 'empty-icon')}<p>No threats blocked in the last 24 hours.</p></div>`;
}

function categoryRow(category, index) {
  return html`
    <div class="rank-row${firstLoad ? ' reveal' : ' fade-in'}" style="--i:${index}" data-key="${category.key}">
      <div class="rank-num">${index + 1}</div>
      <div class="rank-main">
        <div class="rank-name" style="--cat:${category.color}">${category.name}</div>
        <div class="rank-count">${fmt.int(category.blocks)} blocks</div>
      </div>
      <div class="rank-bar">
        <div class="bar"><span class="bar-fill" data-scale="${category.pct}"></span></div>
        <span class="rank-pct">${Math.round(category.pct)}%</span>
      </div>
    </div>`;
}

function renderCategories(categories) {
  const keys = categories.map((c) => c.key).join();
  if (keys && els.categories.dataset.keys === keys) {
    categories.forEach((category) => {
      const row = els.categories.querySelector(`[data-key="${category.key}"]`);
      if (!row) return;
      row.querySelector('.rank-count').textContent = `${fmt.int(category.blocks)} blocks`;
      row.querySelector('.rank-pct').textContent = `${Math.round(category.pct)}%`;
      row.querySelector('.bar-fill').dataset.scale = category.pct;
    });
    animateBars(els.categories);
    return;
  }
  els.categories.dataset.keys = keys;
  els.categories.innerHTML = categories.length
    ? html`${categories.map(categoryRow)}`
    : html`<div class="empty-state">${icon('circle-check', 'empty-icon')}<p>Nothing blocked yet today.</p></div>`;
  animateBars(els.categories);
}

function statusCard(card, index) {
  return html`
    <div class="status-card${firstLoad ? ' reveal' : ''}" style="--i:${index}" data-key="${card.key}">
      <div class="status-head"><span>${card.title}</span><span class="dot dot-${card.tone} pulse"></span></div>
      <div class="status-state ${card.tone === 'green' ? '' : `tone-${card.tone}`}">${card.state}</div>
      <div class="status-detail" title="${card.detail}">${card.detail}</div>
    </div>`;
}

function renderStatus(status) {
  applyStatus(status);
  const cards = $$('.status-card[data-key]', els.status);
  if (cards.length !== status.cards.length) {
    els.status.innerHTML = html`${status.cards.map(statusCard)}`;
    return;
  }
  status.cards.forEach((card, i) => {
    const el = cards[i];
    $('.dot', el).className = `dot dot-${card.tone} pulse`;
    const state = $('.status-state', el);
    state.className = `status-state ${card.tone === 'green' ? '' : `tone-${card.tone}`}`;
    state.textContent = card.state;
    $('.status-detail', el).textContent = card.detail;
  });
}

async function refresh() {
  const { data } = await api('/api/dashboard');
  renderSummary(data.summary);
  renderThreats(data.threats);
  renderCategories(data.categories);
  renderStatus(data.status);
  setSeries(chart, data.traffic.labels, [data.traffic.allowed, data.traffic.blocked]);
  markUpdated();
  firstLoad = false;
  failures = 0;
}

poll(refresh, REFRESH_MS, (error) => {
  failures += 1;
  applyStatus({ overall: 'offline' });
  if (failures === 1) toast(error.message, 'error');
});

setInterval(() => {
  $$('[data-ts]', els.threats).forEach((el) => { el.textContent = timeAgo(Number(el.dataset.ts)); });
}, 15000);
