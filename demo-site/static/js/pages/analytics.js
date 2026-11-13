/* Analytics: KPIs, traffic, record types, categories, sources, latency and top lists. */
import { $, animateBars, api, countUp, fmt, html, poll } from '../core.js';
import { segmented, toast } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';
import { COLORS, PALETTE, barChart, doughnutChart, latencyChart, setSeries, trafficChart } from '../charts.js';

const REFRESH_MS = 30000;
const SOURCE_COLORS = { feed: '#3b82f6', policy: '#facc15', ml: '#a78bfa' };
const RANGE_NOTES = { '24h': 'Last 24 hours, hourly buckets', '7d': 'Last 7 days, daily buckets' };

initShell();
const charts = {
  traffic: trafficChart($('#traffic-chart')),
  qtypes: doughnutChart($('#qtype-chart')),
  categories: barChart($('#category-chart')),
  sources: doughnutChart($('#source-chart')),
  latency: latencyChart($('#latency-chart')),
};
let range = '24h';
let stopPolling = null;
let requestSeq = 0;  // only the newest request may render (range switches race slow responses)

function renderKpis(kpis) {
  countUp($('#kpi-total'), kpis.total);
  countUp($('#kpi-block-rate'), kpis.block_rate, { decimals: 1, suffix: '%' });
  countUp($('#kpi-latency'), kpis.avg_ms, { decimals: 1, suffix: 'ms' });
  countUp($('#kpi-clients'), kpis.clients);
  $('#kpi-domains').textContent = `${fmt.int(kpis.domains)} unique domains`;
  $('#kpi-blocked').textContent = `${fmt.int(kpis.blocked)} blocked`;
  $('#kpi-cache').textContent = `${fmt.pct(kpis.cache_rate)} cache hit rate`;
}

function renderLegend(el, items) {
  const total = items.reduce((sum, item) => sum + item.value, 0);
  el.innerHTML = html`${items.map((item) => html`
    <li><i style="--c:${item.color}"></i><span class="name">${item.label}</span>
      <span class="val">${total ? fmt.pct((item.value / total) * 100, 0) : '0%'}</span></li>`)}`;
}

function renderDonut(chart, legendEl, items) {
  setSeries(chart, items.map((i) => i.label), [items.map((i) => i.value)], items.map((i) => i.color));
  renderLegend(legendEl, items);
}

function renderTopList(el, rows, { name, note, color }) {
  if (!rows.length) {
    el.innerHTML = html`<p class="empty">No data in this window.</p>`;
    return;
  }
  const max = Math.max(...rows.map((row) => row.count));
  el.innerHTML = html`${rows.map((row, i) => html`
    <div class="top-row fade-in" style="animation-delay:${i * 45}ms">
      <span class="top-name" title="${name(row)}">${name(row)}${note(row) ? html`<small>${note(row)}</small>` : ''}</span>
      <span class="top-count">${fmt.int(row.count)}</span>
      <span class="top-bar"><span data-scale="${(row.count / max) * 100}" style="--bar:${color(row)}"></span></span>
    </div>`)}`;
  animateBars(el);
}

async function load() {
  const seq = ++requestSeq;
  const { data } = await api(`/api/analytics?range=${range}`);
  if (seq !== requestSeq) return;
  renderKpis(data.kpis);
  setSeries(charts.traffic, data.traffic.labels, [data.traffic.allowed, data.traffic.blocked]);
  setSeries(charts.latency, data.traffic.labels, [data.traffic.avg_ms, data.traffic.cache_rate]);
  renderDonut(charts.qtypes, $('#qtype-legend'), data.qtypes.slice(0, 8).map((q, i) => ({
    label: q.type, value: q.count, color: PALETTE[i % PALETTE.length],
  })));
  renderDonut(charts.sources, $('#source-legend'), data.sources.map((s) => ({
    label: s.label, value: s.count, color: SOURCE_COLORS[s.key] || COLORS.blue,
  })));
  setSeries(charts.categories, data.categories.map((c) => c.name), [data.categories.map((c) => c.blocks)],
    data.categories.map((c) => c.color));
  renderTopList($('#top-domains'), data.top_domains, { name: (r) => r.domain, note: () => '', color: () => COLORS.blue });
  renderTopList($('#top-blocked'), data.top_blocked, {
    name: (r) => r.domain, note: (r) => r.category?.name || '', color: (r) => r.category?.color || COLORS.red,
  });
  renderTopList($('#top-clients'), data.top_clients, {
    name: (r) => r.client_ip,
    note: (r) => r.hostname || '',
    color: (r) => (r.blocked / r.count > 0.3 ? COLORS.red : COLORS.green),
  });
  markUpdated();
}

function start() {
  stopPolling?.();
  stopPolling = poll(load, REFRESH_MS, (error) => toast(error.message, 'error'));
}

segmented($('#range-switch'), (value) => {
  range = value;
  $('#range-note').textContent = RANGE_NOTES[value];
  start();
});
start();
