/* Chart.js theme and chart factories matching the dark console design. */

const { Chart } = window;

export const COLORS = Object.freeze({
  blue: '#3b82f6',
  blueLight: '#60a5fa',
  red: '#ef4444',
  green: '#22c55e',
  amber: '#eab308',
  violet: '#a78bfa',
  cyan: '#22d3ee',
  grid: 'rgba(31, 41, 55, 0.6)',
  text: '#6b7280',
  panel: '#0a0d14',
});

export const PALETTE = ['#3b82f6', '#22d3ee', '#a78bfa', '#facc15', '#4ade80', '#fb923c', '#f472b6', '#f87171', '#9ca3af'];

let themed = false;

function applyTheme() {
  if (themed || !Chart) return;
  themed = true;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.font.size = 11;
  Chart.defaults.color = COLORS.text;
  Chart.defaults.borderColor = COLORS.grid;
  Chart.defaults.maintainAspectRatio = false;
  Chart.defaults.responsive = true;
  Chart.defaults.animation.duration = 900;
  Chart.defaults.animation.easing = 'easeOutQuart';
  Chart.defaults.plugins.legend.display = false;
  Object.assign(Chart.defaults.plugins.tooltip, {
    backgroundColor: 'rgba(10, 13, 20, 0.96)',
    borderColor: '#283142',
    borderWidth: 1,
    titleColor: '#e5e7eb',
    bodyColor: '#9ca3af',
    padding: 10,
    cornerRadius: 6,
    boxPadding: 4,
    usePointStyle: true,
  });
}

const rgba = (hex, alpha) => {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
};

/** Vertical fade from `color` to transparent, computed against the live chart area. */
function gradient(color, alpha = 0.32) {
  return ({ chart }) => {
    const { ctx, chartArea } = chart;
    if (!chartArea) return rgba(color, alpha / 3);
    const fill = ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
    fill.addColorStop(0, rgba(color, alpha));
    fill.addColorStop(1, rgba(color, 0));
    return fill;
  };
}

const lineDataset = (label, color, extra = {}) => ({
  label,
  data: [],
  borderColor: color,
  backgroundColor: gradient(color),
  fill: true,
  tension: 0.38,
  borderWidth: 2,
  pointRadius: 0,
  pointHoverRadius: 4,
  pointHoverBackgroundColor: color,
  pointHoverBorderColor: '#fff',
  ...extra,
});

const axisX = { grid: { display: false }, border: { display: false }, ticks: { maxRotation: 0, autoSkipPadding: 18 } };
const axisY = { beginAtZero: true, grid: { color: COLORS.grid }, border: { display: false }, ticks: { precision: 0 } };

export function trafficChart(canvas) {
  applyTheme();
  return new Chart(canvas, {
    type: 'line',
    data: { labels: [], datasets: [lineDataset('Allowed', COLORS.blue), lineDataset('Blocked', COLORS.red)] },
    options: { interaction: { mode: 'index', intersect: false }, scales: { x: axisX, y: axisY } },
  });
}

export function latencyChart(canvas) {
  applyTheme();
  return new Chart(canvas, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        lineDataset('Avg response (ms)', COLORS.blueLight, { yAxisID: 'y' }),
        lineDataset('Cache hit (%)', COLORS.green, { yAxisID: 'y1', fill: false, borderDash: [4, 4] }),
      ],
    },
    options: {
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: axisX,
        y: { ...axisY, ticks: { callback: (v) => `${v}ms` } },
        y1: { position: 'right', min: 0, max: 100, grid: { display: false }, border: { display: false }, ticks: { callback: (v) => `${v}%` } },
      },
    },
  });
}

export function doughnutChart(canvas) {
  applyTheme();
  return new Chart(canvas, {
    type: 'doughnut',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: COLORS.panel, borderWidth: 3, hoverOffset: 8 }] },
    options: { cutout: '70%', animation: { animateRotate: true, animateScale: true } },
  });
}

export function barChart(canvas) {
  applyTheme();
  return new Chart(canvas, {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, borderSkipped: false, barThickness: 14 }] },
    options: {
      indexAxis: 'y',
      scales: {
        x: { ...axisY, ticks: { precision: 0 } },
        y: { grid: { display: false }, border: { display: false } },
      },
    },
  });
}

/** Replace labels and dataset values; Chart.js animates from the previous state. */
export function setSeries(chart, labels, series, colors) {
  chart.data.labels = labels;
  series.forEach((values, i) => {
    chart.data.datasets[i].data = values;
    if (colors) chart.data.datasets[i].backgroundColor = colors;
  });
  chart.update();
}
