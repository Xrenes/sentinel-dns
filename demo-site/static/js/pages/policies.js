/* Policies: blocklist categories, custom allow/block rules and ML detector settings. */
import { $, $$, api, countUp, fmt, html, icon, isAdmin, sevBadge, timeAgo } from '../core.js';
import { applyRole, clearFieldErrors, confirmDialog, showFieldErrors, toast, withBusy } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';

initShell();
applyRole(isAdmin);

const MIN_SPIN_MS = 900;
let categories = [];
let rules = [];
let ml = null;

const categoryByKey = (key) => categories.find((c) => c.key === key);

function renderKpis() {
  const enabled = categories.filter((c) => c.enabled);
  const blockRules = rules.filter((r) => r.action === 'block').length;
  countUp($('#kpi-active'), enabled.length);
  countUp($('#kpi-domains'), enabled.reduce((sum, c) => sum + c.domain_count, 0));
  countUp($('#kpi-rules'), rules.length);
  $('#kpi-active-sub').textContent = `of ${categories.length} categories`;
  $('#kpi-rules-sub').textContent = `${blockRules} block · ${rules.length - blockRules} allow`;
  if (ml) {
    $('#kpi-ml').textContent = ml.threshold.toFixed(2);
    $('#kpi-ml-sub').textContent = ml.auto_block ? 'auto-block on' : 'monitor only';
  }
}

function categoryCard(category, index) {
  return html`
    <article class="cat-card reveal${category.enabled ? '' : ' is-off'}" style="--i:${index};--cat:${category.color}" data-key="${category.key}">
      <div class="cat-head">
        <div class="cat-name">${category.name}</div>
        <label class="switch" title="${category.enabled ? 'Disable' : 'Enable'} ${category.name}">
          <input type="checkbox" data-toggle="${category.key}" aria-label="Enable ${category.name}"
            ${category.enabled ? 'checked' : ''} ${isAdmin ? '' : 'disabled'}>
          <span class="track"></span><span class="thumb"></span>
        </label>
      </div>
      <p class="cat-desc">${category.description}</p>
      <div class="cat-foot">
        <div><div class="cat-count" data-count>${fmt.int(category.domain_count)}</div><span class="muted-note">domains</span></div>
        <div class="cat-feed">${sevBadge(category.severity)}<div>${category.feed}</div></div>
      </div>
    </article>`;
}

function renderSyncNote() {
  const synced = categories.filter((c) => c.is_feed && c.last_synced_at).map((c) => c.last_synced_at);
  $('#sync-note').textContent = synced.length ? `Last sync ${timeAgo(Math.max(...synced))}` : 'Never synced';
}

function renderCategories() {
  $('#cat-grid').innerHTML = html`${categories.map(categoryCard)}`;
  $('#rule-category').innerHTML = html`${categories.map((c) => html`
    <option value="${c.key}" ${c.key === 'other' ? 'selected' : ''}>${c.name}</option>`)}`;
  renderSyncNote();
}

function updateCategoryCounts() {
  categories.forEach((category) => {
    const count = $(`[data-key="${category.key}"] [data-count]`);
    countUp(count, category.domain_count, { duration: 900 });
  });
  renderSyncNote();
}

function ruleRow(rule) {
  const category = categoryByKey(rule.category);
  return html`
    <tr class="fade-in" data-id="${rule.id}">
      <td class="cell-strong">${rule.domain}</td>
      <td><span class="badge ${rule.action === 'block' ? 'badge-red' : 'badge-green'}">${rule.action.toUpperCase()}</span></td>
      <td><span style="color:${category?.color || '#d1d5db'}">${category?.name || rule.category}</span></td>
      <td class="cell-dim cell-wrap" title="${rule.note}">${rule.note || '—'}</td>
      <td class="cell-dim" title="${fmt.dateTime(rule.created_at)} by ${rule.created_by}">${timeAgo(rule.created_at)}</td>
      <td class="actions">${isAdmin ? html`
        <button class="icon-btn danger" type="button" data-delete="${rule.id}" aria-label="Delete rule for ${rule.domain}">${icon('trash-2', 'icon-sm')}</button>` : ''}</td>
    </tr>`;
}

function renderRules() {
  $('#rules-body').innerHTML = rules.length
    ? html`${rules.map(ruleRow)}`
    : html`<tr><td colspan="6" class="empty">No custom rules yet.</td></tr>`;
}

function paintThreshold() {
  const input = $('#ml-threshold');
  const value = Number(input.value);
  $('#ml-threshold-value').textContent = value.toFixed(2);
  input.style.setProperty('--fill', `${((value - 0.5) / 0.49) * 100}%`);
}

function renderMl() {
  $('#ml-model').textContent = ml.model;
  $('#ml-threshold').value = ml.threshold;
  $('#ml-auto').checked = ml.auto_block;
  $('#ml-dot').className = `dot ${ml.auto_block ? 'dot-green' : 'dot-amber'} pulse`;
  paintThreshold();
}

function syncCategoryCard(key) {
  const category = categoryByKey(key);
  const input = $(`[data-toggle="${key}"]`);
  if (!category || !input) return;
  input.checked = category.enabled;
  input.closest('.cat-card').classList.toggle('is-off', !category.enabled);
}

$('#cat-grid').addEventListener('change', async (event) => {
  const input = event.target.closest('[data-toggle]');
  if (!input) return;
  const { toggle: key } = input.dataset;
  const enabled = input.checked;
  const card = input.closest('.cat-card');
  card.classList.toggle('is-off', !enabled);
  try {
    const { data } = await api(`/api/policies/categories/${encodeURIComponent(key)}`, { method: 'PATCH', body: { enabled } });
    categories = categories.map((c) => (c.key === key ? data : c));
    if (key === 'ml' && ml) {  // the ML category switch is also the detector's auto-block switch
      ml = { ...ml, auto_block: data.enabled };
      renderMl();
    }
    renderKpis();
    toast(`${data.name} ${enabled ? 'enabled' : 'disabled'}`, 'success');
  } catch (error) {
    input.checked = !enabled;
    card.classList.toggle('is-off', enabled);
    toast(error.message, 'error');
  }
});

$('#sync-btn').addEventListener('click', () => {
  const button = $('#sync-btn');
  const spinner = $('.icon', button);
  spinner.classList.add('spin');
  withBusy(button, async () => {
    try {
      const pause = new Promise((resolve) => { setTimeout(resolve, MIN_SPIN_MS); });
      const [{ data }] = await Promise.all([api('/api/policies/sync', { method: 'POST' }), pause]);
      categories = data.categories;
      updateCategoryCounts();
      renderKpis();
      const failed = data.failed || [];  // bind mode: categories whose download failed keep their previous list
      if (!failed.length) toast(`Synced ${data.synced} threat feeds`, 'success');
      else toast(`Synced ${data.synced} threat feeds; not updated: ${failed.join(', ')} (previous lists kept)`,
        data.synced ? 'info' : 'error', 8000);
    } catch (error) {
      toast(error.message, 'error');
    } finally {
      spinner.classList.remove('spin');
    }
  });
});

$('#rule-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = Object.fromEntries(new FormData(form));
  withBusy(form.querySelector('[type="submit"]'), async () => {
    try {
      const { data } = await api('/api/policies/rules', { method: 'POST', body });
      rules = [data, ...rules];
      clearFieldErrors(form);
      form.reset();
      $('#rule-category').value = 'other';
      renderRules();
      renderKpis();
      toast(`Rule added: ${data.action} ${data.domain}`, 'success');
    } catch (error) {
      if (!showFieldErrors(form, error)) toast(error.message, 'error');
    }
  });
});

$('#rules-body').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-delete]');
  if (!button) return;
  const rule = rules.find((r) => String(r.id) === button.dataset.delete);
  if (!rule) return;
  const confirmed = await confirmDialog({
    title: 'Delete rule',
    message: html`Remove the <strong>${rule.action}</strong> rule for <strong>${rule.domain}</strong>?`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!confirmed) return;
  try {
    await api(`/api/policies/rules/${rule.id}`, { method: 'DELETE' });
    rules = rules.filter((r) => r.id !== rule.id);
    renderRules();
    renderKpis();
    toast(`Rule for ${rule.domain} deleted`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
});

$('#ml-threshold').addEventListener('input', paintThreshold);
$('#ml-save').addEventListener('click', () => withBusy($('#ml-save'), async () => {
  try {
    const body = { threshold: Number($('#ml-threshold').value), auto_block: $('#ml-auto').checked };
    const { data } = await api('/api/policies/ml', { method: 'PUT', body });
    ml = data;
    categories = categories.map((c) => (c.key === 'ml' ? { ...c, enabled: data.auto_block } : c));
    syncCategoryCard('ml');
    renderMl();
    renderKpis();
    toast('ML detector settings saved', 'success');
  } catch (error) {
    toast(error.message, 'error');
  }
}));

async function load() {
  const { data } = await api('/api/policies');
  ({ categories, rules, ml } = data);
  renderCategories();
  renderRules();
  renderMl();
  renderKpis();
  markUpdated();
}

load().catch((error) => toast(error.message, 'error'));
$$('[data-admin]').forEach((el) => { if (!isAdmin) el.setAttribute('aria-disabled', 'true'); });
