/* Settings: forwarders, ACL, retention, privacy, rate limiting, DNSSEC and system info. */
import { $, $$, api, fmt, html, icon, isAdmin, timeAgo } from '../core.js';
import { applyRole, copyText, toast, withBusy } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';

initShell();
applyRole(isAdmin);
const form = $('#settings-form');
const saveBar = $('#save-bar');
let saved = null;
let dsRecord = null;

function tagMarkup(values, fresh, placeholder) {
  return html`${values.map((value, i) => html`
    <span class="tag${i === fresh ? ' pop-in' : ''}">${value}${isAdmin ? html`
      <button type="button" data-remove="${i}" aria-label="Remove ${value}">${icon('x', 'icon-xs')}</button>` : ''}</span>`)}
    <input class="tag-input" placeholder="${placeholder}" aria-label="${placeholder}" ${isAdmin ? '' : 'disabled'}>`;
}

function bindTagEvents(root, editor) {
  root.addEventListener('click', (event) => {
    const remove = event.target.closest('[data-remove]');
    if (remove) editor.removeAt(Number(remove.dataset.remove));
    else if (event.target === root) editor.focus();
  });
  root.addEventListener('keydown', (event) => {
    const field = event.target.closest('.tag-input');
    if (!field) return;
    if (['Enter', ',', ' ', 'Tab'].includes(event.key) && field.value.trim()) {
      event.preventDefault();
      editor.add(field.value);
    } else if (event.key === 'Backspace' && !field.value) {
      editor.removeLast();
    }
  });
  root.addEventListener('focusout', (event) => {
    if (event.target.matches('.tag-input') && event.target.value.trim()) editor.add(event.target.value);
  });
}

function tagEditor(root, onChange) {
  let values = [];
  const placeholder = root.dataset.placeholder;
  const render = (fresh = -1) => { root.innerHTML = tagMarkup(values, fresh, placeholder); };
  const focus = () => $('.tag-input', root)?.focus();
  const update = (next, fresh = -1) => {
    values = next;
    render(fresh);
    onChange();
    focus();
  };
  const editor = {
    add(text) {
      const value = text.trim().replace(/,$/, '');
      if (value && !values.includes(value)) update([...values, value], values.length);
      else focus();
    },
    removeAt: (index) => update(values.filter((_, i) => i !== index)),
    removeLast: () => values.length && update(values.slice(0, -1)),
    focus,
  };
  bindTagEvents(root, editor);
  return {
    get: () => [...values],
    set(next) {
      values = [...next];
      render();
    },
  };
}

const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const editors = {};

function currentValues() {
  return {
    forwarders: editors.forwarders.get(),
    acl: editors.acl.get(),
    retention_days: Number(form.elements.retention_days.value),
    rrl_rps: Number(form.elements.rrl_rps.value),
    anonymize_clients: form.elements.anonymize_clients.checked,
  };
}

function refreshDirty() {
  saveBar.classList.toggle('is-visible', Boolean(saved) && !sameJson(currentValues(), saved));
}

editors.forwarders = tagEditor($('#forwarders'), refreshDirty);
editors.acl = tagEditor($('#acl'), refreshDirty);

function clearErrors() {
  $$('[data-error]').forEach((el) => { el.textContent = ''; });
  $$('.is-invalid').forEach((el) => el.classList.remove('is-invalid'));
}

function fill(values) {
  editors.forwarders.set(values.forwarders);
  editors.acl.set(values.acl);
  form.elements.retention_days.value = values.retention_days;
  form.elements.rrl_rps.value = values.rrl_rps;
  form.elements.anonymize_clients.checked = values.anonymize_clients;
  $$('input', form).forEach((el) => { if (!isAdmin) el.disabled = true; });
  clearErrors();
  refreshDirty();
}

const info = (label, value, tone = '') => html`<div><dt>${label}</dt><dd class="${tone}" title="${value}">${value}</dd></div>`;

const DASH = '—';

function dnssecStatus(state) {
  if (state.enabled === null || state.enabled === undefined) return ['UNKNOWN', 'tone-amber'];  // not read from BIND yet
  if (!state.enabled) return ['UNSIGNED', 'tone-amber'];
  return [`SIGNED${state.simulated ? ' (DEMO)' : ''}`, 'tone-green'];
}

function renderDnssec(state) {
  const [status, tone] = dnssecStatus(state);
  const remaining = state.expires_at ? state.expires_at - Date.now() / 1000 : null;
  const expires = remaining === null ? DASH : remaining > 0 ? `in ${Math.ceil(remaining / 86400)} days` : 'EXPIRED';
  $('#dnssec-info').innerHTML = html`
    ${info('Status', status, tone)}
    ${info('Algorithm', state.algorithm ? `${state.algorithm} · ${state.algorithm_id}` : DASH)}
    ${info('KSK tag', state.ksk_tag ?? DASH)}
    ${info('ZSK tag', state.zsk_tag ?? DASH)}
    ${info('Last signed', state.signed_at ? timeAgo(state.signed_at) : DASH)}
    ${info('Signatures expire', expires, remaining !== null && remaining <= 7 * 86400 ? 'tone-red' : '')}
    ${info('Zone', state.zone)}
    ${info('SOA serial', state.serial)}`;
  dsRecord = state.ds_record || null;
  $('#ds-record').textContent = dsRecord || `${DASH} (not available)`;
}

function renderSystem(system) {
  $('#system-info').innerHTML = html`
    ${info('Mode', system.mode === 'demo' ? 'DEMO (simulated traffic)' : 'BIND (read-only)', system.mode === 'demo' ? 'tone-amber' : 'tone-green')}
    ${info('Version', `Sentinel ${system.version}`)}
    ${info('Python', system.python ?? DASH)}
    ${info('Panel uptime', system.uptime)}
    ${info('Database size', system.db_size_bytes === undefined ? DASH : fmt.bytes(system.db_size_bytes))}
    ${info('Logged queries', fmt.int(system.query_log_rows))}
    ${info('Forward zone', system.zone)}
    ${info('Reverse zone', system.reverse_zone)}`;
}

form.addEventListener('input', refreshDirty);
form.addEventListener('change', refreshDirty);
form.addEventListener('submit', (event) => event.preventDefault());
$('#discard-btn').addEventListener('click', () => saved && fill(saved));

$('#save-btn').addEventListener('click', () => withBusy($('#save-btn'), async () => {
  clearErrors();
  try {
    const { data } = await api('/api/settings', { method: 'PUT', body: currentValues() });
    saved = data;
    fill(data);
    toast('Settings saved', 'success');
  } catch (error) {
    Object.entries(error.details || {}).forEach(([field, message]) => {
      const slot = $(`[data-error="${field}"]`);
      if (slot) slot.textContent = message;
      const target = editors[field] ? $(`#${field}`) : form.elements[field];
      target?.classList.add('is-invalid');
    });
    toast(error.message, 'error');
  }
}));

$('#resign-btn').addEventListener('click', () => withBusy($('#resign-btn'), async () => {
  const spinner = $('#resign-btn .icon');
  spinner.classList.add('spin');
  try {
    const { data } = await api('/api/dnssec/sign', { method: 'POST' });
    renderDnssec(data);
    toast(`Zone ${data.zone} re-signed · serial ${data.serial}`, 'success');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    spinner.classList.remove('spin');
  }
}));

$('#copy-ds').addEventListener('click', async () => {
  if (!dsRecord) {
    toast('There is no DS record to copy yet', 'info');
    return;
  }
  const copied = await copyText(dsRecord);
  toast(copied ? 'DS record copied' : 'Copy failed - select the text manually', copied ? 'success' : 'error');
});

async function load() {
  const [settings, dnssec, system] = await Promise.all([api('/api/settings'), api('/api/dnssec'), api('/api/system')]);
  saved = settings.data;
  fill(saved);
  renderDnssec(dnssec.data);
  renderSystem(system.data);
  markUpdated();
}

load().catch((error) => toast(error.message, 'error'));
