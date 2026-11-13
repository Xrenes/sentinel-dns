/* Domains: zone overview, record table with filters, add/edit/delete dialogs, zone-file viewer. */
import { $, $$, api, fmt, html, icon, isAdmin, timeAgo } from '../core.js';
import { applyRole, confirmDialog, copyText, openModal, showFieldErrors, toast } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';

const TYPES = { forward: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'], reverse: ['PTR', 'NS'] };
const HINTS = {
  A: '192.168.56.50', AAAA: 'fd00:56::50', CNAME: 'www  or  host.example.com', MX: 'mail',
  TXT: 'v=spf1 mx -all', NS: 'ns1', PTR: 'host.lab.local',
};

initShell();
applyRole(isAdmin);
let zones = [];
let activeZone = null;
let records = [];
let typeFilter = 'ALL';
let search = '';

const zoneByName = (name) => zones.find((z) => z.name === name);

function dnssecBadge(signed) {
  if (signed === null || signed === undefined) {  // bind mode: key state is not read from BIND yet
    return html`<span class="badge badge-muted" title="Not read from BIND yet">${icon('shield', 'icon-xs')}DNSSEC ?</span>`;
  }
  return html`<span class="badge ${signed ? 'badge-green' : 'badge-muted'}">${icon(signed ? 'shield-check' : 'shield-off', 'icon-xs')}${signed ? 'DNSSEC' : 'UNSIGNED'}</span>`;
}

function zoneCard(zone, index) {
  return html`
    <button class="card zone-card reveal${zone.name === activeZone ? ' is-active' : ''}" style="--i:${index}" type="button" data-zone="${zone.name}">
      <span class="zone-top">
        <span class="zone-name">${zone.name}</span>
        ${dnssecBadge(zone.dnssec_enabled)}
      </span>
      <span class="zone-meta">
        <span>${zone.kind === 'forward' ? 'Forward zone' : 'Reverse zone'}</span>
        <span>Serial <b>${zone.serial}</b></span>
        <span><b>${fmt.int(zone.record_count)}</b> records</span>
        <span>Updated <b>${timeAgo(zone.updated_at)}</b></span>
      </span>
    </button>`;
}

function renderZones() {
  $('#zone-grid').innerHTML = html`${zones.map(zoneCard)}`;
}

function renderChips() {
  const kind = zoneByName(activeZone)?.kind || 'forward';
  const types = ['ALL', ...TYPES[kind]];
  if (!types.includes(typeFilter)) typeFilter = 'ALL';
  $('#type-chips').innerHTML = html`${types.map((t) => html`
    <button class="chip${t === typeFilter ? ' is-active' : ''}" type="button" data-type="${t}">${t}</button>`)}`;
}

const displayValue = (record) => (record.type === 'MX' ? `${record.priority} ${record.value}` : record.value);

function recordRow(record, index) {
  return html`
    <tr class="fade-in" style="animation-delay:${Math.min(index, 12) * 30}ms" data-id="${record.id}">
      <td class="cell-strong">${record.name}</td>
      <td><span class="rtype rtype-${record.type}">${record.type}</span></td>
      <td class="cell-wrap" title="${displayValue(record)}">${displayValue(record)}</td>
      <td class="cell-dim">${fmt.int(record.ttl)}</td>
      <td class="cell-dim" title="${fmt.dateTime(record.updated_at)}">${timeAgo(record.updated_at)}</td>
      <td class="actions">${isAdmin ? html`
        <button class="icon-btn subtle" type="button" data-edit="${record.id}" aria-label="Edit ${record.name}">${icon('pencil', 'icon-sm')}</button>
        <button class="icon-btn danger" type="button" data-delete="${record.id}" aria-label="Delete ${record.name}">${icon('trash-2', 'icon-sm')}</button>` : ''}</td>
    </tr>`;
}

function renderRecords() {
  const needle = search.toLowerCase();
  const visible = records.filter((r) => (typeFilter === 'ALL' || r.type === typeFilter)
    && (!needle || r.name.includes(needle) || displayValue(r).toLowerCase().includes(needle)));
  $('#records-body').innerHTML = visible.length
    ? html`${visible.map(recordRow)}`
    : html`<tr><td colspan="6" class="empty">No records match.</td></tr>`;
}

async function loadRecords() {
  const { data } = await api(`/api/zones/${encodeURIComponent(activeZone)}/records`);
  records = data;
  renderChips();
  renderRecords();
  markUpdated();
}

async function loadZones(selected) {
  const { data } = await api('/api/zones');
  zones = data;
  activeZone = selected || activeZone || zones[0]?.name;
  renderZones();
  await loadRecords();
}

function recordForm(zone, record) {
  const types = TYPES[zone.kind];
  const current = record?.type || types[0];
  return html`
    <form class="form-grid" id="record-form" novalidate>
      <label class="field"><span class="field-label">Type</span>
        <select class="select" name="type">${types.map((t) => html`<option value="${t}" ${t === current ? 'selected' : ''}>${t}</option>`)}</select>
        <span class="field-error"></span></label>
      <label class="field"><span class="field-label">TTL (seconds)</span>
        <input class="input" name="ttl" type="number" min="60" max="604800" value="${record?.ttl ?? 3600}">
        <span class="field-error"></span></label>
      <label class="field full"><span class="field-label">Name</span>
        <input class="input" name="name" value="${record?.name ?? ''}" autocomplete="off" spellcheck="false"
          placeholder="${zone.kind === 'forward' ? 'www   (use @ for the zone apex)' : '50   (host octet)'}">
        <span class="muted-note">Full name: <span id="fqdn-preview">…</span></span>
        <span class="field-error"></span></label>
      <label class="field full" data-priority ${current === 'MX' ? '' : 'hidden'}><span class="field-label">Priority</span>
        <input class="input" name="priority" type="number" min="0" max="65535" value="${record?.priority ?? 10}">
        <span class="field-error"></span></label>
      <label class="field full"><span class="field-label">Value</span>
        <input class="input" name="value" value="${record?.value ?? ''}" autocomplete="off" spellcheck="false" placeholder="${HINTS[current]}">
        <span class="field-error"></span></label>
    </form>`;
}

function wireRecordForm(form, zone) {
  const type = form.elements.type;
  const name = form.elements.name;
  const preview = $('#fqdn-preview', form);
  const update = () => {
    $('[data-priority]', form).hidden = type.value !== 'MX';
    form.elements.value.placeholder = HINTS[type.value];
    const label = name.value.trim();
    preview.textContent = !label || label === '@' ? `${zone.name}.` : `${label}.${zone.name}.`;
  };
  type.addEventListener('change', update);
  name.addEventListener('input', update);
  update();
}

async function saveRecord(modal, zone, record) {
  const form = $('#record-form', modal.el);
  const { priority, ...rest } = Object.fromEntries(new FormData(form));
  const body = rest.type === 'MX' ? { ...rest, priority } : rest;
  try {
    const path = record ? `/api/records/${record.id}` : `/api/zones/${encodeURIComponent(zone.name)}/records`;
    const { data } = await api(path, { method: record ? 'PUT' : 'POST', body });
    toast(`${record ? 'Updated' : 'Added'} ${data.record.type} record "${data.record.name}" · serial ${data.zone.serial}`, 'success');
    await loadZones(zone.name);
    return true;
  } catch (error) {
    if (!showFieldErrors(form, error)) toast(error.message, 'error');
    return false;
  }
}

function openRecordDialog(record) {
  const zone = zoneByName(activeZone);
  if (!zone) return;
  const modal = openModal({
    title: record ? `Edit record · ${zone.name}` : `Add record · ${zone.name}`,
    body: recordForm(zone, record),
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      { label: record ? 'Save changes' : 'Add record', variant: 'primary', icon: 'save', onClick: (m) => saveRecord(m, zone, record) },
    ],
  });
  const form = $('#record-form', modal.el);
  wireRecordForm(form, zone);
  form.addEventListener('submit', (event) => {
    event.preventDefault();
    $('.modal-foot .btn-primary', modal.el)?.click();
  });
}

async function deleteRecord(record) {
  const confirmed = await confirmDialog({
    title: 'Delete record',
    message: html`Delete <strong>${record.type}</strong> record <strong>${record.name}</strong> → ${displayValue(record)}? The zone serial will be increased.`,
    confirmLabel: 'Delete',
    danger: true,
  });
  if (!confirmed) return;
  try {
    await api(`/api/records/${record.id}`, { method: 'DELETE' });
    toast(`Deleted ${record.type} record "${record.name}"`, 'success');
    await loadZones(activeZone);
  } catch (error) {
    toast(error.message, 'error');
  }
}

function highlightLine(line) {
  if (line.startsWith(';')) return html`<span class="c-comment">${line}</span>`;
  if (line.startsWith('$')) return html`<span class="c-directive">${line}</span>`;
  return html`${line.split(/("(?:[^"\\]|\\.)*")/).map((part) => {
    if (part.startsWith('"')) return html`<span class="c-string">${part}</span>`;
    return part.split(/(\s+)/).map((token) => {
      if (/^(IN|SOA|NS|A|AAAA|CNAME|MX|TXT|PTR)$/.test(token)) return html`<span class="c-type">${token}</span>`;
      if (/^\d+$/.test(token)) return html`<span class="c-num">${token}</span>`;
      return token;
    });
  })}`;
}

async function showZoneFile() {
  try {
    const { data } = await api(`/api/zones/${encodeURIComponent(activeZone)}/zonefile`);
    const lines = data.text.replace(/\n$/, '').split('\n');
    openModal({
      title: `Zone file · ${data.zone}`,
      wide: true,
      body: html`<p class="muted-note">This is the BIND zone file Sentinel generates for this zone from its database.</p>
        <pre class="code">${lines.map((line, i) => html`${i ? '\n' : ''}${highlightLine(line)}`)}</pre>`,
      actions: [
        { label: 'Close', variant: 'ghost' },
        {
          label: 'Copy', variant: 'primary', icon: 'copy',
          onClick: async () => {
            toast(await copyText(data.text) ? 'Zone file copied' : 'Copy failed - select the text manually', 'info');
            return false;
          },
        },
      ],
    });
  } catch (error) {
    toast(error.message, 'error');
  }
}

$('#zone-grid').addEventListener('click', (event) => {
  const card = event.target.closest('[data-zone]');
  if (!card || card.dataset.zone === activeZone) return;
  activeZone = card.dataset.zone;
  $$('.zone-card').forEach((el) => el.classList.toggle('is-active', el.dataset.zone === activeZone));
  loadRecords().catch((error) => toast(error.message, 'error'));
});

$('#type-chips').addEventListener('click', (event) => {
  const chip = event.target.closest('[data-type]');
  if (!chip) return;
  typeFilter = chip.dataset.type;
  $$('.chip', $('#type-chips')).forEach((el) => el.classList.toggle('is-active', el === chip));
  renderRecords();
});

$('#record-search').addEventListener('input', (event) => {
  search = event.target.value.trim();
  renderRecords();
});

$('#records-body').addEventListener('click', (event) => {
  const edit = event.target.closest('[data-edit]');
  const remove = event.target.closest('[data-delete]');
  const id = (edit || remove)?.dataset.edit || (edit || remove)?.dataset.delete;
  const record = records.find((r) => String(r.id) === id);
  if (!record) return;
  if (edit) openRecordDialog(record);
  else deleteRecord(record);
});

$('#add-record-btn').addEventListener('click', () => openRecordDialog(null));
$('#zonefile-btn').addEventListener('click', showZoneFile);

loadZones().catch((error) => toast(error.message, 'error'));
