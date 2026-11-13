/* UI primitives: toasts, modal dialogs, confirmations, form errors, segmented controls. */
import { $, $$, html, icon } from './core.js';

const TOAST_ICONS = { success: 'circle-check', error: 'circle-alert', info: 'info' };

export function toast(message, type = 'info', timeout = 4000) {
  const stack = $('#toasts');
  if (!stack) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.setAttribute('role', type === 'error' ? 'alert' : 'status');
  el.innerHTML = html`${icon(TOAST_ICONS[type] || 'info', 'icon-sm')}<span>${message}</span>`;
  stack.appendChild(el);
  let removed = false;
  const remove = () => {
    if (removed) return;
    removed = true;
    el.classList.add('is-leaving');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  };
  setTimeout(remove, timeout);
  el.addEventListener('click', remove);
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function trapFocus(event, container) {
  const items = $$(FOCUSABLE, container);
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

/**
 * Open a modal dialog.
 * actions: [{ label, variant, icon, onClick(modal) }] - return false from onClick to keep it open.
 */
function modalMarkup({ title, body, actions, wide }) {
  return html`
    <div class="modal-backdrop" data-close></div>
    <div class="modal${wide ? ' wide' : ''}" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabindex="-1">
      <div class="modal-head">
        <h2 class="modal-title" id="modal-title">${title}</h2>
        <button class="icon-btn subtle" type="button" data-close aria-label="Close">${icon('x')}</button>
      </div>
      <div class="modal-body">${body}</div>
      ${actions.length ? html`<div class="modal-foot">${actions.map((action, i) => html`
        <button type="button" class="btn ${action.variant ? `btn-${action.variant}` : ''}" data-action="${i}">
          ${action.icon ? icon(action.icon) : ''}<span>${action.label}</span>
        </button>`)}</div>` : ''}
    </div>`;
}

function createModal(root, dialog, { onClose, opener }) {
  let closed = false;
  const modal = {
    el: dialog,
    close() {
      if (closed) return;
      closed = true;
      root.classList.remove('is-open');
      document.removeEventListener('keydown', onKey);
      setTimeout(() => {
        if (!root.classList.contains('is-open')) {
          root.hidden = true;
          root.innerHTML = '';
        }
      }, 350);
      onClose?.();
      opener?.focus?.();
    },
    setBusy(busy) {
      $$('.modal-foot .btn', dialog).forEach((button) => { button.disabled = busy; });
    },
  };

  function onKey(event) {
    if (event.key === 'Escape') modal.close();
    if (event.key === 'Tab') trapFocus(event, dialog);
  }
  document.addEventListener('keydown', onKey);
  return modal;
}

function bindActions(root, modal, actions) {
  root.onclick = async (event) => {
    if (event.target.closest('[data-close]')) {
      modal.close();
      return;
    }
    const button = event.target.closest('[data-action]');
    if (!button) return;
    const action = actions[Number(button.dataset.action)];
    if (!action?.onClick) {
      modal.close();
      return;
    }
    modal.setBusy(true);
    try {
      const keepOpen = (await action.onClick(modal)) === false;
      if (!keepOpen) modal.close();
    } finally {
      modal.setBusy(false);
    }
  };
}

export function openModal({ title, body, actions = [], wide = false, onClose } = {}) {
  const root = $('#modal-root');
  if (!root) return null;
  const opener = document.activeElement;
  root.innerHTML = modalMarkup({ title, body, actions, wide });
  root.hidden = false;
  const dialog = $('.modal', root);
  const modal = createModal(root, dialog, { onClose, opener });
  bindActions(root, modal, actions);
  requestAnimationFrame(() => root.classList.add('is-open'));
  setTimeout(() => ($('[autofocus], input, select, textarea', dialog) || dialog).focus(), 60);
  return modal;
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    let answered = false;
    const answer = (value) => {
      if (!answered) {
        answered = true;
        resolve(value);
      }
    };
    openModal({
      title,
      body: html`<p class="modal-text">${message}</p>`,
      actions: [
        { label: 'Cancel', variant: 'ghost', onClick: () => answer(false) },
        { label: confirmLabel, variant: danger ? 'danger' : 'primary', icon: danger ? 'trash-2' : 'check', onClick: () => answer(true) },
      ],
      onClose: () => answer(false),
    });
  });
}

/** Show per-field API validation errors inside a form. Returns true if any were shown. */
export function showFieldErrors(form, error) {
  $$('.is-invalid', form).forEach((el) => el.classList.remove('is-invalid'));
  $$('.field-error', form).forEach((el) => { el.textContent = ''; });
  const details = error?.details || {};
  Object.entries(details).forEach(([field, message]) => {
    const input = form.querySelector(`[name="${CSS.escape(field)}"]`);
    if (!input) return;
    input.classList.add('is-invalid');
    const slot = input.closest('.field')?.querySelector('.field-error');
    if (slot) slot.textContent = message;
  });
  return Object.keys(details).length > 0;
}

export function clearFieldErrors(form) {
  showFieldErrors(form, null);
}

/** Animated segmented control. Calls onChange(value) when the selection changes. */
export function segmented(container, onChange) {
  const pill = document.createElement('span');
  pill.className = 'seg-pill';
  container.prepend(pill);
  const buttons = $$('button', container);
  const move = (button) => {
    if (!button) return;
    pill.style.width = `${button.offsetWidth}px`;
    pill.style.transform = `translateX(${button.offsetLeft}px)`;
  };
  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      if (button.classList.contains('is-active')) return;
      buttons.forEach((b) => {
        b.classList.toggle('is-active', b === button);
        b.setAttribute('aria-selected', String(b === button));
      });
      move(button);
      onChange(button.dataset.value);
    });
  });
  const current = () => buttons.find((b) => b.classList.contains('is-active')) || buttons[0];
  requestAnimationFrame(() => move(current()));
  window.addEventListener('resize', () => move(current()));
}

/** Disable admin-only controls and hide admin-only sections for read-only users. */
export function applyRole(isAdmin) {
  if (isAdmin) return;
  $$('[data-admin]').forEach((el) => {
    el.disabled = true;
    el.title = 'Administrator role required';
  });
  $$('[data-admin-only]').forEach((el) => { el.hidden = true; });
}

/** Copy text to the clipboard; falls back to execCommand on plain-HTTP LAN addresses. */
export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      /* Permission denied: fall back to the legacy copy path below. */
    }
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  area.remove();
  return copied;
}

export async function withBusy(button, task) {
  button?.classList.add('is-busy');
  try {
    return await task();
  } finally {
    button?.classList.remove('is-busy');
  }
}
