/* Users: accounts, add/delete users, change own password, login activity and audit trail. */
import { $, api, ctx, fmt, html, icon, isAdmin, timeAgo } from '../core.js';
import { applyRole, clearFieldErrors, confirmDialog, openModal, showFieldErrors, toast, withBusy } from '../ui.js';
import { initShell, markUpdated } from '../shell.js';

initShell();
applyRole(isAdmin);
let me = null;
let users = [];

if (ctx.must_change) {
  $('#content').insertAdjacentHTML('afterbegin', String(html`
    <div class="callout setup-callout" role="alert" style="--accent:#eab308">${icon('key-round')}
      <div><strong>Choose a new password to continue.</strong> This account still uses the generated
        first-run password. The other pages unlock as soon as you change it below.</div>
    </div>`));
}

function userRow(user, index) {
  const self = user.id === me.id;
  return html`
    <tr class="fade-in" style="animation-delay:${index * 50}ms">
      <td><span class="user-cell"><span class="avatar">${user.username.slice(0, 2)}</span>
        <span class="cell-strong">${user.username}</span>${self ? html`<span class="you-tag">YOU</span>` : ''}</span></td>
      <td><span class="badge ${user.role === 'admin' ? 'sev-low' : 'badge-muted'}">${user.role.toUpperCase()}</span></td>
      <td class="cell-dim">${fmt.dateTime(user.created_at)}</td>
      <td class="cell-dim" title="${fmt.dateTime(user.last_login_at)}">${timeAgo(user.last_login_at)}</td>
      <td class="actions">${isAdmin && !self ? html`
        <button class="icon-btn danger" type="button" data-delete="${user.id}" aria-label="Delete ${user.username}">${icon('trash-2', 'icon-sm')}</button>` : ''}</td>
    </tr>`;
}

async function loadUsers() {
  const { data } = await api('/api/users');
  ({ me, users } = data);
  $('#users-body').innerHTML = html`${users.map(userRow)}`;
  markUpdated();
}

async function loadActivity() {
  if (!isAdmin) return;
  const { data } = await api('/api/activity');
  $('#logins-body').innerHTML = data.logins.length ? html`${data.logins.map((e) => html`
    <tr><td class="cell-dim" title="${fmt.dateTime(e.ts)}">${timeAgo(e.ts)}</td><td>${e.username}</td><td class="cell-dim">${e.ip}</td>
      <td><span class="badge ${e.success ? 'badge-green' : 'badge-red'}">${e.success ? 'SUCCESS' : 'FAILED'}</span></td></tr>`)}`
    : html`<tr><td colspan="4" class="empty">No sign-ins recorded.</td></tr>`;
  $('#audit-body').innerHTML = data.audit.length ? html`${data.audit.map((e) => html`
    <tr><td class="cell-dim" title="${fmt.dateTime(e.ts)}">${timeAgo(e.ts)}</td><td>${e.username}</td>
      <td><code>${e.action}</code></td><td class="cell-dim cell-wrap" title="${e.detail}">${e.detail}</td></tr>`)}`
    : html`<tr><td colspan="4" class="empty">No administrative actions yet.</td></tr>`;
}

function newUserForm() {
  return html`
    <form class="stack-form" id="user-form" novalidate>
      <label class="field"><span class="field-label">Username</span>
        <input class="input" name="username" maxlength="32" autocomplete="off" placeholder="e.g. lab-assistant" autofocus>
        <span class="field-error"></span></label>
      <label class="field"><span class="field-label">Password (10+ characters)</span>
        <input class="input" type="password" name="password" maxlength="128" autocomplete="new-password">
        <span class="field-error"></span></label>
      <label class="field"><span class="field-label">Role</span>
        <select class="select" name="role"><option value="viewer">Viewer · read only</option><option value="admin">Admin · full control</option></select>
        <span class="field-error"></span></label>
    </form>`;
}

$('#add-user-btn').addEventListener('click', () => {
  openModal({
    title: 'Add user',
    body: newUserForm(),
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: 'Create user', variant: 'primary', icon: 'user-plus',
        onClick: async (modal) => {
          const form = $('#user-form', modal.el);
          try {
            const { data } = await api('/api/users', { method: 'POST', body: Object.fromEntries(new FormData(form)) });
            toast(`User ${data.username} created`, 'success');
            await Promise.all([loadUsers(), loadActivity()]);
            return true;
          } catch (error) {
            if (!showFieldErrors(form, error)) toast(error.message, 'error');
            return false;
          }
        },
      },
    ],
  });
});

$('#users-body').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-delete]');
  const user = button && users.find((u) => String(u.id) === button.dataset.delete);
  if (!user) return;
  const confirmed = await confirmDialog({
    title: 'Delete user',
    message: html`Delete the account <strong>${user.username}</strong>? They will be signed out immediately.`,
    confirmLabel: 'Delete user',
    danger: true,
  });
  if (!confirmed) return;
  try {
    await api(`/api/users/${user.id}`, { method: 'DELETE' });
    toast(`User ${user.username} deleted`, 'success');
    await Promise.all([loadUsers(), loadActivity()]);
  } catch (error) {
    toast(error.message, 'error');
  }
});

function strength(password) {
  const checks = [password.length >= 10, password.length >= 14, /[A-Z]/.test(password) && /[a-z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)];
  return checks.filter(Boolean).length / checks.length;
}

const passwordForm = $('#password-form');
passwordForm.elements.new_password.addEventListener('input', (event) => {
  const score = strength(event.target.value);
  const bar = $('#strength-bar');
  bar.style.transform = `scaleX(${score})`;
  bar.style.setProperty('--strength', score < 0.4 ? '#ef4444' : score < 0.8 ? '#eab308' : '#22c55e');
});

passwordForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const values = Object.fromEntries(new FormData(passwordForm));
  if (values.new_password !== values.confirm_password) {
    showFieldErrors(passwordForm, { details: { confirm_password: 'Passwords do not match' } });
    return;
  }
  withBusy(passwordForm.querySelector('[type="submit"]'), async () => {
    try {
      await api('/api/account/password', {
        method: 'POST',
        body: { current_password: values.current_password, new_password: values.new_password },
      });
      clearFieldErrors(passwordForm);
      passwordForm.reset();
      $('#strength-bar').style.transform = 'scaleX(0)';
      toast('Password updated', 'success');
      if (ctx.must_change) {
        window.location.assign('/');  // the rest of the dashboard is now unlocked
        return;
      }
      await loadActivity();
    } catch (error) {
      if (!showFieldErrors(passwordForm, error)) toast(error.message, 'error');
    }
  });
});

Promise.all([loadUsers(), loadActivity()]).catch((error) => toast(error.message, 'error'));
