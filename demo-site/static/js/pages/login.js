/* Login page: show / hide password and prevent double submits. */
const toggle = document.getElementById('toggle-password');
const password = document.getElementById('password');
const form = document.querySelector('.login-form');

toggle?.addEventListener('click', () => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  toggle.setAttribute('aria-pressed', String(show));
  toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  const use = toggle.querySelector('use');
  const href = use?.getAttribute('href') || '';
  use?.setAttribute('href', href.replace(/#.*$/, show ? '#eye-off' : '#eye'));
  password.focus();
});

form?.addEventListener('submit', () => {
  const button = form.querySelector('button[type="submit"]');
  button?.classList.add('is-busy');
});
