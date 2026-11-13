/* Help page: accordion FAQ. */
import { $$ } from '../core.js';
import { initShell } from '../shell.js';

initShell();

$$('.accordion-item').forEach((item) => {
  const trigger = item.querySelector('.accordion-trigger');
  trigger?.addEventListener('click', () => {
    const open = !item.classList.contains('is-open');
    item.classList.toggle('is-open', open);
    trigger.setAttribute('aria-expanded', String(open));
  });
});
