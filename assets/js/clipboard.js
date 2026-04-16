/**
 * Clipboard utilities for Eventful
 */

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for older browsers or non-HTTPS
    const el = document.createElement('textarea');
    el.value = text;
    el.style.position = 'fixed';
    el.style.opacity = '0';
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(el);
    return ok;
  }
}

export function attachCopyButton(btn, getText) {
  btn.addEventListener('click', async () => {
    const text = typeof getText === 'function' ? getText() : getText;
    const ok = await copyToClipboard(text);
    if (ok) {
      btn.classList.add('copied');
      btn.textContent = '✓ Copied';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.textContent = 'Copy';
      }, 2000);
    }
  });
}

export function copyShareURL(eventId) {
  const url = `${location.origin}${location.pathname}#id=${eventId}`;
  return copyToClipboard(url);
}
