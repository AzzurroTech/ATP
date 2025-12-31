// utils.js – generic helpers used across modules
import { CONFIG } from './config.js';

/* ---------------------------------------------------------
   debounce(fn, wait) – returns a debounced version of fn
--------------------------------------------------------- */
export function debounce(fn, wait) {
    let timer = null;
    return (...args) => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
            timer = null;
            fn(...args);
        }, wait);
    };
}

/* ---------------------------------------------------------
   apiFetch(path, options) – wrapper around fetch()
   - Prepends CONFIG.apiBase
   - Checks for 401 and forces logout
   - Returns the raw Response (caller decides json/text)
--------------------------------------------------------- */
export async function apiFetch(path, options = {}) {
    const resp = await fetch(`${CONFIG.apiBase}${path}`, options);
    if (resp.status === 401) {
        // Lazy‑load auth module to avoid circular dependency
        const { logout } = await import('./auth.js');
        logout(); // forces UI logout
        throw new Error('Session expired – logged out');
    }
    if (!resp.ok) {
        const txt = await resp.text();
        throw new Error(`HTTP ${resp.status}: ${txt}`);
    }
    return resp;
}

/* ---------------------------------------------------------
   Simple toast notification (re‑used by many modules)
--------------------------------------------------------- */
export function toast(msg, error = false) {
    const el = document.createElement('div');
    el.textContent = msg;
    el.style.position = 'fixed';
    el.style.bottom = '1rem';
    el.style.right = '1rem';
    el.style.padding = '0.6rem 1rem';
    el.style.background = error ? '#e53935' : '#4caf50';
    el.style.color = '#fff';
    el.style.borderRadius = '4px';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

/* ---------------------------------------------------------
   Spinner overlay (simple visual feedback)
--------------------------------------------------------- */
export function showSpinner(message = 'Processing…') {
    const overlay = document.getElementById('spinnerOverlay');
    overlay.hidden = false;
    overlay.setAttribute('aria-label', message);
}
export function hideSpinner() {
    const overlay = document.getElementById('spinnerOverlay');
    overlay.hidden = true;
}