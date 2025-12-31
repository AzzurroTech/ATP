// auth.js – login / logout / token handling
import { CONFIG } from './config.js';
import { apiFetch, toast, showSpinner, hideSpinner } from './utils.js';
import { deriveKeyFromPassword } from './crypto.js';
import { scheduleSync } from './sync.js';

export const authState = {
    token: localStorage.getItem(CONFIG.tokenKey) || null,
    cryptoKey: null, // CryptoKey derived from password
};

/* ---------------------------------------------------------
   login() – prompts for credentials, derives encryption key,
   obtains JWT token from the server, updates UI.
--------------------------------------------------------- */
export async function login() {
    const login = prompt('Enter your login (email/username):');
    const password = prompt('Enter your password:');
    if (!login || !password) {
        toast('Login cancelled', true);
        return;
    }

    // Derive client‑side encryption key (used for encrypt/decrypt)
    try {
        authState.cryptoKey = await deriveKeyFromPassword(password);
    } catch (e) {
        toast('Failed to derive encryption key', true);
        return;
    }

    showSpinner('Logging in…');
    try {
        const resp = await apiFetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ login, password })
        });
        const data = await resp.json(); // { token: "…" }
        authState.token = data.token;
        localStorage.setItem(CONFIG.tokenKey, authState.token);
        document.getElementById('loginBtn').hidden = true;
        document.getElementById('logoutBtn').hidden = false;
        toast('Logged in successfully');
    } catch (e) {
        toast(`Login failed: ${e.message}`, true);
    } finally {
        hideSpinner();
    }
}

/* ---------------------------------------------------------
   logout() – clears token, crypto key, pending sync timer,
   updates UI.
--------------------------------------------------------- */
export function logout() {
    authState.token = null;
    authState.cryptoKey = null;
    localStorage.removeItem(CONFIG.tokenKey);
    // Cancel any pending auto‑sync
    if (window.__syncTimer) {
        clearTimeout(window.__syncTimer);
        window.__syncTimer = null;
    }
    document.getElementById('loginBtn').hidden = false;
    document.getElementById('logoutBtn').hidden = true;
    toast('Logged out');
}

/* ---------------------------------------------------------
   authHeaders() – returns minimal headers for authenticated
   requests (adds Authorization bearer token).
--------------------------------------------------------- */
export function authHeaders() {
    const hdr = { 'Content-Type': 'application/octet-stream' };
    if (authState.token) {
        hdr['Authorization'] = `Bearer ${authState.token}`;
    }
    return hdr;
}