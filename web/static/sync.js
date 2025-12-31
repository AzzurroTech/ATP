// sync.js – auto‑sync, manual push, upload / download encrypted contexts
import { CONFIG } from './config.js';
import { apiFetch, toast, showSpinner, hideSpinner } from './utils.js';
import { authState, authHeaders } from './auth.js';
import { collectContext } from './workspace.js';
import { encryptData, decryptData } from './crypto.js';
import { uiState } from './workspace.js';   // <-- need access to lastSyncedSnapshot

/* ---------------------------------------------------------
   scheduleSync() – debounced auto‑sync (2 seconds by default)
--------------------------------------------------------- */
export const scheduleSync = (() => {
    let timer = null;
    return () => {
        if (timer) clearTimeout(timer);
        timer = setTimeout(() => {
            timer = null;
            syncToServer();
        }, CONFIG.syncDebounce);
    };
})();

/* ---------------------------------------------------------
   syncToServer() – encrypt current workspace and POST it.
   Skips if not logged in or if nothing changed since last sync.
--------------------------------------------------------- */
async function syncToServer() {
    if (!authState.token) {
        console.info('Auto‑sync skipped – not logged in');
        return;
    }
    if (!authState.cryptoKey) {
        toast('Missing encryption key – cannot sync', true);
        return;
    }

    const payload = JSON.stringify(collectContext());

    // Compare with the snapshot stored in uiState
    if (payload === uiState.lastSyncedSnapshot) {
        console.info('Auto‑sync: no changes detected');
        return;
    }

    showSpinner('Synchronizing…');
    try {
        const encrypted = await encryptData(payload, authState.cryptoKey);
        await apiFetch('/context/upload', {
            method: 'POST',
            headers: authHeaders(),
            body: encrypted
        });
        uiState.lastSyncedSnapshot = payload;   // remember successful snapshot
        console.info('Auto‑sync succeeded');
    } catch (e) {
        console.error('Auto‑sync failed:', e);
        toast('Auto‑sync failed – will retry on next change', true);
    } finally {
        hideSpinner();
    }
}

/* ---------------------------------------------------------
   pushCurrentState() – manual “Push to server” button.
   Cancels any pending debounce and forces an immediate sync.
--------------------------------------------------------- */
export async function pushCurrentState() {
    if (!authState.token) {
        toast('You must be logged in to push', true);
        return;
    }
    // Cancel any pending auto‑sync timer
    if (window.__syncTimer) {
        clearTimeout(window.__syncTimer);
        window.__syncTimer = null;
    }
    await syncToServer();
    toast('Current state pushed to server');
}

/* ---------------------------------------------------------
   uploadEncryptedContext(file) – user selects a .txt/.enc file
   and uploads the raw base64 payload to the server.
--------------------------------------------------------- */
export async function uploadEncryptedContext(file) {
    if (!authState.token) {
        toast('You must be logged in to upload', true);
        return;
    }
    const reader = new FileReader();
    reader.onload = async ev => {
        try {
            await apiFetch('/context/upload', {
                method: 'POST',
                headers: authHeaders(),
                body: ev.target.result // raw base64 string
            });
            toast('Encrypted context uploaded successfully');
        } catch (e) {
            toast(`Upload failed: ${e.message}`, true);
        }
    };
    reader.readAsText(file);
}

/* ---------------------------------------------------------
   downloadEncryptedContext() – fetches the encrypted blob,
   converts it to a Blob, then hands it to workspace.decryptContext().
--------------------------------------------------------- */
export async function downloadEncryptedContext() {
    if (!authState.token) {
        toast('You must be logged in to download', true);
        return;
    }
    try {
        const resp = await apiFetch('/context/download', {
            method: 'GET',
            headers: authHeaders()
        });
        const b64 = await resp.text();

        // Convert base64 → Uint8Array → Blob
        const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const blob = new Blob([binary], { type: 'text/plain' });

        // Delegate decryption to workspace module
        const { decryptContext } = await import('./workspace.js');
        await decryptContext(blob);
    } catch (e) {
        toast(`Download failed: ${e.message}`, true);
    }
}