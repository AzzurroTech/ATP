/*
Directory structure
atp/
├─ .gitignore
├─ README.md
├─ LICENSE
├─ go.mod
├─ Dockerfile
├─ Caddyfile
├─ docker-compose.yml
├─ server/
│   └─ main.go
├─ web/
│   ├─ templates/
│   │   └─ index.html.tmpl
│   └─ static/
│       ├─ styles.css
│       └─ ui.js
├─ data/            # created at runtime (users.json, *.ctx)
└─ assets/          # optional – place dolphin logo, favicons, etc.


File: web/static/ui.js
 ============================================================
   ui.js – Complete front‑end logic for the Azzurro Technical Platform
   ------------------------------------------------------------
   • Pure vanilla JavaScript (ES‑6) – no external dependencies
   • Uses only standard browser APIs:
        – DOM manipulation
        – LocalStorage
        – Fetch API
        – Web Crypto API (AES‑GCM, PBKDF2, HMAC‑SHA‑256)
        – FileReader / Blob / URL.createObjectURL
   • Implements:
        – Form‑Library creation & persistence
        – Adding / nesting / deleting articles (forms)
        – Keyword‑based ad generation
        – Search / filter of fields (fluid & responsive)
        – Persist field values without submitting
        – Export / Import of workspace as JSON “context”
        – Client‑side encryption / decryption
        – Authentication (login / logout) with rate‑limited server
        – Auto‑sync to server on significant change (debounced)
        – Manual “Push to server” button
        – Mobile‑responsive UI (handled by CSS)
   ============================================================ */

(() => {
    /* ---------------------------------------------------------
       1️⃣ Constants & selector shortcuts
    --------------------------------------------------------- */
    const API_BASE   = '/api';
    const STORAGE_KEY = 'atp_form_library';   // library templates
    const FIELD_VAL_KEY = 'atp_field_values'; // persisted field values
    const TOKEN_KEY   = 'atp_auth_token';

    const $  = sel => document.querySelector(sel);
    const $$ = sel => Array.from(document.querySelectorAll(sel));

    /* ---------------------------------------------------------
       2️⃣ Global mutable state
    --------------------------------------------------------- */
    const state = {
        library: [],          // [{name:string, inputs:[{label,type,name}]}]
        token:   localStorage.getItem(TOKEN_KEY) || null,
        cryptoKey: null,      // derived from password (AES‑GCM)
        articleSeq: 0,        // incremental id for <article>
        syncTimer: null,      // debounce timer for auto‑sync
        lastSyncedSnapshot: '' // JSON snapshot of last successful sync
    };

    /* ---------------------------------------------------------
       3️⃣ Toast notification (quick feedback)
    --------------------------------------------------------- */
    function toast(msg, error = false) {
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
       4️⃣ Library persistence (localStorage)
    --------------------------------------------------------- */
    function saveLibrary() {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state.library));
    }
    function loadLibrary() {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (raw) {
            try { state.library = JSON.parse(raw); }
            catch (_) { state.library = []; }
        }
    }

    /* ---------------------------------------------------------
       5️⃣ Field‑value persistence (localStorage)
    --------------------------------------------------------- */
    function loadFieldValues() {
        const raw = localStorage.getItem(FIELD_VAL_KEY);
        return raw ? JSON.parse(raw) : {};
    }
    function saveFieldValues(map) {
        localStorage.setItem(FIELD_VAL_KEY, JSON.stringify(map));
    }
    const persistedFieldMap = loadFieldValues();

    function persistFieldValue(articleId, fieldName, value) {
        const map = loadFieldValues();
        const key = `${articleId}|${fieldName}`;
        map[key] = value;
        saveFieldValues(map);
    }

    /* ---------------------------------------------------------
       6️⃣ Render the list of saved templates
    --------------------------------------------------------- */
    function renderLibraryList() {
        const ul = $('#templateList');
        ul.innerHTML = '';
        state.library.forEach(tpl => {
            const li = document.createElement('li');
            li.textContent = tpl.name;

            const btn = document.createElement('button');
            btn.textContent = 'Use';
            btn.onclick = () => addArticleFromTemplate(tpl);
            li.appendChild(btn);
            ul.appendChild(li);
        });
    }

    /* ---------------------------------------------------------
       7️⃣ Add a new input row to the library form
    --------------------------------------------------------- */
    function addInputRow(container, type = 'text', label = '', name = '') {
        const row = document.createElement('div');
        row.className = 'input-row';

        const lbl = document.createElement('input');
        lbl.type = 'text';
        lbl.placeholder = 'Label';
        lbl.value = label;
        row.appendChild(lbl);

        const sel = document.createElement('select');
        ['text','email','number','date','checkbox','radio'].forEach(opt => {
            const o = document.createElement('option');
            o.value = opt;
            o.textContent = opt;
            if (opt === type) o.selected = true;
            sel.appendChild(o);
        });
        row.appendChild(sel);

        const nam = document.createElement('input');
        nam.type = 'text';
        nam.placeholder = 'Name';
        nam.value = name;
        row.appendChild(nam);

        const del = document.createElement('button');
        del.textContent = '✕';
        del.onclick = () => row.remove();
        row.appendChild(del);

        container.appendChild(row);
    }

    /* ---------------------------------------------------------
       8️⃣ Library form submit handler (save template)
    --------------------------------------------------------- */
    $('#libraryForm').addEventListener('submit', e => {
        e.preventDefault();
        const name = $('#libName').value.trim();
        if (!name) return toast('Template name required', true);

        const rows = $$('#inputsFieldset .input-row');
        const inputs = rows.map(r => ({
            label: r.children[0].value.trim(),
            type:  r.children[1].value,
            name:  r.children[2].value.trim()
        }));

        state.library.push({ name, inputs });
        saveLibrary();
        renderLibraryList();
        e.target.reset();
        $('#inputsFieldset').innerHTML = '';
        toast('Template saved');
    });
    $('#addInputBtn').onclick = () => addInputRow($('#inputsFieldset'));

    /* ---------------------------------------------------------
       9️⃣ Create an <article> (form instance) in the workspace
    --------------------------------------------------------- */
    function createArticleNode(tpl, parentArticle = null) {
        const article = document.createElement('article');
        const id = ++state.articleSeq;
        article.dataset.id = id;

        // ---- Header (title) ----
        const hdr = document.createElement('header');
        hdr.textContent = tpl.name;
        article.appendChild(hdr);

        // ---- Delete button ----
        const delBtn = document.createElement('button');
        delBtn.className = 'control';
        delBtn.title = 'Delete';
        delBtn.textContent = '✕';
        delBtn.onclick = () => {
            article.remove();
            generateAdsFromMain();
            scheduleSync(); // removal counts as a significant change
        };
        article.appendChild(delBtn);

        // ---- Toggle (expand/collapse) button ----
        const togBtn = document.createElement('button');
        togBtn.className = 'control';
        togBtn.style.right = '2.5rem';
        togBtn.title = 'Toggle';
        togBtn.textContent = '▾';
        togBtn.onclick = () => {
            const body = article.querySelector('.body');
            if (body) {
                const hidden = body.hidden = !body.hidden;
                togBtn.textContent = hidden ? '▸' : '▾';
            }
        };
        article.appendChild(togBtn);

        // ---- Add child button ----
        const childBtn = document.createElement('button');
        childBtn.className = 'control';
        childBtn.style.right = '4.5rem';
        childBtn.title = 'Add child';
        childBtn.textContent = '+';
        childBtn.onclick = () => {
            const childName = prompt('Enter name of saved template to add as child:');
            if (!childName) return;
            const childTpl = state.library.find(t => t.name === childName);
            if (!childTpl) return toast('Template not found', true);
            addArticleFromTemplate(childTpl, article);
        };
        article.appendChild(childBtn);

        // ---- Body – actual form fields ----
        const bodyDiv = document.createElement('div');
        bodyDiv.className = 'body';
        tpl.inputs.forEach(inp => {
            const wrapper = document.createElement('div');
            const label = document.createElement('label');
            label.textContent = inp.label;

            const field = document.createElement('input');
            field.type = inp.type;
            field.name = inp.name;

            // Restore persisted value if any
            const persistedKey = `${id}|${inp.name}`;
            if (persistedFieldMap[persistedKey] !== undefined) {
                field.value = persistedFieldMap[persistedKey];
            }

            // Persist on every change
            field.addEventListener('input', () => {
                persistFieldValue(id, inp.name, field.value);
                scheduleSync(); // any edit triggers auto‑sync debounce
            });

            label.appendChild(field);
            wrapper.appendChild(label);
            bodyDiv.appendChild(wrapper);
        });
        article.appendChild(bodyDiv);

        // ---- Insert into DOM ----
        if (parentArticle) {
            const parentBody = parentArticle.querySelector('.body');
            parentBody.appendChild(article);
        } else {
            $('#mainContent').appendChild(article);
        }

        // Remove placeholder paragraph if present
        const placeholder = $('#mainContent .placeholder');
        if (placeholder) placeholder.remove();

        generateAdsFromMain();
    }

    /* Public helper used by the library UI */
    function addArticleFromTemplate(tpl, parentArticle = null) {
        createArticleNode(tpl, parentArticle);
    }

    /* ---------------------------------------------------------
       10️⃣ Keyword‑based ad generation
    --------------------------------------------------------- */
    function generateAdsFromMain() {
        const text = $('#mainContent').innerText.toLowerCase();
        const container = $('#adsContainer');
        container.innerHTML = '';

        const map = [
            { word: 'email',    ad: 'Secure your inbox with Proton Mail.' },
            { word: 'vpn',      ad: 'Browse safely using Proton VPN.' },
            { word: 'cloud',    ad: 'Store files privately with Proton Drive.' },
            { word: 'calendar', ad: 'Organise meetings with Proton Calendar.' }
        ];

        let any = false;
        map.forEach(m => {
            if (text.includes(m.word)) {
                any = true;
                const div = document.createElement('div');
                div.className = 'ad-item';
                div.textContent = m.ad;
                container.appendChild(div);
            }
        });

        if (!any) {
            const fallback = document.createElement('div');
            fallback.className = 'ad-item';
            fallback.textContent = 'Explore Proton’s privacy‑focused services.';
            container.appendChild(fallback);
        }
    }

    /* ---------------------------------------------------------
       11️⃣ Context export / import (JSON)
    --------------------------------------------------------- */
    function collectContext() {
        const articles = [];

        function walk(el, parentId = null) {
            const id = el.dataset.id;
            const title = el.querySelector('header').textContent;
            const inputs = Array.from(el.querySelectorAll('.body input')).map(inp => ({
                name:  inp.name,
                type:  inp.type,
                value: inp.value
            }));
            articles.push({ id, title, inputs, parentId });

            const childArts = el.querySelectorAll(':scope > .body > article');
            childArts.forEach(c => walk(c, id));
        }

        $$('#mainContent > article').forEach(a => walk(a));
        return { version: 1, timestamp: Date.now(), articles };
    }

    function exportContext() {
        const payload = collectContext();
        const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `atp-context-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function importContext(file) {
        const reader = new FileReader();
        reader.onload = ev => {
            try {
                const data = JSON.parse(ev.target.result);
                if (!Array.isArray(data.articles)) throw new Error('Invalid format');

                // Clear workspace
                $('#mainContent').innerHTML = '';

                // Map of id → article element for nesting
                const lookup = {};

                data.articles.forEach(rec => {
                    const article = document.createElement('article');
                    article.dataset.id = rec.id;

                    const hdr = document.createElement('header');
                    hdr.textContent = rec.title;
                    article.appendChild(hdr);

                    // Controls (same as createArticleNode)
                    const delBtn = document.createElement('button');
                    delBtn.className = 'control';
                    delBtn.title = 'Delete';
                    delBtn.textContent = '✕';
                    delBtn.onclick = () => {
                        article.remove();
                        generateAdsFromMain();
                        scheduleSync();
                    };
                    article.appendChild(delBtn);

                    const togBtn = document.createElement('button');
                    togBtn.className = 'control';
                    togBtn.style.right = '2.5rem';
                    togBtn.title = 'Toggle';
                    togBtn.textContent = '▾';
                    togBtn.onclick = () => {
                        const body = article.querySelector('.body');
                        if (body) {
                            const hidden = body.hidden = !body.hidden;
                            togBtn.textContent = hidden ? '▸' : '▾';
                        }
                    };
                    article.appendChild(togBtn);

                    const childBtn = document.createElement('button');
                    childBtn.className = 'control';
                    childBtn.style.right = '4.5rem';
                    childBtn.title = 'Add child';
                    childBtn.textContent = '+';
                    childBtn.onclick = () => {
                        const childName = prompt('Enter name of saved template to add as child:');
                        if (!childName) return;
                        const childTpl = state.library.find(t => t.name === childName);
                        if (!childTpl) return toast('Template not found', true);
                        addArticleFromTemplate(childTpl, article);
                    };
                    article.appendChild(childBtn);

                    const bodyDiv = document.createElement('div');
                    bodyDiv.className = 'body';
                    rec.inputs.forEach(inp => {
                        const wrapper = document.createElement('div');
                        const label = document.createElement('label');
                        label.textContent = inp.name;
                        const field = document.createElement('input');
                        field.type = inp.type;
                        field.name = inp.name;
                        field.value = inp.value || '';

                        // Restore persisted value if any
                        const persistedKey = `${rec.id}|${inp.name}`;
                        const persistedMap = loadFieldValues();
                        if (persistedMap[persistedKey] !== undefined) {
                            field.value = persistedMap[persistedKey];
                        }

                        // Persist on change
                        field.addEventListener('input', () => {
                            persistFieldValue(rec.id, inp.name, field.value);
                            scheduleSync();
                        });

                        label.appendChild(field);
                        wrapper.appendChild(label);
                        bodyDiv.appendChild(wrapper);
                    });
                    article.appendChild(bodyDiv);

                    // Insert according to parentId
                    if (rec.parentId && lookup[rec.parentId]) {
                        const parentBody = lookup[rec.parentId].querySelector('.body');
                        parentBody.appendChild(article);
                    } else {
                        $('#mainContent').appendChild(article);
                    }
                    lookup[rec.id] = article;
                });

                generateAdsFromMain();
                toast('Context imported');
            } catch (e) {
                toast('Import failed: ' + e.message, true);
            }
        };
        reader.readAsText(file);
    }

    /* ---------------------------------------------------------
       12️⃣ Web Crypto helpers (key derivation, encrypt, decrypt)
    --------------------------------------------------------- */
    async function deriveKeyFromPassword(pw) {
        const enc = new TextEncoder();
        const salt = enc.encode('atp-static-salt'); // static demo salt
        const baseKey = await crypto.subtle.importKey(
            'raw',
            enc.encode(pw),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function encryptContext() {
        if (!state.cryptoKey) return toast('Set a password first (log in)', true);
        const payload = JSON.stringify(collectContext());
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const cipher = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            state.cryptoKey,
            enc.encode(payload)
        );

        const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(cipher), iv.byteLength);
        const b64 = btoa(String.fromCharCode(...combined));

        const blob = new Blob([b64], {type:'text/plain'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `atp-encrypted-${Date.now()}.txt`;
        a.click();
        URL.revokeObjectURL(url);
        toast('Context encrypted & downloaded');
    }

    async function decryptContext(file) {
        // The user must have derived a cryptoKey (by logging in)
        if (!state.cryptoKey) {
            toast('Set a password first (log in)', true);
            return;
        }

        const reader = new FileReader();
        reader.onload = async ev => {
            try {
                // The file contains a base64 string: IV (12 bytes) + ciphertext
                const b64 = ev.target.result.trim();
                const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

                const iv = binary.slice(0, 12);
                const cipher = binary.slice(12);

                const plain = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv },
                    state.cryptoKey,
                    cipher
                );

                const decoded = new TextDecoder().decode(plain);
                const data = JSON.parse(decoded);

                // Replace the current workspace with the decrypted data
                $('#mainContent').innerHTML = '';
                const tempBlob = new Blob([JSON.stringify(data)], { type: 'application/json' });
                await importContext(tempBlob);
                toast('Context decrypted & loaded');
            } catch (e) {
                toast('Decryption failed: ' + e.message, true);
            }
        };
        reader.readAsText(file);
    }

        /* ---------------------------------------------------------
       Login – prompts for credentials, derives encryption key,
       obtains JWT token from the server, and updates UI.
    --------------------------------------------------------- */
    async function login() {
        const login = prompt('Enter your login (email/username):');
        const password = prompt('Enter your password:');
        if (!login || !password) return toast('Login cancelled', true);

        // Derive the client‑side encryption key (used for encrypt/decrypt)
        try {
            state.cryptoKey = await deriveKeyFromPassword(password);
        } catch (e) {
            return toast('Key derivation failed', true);
        }

        // Send credentials to the server (HTTPS in production)
        try {
            const resp = await fetch(`${API_BASE}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ login, password })
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json(); // { token: "…" }
            state.token = data.token;
            localStorage.setItem(TOKEN_KEY, state.token);
            $('#loginBtn').hidden = true;
            $('#logoutBtn').hidden = false;
            toast('Logged in successfully');
        } catch (e) {
            toast('Login failed: ' + e.message, true);
        }
    }

    /* ---------------------------------------------------------
       Logout – clears token, crypto key, and any pending sync timer.
    --------------------------------------------------------- */
    function logout() {
        state.token = null;
        state.cryptoKey = null;
        localStorage.removeItem(TOKEN_KEY);
        if (state.syncTimer) {
            clearTimeout(state.syncTimer);
            state.syncTimer = null;
        }
        $('#loginBtn').hidden = false;
        $('#logoutBtn').hidden = true;
        toast('Logged out');
    }

    /* ---------------------------------------------------------
       Helper to attach Authorization header when we have a token.
    --------------------------------------------------------- */
    function authHeaders() {
        const hdr = { 'Content-Type': 'application/octet-stream' };
        if (state.token) hdr['Authorization'] = `Bearer ${state.token}`;
        return hdr;
    }

    /* ---------------------------------------------------------
   1️⃣ Upload encrypted context (requires auth)
   --------------------------------------------------------- */
async function uploadEncryptedContext(file) {
    if (!state.token) {
        toast('You must be logged in to upload', true);
        return;
    }

    const reader = new FileReader();
    reader.onload = async ev => {
        try {
            const resp = await fetch(`${API_BASE}/context/upload`, {
                method: 'POST',
                headers: authHeaders(),          // includes Authorization bearer token
                body: ev.target.result           // raw base64 string from the file
            });

            if (!resp.ok) {
                throw new Error(`HTTP ${resp.status}`);
            }
            toast('Encrypted context uploaded successfully');
        } catch (err) {
            toast('Upload failed: ' + err.message, true);
        }
    };
    reader.readAsText(file);
}

/* ---------------------------------------------------------
   2️⃣ Download encrypted context (requires auth)
   --------------------------------------------------------- */
async function downloadEncryptedContext() {
    if (!state.token) {
        toast('You must be logged in to download', true);
        return;
    }

    try {
        const resp = await fetch(`${API_BASE}/context/download`, {
            method: 'GET',
            headers: authHeaders()
        });

        if (!resp.ok) {
            if (resp.status === 404) {
                throw new Error('No encrypted context stored for this account');
            }
            throw new Error(`HTTP ${resp.status}`);
        }

        // Server returns a plain‑text base64 string.
        const b64 = await resp.text();

        // Convert the base64 string into a Blob so we can reuse decryptContext().
        const binary = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        const blob = new Blob([binary], { type: 'text/plain' });

        // Feed the blob straight into the decryption routine.
        await decryptContext(blob);
    } catch (err) {
        toast('Download failed: ' + err.message, true);
    }
}

        /* ---------------------------------------------------------
       Auto‑sync – encrypts current workspace and uploads it.
       Called after a debounce (default 2 seconds) whenever a
       “significant” change occurs (field edit, article add/remove, etc.).
    --------------------------------------------------------- */
    async function syncToServer() {
        if (!state.token) {
            console.info('Auto‑sync skipped – not logged in');
            return;
        }
        if (!state.cryptoKey) {
            toast('Missing encryption key – cannot sync', true);
            return;
        }

        const payload = JSON.stringify(collectContext());

        // Skip if nothing changed since last successful sync
        if (payload === state.lastSyncedSnapshot) {
            console.info('Auto‑sync: no changes detected');
            return;
        }

        // Encrypt the payload (same format as manual encrypt)
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const enc = new TextEncoder();
        const cipher = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            state.cryptoKey,
            enc.encode(payload)
        );

        const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(cipher), iv.byteLength);
        const b64 = btoa(String.fromCharCode(...combined));

        // POST to the same endpoint used for manual upload
        try {
            const resp = await fetch(`${API_BASE}/context/upload`, {
                method: 'POST',
                headers: authHeaders(),
                body: b64
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

            // Remember this snapshot as the last successful sync
            state.lastSyncedSnapshot = payload;
            console.info('Auto‑sync succeeded');
        } catch (e) {
            console.error('Auto‑sync failed:', e);
            toast('Auto‑sync failed – will retry on next change', true);
        }
    }

    /* ---------------------------------------------------------
       Debounce wrapper – schedule a sync after `delayMs` ms of
       inactivity (default 2000 ms).
    --------------------------------------------------------- */
    function scheduleSync(delayMs = 2000) {
        if (state.syncTimer) clearTimeout(state.syncTimer);
        state.syncTimer = setTimeout(() => {
            state.syncTimer = null;
            syncToServer();
        }, delayMs);
    }

    /* ---------------------------------------------------------
       Manual “Push to server” button – forces an immediate sync.
    --------------------------------------------------------- */
    async function pushCurrentState() {
        if (!state.token) {
            toast('You must be logged in to push', true);
            return;
        }
        if (state.syncTimer) {
            clearTimeout(state.syncTimer);
            state.syncTimer = null;
        }
        await syncToServer();
        toast('Current state pushed to server');
    }

        /* ---------------------------------------------------------
       Search / filter – matches against label text, placeholder,
       or input name (case‑insensitive). Ancestors of matching
       articles stay visible.
    --------------------------------------------------------- */
    function articleMatchesSearch(articleEl, term) {
        const lowered = term.toLowerCase();
        const inputs = articleEl.querySelectorAll('input');
        for (const inp of inputs) {
            const label = inp.closest('label');
            const labelText = label ? label.textContent.trim().toLowerCase() : '';
            const placeholder = (inp.placeholder || '').toLowerCase();
            const name = (inp.name || '').toLowerCase();
            if (labelText.includes(lowered) ||
                placeholder.includes(lowered) ||
                name.includes(lowered)) {
                return true;
            }
        }
        return false;
    }

    function filterArticles(term) {
        const root = $('#mainContent');
        const allArticles = root.querySelectorAll('article');

        // First pass – direct matches
        const matches = new Map(); // articleEl -> boolean
        allArticles.forEach(a => matches.set(a, articleMatchesSearch(a, term)));

        // Second pass – propagate matches upward so parents stay visible
        function propagate(el) {
            if (!el) return false;
            const direct = matches.get(el);
            const childMatch = Array.from(el.children).some(ch => {
                if (ch.tagName.toLowerCase() === 'article') return propagate(ch);
                return false;
            });
            const keep = direct || childMatch;
            el.style.display = keep ? '' : 'none';
            return keep;
        }

        // Start from top‑level articles
        root.querySelectorAll(':scope > article').forEach(propagate);
    }

    // Debounced input handler
    let searchDebounce = null;
    function applyFilter() {
        const term = $('#searchInput').value.trim();
        if (searchDebounce) clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => filterArticles(term), 150);
    }

        /* ---------------------------------------------------------
       Bind all UI elements once the DOM is ready.
    --------------------------------------------------------- */
    document.addEventListener('DOMContentLoaded', () => {
        // Load persisted data
        loadLibrary();
        renderLibraryList();

        // ----- Auth buttons -------------------------------------------------
        $('#loginBtn').onclick = login;
        $('#logoutBtn').onclick = logout;

        // ----- Context export / import --------------------------------------
        $('#exportBtn').onclick = exportContext;

        // Import file selector (JSON context)
        $('#importFile').onchange = e => {
            const file = e.target.files[0];
            if (file) importContext(file);
            e.target.value = ''; // allow re‑selecting same file later
        };

        // ----- Encryption / decryption --------------------------------------
        $('#encryptBtn').onclick = encryptContext;
        $('#decryptBtn').onclick = async () => {
            const file = await new Promise(resolve => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = '.txt,.enc';
                input.onchange = ev => resolve(ev.target.files[0]);
                input.click();
            });
            if (file) await decryptContext(file);
        };

        // ----- Sync (upload / download) -------------------------------------
        $('#syncUploadBtn').onclick = async () => {
            const file = await new Promise(resolve => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = '.txt,.enc';
                input.onchange = ev => resolve(ev.target.files[0]);
                input.click();
            });
            if (file) await uploadEncryptedContext(file);
        };
        $('#syncDownloadBtn').onclick = downloadEncryptedContext;

        // ----- Manual push button -------------------------------------------
        $('#pushBtn').onclick = pushCurrentState;

        // ----- Search box ---------------------------------------------------
        const searchBox = $('#searchInput');
        if (searchBox) {
            searchBox.addEventListener('input', applyFilter);
        }

        // Initial UI state (login/logout visibility)
        if (state.token) {
            $('#loginBtn').hidden = true;
            $('#logoutBtn').hidden = false;
        } else {
            $('#loginBtn').hidden = false;
            $('#logoutBtn').hidden = true;
        }

        // Generate ads for any pre‑existing content
        generateAdsFromMain();
    });
})();