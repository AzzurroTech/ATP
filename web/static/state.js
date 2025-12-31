// -----------------------------------------------------------
// Shared mutable state (singleton)
// -----------------------------------------------------------
export const state = {
    library: [],               // [{name, inputs:[{label,type,name}]}]
    token: localStorage.getItem('atp_auth_token') || null,
    cryptoKey: null,           // derived from password (AES‑GCM)
    articleSeq: 0,             // incremental id for <article>
    syncTimer: null,           // debounce timer for auto‑sync
    lastSyncedSnapshot: '',    // JSON string of last successful sync
    fieldValueMap: {}          // { "<articleId>|<fieldName>": "value" }
};