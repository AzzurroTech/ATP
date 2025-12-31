// config.js – shared constants for the front‑end
export const CONFIG = {
    apiBase: '/api',
    maxUploadSize: 5 << 20,               // 5 MiB
    searchDebounce: 150,                  // ms
    syncDebounce: 2000,                   // ms (auto‑sync)
    tokenKey: 'atp_auth_token',
    libraryKey: 'atp_form_library',
    fieldValuesKey: 'atp_field_values',
    tokenMaxAgeMs: 24 * 60 * 60 * 1000,    // 24 h
};