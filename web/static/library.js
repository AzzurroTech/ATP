import { CONFIG } from './config.js';
import { renderLibraryList, addInputRow } from './workspace.js';
import { toast } from './workspace.js'; // reuse toast from workspace

// Load / save library (templates) from localStorage
export function loadLibrary() {
    const raw = localStorage.getItem(CONFIG.libraryKey);
    if (raw) {
        try {
            return JSON.parse(raw);
        } catch (_) {
            return [];
        }
    }
    return [];
}
export function saveLibrary(library) {
    localStorage.setItem(CONFIG.libraryKey, JSON.stringify(library));
}

// Initialize library UI (called once on page load)
export function initLibraryUI(state) {
    // Populate the saved template list
    renderLibraryList(state.library);

    // Library form submit – create a new template
    const libForm = document.getElementById('libraryForm');
    libForm.addEventListener('submit', e => {
        e.preventDefault();
        const name = document.getElementById('libName').value.trim();
        if (!name) return toast('Template name required', true);

        const rows = document.querySelectorAll('#inputsFieldset .input-row');
        const inputs = Array.from(rows).map(r => ({
            label: r.children[0].value.trim(),
            type:  r.children[1].value,
            name:  r.children[2].value.trim()
        }));

        state.library.push({ name, inputs });
        saveLibrary(state.library);
        renderLibraryList(state.library);
        libForm.reset();
        document.getElementById('inputsFieldset').innerHTML = '';
        toast('Template saved');
    });

    // Add‑input button
    document.getElementById('addInputBtn')
            .addEventListener('click', () => addInputRow(document.getElementById('inputsFieldset')));
}