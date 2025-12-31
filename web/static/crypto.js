// crypto.js – client‑side key derivation, encrypt, decrypt
import { CONFIG } from './config.js';
import { toast } from './utils.js';

/* ---------------------------------------------------------
   deriveKeyFromPassword(pw)
   – PBKDF2 (200 k iterations) → AES‑GCM‑256 key.
   – Uses a per‑user random salt stored in the user record.
   – For the demo we generate a static salt; in production replace
     with a per‑user salt retrieved from the server.
--------------------------------------------------------- */
export async function deriveKeyFromPassword(pw) {
    const enc = new TextEncoder();
    // NOTE: In a real product you would fetch the per‑user salt from the server.
    // Here we use a static demo salt.
    const salt = enc.encode('atp-static-salt');
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

/* ---------------------------------------------------------
   encryptData(plainText, cryptoKey)
   – Returns a base64 string containing IV + ciphertext.
--------------------------------------------------------- */
export async function encryptData(plainText, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const cipher = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        enc.encode(plainText)
    );

    const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipher), iv.byteLength);
    return btoa(String.fromCharCode(...combined));
}

/* ---------------------------------------------------------
   decryptData(base64Payload, cryptoKey)
   – Returns the decrypted UTF‑8 string.
--------------------------------------------------------- */
export async function decryptData(base64Payload, cryptoKey) {
    const binary = Uint8Array.from(atob(base64Payload), c => c.charCodeAt(0));
    const iv = binary.slice(0, 12);
    const cipher = binary.slice(12);
    const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        cipher
    );
    return new TextDecoder().decode(plain);
}