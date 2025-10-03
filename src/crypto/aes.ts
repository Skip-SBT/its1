import { base64 } from "../utils/base64";
/**
 * Purpose: Thin AES wrappers (Web Crypto) to keep modes clean
 */

export async function aesGcmEncrypt(plaintext: Uint8Array, key: CryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, plaintext);
    return { ciphertext: ct, ivBase64: base64.encode(iv), tagLength: 128 as const };
}

export async function aesGcmDecrypt(ciphertext: Uint8Array, ivBase64: string, tagLength: number | undefined, key: CryptoKey) {
    const iv = base64.decode(ivBase64);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: tagLength ?? 128 }, key, ciphertext);
    return new Uint8Array(pt);
}

export async function aesCbcEncrypt(plaintextPadded: Uint8Array, key: CryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, plaintextPadded);
    return { ciphertext: ct, ivBase64: base64.encode(iv) };
}

export async function aesCbcDecrypt(ciphertext: Uint8Array, ivBase64: string, key: CryptoKey) {
    const iv = base64.decode(ivBase64);
    const pt = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
    return new Uint8Array(pt);
}
