/**
 * Purpose: Derive encryption and MAC keys from the user passphrase (PBKDF2).
 */

export async function deriveEncryptionAndMacKeys(passphrase: string, saltBytes: Uint8Array) {
    const te = new TextEncoder();
    const passphraseKey = await crypto.subtle.importKey("raw", te.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        {name: "PBKDF2", salt: saltBytes, iterations: 250_000, hash: "SHA-256"},
        passphraseKey,
        512,
    );
    const derived = new Uint8Array(bits);
    const aesKeyBytes = derived.slice(0, 32);
    const hmacKeyBytes = derived.slice(32);

    return {
        aesGcmKey: await crypto.subtle.importKey("raw", aesKeyBytes, "AES-GCM", false, ["encrypt", "decrypt"]),
        aesCbcKey: await crypto.subtle.importKey("raw", aesKeyBytes, "AES-CBC", false, ["encrypt", "decrypt"]),
        hmacKey: await crypto.subtle.importKey("raw", hmacKeyBytes, {
            name: "HMAC",
            hash: "SHA-256",
        }, false, ["sign", "verify"]),
    };
}
