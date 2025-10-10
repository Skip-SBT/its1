export const HMAC_TAG_BYTES = 32; // SHA-256 output size in bytes

/**
 *  Purpose: Encapsulate HMAC-SHA-256 tag computation and verification.
 */
export async function computeHmacTag(
    data: ArrayBuffer | Uint8Array,
    hmacKey: CryptoKey,
): Promise<Uint8Array> {
    const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
    const tag = await crypto.subtle.sign("HMAC", hmacKey, buf);
    return new Uint8Array(tag);
}

/**
 * Verify HMAC-SHA-256 tag over data using a Web Crypto HMAC key.
 * Returns true if tag matches; false otherwise.
 */
export async function verifyHmacTag(
    expectedTag: ArrayBuffer | Uint8Array,
    data: ArrayBuffer | Uint8Array,
    hmacKey: CryptoKey,
): Promise<boolean> {
    const tag = expectedTag instanceof Uint8Array ? expectedTag : new Uint8Array(expectedTag);
    const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
    return crypto.subtle.verify("HMAC", hmacKey, tag, buf);
}
