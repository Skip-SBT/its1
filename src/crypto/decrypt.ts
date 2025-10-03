import { base64 } from "../utils/base64";
import { encoder, uint32BE, concatBuffers } from "../utils/buffers";
import { deriveEncryptionAndMacKeys } from "./kdf";
import { aesGcmDecrypt, aesCbcDecrypt } from "./aes";
import { pkcs7 } from "./padding";
import { parseContainer } from "./container";
import { verifyHmacTag } from "./hmac";
import { IntegrityError } from "../types/errors";

/**
 * Purpose: High-level decryption orchestration (what the UI calls).
 *
 * Function:
 *  - decryptFileBlob(blob, passphrase)
 *      Steps:
 *       1) Parse container; read header and ciphertext (and mac, if present).
 *       2) Re-derive keys via PBKDF2 using header.kdf.saltBase64.
 *       3) If header.hasMac → verify HMAC over MAGIC||len||header||ciphertext.
 *          - If mismatch → throw IntegrityError.
 *       4) Decrypt:
 *          - GCM → AEAD verify inside decrypt() (throws on tamper/wrong key).
 *          - CBC → decrypt → PKCS#7 unpad.
 *       5) Return { fileName, data:Uint8Array } for download.
 */

export async function decryptFileBlob(blob: Blob, passphrase: string) {
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const { header, ciphertext, macBytes } = parseContainer(bytes);

    const { aesGcmKey, aesCbcKey, hmacKey } = await deriveEncryptionAndMacKeys(passphrase, base64.decode(header.kdf.saltBase64));

    if (header.hasMac) {
        const headerBytes = encoder.encode(JSON.stringify(header));
        const authCore = concatBuffers(new TextEncoder().encode("AESPACK"), uint32BE(headerBytes.byteLength), headerBytes, ciphertext);
        const ok = await verifyHmacTag(macBytes!, authCore, hmacKey);
        if (!ok) throw new IntegrityError("Integrity check failed (HMAC mismatch).");
    }

    if (header.mode === "AES-GCM") {
        const plaintext = await aesGcmDecrypt(ciphertext, header.ivBase64, header.tagLength, aesGcmKey);
        return { fileName: header.originalFileName || "decrypted.bin", data: plaintext };
    }

    // AES-CBC
    const padded = await aesCbcDecrypt(ciphertext, header.ivBase64, aesCbcKey);
    const plaintext = pkcs7.unpad(padded);
    return { fileName: header.originalFileName || "decrypted.bin", data: plaintext };
}
