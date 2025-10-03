import { base64 } from "../utils/base64";
import { encoder, uint32BE, concatBuffers } from "../utils/buffers";
import { deriveEncryptionAndMacKeys } from "./kdf";
import { aesGcmDecrypt, aesCbcDecrypt } from "./aes";
import { pkcs7 } from "./padding";
import { parseContainer } from "./container";
import { verifyHmacTag } from "./hmac";
import { IntegrityError } from "../types/errors";

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
