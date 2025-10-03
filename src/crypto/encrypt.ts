import { base64 } from "../utils/base64";
import { FORMAT_VERSION, encoder, uint32BE, concatBuffers } from "../utils/buffers";
import { ContainerHeader, AesMode } from "../types/crypto";
import { deriveEncryptionAndMacKeys } from "./kdf";
import { pkcs7 } from "./padding";
import { aesGcmEncrypt, aesCbcEncrypt } from "./aes";
import { computeHmacTag } from "./hmac";
import { packageContainer } from "./container";

export async function encryptFileBlob(file: File, passphrase: string, mode: AesMode): Promise<Blob> {
    const plaintext = new Uint8Array(await file.arrayBuffer());
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { aesGcmKey, aesCbcKey, hmacKey } = await deriveEncryptionAndMacKeys(passphrase, salt);

    const kdf = { name: "PBKDF2" as const, hash: "SHA-256" as const, iterations: 250000, saltBase64: base64.encode(salt) };
    const common = { version: FORMAT_VERSION, originalFileName: file.name, originalFileSize: plaintext.byteLength, mode, kdf };

    if (mode === "AES-GCM") {
        const { ciphertext, ivBase64, tagLength } = await aesGcmEncrypt(plaintext, aesGcmKey);
        const header: ContainerHeader = { ...common, ivBase64, tagLength, hasMac: false };
        return packageContainer(header, ciphertext);
    }

    // AES-CBC + HMAC
    const padded = pkcs7.pad(plaintext);
    const { ciphertext, ivBase64 } = await aesCbcEncrypt(padded, aesCbcKey);
    const header: ContainerHeader = { ...common, ivBase64, hasMac: true, mac: { algo: "HMAC-SHA-256" } };

    const headerBytes = encoder.encode(JSON.stringify(header));
    const authCore = concatBuffers(
        // replicate pack()'s prefix for MAC coverage: MAGIC + len + header + ciphertext
        new TextEncoder().encode("AESPACK"),
        uint32BE(headerBytes.byteLength),
        headerBytes,
        ciphertext
    );

    const mac = await computeHmacTag(authCore, hmacKey);
    return packageContainer(header, ciphertext, mac);
}
