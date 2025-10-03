import { ContainerHeader } from "../types/crypto";
import { FILE_MAGIC, encoder, decoder, uint32BE, concatBuffers, constantTimeEqual } from "../utils/buffers";
import { HMAC_TAG_BYTES } from "./hmac";
import { FormatError } from "../types/errors";

/**
 * Purpose: Self-contained .aespack container read/write (format boundary).
 *
 * Guarantees:
 *  - Validates magic and minimum structure.
 *  - Leaves integrity/auth decisions to HMAC/AEAD layers.
 */

export function packageContainer(header: ContainerHeader, ciphertext: ArrayBuffer, mac?: ArrayBuffer) {
    const headerBytes = encoder.encode(JSON.stringify(header));
    const core = concatBuffers(FILE_MAGIC, uint32BE(headerBytes.byteLength), headerBytes, ciphertext);
    return new Blob([mac ? concatBuffers(core, mac) : core], { type: "application/octet-stream" });
}

export function parseContainer(data: Uint8Array) {
    if (data.byteLength < FILE_MAGIC.byteLength + 4) throw new FormatError("File too short");
    if (!constantTimeEqual(data.slice(0, FILE_MAGIC.byteLength), new Uint8Array(FILE_MAGIC)))
        throw new FormatError("Not an AESPACK file");

    const headerLength = new DataView(data.buffer, FILE_MAGIC.byteLength, 4).getUint32(0, false);
    const headerStart = FILE_MAGIC.byteLength + 4;
    const headerEnd = headerStart + headerLength;
    const headerJson = decoder.decode(data.slice(headerStart, headerEnd));
    const header = JSON.parse(headerJson) as ContainerHeader;

    const macLength = header.hasMac ? HMAC_TAG_BYTES : 0;
    if (data.byteLength < headerEnd + macLength) throw new FormatError("Corrupted file");

    const ciphertext = data.slice(headerEnd, data.byteLength - macLength);
    const macBytes = macLength ? data.slice(data.byteLength - macLength) : null;

    return { header, ciphertext, macBytes };
}
