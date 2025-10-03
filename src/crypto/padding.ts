import { PaddingError } from "../types/errors";

/**
 * Purpose: PKCS#7 padding for AES-CBC (WebCrypto doesn't add/remove it for us).
 *
 * Exports:
 *  - pkcs7.pad(plaintextU8): ensures length is a multiple of 16 (adds full block if already aligned).
 *  - pkcs7.unpad(paddedU8): validates and removes PKCS#7 bytes.
 */
export const pkcs7 = {
    pad: (data: Uint8Array) => {
        const block = 16;
        let pad = block - (data.byteLength % block);
        if (pad === 0) pad = block;
        const out = new Uint8Array(data.byteLength + pad);
        out.set(data);
        out.fill(pad, data.byteLength);
        return out;
    },
    unpad: (data: Uint8Array) => {
        if (data.byteLength === 0) throw new PaddingError();
        const pad = data[data.byteLength - 1];
        if (pad < 1 || pad > 16 || pad > data.byteLength) throw new PaddingError();
        for (let i = data.byteLength - pad; i < data.byteLength; i++) if (data[i] !== pad) throw new PaddingError();
        return data.slice(0, data.byteLength - pad);
    },
};
