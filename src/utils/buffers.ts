export const encoder = new TextEncoder();
export const decoder = new TextDecoder();

export const FILE_MAGIC = encoder.encode("AESPACK");
export const FORMAT_VERSION = 1;

export const uint32BE = (value: number) => {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, value, false);
    return buf;
};

export const concatBuffers = (...buffers: (ArrayBuffer | Uint8Array)[]) => {
    const arrays = buffers.map(b => b instanceof Uint8Array ? b : new Uint8Array(b));
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.byteLength, 0));
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.byteLength; }
    return out.buffer;
};

export const constantTimeEqual = (a: Uint8Array, b: Uint8Array) =>
    a.byteLength === b.byteLength && !a.some((v, i) => v ^ b[i]);
