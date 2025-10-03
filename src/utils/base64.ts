export const base64 = {
    encode: (data: ArrayBuffer | Uint8Array) =>
        btoa(String.fromCharCode(...Array.from(new Uint8Array(data instanceof Uint8Array ? data : new Uint8Array(data))))),
    decode: (str: string) => Uint8Array.from(atob(str), c => c.charCodeAt(0)),
};
