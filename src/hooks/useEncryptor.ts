import React from "react";
import { encryptFileBlob } from "../crypto/encrypt";
import { decryptFileBlob } from "../crypto/decrypt";
import type { AesMode } from "../types/crypto";

export function useEncryptor() {
    const [success, setSuccess] = React.useState<string | null>(null);
    const [error, setError] = React.useState<string | null>(null);

    const encrypt = async (file: File, passphrase: string, mode: AesMode) => {
        setSuccess(null); setError(null);
        try {
            const out = await encryptFileBlob(file, passphrase, mode);
            setSuccess(`Encrypted with ${mode}. Fresh salt & IV ensure different ciphertext each time.`);
            return out;
        } catch (e: any) { setError(e.message || String(e)); throw e; }
    };

    const decrypt = async (file: File, passphrase: string) => {
        setSuccess(null); setError(null);
        try {
            const result = await decryptFileBlob(file, passphrase);
            setSuccess("Decryption successful. Integrity verified.");
            return result;
        } catch (e: any) { setError(e.message || String(e)); throw e; }
    };

    return { encrypt, decrypt, success, error, setSuccess, setError };
}
