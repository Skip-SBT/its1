import React from "react";
import { Box, Button, Container, Stack, Typography, Alert } from "@mui/material";
import EncryptionDropdown, { AesMode } from "./components/EncryptionDropdown";
import UserKeyInput from "./components/UserKeyInput";
import FileUpload from "./components/FileUpload";

// ---------- small helpers ----------
const te = new TextEncoder();
const td = new TextDecoder();

const MAGIC = te.encode("AESPACK"); // 7 bytes
const VERSION = 1;

const toB64 = (a: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...Array.from(new Uint8Array(a instanceof Uint8Array ? a : new Uint8Array(a)))));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const concat = (...bufs: (ArrayBuffer | Uint8Array)[]) => {
    const total = bufs.reduce((n, b) => n + (b instanceof Uint8Array ? b.byteLength : b.byteLength), 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const b of bufs) {
        const u = b instanceof Uint8Array ? b : new Uint8Array(b);
        out.set(u, off);
        off += u.byteLength;
    }
    return out.buffer;
};

const u32 = (n: number) => {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, n, false); // big endian
    return b;
};

const eqConst = (a: Uint8Array, b: Uint8Array) => {
    if (a.byteLength !== b.byteLength) return false;
    let v = 0;
    for (let i = 0; i < a.byteLength; i++) v |= a[i] ^ b[i];
    return v === 0;
};

// PKCS#7 for CBC (16-byte block)
const pkcs7Pad = (plain: Uint8Array) => {
    const bs = 16;
    const padLen = bs - (plain.byteLength % bs || bs);
    const out = new Uint8Array(plain.byteLength + padLen);
    out.set(plain);
    out.fill(padLen, plain.byteLength);
    return out;
};
const pkcs7Unpad = (buf: Uint8Array) => {
    if (buf.byteLength === 0) throw new Error("Invalid padding");
    const pad = buf[buf.byteLength - 1];
    if (pad === 0 || pad > 16 || pad > buf.byteLength) throw new Error("Invalid padding");
    for (let i = buf.byteLength - pad; i < buf.byteLength; i++) if (buf[i] !== pad) throw new Error("Invalid padding");
    return buf.slice(0, buf.byteLength - pad);
};

// ---------- KDF: PBKDF2 -> 64 bytes -> split keys ----------
async function deriveKeys(passphrase: string, salt: Uint8Array) {
    const passRaw = te.encode(passphrase);
    const baseKey = await crypto.subtle.importKey("raw", passRaw, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt, iterations: 250_000, hash: "SHA-256" },
        baseKey,
        512 // 64 bytes
    );
    const full = new Uint8Array(bits);
    const encBytes = full.slice(0, 32);
    const macBytes = full.slice(32);
    const encKey = await crypto.subtle.importKey("raw", encBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    const cbcKey = await crypto.subtle.importKey("raw", encBytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
    const macKey = await crypto.subtle.importKey("raw", macBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    return { encKeyGcm: encKey, encKeyCbc: cbcKey, macKey };
}

// ---------- Encrypt ----------
async function encryptFile(file: File, passphrase: string, mode: AesMode): Promise<Blob> {
    const plain = new Uint8Array(await file.arrayBuffer());
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { encKeyGcm, encKeyCbc, macKey } = await deriveKeys(passphrase, salt);

    const headerCommon: any = {
        version: VERSION,
        originalName: file.name,
        originalSize: plain.byteLength,
        mode,
        kdf: { name: "PBKDF2", hash: "SHA-256", iterations: 250000, saltB64: toB64(salt) },
    };

    let ciphertext: ArrayBuffer;
    let header: any;

    if (mode === "AES-GCM") {
        let iv = crypto.getRandomValues(new Uint8Array(12));
        ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, tagLength: 128 }, encKeyGcm, plain);
        header = { ...headerCommon, ivB64: toB64(iv), tagLength: 128, hasMac: false };
        // package: MAGIC | u32(len) | header | ciphertext
        const headerBytes = te.encode(JSON.stringify(header));
        const packed = concat(MAGIC, u32(headerBytes.byteLength), headerBytes, ciphertext);
        return new Blob([packed], { type: "application/octet-stream" });
    } else {
        // AES-CBC + HMAC
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const padded = pkcs7Pad(plain);
        ciphertext = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, encKeyCbc, padded);
        header = { ...headerCommon, ivB64: toB64(iv), hasMac: true, mac: { algo: "HMAC-SHA-256" } };

        const headerBytes = te.encode(JSON.stringify(header));
        const core = concat(MAGIC, u32(headerBytes.byteLength), headerBytes, ciphertext);
        const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, core));
        const packed = concat(core, mac.buffer);
        return new Blob([packed], { type: "application/octet-stream" });
    }
}

// ---------- Decrypt ----------
async function decryptBlob(blob: Blob, passphrase: string): Promise<{ fileName: string; data: Uint8Array }> {
    const buf = new Uint8Array(await blob.arrayBuffer());

    // parse MAGIC
    if (buf.byteLength < MAGIC.byteLength + 4) throw new Error("File too short");
    if (!eqConst(buf.slice(0, MAGIC.byteLength), new Uint8Array(MAGIC))) throw new Error("Not an AESPACK file");

    const dv = new DataView(buf.buffer, MAGIC.byteLength, 4);
    const headerLen = dv.getUint32(0, false);
    const headerStart = MAGIC.byteLength + 4;
    const headerEnd = headerStart + headerLen;
    const headerJson = td.decode(buf.slice(headerStart, headerEnd));
    const header = JSON.parse(headerJson);

    const salt = fromB64(header.kdf.saltB64);
    const { encKeyGcm, encKeyCbc, macKey } = await deriveKeys(passphrase, salt);

    // ciphertext and optional mac
    let ctStart = headerEnd;
    let ctEnd = buf.byteLength;
    let mac: Uint8Array | null = null;

    if (header.hasMac) {
        if (buf.byteLength < headerEnd + 32) throw new Error("Corrupted file");
        mac = buf.slice(buf.byteLength - 32);
        ctEnd = buf.byteLength - 32;
        const core = buf.slice(0, ctEnd);
        // Validation
        const good = await crypto.subtle.verify("HMAC", macKey, mac, core);
        if (!good) throw new Error("Integrity check failed (HMAC mismatch). File was modified or passphrase is wrong.");
    }

    const ciphertext = buf.slice(ctStart, ctEnd);

    if (header.mode === "AES-GCM") {
        const iv = fromB64(header.ivB64);
        const plain = new Uint8Array(
            await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: header.tagLength || 128 }, encKeyGcm, ciphertext)
        );
        return { fileName: header.originalName || "decrypted.bin", data: plain };
    } else if (header.mode === "AES-CBC") {
        const iv = fromB64(header.ivB64);
        const padded = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, encKeyCbc, ciphertext));
        const plain = pkcs7Unpad(padded);
        return { fileName: header.originalName || "decrypted.bin", data: plain };
    } else {
        throw new Error("Unsupported mode in header");
    }
}

// ---------- UI ----------
export default function App() {
    const [file, setFile] = React.useState<File | null>(null);
    const [mode, setMode] = React.useState<AesMode>("AES-GCM");
    const [passphrase, setPassphrase] = React.useState("");
    const [msg, setMsg] = React.useState<string | null>(null);
    const [err, setErr] = React.useState<string | null>(null);

    const download = (data: Blob, name: string) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(data);
        a.download = name;
        a.click();
        URL.revokeObjectURL(a.href);
    };

    const onEncrypt = async () => {
        setErr(null);
        setMsg(null);
        try {
            if (!file) throw new Error("Select a file first.");
            if (!passphrase) throw new Error("Enter a passphrase.");
            const out = await encryptFile(file, passphrase, mode);
            const outName = `${file.name}.aespack`;
            download(out, outName);
            setMsg(
                `Encrypted (${mode}). New random salt/IV used ⇒ re-encrypting will produce a different ciphertext each time.`
            );
        } catch (e: any) {
            setErr(e.message || String(e));
        }
    };

    const onDecrypt = async () => {
        setErr(null);
        setMsg(null);
        try {
            if (!file) throw new Error("Select an .aespack file first.");
            if (!passphrase) throw new Error("Enter a passphrase.");
            const { fileName, data } = await decryptBlob(file, passphrase);
            const out = new Blob([data], { type: "application/octet-stream" });
            download(out, `DECRYPTED_${fileName}`);
            setMsg("Decryption successful. Integrity verified.");
        } catch (e: any) {
            setErr(e.message || String(e));
        }
    };

    return (
        <Container maxWidth="md" sx={{ py: 4 }}>
            <Typography variant="h4" gutterBottom>AES File Encryptor / Decryptor</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Modes: AES-GCM (AEAD) or AES-CBC with HMAC. Keys derived with PBKDF2 (250k iters + salt). Packaged as a single portable .aespack file.
            </Typography>

            <EncryptionDropdown mode={mode} onChange={setMode} />
            <UserKeyInput passphrase={passphrase} onChange={setPassphrase} />
            <FileUpload file={file} onFile={setFile} />

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ m: 2 }}>
                <Button variant="contained" onClick={onEncrypt} disabled={!file || !passphrase}>
                    Encrypt → Download
                </Button>
                <Button variant="outlined" onClick={onDecrypt} disabled={!file || !passphrase}>
                    Decrypt → Download
                </Button>
            </Stack>

            {msg && <Alert severity="success" sx={{ mt: 2 }}>{msg}</Alert>}
            {err && <Alert severity="error" sx={{ mt: 2 }}>{err}</Alert>}
        </Container>
    );
}
