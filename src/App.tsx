import React from "react";
import { Button, Container, Stack, Typography, Alert } from "@mui/material";
import EncryptionDropdown from "./components/EncryptionDropdown";
import UserKeyInput from "./components/UserKeyInput";
import FileUpload from "./components/FileUpload";
import { useEncryptor } from "./hooks/useEncryptor";
import { downloadBlob } from "./utils/download";
import type { AesMode } from "./types/crypto";

export default function App() {
    const [file, setFile] = React.useState<File | null>(null);
    const [mode, setMode] = React.useState<AesMode>("AES-GCM");
    const [passphrase, setPassphrase] = React.useState("");
    const { encrypt, decrypt, success, error, setSuccess, setError } = useEncryptor();

    const handleEncrypt = async () => {
        setSuccess(null); setError(null);
        if (!file) return setError("No file selected.");
        if (!passphrase) return setError("No passphrase entered.");
        const out = await encrypt(file, passphrase, mode);
        downloadBlob(out, `${file.name}.aespack`);
    };

    const handleDecrypt = async () => {
        setSuccess(null); setError(null);
        if (!file) return setError("No .aespack file selected.");
        if (!passphrase) return setError("No passphrase entered.");
        const { fileName, data } = await decrypt(file, passphrase);
        downloadBlob(new Blob([data], { type: "application/octet-stream" }), `DECRYPTED_${fileName}`);
    };

    return (
        <Container maxWidth="md" sx={{ py: 4 }}>
            <Typography variant="h4" gutterBottom>AES File Encryptor / Decryptor</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                AES-GCM (authenticated) or AES-CBC + HMAC. PBKDF2 (250k iterations + salt). Portable .aespack.
            </Typography>

            <EncryptionDropdown mode={mode} onChange={setMode} />
            <UserKeyInput passphrase={passphrase} onChange={setPassphrase} />
            <FileUpload file={file} onFile={setFile} />

            <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ m: 2 }}>
                <Button variant="contained" onClick={handleEncrypt} disabled={!file || !passphrase}>Encrypt → Download</Button>
                <Button variant="outlined" onClick={handleDecrypt} disabled={!file || !passphrase}>Decrypt → Download</Button>
            </Stack>

            {success && <Alert severity="success" sx={{ mt: 2 }}>{success}</Alert>}
            {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </Container>
    );
}
