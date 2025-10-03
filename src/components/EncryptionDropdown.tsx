import React from "react";
import { FormControl, InputLabel, MenuItem, Select, SelectChangeEvent } from "@mui/material";

export type AesMode = "AES-GCM" | "AES-CBC";

type Props = {
    mode: AesMode;
    onChange: (m: AesMode) => void;
};

export default function EncryptionDropdown({ mode, onChange }: Props) {
    const handleChange = (event: SelectChangeEvent) => onChange(event.target.value as AesMode);

    return (
        <FormControl fullWidth sx={{ m: 2 }}>
            <InputLabel id="enc-mode-label">AES mode</InputLabel>
            <Select labelId="enc-mode-label" value={mode} label="AES mode" onChange={handleChange}>
                <MenuItem value="AES-GCM">AES-GCM</MenuItem>
                <MenuItem value="AES-CBC">AES-CBC + HMAC</MenuItem>
            </Select>
        </FormControl>
    );
}
