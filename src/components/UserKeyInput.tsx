import React from "react";
import { TextField, InputAdornment, IconButton, Tooltip, LinearProgress, Box } from "@mui/material";
import { Visibility, VisibilityOff } from "@mui/icons-material";

type Props = {
    passphrase: string;
    onChange: (v: string) => void;
};

export default function UserKeyInput({ passphrase, onChange }: Props) {
    const [show, setShow] = React.useState(false);

    return (
        <Box sx={{ m: 2, width: "100%" }}>
            <TextField
                fullWidth
                label="Passphrase"
                value={passphrase}
                onChange={(e) => onChange(e.target.value)}
                type={show ? "text" : "password"}
                InputProps={{
                    endAdornment: (
                        <InputAdornment position="end">
                            <Tooltip title={show ? "Hide" : "Show"}>
                                <IconButton onClick={() => setShow((s) => !s)} edge="end">
                                    {show ? <VisibilityOff /> : <Visibility />}
                                </IconButton>
                            </Tooltip>
                        </InputAdornment>
                    ),
                }}
            />
        </Box>
    );
}
