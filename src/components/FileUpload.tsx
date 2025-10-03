import React from "react";
import { styled } from "@mui/material/styles";
import Button from "@mui/material/Button";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import { Box, Typography } from "@mui/material";

const HiddenInput = styled("input")({
    clip: "rect(0 0 0 0)",
    clipPath: "inset(50%)",
    height: 1,
    overflow: "hidden",
    position: "absolute",
    bottom: 0,
    left: 0,
    whiteSpace: "nowrap",
    width: 1,
});

type Props = {
    file: File | null;
    onFile: (f: File | null) => void;
};

export default function FileUpload({ file, onFile }: Props) {
    return (
        <Box sx={{ m: 2 }}>
            <Button
                fullWidth
                component="label"
                role={undefined}
                variant="contained"
                startIcon={<CloudUploadIcon />}
            >
                {file ? "Replace file" : "Choose file"}
                <HiddenInput
                    type="file"
                    onChange={(e) => onFile(e.target.files && e.target.files[0] ? e.target.files[0] : null)}
                />
            </Button>
            {file && (
                <Box sx={{ mt: 1, display: "flex", alignItems: "center", gap: 2 }}>
                    <Typography variant="body2">
                        Selected: <strong>{file.name}</strong> ({file.size.toLocaleString()} bytes)
                    </Typography>
                    <Button size="small" variant="text" startIcon={<DeleteOutlineIcon />} onClick={() => onFile(null)}>
                        Clear
                    </Button>
                </Box>
            )}
        </Box>
    );
}
