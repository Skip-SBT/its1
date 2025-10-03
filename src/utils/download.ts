export function downloadBlob(data: Blob, filename: string) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(data);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
}
