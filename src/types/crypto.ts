export type AesMode = "AES-GCM" | "AES-CBC";

export type KdfSpec = {
    name: "PBKDF2";
    hash: "SHA-256";
    iterations: number;
    saltBase64: string;
};

export type ContainerHeader = {
    version: number;
    originalFileName: string;
    originalFileSize: number;
    mode: AesMode;
    ivBase64: string;          // 12 bytes for GCM, 16 for CBC
    kdf: KdfSpec;
    tagLength?: number;        // GCM only
    hasMac: boolean;
    mac?: { algo: "HMAC-SHA-256" };
};
