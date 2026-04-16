# AESPack

**AESPack** is a browser-based AES file encryption and decryption tool. All cryptographic operations run entirely on the client — no file data is ever transmitted to a server.

🔗 **Live demo**: [skip-sbt.github.io/AESPack](https://skip-sbt.github.io/AESPack)

---

## Features

- **AES-GCM** — authenticated encryption with a 128-bit authentication tag; integrity and confidentiality in a single pass.
- **AES-CBC + HMAC-SHA256** — encrypt-then-MAC construction; the HMAC is verified before decryption to prevent padding-oracle attacks.
- **PBKDF2 key derivation** — 250 000 iterations with a cryptographically random 16-byte salt, producing a 256-bit AES key (and a separate 256-bit HMAC key for CBC mode).
- **Portable `.aespack` format** — a self-contained binary container bundling the algorithm identifier, salt, IV, ciphertext, and authentication tag / HMAC into a single downloadable file.
- **Zero server-side processing** — the Web Crypto API handles all cryptographic work inside the browser; nothing leaves the user's device.
- **React 18 + TypeScript** — fully typed component tree with a clean Material UI interface.
- **Webpack + Gulp** — production build pipeline with tree-shaking, asset hashing, and one-command GitHub Pages deployment.
- **CI pipeline (GitHub Actions)** — ESLint, Stylelint, and CSpell run automatically on every push and pull request.

---

## Getting Started

```bash
npm install        # install dependencies
npm start          # start the development server
npm run build:prod # create an optimised production build in /dist
npm run deploy     # build and publish to GitHub Pages
```

---

## Security Design

| Property | Mechanism |
|---|---|
| Confidentiality | AES-256 (GCM or CBC) |
| Authenticity / Integrity | GCM authentication tag **or** HMAC-SHA256 (CBC) |
| Key derivation | PBKDF2-SHA256 — 250 000 iterations, 128-bit random salt |
| IV / Nonce | 96-bit random (GCM) · 128-bit random (CBC) |
| Padding | PKCS#7 (CBC only) |

---

## Project Structure

```
src/
├── App.tsx                  # Root UI component
├── components/
│   ├── EncryptionDropdown   # AES mode selector (GCM / CBC)
│   ├── FileUpload           # Drag-and-drop / click file input
│   └── UserKeyInput         # Passphrase field
├── crypto/
│   ├── aes.ts               # AES-GCM and AES-CBC encrypt/decrypt
│   ├── container.ts         # .aespack binary format (pack / unpack)
│   ├── decrypt.ts           # High-level decrypt orchestration
│   ├── encrypt.ts           # High-level encrypt orchestration
│   ├── hmac.ts              # HMAC-SHA256 sign / verify
│   ├── kdf.ts               # PBKDF2 key derivation
│   └── padding.ts           # PKCS#7 pad / unpad
├── hooks/
│   └── useEncryptor.ts      # React hook wiring crypto to UI state
├── types/
│   └── crypto.ts            # Shared TypeScript types
└── utils/
    └── download.ts          # Blob → browser download helper
```

---

## CI Workflow

The GitHub Actions pipeline runs on every push or pull request to `main`, `live`, or `testing`:

| Step | Command |
|---|---|
| Install dependencies | `npm ci` |
| Lint TypeScript / JSX | `npm run check:eslint` |
| Lint CSS / SCSS | `npm run check:stylelint` |
| Spellcheck | `npm run check:spellcheck` |

To adjust linting rules or add accepted words to the spellcheck dictionary, edit `eslint.config.mjs`, `.stylelintrc.cjs`, or `cspell.json`.

---

## Deployment

```bash
npm run deploy
```

This builds the project in production mode and publishes the `/dist` output to the `gh-pages` branch. Make sure GitHub Pages is enabled in your repository settings and pointed at the `gh-pages` branch.

---

## Tech Stack

React · TypeScript · Material UI · Web Crypto API · Webpack · Gulp · GitHub Actions · GitHub Pages

