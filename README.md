# Passman

A local-first desktop password manager built with Rust, Tauri 2, and TypeScript. Passman generates strong passwords and stores credentials in one encrypted vault on this device.

## Features

- Create and unlock a vault with a master password (minimum 12 characters).
- Generate 8–128 character passwords with selectable uppercase, lowercase, number, and symbol sets. Rust uses rejection-sampled operating-system cryptographic randomness.
- Save, search, edit, favorite, copy, and delete login entries.
- Store an optional authenticator setup key with an entry, then generate standards-based six-digit TOTP codes that refresh every 30 seconds.
- Encrypt the vault with XChaCha20-Poly1305; derive a 256-bit key using Argon2id with a random salt.
- Decrypted vault data and the key are held in application memory only while unlocked. Lock the vault or leave it idle for five minutes to clear that state.
- Copied passwords are cleared from the clipboard after 30 seconds when clipboard read-back is permitted.

## Requirements

- Rust stable toolchain and Cargo
- Node.js 20.19+ or 22.12+ and npm
- Tauri's platform prerequisites. On Linux, install the development packages for GTK 3, WebKit2GTK 4.1, librsvg, and build tools for your distribution before compiling.

## Run in development

Install JavaScript dependencies with `npm install`, then start the desktop app with `npm run tauri dev`.

Build a distributable app with `npm run tauri build`.

Run the Rust tests with `cargo test --manifest-path src-tauri/Cargo.toml`. Build and type-check the frontend with `npm run build`.

## Vault storage

The vault is kept in the operating system's per-user application data directory, in a file named `vault.json`. Its salt, nonce, and ciphertext are base64-encoded; saved entry fields are authenticated ciphertext. Every save uses a fresh random XChaCha20-Poly1305 nonce. The temporary write file is atomically renamed after serialization.

## Security notes and limitations

See [SECURITY.md](SECURITY.md) for security best practices, backup guidance, and vulnerability reporting notes.

- This is an MVP for one local vault. It has no sync, browser integration, or multi-user support.
- The master password is not stored and cannot be recovered. If forgotten, use the in-app reset option to delete the vault and start over; existing entries cannot be recovered.
- Use a strong, unique master password. A local attacker with a copy of the vault can attempt offline guesses; Argon2id makes guesses more expensive but does not make weak passwords safe.
- This app has not undergone an independent security audit. Lock your vault when leaving the device unattended, and keep encrypted backups if you need recovery from device loss. Backups remain protected only as strongly as the master password.
- Clipboard clearing is best-effort because desktop clipboard permissions and clipboard managers vary. Other applications may also retain copied content.
- TOTP setup keys are encrypted with the rest of the vault and never shown in entry summaries. The current implementation supports Base32 secrets and six-digit, 30-second HMAC-SHA1 codes; QR-code scanning and custom issuer/algorithm options are not included.
- Add or update an entry before attaching its authenticator. In the entry editor, paste the Base32 setup key under “Authenticator codes”; select the key icon on the saved item to view/copy the current code.
- The interface uses local system font fallbacks and does not need a network connection.
