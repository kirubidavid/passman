# Passman

A local-first desktop password manager built with Rust, Tauri 2, and TypeScript. Passman generates strong passwords and stores credentials in one encrypted vault on this device.

## Features

- Create and unlock a vault with a master password (minimum 12 characters).
- Generate 8–128 character passwords with selectable uppercase, lowercase, number, and symbol sets. Rust uses rejection-sampled operating-system cryptographic randomness.
- Save, search, edit, favorite, copy, and delete login entries.
- Store an optional authenticator setup key with an entry, then generate standards-based six-digit TOTP codes that refresh every 30 seconds.
- Export and restore portable encrypted backups without exposing decrypted vault contents to the frontend.
- Change the master password by verifying the current password and re-encrypting the vault with a fresh random salt.
- Encrypt the vault with XChaCha20-Poly1305; derive a 256-bit key using Argon2id with a random salt.
- Decrypted vault data and the key are held in application memory only while unlocked. The configurable auto-lock timeout defaults to five minutes and is checked again after window focus, visibility, suspend/resume, and supported workstation-lock transitions.
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

## Backups and master-password changes

Open **Vault settings** from the sidebar to export a `.passman` backup to the operating system's Downloads folder, restore an exported backup, or change the master password.

- An exported backup is a newly encrypted snapshot containing the vault salt, a fresh nonce, and authenticated ciphertext. Decrypted entries and keys are never sent to the frontend or written to the backup.
- A backup remains protected by the master password that was active when it was exported. Changing the current vault's master password does not change existing backup passwords.
- Restoring requires the backup's master password. The frontend reads only the encrypted backup envelope; Passman decrypts and validates it in Rust before replacing the active vault, then writes the restored data with a fresh nonce.
- Changing the master password verifies the current password, generates a fresh random salt, derives a new key, and re-encrypts the vault. The previous master password no longer unlocks the active vault.

Keep backup files in a separate, access-controlled location. Their security still depends on the strength of the master password that protects them.

## Security notes and limitations

See [SECURITY.md](SECURITY.md) for security best practices, backup guidance, and vulnerability reporting notes.

- This is an MVP for one local vault. It has no sync, browser integration, or multi-user support.
- The master password is not stored and cannot be recovered. If forgotten, use the in-app reset option to delete the vault and start over; existing entries cannot be recovered.
- Use a strong, unique master password. A local attacker with a copy of the vault can attempt offline guesses; Argon2id makes guesses more expensive but does not make weak passwords safe.
- This app has not undergone an independent security audit. Lock your vault when leaving the device unattended, and keep encrypted backups in a separate location if you need recovery from device loss. Backups remain protected only as strongly as their master passwords.
- Clipboard clearing is best-effort because desktop clipboard permissions and clipboard managers vary. Other applications may also retain copied content.
- TOTP setup keys are encrypted with the rest of the vault and never shown in entry summaries. The current implementation supports Base32 secrets and six-digit, 30-second HMAC-SHA1 codes; QR-code scanning and custom issuer/algorithm options are not included.
- Add or update an entry before attaching its authenticator. In the entry editor, paste the Base32 setup key under “Authenticator codes”; select the key icon on the saved item to view/copy the current code.
- The interface uses local system font fallbacks and does not need a network connection.
