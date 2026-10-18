# Passman

A local-first desktop password manager built with Rust, Tauri 2, and TypeScript. Passman generates strong passwords and stores credentials in one encrypted vault on this device.

## Features

- Create and unlock a vault with a master password (minimum 12 characters).
- Generate 8–128 character passwords with selectable uppercase, lowercase, number, and symbol sets. Rust uses rejection-sampled operating-system cryptographic randomness.
- Save, search, edit, favorite, copy, and delete login entries.
- Track password age independently from other entry edits, with green, yellow, and red indicators based on a configurable global limit that defaults to 90 days. Legacy entries remain marked **Age unknown** until their password changes; their last-updated date is shown only as an estimate alongside the encrypted migration timestamp that records when tracking began.
- Review password health with Rust-only exact duplicate detection, offline zxcvbn strength scoring, issue counts, clear text labels, and urgency sorting. Password values are not included in frontend summaries.
- Store an optional authenticator setup key with an entry, then generate standards-based six-digit TOTP codes that refresh every 30 seconds.
- Export and restore portable encrypted backups through native save/open dialogs without exposing decrypted vault contents or backup file contents to the frontend.
- Change the master password by verifying the current password and re-encrypting the vault with a fresh random salt.
- Reset an unlocked vault only after Rust verifies the current master password, with an option to create one final encrypted backup first.
- Recover from a forgotten master password through a separate destructive reset that requires typing `RESET VAULT`, which Rust verifies again before deletion.
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

Use the repository scripts for reproducible local and CI checks:

- `npm test` builds the frontend, runs the Vitest frontend behavior suite, and runs the Rust test suite.
- `npm run test:frontend` runs the frontend auto-lock, modal cleanup, clipboard, search, and error-path tests in a DOM environment.
- `npm run lint` runs Biome on the frontend and Clippy with warnings treated as errors on the Rust backend.
- `npm run format` formats frontend files with Biome and Rust files with rustfmt.
- The `test:rust`, `lint:frontend`, `lint:rust`, `format:frontend`, and `format:rust` scripts can run each surface independently.
- GitHub Actions runs frontend tests, the TypeScript production build, Biome, rustfmt, Clippy, and Rust tests on both Ubuntu and Windows. After those checks pass, Windows builds the enterprise MSI as `passman-enterprise-msi`, and Ubuntu builds the portable AppImage as `passman-linux-appimage`.
- Windows release builds use `tauri.windows.conf.json` to produce MSI packages only; NSIS is not generated.
- Linux release builds use `tauri.linux.conf.json` to produce AppImage packages only; DEB and RPM packages are not generated.

## Code structure

The TypeScript entrypoint in `src/main.ts` only coordinates application startup and lifecycle behavior:

- `vault-api.ts` contains typed Tauri command wrappers.
- `state.ts` owns unlocked UI state and auto-lock scheduling.
- `clipboard.ts` owns timed clipboard clearing.
- `modal.ts` owns entry, TOTP, backup, and vault-settings dialogs.
- `generator.ts` owns password generation UI behavior.
- `rendering.ts` owns authentication, dashboard, filtering, and entry-list rendering.
- `ui.ts` contains shared DOM, icon, escaping, toast, and error helpers.

The Rust entrypoint in `src-tauri/src/lib.rs` only assembles Tauri state and commands:

- `models.rs` defines encrypted-vault and command response models.
- `crypto.rs` owns Argon2id derivation and XChaCha20-Poly1305 sealing/opening.
- `persistence.rs` owns vault paths, atomic writes, and encrypted-file loading.
- `totp.rs` owns Base32 secret handling and TOTP generation.
- `commands.rs` validates command input, coordinates the other backend modules, and applies persisted mutations through revision-checked transactions.

## Vault storage

The vault is kept in the operating system's per-user application data directory, in a file named `vault.json`. Its salt, nonce, and ciphertext are base64-encoded; saved entries and vault preferences are authenticated ciphertext. The password-age limit travels with the encrypted vault and its backups, while auto-lock remains a device-specific setting in local application storage. Older vaults whose encrypted payload contains only an entry array load with the default 90-day password-age limit and migrate to the structured payload when age metadata is initialized or the vault is next saved. On the first unlock after password-age tracking is introduced, entries without a recorded password-change date receive an encrypted migration timestamp and the vault is atomically re-encrypted. Their previous `updatedAt` value remains available only as a clearly labeled age estimate until the password itself changes. Version 2 vault envelopes also record the key-derivation algorithm, Argon2 version, memory cost, iteration count, parallelism, and output length. This lets supported Argon2id parameter sets coexist and allows future parameter upgrades without making older vaults unreadable. Version 1 vaults remain compatible through their original fixed Argon2id settings, and imported parameters are bounded before key derivation to prevent excessive resource use. Every save uses a fresh random XChaCha20-Poly1305 nonce. The temporary write file is atomically renamed after serialization.

Vault mutations clone the unlocked snapshot while briefly holding the state mutex, then release it before encryption and atomic disk persistence. A dedicated mutation gate orders writers, and an in-memory revision counter must still match before the persisted candidate becomes the active state. Failed persistence and stale candidates leave the active in-memory vault unchanged.

## Backups and master-password changes

Open **Vault settings** from the sidebar to export a `.passman` backup to a destination you choose, restore an exported backup, or change the master password. Native dialogs filter for `.passman` files, and the save dialog warns before replacing an existing backup.

- An exported backup is a newly encrypted snapshot containing the vault salt, a fresh nonce, and authenticated ciphertext for entries and vault preferences. Decrypted entries and keys are never sent to the frontend or written to the backup.
- A backup remains protected by the master password that was active when it was exported. Changing the current vault's master password does not change existing backup passwords.
- Restoring requires the backup's master password. Rust opens and size-checks the selected backup directly before reading, decrypting, and validating it; backup bytes never pass through JavaScript. The active vault is replaced only after validation, then written with a fresh nonce.
- Changing the master password verifies the current password, generates a fresh random salt, derives a new key, and re-encrypts the vault. The previous master password no longer unlocks the active vault.
- Resetting from Vault Settings verifies the current master password in Rust. The final-backup option is enabled by default; cancelling or failing that backup leaves the vault intact.
- If the master password is forgotten, the lock screen offers a separate recovery reset. It cannot create a usable new backup because the vault cannot be decrypted, and Rust requires the exact phrase `RESET VAULT` before deletion.

Keep backup files in a separate, access-controlled location. Their security still depends on the strength of the master password that protects them.

## Security notes and limitations

See [SECURITY.md](SECURITY.md) for security best practices, backup guidance, and vulnerability reporting notes.

- This is an MVP for one local vault. It has no sync, browser integration, or multi-user support.
- The master password is not stored and cannot be recovered. If forgotten, use the recovery reset option to delete the vault and start over; existing entries cannot be recovered. Recovery reset cannot produce a new backup, so retain previously exported backups.
- Use a strong, unique master password. A local attacker with a copy of the vault can attempt offline guesses; Argon2id makes guesses more expensive but does not make weak passwords safe.
- This app has not undergone an independent security audit. Lock your vault when leaving the device unattended, and keep encrypted backups in a separate location if you need recovery from device loss. Backups remain protected only as strongly as their master passwords.
- Clipboard clearing is best-effort because desktop clipboard permissions and clipboard managers vary. Other applications may also retain copied content.
- TOTP setup keys are encrypted with the rest of the vault and never shown in entry summaries. The current implementation supports Base32 secrets and six-digit, 30-second HMAC-SHA1 codes; QR-code scanning and custom issuer/algorithm options are not included.
- Add or update an entry before attaching its authenticator. In the entry editor, paste the Base32 setup key under “Authenticator codes”; select the key icon on the saved item to view/copy the current code.
- The interface uses local system font fallbacks and does not need a network connection.
