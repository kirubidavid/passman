# Passman workspace instructions

- This is Passman, a local-first password manager using Rust, Tauri 2, and a TypeScript/Vite frontend.
- Keep credential secrets inside the Rust backend except when the user explicitly requests copy or edit. Never log passwords, master passwords, vault keys, or clipboard contents.
- Persist the vault only as authenticated ciphertext. Use OS-backed cryptographic randomness, Argon2id for key derivation, XChaCha20-Poly1305 for encryption, and zeroize temporary/in-memory secrets where practical.
- Do not add network services, sync, analytics, remote assets, or external fonts without explicit user approval.
- Keep frontend interfaces responsive and accessible; validate Rust commands and frontend with `cargo test --manifest-path src-tauri/Cargo.toml` and `npm run build`.
- Read README.md for current development setup and security limitations.

## Project setup checklist

- [x] Verify workspace instructions file exists and requirements are clarified.
- [x] Scaffold the Rust, Tauri v2, TypeScript, and Vite app in the workspace root.
- [x] Implement vault creation/unlock/lock, encrypted persistence, and a configurable password generator.
- [x] Scaffold includes recommended Tauri and rust-analyzer editor extensions; none were installed automatically.
- [x] Compile and run checks. `npm run build`, Rust formatting, and Rust tests pass (4 tests).
- [x] No VS Code task or app launch was requested; do not launch until the user confirms.
- [x] README includes setup instructions, workflow, and security limitations.
