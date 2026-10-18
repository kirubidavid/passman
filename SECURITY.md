# Passman Security Best Practices

Passman stores passwords and authenticator setup keys. Treat the vault and every device that can unlock it as sensitive.

## Protect your vault

- Choose a long, unique master password that you do not use anywhere else. A password manager can help you generate and store it.
- The master password cannot be recovered. Keep a secure recovery copy somewhere separate from the device, or be prepared to lose vault contents if it is forgotten.
- Lock Passman when leaving your device. The app also locks after five minutes of inactivity; do not rely on this if your device may be accessible to others.
- Keep your operating system, Passman, and its dependencies updated. Install Passman only from trusted sources.
- Use full-disk encryption and a strong OS login password. The vault is encrypted, but malware or an already-unlocked session can access secrets.
- Do not use Passman on a shared or untrusted device. Avoid screen sharing while viewing credentials or one-time codes.

## Handle secrets carefully

- Reveal or copy a password or TOTP code only when needed. Clipboard clearing after 30 seconds is best-effort; clipboard managers or other apps may retain copied data.
- Do not paste vault data, master passwords, recovery copies, or authenticator setup keys into issue reports, chat, logs, or screenshots.
- Keep authenticator setup keys private. Anyone who has the key can generate valid one-time codes for that account.
- Do not store a site's recovery codes as ordinary notes unless you have considered the risk. Keep backup codes in a separate secure location when practical.

## Backups and recovery

- Passman currently has no built-in sync or backup. Back up the encrypted vault file only if you need recovery from device loss or failure.
- Keep backups encrypted, restrict access to them, and store them separately from the computer. The vault's security depends on the strength of the master password even when a backup is copied.
- Test that a backup is readable before relying on it, and securely remove outdated copies. Deleting a file does not guarantee secure erasure on SSDs, snapshots, or cloud-backed storage.
- Resetting the vault permanently deletes its saved entries. Confirm you have a usable backup before resetting.

## Security limitations

- Passman is an MVP and has not undergone an independent security audit. Do not treat it as a certified or audited password manager.
- A copied vault permits offline guesses at the master password. Argon2id increases the cost of guesses but cannot compensate for a weak master password.
- Secrets necessarily exist in application memory while the vault is unlocked. Zeroization is best-effort and cannot protect against a compromised operating system, debugger, memory dump, or malicious process running as your user.
- TOTP support currently uses Base32 setup keys and six-digit, 30-second HMAC-SHA1 codes. Protect the setup key like a password.
- Clipboard clearing and automatic locking are convenience protections, not a substitute for a trusted, locked device.

## Reporting a vulnerability

If you find a security issue, please report it privately to the project maintainer rather than posting exploit details or sensitive data publicly. Include the affected Passman version, platform, and steps to reproduce, but never include real credentials, master passwords, vault files, or TOTP setup keys.
