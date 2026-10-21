use crate::{
    models::{
        CURRENT_KDF, Entry, KEY_LEN, KdfAlgorithm, KdfParameters, MAX_ENTRIES, MAX_SSH_KEYS,
        NONCE_LEN, SALT_LEN, SshKey, VaultData, VaultPreferences, evaluate_password_strength,
    },
    totp::decode_totp_secret,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand::{RngCore, rngs::OsRng};
use zeroize::Zeroizing;

const MAX_KDF_MEMORY_KIB: u32 = 262_144;
const MAX_KDF_ITERATIONS: u32 = 10;
const MAX_KDF_PARALLELISM: u32 = 8;

pub(crate) fn fresh_salt() -> [u8; SALT_LEN] {
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub(crate) fn derive_key(
    password: &str,
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    derive_key_with_kdf(password, salt, &CURRENT_KDF)
}

pub(crate) fn derive_key_with_kdf(
    password: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParameters,
) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    if kdf.output_length != KEY_LEN as u32 {
        return Err("Vault KDF output length is not supported".into());
    }
    if kdf.memory_kib > MAX_KDF_MEMORY_KIB
        || kdf.iterations > MAX_KDF_ITERATIONS
        || kdf.parallelism > MAX_KDF_PARALLELISM
    {
        return Err("Vault KDF parameters exceed supported safety limits".into());
    }
    let algorithm = match kdf.algorithm {
        KdfAlgorithm::Argon2id => Algorithm::Argon2id,
    };
    let version = match kdf.version {
        0x13 => Version::V0x13,
        _ => return Err("Vault Argon2 version is not supported".into()),
    };
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(kdf.output_length as usize),
    )
    .map_err(|error| format!("Vault KDF parameters are invalid: {error}"))?;
    let argon2 = Argon2::new(algorithm, version, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

pub(crate) fn seal(
    key: &[u8; KEY_LEN],
    entries: &[Entry],
    ssh_keys: &[SshKey],
    preferences: &VaultPreferences,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut nonce = vec![0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct VaultDataRef<'a> {
        entries: &'a [Entry],
        ssh_keys: &'a [SshKey],
        preferences: &'a VaultPreferences,
    }
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&VaultDataRef {
            entries,
            ssh_keys,
            preferences,
        })
        .map_err(|e| format!("Could not encode vault: {e}"))?,
    );
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| "Could not encrypt vault".to_string())?;
    Ok((nonce, ciphertext))
}

#[cfg(test)]
pub(crate) fn seal_legacy_entries(
    key: &[u8; KEY_LEN],
    entries: &[Entry],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut nonce = vec![0_u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = Zeroizing::new(
        serde_json::to_vec(entries).map_err(|e| format!("Could not encode vault: {e}"))?,
    );
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| "Could not encrypt vault".to_string())?;
    Ok((nonce, ciphertext))
}

pub(crate) fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<VaultData, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| "Incorrect master password or damaged vault".to_string())?,
    );
    let mut data = serde_json::from_slice::<VaultData>(plaintext.as_slice()).or_else(|_| {
        serde_json::from_slice::<Vec<Entry>>(plaintext.as_slice()).map(|entries| VaultData {
            entries,
            ssh_keys: Vec::new(),
            preferences: VaultPreferences::default(),
        })
    })
    .map_err(|_| "Vault data is invalid".to_string())?;
    let preferences = data.preferences.validate()?;
    if data.entries.len() > MAX_ENTRIES {
        return Err("Vault contains too many entries".into());
    }
    if data.ssh_keys.len() > MAX_SSH_KEYS {
        return Err("Vault contains too many SSH keys".into());
    }
    if data.entries.iter().any(|entry| {
        entry.title.is_empty()
            || entry.title.chars().count() > 200
            || entry.username.chars().count() > 500
            || entry.website.chars().count() > 2_000
            || entry.notes.chars().count() > 10_000
            || entry.password.is_empty()
            || entry.password.chars().count() > 4_096
            || entry
                .totp_secret
                .as_ref()
                .is_some_and(|secret| secret.len() > 128)
            || entry
                .totp_secret
                .as_ref()
                .is_some_and(|secret| decode_totp_secret(secret).is_err())
    }) {
        return Err("Vault contains invalid entry data".into());
    }
    for entry in &mut data.entries {
        if entry.password_strength_score > 4 {
            entry.password_strength_score = evaluate_password_strength(entry)?;
        }
    }
    if data.ssh_keys.iter().any(|key| {
        key.id.is_empty()
            || key.id.chars().count() > 200
            || key.title.trim().is_empty()
            || key.title.chars().count() > 200
            || key.algorithm != "Ed25519"
            || key.fingerprint.chars().count() > 200
            || !key.public_key.starts_with("ssh-ed25519 ")
            || key.public_key.chars().count() > 2_000
            || !key.private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
            || key.private_key.chars().count() > 20_000
            || key.notes.chars().count() > 10_000
    }) {
        return Err("Vault contains invalid SSH key data".into());
    }
    Ok(VaultData {
        entries: data.entries,
        ssh_keys: data.ssh_keys,
        preferences,
    })
}
