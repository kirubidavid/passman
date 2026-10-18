use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::Deserializer;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::{fs, path::PathBuf, sync::Mutex};
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

const VAULT_FILE: &str = "vault.json";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultFile {
    version: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Entry {
    id: String,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
    #[serde(default, deserialize_with = "deserialize_totp_secret")]
    totp_secret: Option<String>,
    #[serde(default)]
    favorite: bool,
    updated_at: u64,
}

fn deserialize_totp_secret<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let secret = Option::<String>::deserialize(deserializer)?;
    Ok(secret.map(|mut value| {
        let stored = value.clone();
        value.zeroize();
        stored
    }))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntrySummary {
    id: String,
    title: String,
    username: String,
    website: String,
    notes: String,
    has_totp: bool,
    favorite: bool,
    updated_at: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryDetails {
    id: String,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
    favorite: bool,
    updated_at: u64,
    has_totp: bool,
}

impl From<&Entry> for EntryDetails {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            password: entry.password.clone(),
            website: entry.website.clone(),
            notes: entry.notes.clone(),
            favorite: entry.favorite,
            updated_at: entry.updated_at,
            has_totp: entry.totp_secret.is_some(),
        }
    }
}

impl From<&Entry> for EntrySummary {
    fn from(entry: &Entry) -> Self {
        Self {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            website: entry.website.clone(),
            notes: entry.notes.clone(),
            has_totp: entry.totp_secret.is_some(),
            favorite: entry.favorite,
            updated_at: entry.updated_at,
        }
    }
}

#[derive(Default)]
struct AppState {
    vault: Mutex<Option<UnlockedVault>>,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Ok(vault) = self.vault.get_mut() {
            *vault = None;
        }
    }
}

struct UnlockedVault {
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
    entries: Vec<Entry>,
}

fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("Could not create vault directory: {e}"))?;
    Ok(dir.join(VAULT_FILE))
}

fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let params = Params::new(19_456, 2, 1, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

fn seal(key: &[u8; KEY_LEN], entries: &[Entry]) -> Result<(Vec<u8>, Vec<u8>), String> {
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

fn open(key: &[u8; KEY_LEN], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<Entry>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| "Incorrect master password or damaged vault".to_string())?,
    );
    let entries: Vec<Entry> = serde_json::from_slice(plaintext.as_slice())
        .map_err(|_| "Vault data is invalid".to_string())?;
    if entries.len() > MAX_ENTRIES {
        return Err("Vault contains too many entries".into());
    }
    if entries.iter().any(|entry| {
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
    Ok(entries)
}

fn write_vault(
    path: &PathBuf,
    salt: &[u8; SALT_LEN],
    key: &[u8; KEY_LEN],
    entries: &[Entry],
) -> Result<(), String> {
    let (nonce, ciphertext) = seal(key, entries)?;
    let file = VaultFile {
        version: 1,
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    };
    let data =
        serde_json::to_vec(&file).map_err(|e| format!("Could not encode vault file: {e}"))?;
    let temp = path.with_extension("tmp");
    fs::write(&temp, data).map_err(|e| format!("Could not save vault: {e}"))?;
    fs::rename(&temp, path).map_err(|e| format!("Could not finalize vault save: {e}"))?;
    Ok(())
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|_| format!("Invalid vault {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("Invalid vault {field}"))
}

fn load_vault(
    path: &PathBuf,
    password: &str,
) -> Result<(Zeroizing<[u8; KEY_LEN]>, [u8; SALT_LEN], Vec<Entry>), String> {
    let data = fs::read(path).map_err(|e| format!("Could not read vault: {e}"))?;
    if data.len() > 64 * 1024 * 1024 {
        return Err("Vault file is larger than the supported limit".into());
    }
    let file: VaultFile =
        serde_json::from_slice(&data).map_err(|_| "Vault file is invalid".to_string())?;
    if file.version != 1 {
        return Err("This vault version is not supported".into());
    }
    let salt = decode_fixed::<SALT_LEN>(&file.salt, "salt")?;
    let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
    let ciphertext = BASE64
        .decode(file.ciphertext)
        .map_err(|_| "Invalid vault ciphertext".to_string())?;
    let key = derive_key(password, &salt)?;
    let entries = open(&key, &nonce, &ciphertext)?;
    Ok((key, salt, entries))
}

fn with_vault<T>(
    state: &AppState,
    f: impl FnOnce(&mut UnlockedVault) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    let vault = guard
        .as_mut()
        .ok_or_else(|| "Unlock your vault first".to_string())?;
    f(vault)
}

fn persist(path: &PathBuf, vault: &UnlockedVault) -> Result<(), String> {
    write_vault(path, &vault.salt, &vault.key, &vault.entries)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultStatus {
    exists: bool,
    unlocked: bool,
    entry_count: usize,
}

#[tauri::command]
fn vault_status(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultStatus, String> {
    let exists = vault_path(&app)?.exists();
    let guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    let unlocked = guard.is_some();
    let entry_count = guard.as_ref().map_or(0, |v| v.entries.len());
    Ok(VaultStatus {
        exists,
        unlocked,
        entry_count,
    })
}

#[tauri::command]
fn create_vault(
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    if password.chars().count() < 12 {
        return Err("Choose a master password with at least 12 characters".into());
    }
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("A vault already exists".into());
    }
    let mut salt = [0_u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password.as_str(), &salt)?;
    let entries = Vec::new();
    write_vault(&path, &salt, &key, &entries)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault { key, salt, entries });
    Ok(())
}

#[tauri::command]
fn unlock_vault(
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let (key, salt, entries) = load_vault(&path, password.as_str())?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault { key, salt, entries });
    Ok(())
}

#[tauri::command]
fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
fn reset_vault(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("Could not remove vault: {e}"))?;
    }
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
fn list_entries(state: tauri::State<'_, AppState>) -> Result<Vec<EntrySummary>, String> {
    with_vault(&state, |vault| {
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
fn get_entry(id: String, state: tauri::State<'_, AppState>) -> Result<EntryDetails, String> {
    with_vault(&state, |vault| {
        vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(EntryDetails::from)
            .ok_or_else(|| "Password entry not found".to_string())
    })
}

#[tauri::command]
fn get_entry_password(id: String, state: tauri::State<'_, AppState>) -> Result<String, String> {
    with_vault(&state, |vault| {
        vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.password.clone())
            .ok_or_else(|| "Password entry not found".to_string())
    })
}

fn decode_totp_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let normalized = Zeroizing::new(
        secret
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .map(|character| character.to_ascii_uppercase())
            .collect::<String>(),
    );
    if normalized.is_empty() || normalized.len() > 128 {
        return Err("Enter a valid authenticator secret".into());
    }
    decode_normalized_totp_secret(&normalized)
}

fn decode_normalized_totp_secret(normalized: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|_| "Authenticator secret must use Base32 characters (A–Z and 2–7)".to_string())?;
    if !(10..=64).contains(&decoded.len()) {
        return Err("Authenticator secret must decode to 10–64 bytes".into());
    }
    Ok(Zeroizing::new(decoded))
}

fn totp_code(secret: &[u8], unix_seconds: u64) -> Result<String, String> {
    let counter = unix_seconds / 30;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret)
        .map_err(|_| "Invalid authenticator secret".to_string())?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(format!("{:06}", binary % 1_000_000))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TotpResult {
    code: String,
    seconds_remaining: u8,
}

#[tauri::command]
fn get_totp_code(id: String, state: tauri::State<'_, AppState>) -> Result<TotpResult, String> {
    with_vault(&state, |vault| {
        let entry = vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        let secret_value = Zeroizing::new(
            entry
                .totp_secret
                .as_deref()
                .ok_or_else(|| "No authenticator is set up for this item".to_string())?
                .to_string(),
        );
        let secret = decode_totp_secret(secret_value.as_str())?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "System clock is before the Unix epoch".to_string())?
            .as_secs();
        Ok(TotpResult {
            code: totp_code(&secret, now)?,
            seconds_remaining: (30 - now % 30) as u8,
        })
    })
}

#[tauri::command]
fn set_totp_secret(
    id: String,
    secret: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let secret = Zeroizing::new(secret);
    let normalized = Zeroizing::new(
        secret
            .chars()
            .filter(|character| !character.is_ascii_whitespace() && *character != '-')
            .map(|character| character.to_ascii_uppercase())
            .collect::<String>(),
    );
    let decoded = decode_normalized_totp_secret(&normalized)?;
    let canonical = Zeroizing::new(
        BASE32_NOPAD
            .encode(&decoded)
            .trim_end_matches('=')
            .to_string(),
    );
    if canonical.as_str() != normalized.trim_end_matches('=') {
        return Err("Authenticator secret has invalid Base32 padding".into());
    }
    let path = vault_path(&app)?;
    with_vault(&state, |vault| {
        let index = vault
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        let previous = vault.entries[index]
            .totp_secret
            .replace(canonical.to_string());
        if let Err(error) = persist(&path, vault) {
            vault.entries[index].totp_secret = previous;
            return Err(error);
        }
        if let Some(mut previous) = previous {
            previous.zeroize();
        }
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
fn remove_totp_secret(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let path = vault_path(&app)?;
    with_vault(&state, |vault| {
        let index = vault
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        let previous = vault.entries[index].totp_secret.take();
        if let Err(error) = persist(&path, vault) {
            vault.entries[index].totp_secret = previous;
            return Err(error);
        }
        if let Some(mut previous) = previous {
            previous.zeroize();
        }
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
fn save_entry(
    mut entry: Entry,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    entry.title = entry.title.trim().to_string();
    if entry.title.is_empty() || entry.title.chars().count() > 200 {
        return Err("Enter a title of up to 200 characters".into());
    }
    if entry.username.chars().count() > 500
        || entry.website.chars().count() > 2_000
        || entry.notes.chars().count() > 10_000
        || entry.password.chars().count() > 4_096
    {
        return Err("One or more fields are too long".into());
    }
    if entry.password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    if entry
        .totp_secret
        .as_ref()
        .is_some_and(|secret| decode_totp_secret(secret).is_err())
    {
        return Err("Authenticator secret is invalid".into());
    }
    let path = vault_path(&app)?;
    with_vault(&state, |vault| {
        let original_entries = vault.entries.clone();
        if let Some(index) = vault.entries.iter().position(|e| e.id == entry.id) {
            let stored_totp = vault.entries[index].totp_secret.take();
            if entry.totp_secret.is_none() {
                entry.totp_secret = stored_totp;
            } else if let Some(mut old_secret) = stored_totp {
                old_secret.zeroize();
            }
            let previous = std::mem::replace(&mut vault.entries[index], entry);
            drop(previous);
        } else {
            if vault.entries.len() >= MAX_ENTRIES {
                return Err("Vault has reached its entry limit".into());
            }
            vault.entries.push(entry);
        }
        if let Err(error) = persist(&path, vault) {
            vault.entries = original_entries;
            return Err(error);
        }
        for mut previous in original_entries {
            previous.zeroize();
        }
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
fn delete_entry(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let path = vault_path(&app)?;
    with_vault(&state, |vault| {
        let original_entries = vault.entries.clone();
        vault.entries.retain(|entry| entry.id != id);
        if let Err(error) = persist(&path, vault) {
            vault.entries = original_entries;
            return Err(error);
        }
        for mut previous in original_entries {
            previous.zeroize();
        }
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratorOptions {
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
}

#[tauri::command]
fn generate_password(options: GeneratorOptions) -> Result<String, String> {
    if !(8..=128).contains(&options.length) {
        return Err("Password length must be between 8 and 128".into());
    }
    let groups: Vec<&[u8]> = [
        (options.uppercase, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
        (options.lowercase, b"abcdefghijklmnopqrstuvwxyz".as_slice()),
        (options.numbers, b"0123456789".as_slice()),
        (options.symbols, b"!@#$%^&*()-_=+[]{};:,.?/".as_slice()),
    ]
    .into_iter()
    .filter_map(|(enabled, chars)| enabled.then_some(chars))
    .collect();
    if groups.is_empty() {
        return Err("Select at least one character type".into());
    }
    if groups.len() > options.length {
        return Err("Length must be at least the number of selected character types".into());
    }
    let mut password = Vec::with_capacity(options.length);
    for group in &groups {
        password.push(sample_uniform(group));
    }
    let all: Vec<u8> = groups
        .iter()
        .flat_map(|group| group.iter().copied())
        .collect();
    while password.len() < options.length {
        password.push(sample_uniform(&all));
    }
    for index in (1..password.len()).rev() {
        password.swap(index, sample_index(index + 1));
    }
    String::from_utf8(password).map_err(|_| "Password generation failed".into())
}

fn sample_uniform(values: &[u8]) -> u8 {
    values[sample_index(values.len())]
}

fn sample_index(upper_exclusive: usize) -> usize {
    let upper = upper_exclusive as u64;
    let zone = u64::MAX - u64::MAX % upper;
    loop {
        let candidate = OsRng.next_u64();
        if candidate < zone {
            return (candidate % upper) as usize;
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            vault_status,
            create_vault,
            unlock_vault,
            lock_vault,
            reset_vault,
            list_entries,
            get_entry,
            get_entry_password,
            get_totp_code,
            set_totp_secret,
            remove_totp_secret,
            save_entry,
            delete_entry,
            generate_password
        ])
        .run(tauri::generate_context!())
        .expect("error while running Passman");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_classes_and_length() {
        let password = generate_password(GeneratorOptions {
            length: 32,
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: true,
        })
        .unwrap();
        assert_eq!(password.len(), 32);
        assert!(password.bytes().any(|c| c.is_ascii_uppercase()));
        assert!(password.bytes().any(|c| c.is_ascii_lowercase()));
        assert!(password.bytes().any(|c| c.is_ascii_digit()));
        assert!(password.bytes().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn generated_password_rejects_empty_character_set() {
        assert!(
            generate_password(GeneratorOptions {
                length: 20,
                uppercase: false,
                lowercase: false,
                numbers: false,
                symbols: false
            })
            .is_err()
        );
    }

    #[test]
    fn generated_password_contains_each_selected_character_group() {
        for (uppercase, lowercase, numbers, symbols) in [
            (true, false, true, false),
            (false, true, false, true),
            (true, true, false, false),
            (false, false, true, true),
        ] {
            let password = generate_password(GeneratorOptions {
                length: 12,
                uppercase,
                lowercase,
                numbers,
                symbols,
            })
            .unwrap();
            if uppercase {
                assert!(password.bytes().any(|c| c.is_ascii_uppercase()));
            }
            if lowercase {
                assert!(password.bytes().any(|c| c.is_ascii_lowercase()));
            }
            if numbers {
                assert!(password.bytes().any(|c| c.is_ascii_digit()));
            }
            if symbols {
                assert!(password.bytes().any(|c| !c.is_ascii_alphanumeric()));
            }
        }
    }

    #[test]
    fn encryption_round_trip_and_wrong_key_rejection() {
        let entries = vec![Entry {
            id: "1".into(),
            title: "Example".into(),
            username: "user".into(),
            password: "secret".into(),
            website: "https://example.com".into(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
        }];
        let key = [7_u8; KEY_LEN];
        let (nonce, ciphertext) = seal(&key, &entries).unwrap();
        assert_eq!(
            open(&key, &nonce, &ciphertext).unwrap()[0].password,
            "secret"
        );
        assert!(open(&[8_u8; KEY_LEN], &nonce, &ciphertext).is_err());
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_test_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59).unwrap(), "287082");
        assert_eq!(totp_code(secret, 1_111_111_109).unwrap(), "081804");
    }

    #[test]
    fn base32_totp_secret_decodes_without_exposing_it() {
        let decoded = decode_totp_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(decoded.as_slice(), b"12345678901234567890");
        assert!(decode_totp_secret("not-a-valid-secret").is_err());
    }

    #[test]
    fn old_entries_without_totp_secret_still_deserialize() {
        let entry = r#"{"id":"x","title":"mail","username":"u","password":"p","website":"","notes":"","favorite":false,"updatedAt":1}"#;
        let entry: Entry = serde_json::from_str(entry).unwrap();
        assert!(entry.totp_secret.is_none());
    }
}
