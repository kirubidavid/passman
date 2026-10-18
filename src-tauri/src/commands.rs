use crate::{
    crypto::{derive_key, fresh_salt},
    models::{
        AppState, CURRENT_KDF, Entry, EntryDetails, EntrySummary, MAX_ENTRIES, UnlockedVault,
    },
    persistence::{
        load_vault, load_vault_data, persist, vault_path, write_vault, write_vault_with_kdf,
    },
    totp::{
        TotpResult, decode_normalized_totp_secret, decode_totp_secret, totp_code,
    },
};
#[cfg(test)]
use crate::{
    crypto::{derive_key_with_kdf, open, seal},
    models::{KEY_LEN, KdfAlgorithm, KdfParameters, VAULT_FILE, VaultFile},
    persistence::{atomic_write, atomic_write_with},
};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::fs;
use tauri::Manager;
#[cfg(test)]
use std::{
    io,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

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

fn update_entry_timestamps(entry: &mut Entry, previous: Option<&Entry>, now: u64) {
    entry.updated_at = now;
    entry.password_changed_at = match previous {
        Some(previous) if previous.password == entry.password => {
            if previous.password_changed_at == 0 {
                previous.updated_at
            } else {
                previous.password_changed_at
            }
        }
        _ => now,
    };
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultStatus {
    exists: bool,
    unlocked: bool,
    entry_count: usize,
}

#[tauri::command]
pub(crate) fn vault_status(
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
pub(crate) fn create_vault(
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
    let salt = fresh_salt();
    let key = derive_key(password.as_str(), &salt)?;
    let entries = Vec::new();
    write_vault(&path, &salt, &key, &entries)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault {
        key,
        salt,
        kdf: CURRENT_KDF,
        entries,
    });
    Ok(())
}

#[tauri::command]
pub(crate) fn unlock_vault(
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let (key, salt, kdf, entries) = load_vault(&path, password.as_str())?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault {
        key,
        salt,
        kdf,
        entries,
    });
    Ok(())
}

#[tauri::command]
pub(crate) fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub(crate) fn export_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let directory = app
        .path()
        .download_dir()
        .map_err(|e| format!("Could not locate the Downloads folder: {e}"))?;
    fs::create_dir_all(&directory)
        .map_err(|e| format!("Could not prepare the Downloads folder: {e}"))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock is before the Unix epoch".to_string())?
        .as_secs();
    let filename = format!(
        "passman-backup-{timestamp}-{:08x}.passman",
        OsRng.next_u32()
    );
    let destination = directory.join(&filename);
    with_vault(&state, |vault| {
        write_vault_with_kdf(
            &destination,
            &vault.salt,
            &vault.key,
            &vault.kdf,
            &vault.entries,
        )
            .map_err(|error| format!("Could not export backup: {error}"))?;
        Ok(filename)
    })
}

#[tauri::command]
pub(crate) fn import_backup(
    backup: String,
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let active_path = vault_path(&app)?;
    let backup = Zeroizing::new(backup);
    let password = Zeroizing::new(password);
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    if guard.is_none() {
        return Err("Unlock your vault before restoring a backup".into());
    }
    let (key, salt, kdf, entries) = load_vault_data(backup.as_bytes(), password.as_str())
        .map_err(|error| format!("Could not restore backup: {error}"))?;
    write_vault_with_kdf(&active_path, &salt, &key, &kdf, &entries)
        .map_err(|error| format!("Could not restore backup: {error}"))?;
    let summaries = entries.iter().map(EntrySummary::from).collect();
    *guard = Some(UnlockedVault {
        key,
        salt,
        kdf,
        entries,
    });
    Ok(summaries)
}

#[tauri::command]
pub(crate) fn change_master_password(
    current_password: String,
    new_password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);
    if new_password.chars().count() < 12 {
        return Err("Choose a new master password with at least 12 characters".into());
    }
    if current_password.as_str() == new_password.as_str() {
        return Err("Choose a new master password that is different from the current one".into());
    }
    let path = vault_path(&app)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    if guard.is_none() {
        return Err("Unlock your vault before changing its master password".into());
    }
    let (_, _, _, entries) = load_vault(&path, current_password.as_str())
        .map_err(|_| "Current master password is incorrect".to_string())?;
    let salt = fresh_salt();
    let key = derive_key(new_password.as_str(), &salt)?;
    write_vault(&path, &salt, &key, &entries)?;
    *guard = Some(UnlockedVault {
        key,
        salt,
        kdf: CURRENT_KDF,
        entries,
    });
    Ok(())
}

#[tauri::command]
pub(crate) fn reset_vault(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
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
pub(crate) fn list_entries(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    with_vault(&state, |vault| {
        Ok(vault.entries.iter().map(EntrySummary::from).collect())
    })
}

#[tauri::command]
pub(crate) fn get_entry(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<EntryDetails, String> {
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
pub(crate) fn get_entry_password(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    with_vault(&state, |vault| {
        vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| entry.password.clone())
            .ok_or_else(|| "Password entry not found".to_string())
    })
}

#[tauri::command]
pub(crate) fn get_totp_code(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<TotpResult, String> {
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
pub(crate) fn set_totp_secret(
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
pub(crate) fn remove_totp_secret(
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
pub(crate) fn save_entry(
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock is before the Unix epoch".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "System time is outside the supported range".to_string())?;
    let path = vault_path(&app)?;
    with_vault(&state, |vault| {
        let original_entries = vault.entries.clone();
        if let Some(index) = vault.entries.iter().position(|e| e.id == entry.id) {
            update_entry_timestamps(&mut entry, Some(&vault.entries[index]), now);
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
            update_entry_timestamps(&mut entry, None, now);
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
pub(crate) fn delete_entry(
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
pub(crate) struct GeneratorOptions {
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
}

#[tauri::command]
pub(crate) fn generate_password(options: GeneratorOptions) -> Result<String, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn persistence_test_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "passman-{name}-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn remove_persistence_test_directory(directory: &Path) {
        for entry in fs::read_dir(directory).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    fn persistence_test_entry(password: &str) -> Entry {
        Entry {
            id: "persistence-entry".into(),
            title: "Persistence".into(),
            username: "user".into(),
            password: password.into(),
            website: String::new(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
            password_changed_at: 1,
        }
    }

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
            password_changed_at: 1,
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
        assert_eq!(entry.password_changed_at, 0);
    }

    #[test]
    fn password_age_changes_only_when_the_password_changes() {
        let mut previous = persistence_test_entry("same secret");
        previous.password_changed_at = 0;
        let mut metadata_edit = previous.clone();
        metadata_edit.title = "Renamed".into();
        update_entry_timestamps(&mut metadata_edit, Some(&previous), 500);
        assert_eq!(metadata_edit.updated_at, 500);
        assert_eq!(metadata_edit.password_changed_at, 1);

        let mut password_edit = previous.clone();
        password_edit.password = "new secret".into();
        update_entry_timestamps(&mut password_edit, Some(&previous), 500);
        assert_eq!(password_edit.password_changed_at, 500);

        let mut new_entry = persistence_test_entry("new secret");
        update_entry_timestamps(&mut new_entry, None, 700);
        assert_eq!(new_entry.password_changed_at, 700);
    }

    #[test]
    fn exported_vault_round_trips_with_its_master_password() {
        let path = std::env::temp_dir().join(format!(
            "passman-backup-test-{}.passman",
            OsRng.next_u64()
        ));
        let salt = fresh_salt();
        let key = derive_key("a secure test password", &salt).unwrap();
        let entries = vec![Entry {
            id: "backup-entry".into(),
            title: "Backup".into(),
            username: "user".into(),
            password: "secret".into(),
            website: String::new(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
            password_changed_at: 1,
        }];

        write_vault(&path, &salt, &key, &entries).unwrap();
        let (_, loaded_salt, loaded_kdf, loaded_entries) =
            load_vault(&path, "a secure test password").unwrap();

        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded_kdf, CURRENT_KDF);
        assert_eq!(loaded_entries[0].password, "secret");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_v1_vault_uses_legacy_kdf_parameters() {
        let salt = fresh_salt();
        let key = derive_key("legacy vault password", &salt).unwrap();
        let entries = vec![persistence_test_entry("legacy secret")];
        let (nonce, ciphertext) = seal(&key, &entries).unwrap();
        let legacy_file = VaultFile {
            version: 1,
            kdf: None,
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        let data = serde_json::to_vec(&legacy_file).unwrap();

        let (_, loaded_salt, loaded_kdf, loaded_entries) =
            load_vault_data(&data, "legacy vault password").unwrap();

        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded_kdf, CURRENT_KDF);
        assert_eq!(loaded_entries[0].password, "legacy secret");
    }

    #[test]
    fn v2_vault_records_and_uses_its_kdf_parameters() {
        let directory = persistence_test_directory("kdf-parameters");
        let current_path = directory.join("current.json");
        let alternate_path = directory.join("alternate.json");
        let alternate_kdf = KdfParameters {
            algorithm: KdfAlgorithm::Argon2id,
            version: 0x13,
            memory_kib: 8_192,
            iterations: 3,
            parallelism: 2,
            output_length: KEY_LEN as u32,
        };
        let salt = fresh_salt();
        let entries = vec![persistence_test_entry("parameterized secret")];
        let current_key = derive_key("current parameters password", &salt).unwrap();
        let alternate_key =
            derive_key_with_kdf("alternate parameters password", &salt, &alternate_kdf).unwrap();

        write_vault(&current_path, &salt, &current_key, &entries).unwrap();
        write_vault_with_kdf(
            &alternate_path,
            &salt,
            &alternate_key,
            &alternate_kdf,
            &entries,
        )
        .unwrap();

        let current_file: VaultFile =
            serde_json::from_slice(&fs::read(&current_path).unwrap()).unwrap();
        let (_, _, loaded_alternate_kdf, loaded_entries) =
            load_vault(&alternate_path, "alternate parameters password").unwrap();
        assert_eq!(current_file.kdf, Some(CURRENT_KDF));
        assert_eq!(loaded_alternate_kdf, alternate_kdf);
        assert_eq!(loaded_entries[0].password, "parameterized secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn unsafe_or_unsupported_kdf_metadata_is_rejected() {
        let salt = fresh_salt();
        let key = derive_key("metadata validation password", &salt).unwrap();
        let entries = vec![persistence_test_entry("secret")];
        let (nonce, ciphertext) = seal(&key, &entries).unwrap();
        let mut file = VaultFile {
            version: 2,
            kdf: Some(CURRENT_KDF),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };

        file.kdf.as_mut().unwrap().memory_kib = 262_145;
        let unsafe_error = load_vault_data(
            &serde_json::to_vec(&file).unwrap(),
            "metadata validation password",
        )
        .unwrap_err();
        assert!(unsafe_error.contains("safety limits"));

        file.kdf.as_mut().unwrap().memory_kib = CURRENT_KDF.memory_kib;
        file.kdf.as_mut().unwrap().version = 0x10;
        let version_error = load_vault_data(
            &serde_json::to_vec(&file).unwrap(),
            "metadata validation password",
        )
        .unwrap_err();
        assert!(version_error.contains("Argon2 version"));

        let mut value = serde_json::to_value(file).unwrap();
        value["kdf"]["algorithm"] = serde_json::Value::String("unsupported".into());
        let algorithm_error =
            load_vault_data(&serde_json::to_vec(&value).unwrap(), "metadata validation password")
                .unwrap_err();
        assert!(algorithm_error.contains("Vault file is invalid"));
    }

    #[test]
    fn rekeyed_vault_uses_fresh_salt_and_rejects_old_password() {
        let path =
            std::env::temp_dir().join(format!("passman-rekey-test-{}.json", OsRng.next_u64()));
        let old_salt = fresh_salt();
        let old_key = derive_key("old secure password", &old_salt).unwrap();
        let entries = vec![Entry {
            id: "rekey-entry".into(),
            title: "Rekey".into(),
            username: String::new(),
            password: "secret".into(),
            website: String::new(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
            password_changed_at: 1,
        }];
        write_vault(&path, &old_salt, &old_key, &entries).unwrap();

        let new_salt = fresh_salt();
        let new_key = derive_key("new secure password", &new_salt).unwrap();
        write_vault(&path, &new_salt, &new_key, &entries).unwrap();

        assert_ne!(new_salt, old_salt);
        assert!(load_vault(&path, "old secure password").is_err());
        assert_eq!(
            load_vault(&path, "new secure password").unwrap().3[0].password,
            "secret"
        );
        let rekeyed_file: VaultFile =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(rekeyed_file.version, 2);
        assert_eq!(rekeyed_file.kdf, Some(CURRENT_KDF));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn vault_update_replaces_existing_ciphertext() {
        let directory = persistence_test_directory("update");
        let path = directory.join(VAULT_FILE);
        let salt = fresh_salt();
        let key = derive_key("persistence test password", &salt).unwrap();

        write_vault(
            &path,
            &salt,
            &key,
            &[persistence_test_entry("old secret")],
        )
        .unwrap();
        write_vault(
            &path,
            &salt,
            &key,
            &[persistence_test_entry("new secret")],
        )
        .unwrap();

        let (_, _, _, entries) = load_vault(&path, "persistence test password").unwrap();
        assert_eq!(entries[0].password, "new secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn failed_replacement_preserves_original_and_cleans_temporary_file() {
        let directory = persistence_test_directory("rollback");
        let path = directory.join(VAULT_FILE);
        fs::write(&path, b"original").unwrap();

        let error = atomic_write_with(&path, b"replacement", |_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "simulated replacement failure",
            ))
        })
        .unwrap_err();

        assert!(error.contains("simulated replacement failure"));
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn interrupted_write_does_not_damage_active_vault() {
        let directory = persistence_test_directory("interrupted");
        let path = directory.join(VAULT_FILE);
        let salt = fresh_salt();
        let key = derive_key("interrupted test password", &salt).unwrap();
        write_vault(
            &path,
            &salt,
            &key,
            &[persistence_test_entry("active secret")],
        )
        .unwrap();
        fs::write(
            directory.join(".vault.json.interrupted.tmp"),
            b"partial ciphertext",
        )
        .unwrap();

        let (_, _, _, entries) = load_vault(&path, "interrupted test password").unwrap();
        assert_eq!(entries[0].password, "active secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn stale_temporary_file_does_not_block_future_save() {
        let directory = persistence_test_directory("stale-temp");
        let path = directory.join(VAULT_FILE);
        let stale = directory.join(".vault.json.stale.tmp");
        fs::write(&path, b"old").unwrap();
        fs::write(&stale, b"stale").unwrap();

        atomic_write(&path, b"new").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::read(&stale).unwrap(), b"stale");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn platform_replacement_overwrites_existing_file() {
        let directory = persistence_test_directory("platform-replace");
        let path = directory.join(VAULT_FILE);
        fs::write(&path, b"before").unwrap();

        atomic_write(&path, b"after").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"after");
        remove_persistence_test_directory(&directory);
    }
}
