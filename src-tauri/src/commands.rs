use crate::{
    crypto::{derive_key, fresh_salt},
    models::{
        AppState, CURRENT_KDF, Entry, EntryDetails, EntrySummary, MAX_ENTRIES, MAX_SSH_KEYS,
        SshKey, SshKeyDetails, UnlockedVault, VaultPreferences, VaultSnapshot, entry_details,
        evaluate_password_strength, initialize_legacy_password_age_tracking,
        kdf_upgrade_available, ssh_key_details, summarize_entries,
    },
    persistence::{
        load_vault, persist, vault_path, write_vault, write_vault_with_kdf,
    },
    totp::{
        TotpResult, decode_normalized_totp_secret, decode_totp_secret, totp_code,
    },
};
#[cfg(test)]
use crate::{
    crypto::{derive_key_with_kdf, open, seal, seal_legacy_entries},
    models::{KEY_LEN, KdfAlgorithm, KdfParameters, VAULT_FILE, VaultFile},
    persistence::{atomic_write, atomic_write_with, load_vault_data},
};
#[cfg(test)]
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use ssh_key::{Algorithm as SshAlgorithm, HashAlg, LineEnding, PrivateKey, PublicKey};
use std::fs;
use tauri_plugin_dialog::DialogExt;
#[cfg(test)]
use std::{
    io,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const BACKUP_EXTENSION: &str = "passman";
const RECOVERY_RESET_PHRASE: &str = "RESET VAULT";

fn is_passman_backup_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case(BACKUP_EXTENSION))
}

fn local_backup_path(
    selected: tauri_plugin_dialog::FilePath,
) -> Result<std::path::PathBuf, String> {
    let path = selected
        .into_path()
        .map_err(|_| "The selected backup is not a local file".to_string())?;
    if !is_passman_backup_path(&path) {
        return Err("Choose a file with the .passman extension".into());
    }
    Ok(path)
}

fn suggested_backup_name() -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock is before the Unix epoch".to_string())?
        .as_secs();
    Ok(format!(
        "passman-backup-{timestamp}-{:08x}.passman",
        OsRng.next_u32()
    ))
}

async fn choose_backup_destination(
    app: &tauri::AppHandle,
) -> Result<Option<std::path::PathBuf>, String> {
    let suggested_name = suggested_backup_name()?;
    let dialog_app = app.clone();
    let destination = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .file()
            .add_filter("Passman encrypted backups", &[BACKUP_EXTENSION])
            .set_file_name(suggested_name)
            .blocking_save_file()
    })
    .await
    .map_err(|error| format!("Could not open the backup save dialog: {error}"))?;
    destination.map(local_backup_path).transpose()
}

fn verify_current_master_password(
    path: &std::path::PathBuf,
    password: &str,
) -> Result<(), String> {
    load_vault(path, password)
        .map(|_| ())
        .map_err(|_| "Current master password is incorrect".to_string())
}

fn ensure_loaded_vault_matches_active(
    active: &UnlockedVault,
    loaded_key: &[u8; crate::models::KEY_LEN],
    loaded_salt: &[u8; crate::models::SALT_LEN],
    loaded_kdf: &crate::models::KdfParameters,
) -> Result<(), String> {
    if &active.salt != loaded_salt
        || &active.kdf != loaded_kdf
        || active.key.iter().ne(loaded_key.iter())
    {
        return Err(
            "Vault metadata no longer matches the active key; lock and unlock the vault before retrying"
                .into(),
        );
    }
    Ok(())
}

fn validate_recovery_reset_phrase(confirmation_phrase: &str) -> Result<(), String> {
    if confirmation_phrase != RECOVERY_RESET_PHRASE {
        return Err(format!(
            "Type {RECOVERY_RESET_PHRASE} exactly to reset the vault"
        ));
    }
    Ok(())
}

fn remove_vault_and_clear_state(
    path: &std::path::PathBuf,
    state: &AppState,
) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| format!("Could not remove vault: {error}"))?;
    }
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = None;
    Ok(())
}

fn with_vault<T>(
    state: &AppState,
    f: impl FnOnce(&UnlockedVault) -> Result<T, String>,
) -> Result<T, String> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "Unlock your vault first".to_string())?;
    f(vault)
}

fn lock_mutations(state: &AppState) -> Result<std::sync::MutexGuard<'_, ()>, String> {
    state
        .mutation
        .lock()
        .map_err(|_| "Vault mutations are unavailable".to_string())
}

fn begin_vault_mutation(state: &AppState) -> Result<(u64, UnlockedVault), String> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    let vault = guard
        .as_ref()
        .ok_or_else(|| "Unlock your vault first".to_string())?;
    Ok((vault.revision, vault.clone()))
}

fn commit_vault_mutation(
    state: &AppState,
    expected_revision: u64,
    mut candidate: UnlockedVault,
) -> Result<(), String> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    let current = guard
        .as_ref()
        .ok_or_else(|| "Vault was locked while saving changes".to_string())?;
    if current.revision != expected_revision {
        return Err("Vault changed while saving; retry the operation".into());
    }
    candidate.revision = expected_revision
        .checked_add(1)
        .ok_or_else(|| "Vault revision limit reached".to_string())?;
    *guard = Some(candidate);
    Ok(())
}

fn mutate_vault<T>(
    state: &AppState,
    persist_candidate: impl FnOnce(&UnlockedVault) -> Result<(), String>,
    mutation: impl FnOnce(&mut UnlockedVault) -> Result<T, String>,
) -> Result<T, String> {
    let _mutation_guard = lock_mutations(state)?;
    let (expected_revision, mut candidate) = begin_vault_mutation(state)?;
    let result = mutation(&mut candidate)?;
    persist_candidate(&candidate)?;
    commit_vault_mutation(state, expected_revision, candidate)?;
    Ok(result)
}

fn persist_vault_mutation<T>(
    state: &AppState,
    path: &std::path::PathBuf,
    mutation: impl FnOnce(&mut UnlockedVault) -> Result<T, String>,
) -> Result<T, String> {
    mutate_vault(state, |candidate| persist(path, candidate), mutation)
}

fn update_entry_timestamps(entry: &mut Entry, previous: Option<&Entry>, now: u64) {
    entry.updated_at = now;
    match previous {
        Some(previous) if previous.password == entry.password => {
            entry.password_changed_at = previous.password_changed_at;
            entry.password_age_tracking_started_at =
                previous.password_age_tracking_started_at;
        }
        _ => {
            entry.password_changed_at = now;
            entry.password_age_tracking_started_at = 0;
        }
    }
}

fn current_time_millis() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System clock is before the Unix epoch".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "System time is outside the supported range".to_string())
}

fn generate_ed25519_ssh_key(
    id: String,
    title: String,
    notes: String,
    favorite: bool,
    now: u64,
) -> Result<SshKey, String> {
    let title = title.trim().to_string();
    if id.is_empty() || id.chars().count() > 200 {
        return Err("SSH key identifier is invalid".into());
    }

    fn normalize_ed25519_ssh_key(
        id: String,
        title: String,
        public_key: &str,
        private_key: &str,
        notes: String,
        favorite: bool,
        now: u64,
    ) -> Result<SshKey, String> {
        let title = title.trim().to_string();
        if id.is_empty() || id.chars().count() > 200 {
            return Err("SSH key identifier is invalid".into());
        }
        if title.is_empty() || title.chars().count() > 200 {
            return Err("Enter an SSH key name of up to 200 characters".into());
        }
        if notes.chars().count() > 10_000 {
            return Err("SSH key notes are too long".into());
        }
        let mut parsed_private = PrivateKey::from_openssh(private_key)
            .map_err(|_| "Private key is not a valid OpenSSH private key".to_string())?;
        let parsed_public = PublicKey::from_openssh(public_key)
            .map_err(|_| "Public key is not a valid OpenSSH public key".to_string())?;
        if parsed_private.algorithm() != SshAlgorithm::Ed25519
            || parsed_public.algorithm() != SshAlgorithm::Ed25519
        {
            return Err("Only Ed25519 SSH keys are supported".into());
        }
        if parsed_private.public_key().key_data() != parsed_public.key_data() {
            return Err("SSH public key does not match the private key".into());
        }
        parsed_private.set_comment(title.clone());
        let normalized_public = parsed_private
            .public_key()
            .to_openssh()
            .map_err(|error| format!("Could not encode SSH public key: {error}"))?;
        let fingerprint = parsed_private
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string();
        let encoded_private = parsed_private
            .to_openssh(LineEnding::LF)
            .map_err(|error| format!("Could not encode SSH private key: {error}"))?;
        Ok(SshKey {
            id,
            title,
            algorithm: "Ed25519".into(),
            fingerprint,
            public_key: normalized_public,
            private_key: encoded_private.as_str().to_owned(),
            notes,
            favorite,
            created_at: now,
            updated_at: now,
        })
    }
    if title.is_empty() || title.chars().count() > 200 {
        return Err("Enter an SSH key name of up to 200 characters".into());
    }
    if notes.chars().count() > 10_000 {
        return Err("SSH key notes are too long".into());
    }
    let mut private_key = PrivateKey::random(&mut OsRng, SshAlgorithm::Ed25519)
        .map_err(|error| format!("Could not generate SSH key: {error}"))?;
    private_key.set_comment(title.clone());
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|error| format!("Could not encode SSH public key: {error}"))?;
    let fingerprint = private_key
        .public_key()
        .fingerprint(HashAlg::Sha256)
        .to_string();
    let encoded_private_key = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|error| format!("Could not encode SSH private key: {error}"))?;
    let private_key = encoded_private_key.as_str().to_owned();
    Ok(SshKey {
        id,
        title,
        algorithm: "Ed25519".into(),
        fingerprint,
        public_key,
        private_key,
        notes,
        favorite,
        created_at: now,
        updated_at: now,
    })
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
) -> Result<VaultPreferences, String> {
    let password = Zeroizing::new(password);
    if password.chars().count() < 12 {
        return Err("Choose a master password with at least 12 characters".into());
    }
    let path = vault_path(&app)?;
    let _mutation_guard = lock_mutations(&state)?;
    if path.exists() {
        return Err("A vault already exists".into());
    }
    let salt = fresh_salt();
    let key = derive_key(password.as_str(), &salt)?;
    let entries = Vec::new();
    let preferences = VaultPreferences::default();
    write_vault(&path, &salt, &key, &entries)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault {
        revision: 0,
        key,
        salt,
        kdf: CURRENT_KDF,
        entries,
        ssh_keys: Vec::new(),
        preferences,
    });
    Ok(preferences)
}

#[tauri::command]
pub(crate) fn unlock_vault(
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultPreferences, String> {
    let password = Zeroizing::new(password);
    let path = vault_path(&app)?;
    let _mutation_guard = lock_mutations(&state)?;
    let (key, salt, kdf, mut data) = load_vault(&path, password.as_str())?;
    if initialize_legacy_password_age_tracking(&mut data.entries, current_time_millis()?) {
        write_vault_with_kdf(
            &path,
            &salt,
            &key,
            &kdf,
            &data.entries,
            &data.ssh_keys,
            &data.preferences,
        )?;
    }
    let preferences = data.preferences;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = Some(UnlockedVault {
        revision: 0,
        key,
        salt,
        kdf,
        entries: data.entries,
        ssh_keys: data.ssh_keys,
        preferences,
    });
    Ok(preferences)
}

#[tauri::command]
pub(crate) fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let _mutation_guard = lock_mutations(&state)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| "Vault is unavailable".to_string())?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub(crate) async fn export_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<String>, String> {
    let destination = choose_backup_destination(&app).await?;
    let Some(destination) = destination else {
        return Ok(None);
    };
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "The selected backup file name is invalid".to_string())?
        .to_string();
    let vault = with_vault(&state, |vault| Ok(vault.clone()))?;
    write_vault_with_kdf(
        &destination,
        &vault.salt,
        &vault.key,
        &vault.kdf,
        &vault.entries,
        &vault.ssh_keys,
        &vault.preferences,
    )
    .map_err(|error| format!("Could not export backup: {error}"))?;
    Ok(Some(filename))
}

#[tauri::command]
pub(crate) async fn import_backup(
    password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Option<VaultSnapshot>, String> {
    let active_path = vault_path(&app)?;
    let password = Zeroizing::new(password);
    let dialog_app = app.clone();
    let selected_backup = tauri::async_runtime::spawn_blocking(move || {
        dialog_app
            .dialog()
            .file()
            .add_filter("Passman encrypted backups", &[BACKUP_EXTENSION])
            .blocking_pick_file()
    })
    .await
    .map_err(|error| format!("Could not open the backup file dialog: {error}"))?;
    let Some(selected_backup) = selected_backup else {
        return Ok(None);
    };
    let backup_path = local_backup_path(selected_backup)?;
    let (key, salt, kdf, mut data) = load_vault(&backup_path, password.as_str())
        .map_err(|error| format!("Could not restore backup: {error}"))?;
    initialize_legacy_password_age_tracking(&mut data.entries, current_time_millis()?);
    let snapshot = VaultSnapshot::from_data(&data, &kdf);
    mutate_vault(
        &state,
        |candidate| {
            persist(&active_path, candidate)
                .map_err(|error| format!("Could not restore backup: {error}"))
        },
        move |candidate| {
            candidate.key = key;
            candidate.salt = salt;
            candidate.kdf = kdf;
            candidate.entries = data.entries;
            candidate.ssh_keys = data.ssh_keys;
            candidate.preferences = data.preferences;
            Ok(())
        },
    )?;
    Ok(Some(snapshot))
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
    let _mutation_guard = lock_mutations(&state)?;
    let (expected_revision, mut candidate) = begin_vault_mutation(&state)?;
    let (_, _, _, data) = load_vault(&path, current_password.as_str())
        .map_err(|_| "Current master password is incorrect".to_string())?;
    let salt = fresh_salt();
    let key = derive_key(new_password.as_str(), &salt)?;
    candidate.key = key;
    candidate.salt = salt;
    candidate.kdf = CURRENT_KDF;
    candidate.entries = data.entries;
    candidate.ssh_keys = data.ssh_keys;
    candidate.preferences = data.preferences;
    persist(&path, &candidate)?;
    commit_vault_mutation(&state, expected_revision, candidate)?;
    Ok(())
}

#[tauri::command]
pub(crate) fn upgrade_kdf(
    current_password: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultSnapshot, String> {
    let current_password = Zeroizing::new(current_password);
    let path = vault_path(&app)?;
    let _mutation_guard = lock_mutations(&state)?;
    let (expected_revision, mut candidate) = begin_vault_mutation(&state)?;
    if !kdf_upgrade_available(&candidate.kdf) {
        return Err("Vault security parameters are already current".into());
    }
    let (loaded_key, loaded_salt, loaded_kdf, _) =
        load_vault(&path, current_password.as_str())
            .map_err(|_| "Current master password is incorrect".to_string())?;
    ensure_loaded_vault_matches_active(
        &candidate,
        &loaded_key,
        &loaded_salt,
        &loaded_kdf,
    )?;
    let salt = fresh_salt();
    let key = derive_key(current_password.as_str(), &salt)?;
    candidate.key = key;
    candidate.salt = salt;
    candidate.kdf = CURRENT_KDF;
    persist(&path, &candidate)?;
    let snapshot = VaultSnapshot::from_vault(&candidate);
    commit_vault_mutation(&state, expected_revision, candidate)?;
    Ok(snapshot)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResetResult {
    reset: bool,
    backup_file_name: Option<String>,
}

#[tauri::command]
pub(crate) async fn authenticated_reset_vault(
    current_password: String,
    create_backup: bool,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ResetResult, String> {
    let path = vault_path(&app)?;
    let current_password = Zeroizing::new(current_password);
    verify_current_master_password(&path, current_password.as_str())?;
    let backup_destination = if create_backup {
        let Some(destination) = choose_backup_destination(&app).await? else {
            return Ok(ResetResult {
                reset: false,
                backup_file_name: None,
            });
        };
        Some(destination)
    } else {
        None
    };
    let _mutation_guard = lock_mutations(&state)?;
    let (_, candidate) = begin_vault_mutation(&state)?;
    let backup_file_name = if let Some(destination) = backup_destination {
        let filename = destination
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "The selected backup file name is invalid".to_string())?
            .to_string();
        write_vault_with_kdf(
            &destination,
            &candidate.salt,
            &candidate.key,
            &candidate.kdf,
            &candidate.entries,
            &candidate.ssh_keys,
            &candidate.preferences,
        )
        .map_err(|error| format!("Could not create final backup: {error}"))?;
        Some(filename)
    } else {
        None
    };
    remove_vault_and_clear_state(&path, &state)?;
    Ok(ResetResult {
        reset: true,
        backup_file_name,
    })
}

#[tauri::command]
pub(crate) fn recovery_reset_vault(
    confirmation_phrase: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    validate_recovery_reset_phrase(&confirmation_phrase)?;
    let path = vault_path(&app)?;
    let _mutation_guard = lock_mutations(&state)?;
    remove_vault_and_clear_state(&path, &state)
}

#[tauri::command]
pub(crate) fn list_entries(
    state: tauri::State<'_, AppState>,
) -> Result<VaultSnapshot, String> {
    with_vault(&state, |vault| Ok(VaultSnapshot::from_vault(vault)))
}

#[tauri::command]
pub(crate) fn set_vault_preferences(
    preferences: VaultPreferences,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultPreferences, String> {
    let preferences = preferences.validate()?;
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, |vault| {
        vault.preferences = preferences;
        Ok(vault.preferences)
    })
}

#[tauri::command]
pub(crate) fn get_entry(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<EntryDetails, String> {
    with_vault(&state, |vault| {
        let entry = vault
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        Ok(entry_details(&vault.entries, entry))
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
    persist_vault_mutation(&state, &path, |vault| {
        let index = vault
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        let previous = vault.entries[index].totp_secret.replace(canonical.to_string());
        if let Some(mut previous) = previous {
            previous.zeroize();
        }
        Ok(summarize_entries(&vault.entries))
    })
}

#[tauri::command]
pub(crate) fn remove_totp_secret(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, |vault| {
        let index = vault
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| "Password entry not found".to_string())?;
        let previous = vault.entries[index].totp_secret.take();
        if let Some(mut previous) = previous {
            previous.zeroize();
        }
        Ok(summarize_entries(&vault.entries))
    })
}

#[tauri::command]
pub(crate) fn generate_ssh_key(
    id: String,
    title: String,
    notes: String,
    favorite: bool,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultSnapshot, String> {
    let now = current_time_millis()?;
    let ssh_key = generate_ed25519_ssh_key(id, title, notes, favorite, now)?;
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, move |vault| {
        if vault.ssh_keys.len() >= MAX_SSH_KEYS {
            return Err("Vault has reached its SSH key limit".into());
        }

        #[tauri::command]
        pub(crate) fn store_ssh_key(
            id: String,
            title: String,
            public_key: String,
            private_key: String,
            notes: String,
            favorite: bool,
            app: tauri::AppHandle,
            state: tauri::State<'_, AppState>,
        ) -> Result<VaultSnapshot, String> {
            let public_key = Zeroizing::new(public_key);
            let private_key = Zeroizing::new(private_key);
            let ssh_key = normalize_ed25519_ssh_key(
                id,
                title,
                public_key.as_str(),
                private_key.as_str(),
                notes,
                favorite,
                current_time_millis()?,
            )?;
            let path = vault_path(&app)?;
            persist_vault_mutation(&state, &path, move |vault| {
                if vault.ssh_keys.len() >= MAX_SSH_KEYS {
                    return Err("Vault has reached its SSH key limit".into());
                }
                if vault.ssh_keys.iter().any(|key| key.id == ssh_key.id) {
                    return Err("An SSH key with this identifier already exists".into());
                }
                vault.ssh_keys.push(ssh_key);
                Ok(VaultSnapshot::from_vault(vault))
            })
        }
        if vault.ssh_keys.iter().any(|key| key.id == ssh_key.id) {
            return Err("An SSH key with this identifier already exists".into());
        }
        vault.ssh_keys.push(ssh_key);
        Ok(VaultSnapshot::from_vault(vault))
    })
}

#[tauri::command]
pub(crate) fn get_ssh_key(
    id: String,
    state: tauri::State<'_, AppState>,
) -> Result<SshKeyDetails, String> {
    with_vault(&state, |vault| {
        vault
            .ssh_keys
            .iter()
            .find(|key| key.id == id)
            .map(ssh_key_details)
            .ok_or_else(|| "SSH key not found".to_string())
    })
}

#[tauri::command]
pub(crate) fn delete_ssh_key(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<VaultSnapshot, String> {
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, |vault| {
        let previous_len = vault.ssh_keys.len();
        vault.ssh_keys.retain(|key| key.id != id);
        if vault.ssh_keys.len() == previous_len {
            return Err("SSH key not found".into());
        }
        Ok(VaultSnapshot::from_vault(vault))
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
    entry.password_strength_score = evaluate_password_strength(&entry)?;
    let now = current_time_millis()?;
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, |vault| {
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
        Ok(summarize_entries(&vault.entries))
    })
}

#[tauri::command]
pub(crate) fn delete_entry(
    id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<EntrySummary>, String> {
    let path = vault_path(&app)?;
    persist_vault_mutation(&state, &path, |vault| {
        vault.entries.retain(|entry| entry.id != id);
        Ok(summarize_entries(&vault.entries))
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
            password_age_tracking_started_at: 0,
            password_strength_score: u8::MAX,
        }
    }

    fn mutation_test_state() -> AppState {
        let state = AppState::default();
        *state.vault.lock().unwrap() = Some(UnlockedVault {
            revision: 0,
            key: Zeroizing::new([7_u8; KEY_LEN]),
            salt: [8_u8; crate::models::SALT_LEN],
            kdf: CURRENT_KDF,
            entries: vec![persistence_test_entry("original secret")],
            ssh_keys: Vec::new(),
            preferences: VaultPreferences::default(),
        });
        state
    }

    fn persisted_smoke_state(path: &PathBuf, password: &str, entries: Vec<Entry>) -> AppState {
        let salt = fresh_salt();
        let key = derive_key(password, &salt).unwrap();
        write_vault(path, &salt, &key, &entries).unwrap();
        let state = AppState::default();
        *state.vault.lock().unwrap() = Some(UnlockedVault {
            revision: 0,
            key,
            salt,
            kdf: CURRENT_KDF,
            entries,
            ssh_keys: Vec::new(),
            preferences: VaultPreferences::default(),
        });
        state
    }

    #[test]
    fn backup_paths_require_the_passman_extension() {
        assert!(is_passman_backup_path(Path::new("vault.passman")));
        assert!(is_passman_backup_path(Path::new("VAULT.PASSMAN")));
        assert!(!is_passman_backup_path(Path::new("vault.json")));
        assert!(!is_passman_backup_path(Path::new("vault")));
    }

    #[test]
    fn recovery_reset_requires_the_exact_phrase() {
        assert!(validate_recovery_reset_phrase(RECOVERY_RESET_PHRASE).is_ok());
        assert!(validate_recovery_reset_phrase("reset vault").is_err());
        assert!(validate_recovery_reset_phrase("RESET VAULT ").is_err());
        assert!(validate_recovery_reset_phrase("").is_err());
    }

    #[test]
    fn authenticated_reset_password_is_verified_against_the_encrypted_vault() {
        let directory = persistence_test_directory("reset-password");
        let path = directory.join(VAULT_FILE);
        let salt = fresh_salt();
        let key = derive_key("current secure password", &salt).unwrap();
        write_vault(
            &path,
            &salt,
            &key,
            &[persistence_test_entry("stored secret")],
        )
        .unwrap();

        assert!(verify_current_master_password(&path, "current secure password").is_ok());
        assert!(verify_current_master_password(&path, "wrong password").is_err());
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn generated_ed25519_key_pair_is_valid_openssh_and_contains_no_passphrase() {
        let generated = generate_ed25519_ssh_key(
            "ssh-1".into(),
            "Production server".into(),
            "deploy key".into(),
            true,
            500,
        )
        .unwrap();
        let parsed = PrivateKey::from_openssh(&generated.private_key).unwrap();

        assert_eq!(generated.algorithm, "Ed25519");
        assert!(generated.public_key.starts_with("ssh-ed25519 "));
        assert_eq!(parsed.public_key().to_openssh().unwrap(), generated.public_key);
        assert!(generated.fingerprint.starts_with("SHA256:"));
        assert_eq!(generated.created_at, 500);
        assert_eq!(generated.updated_at, 500);
    }

    #[test]
    fn encrypted_vault_round_trips_generated_ssh_private_key() {
        let directory = persistence_test_directory("ssh-key-round-trip");
        let path = directory.join(VAULT_FILE);
        let password = "ssh vault master password";
        let state = persisted_smoke_state(&path, password, Vec::new());
        let generated = generate_ed25519_ssh_key(
            "ssh-1".into(),
            "Production server".into(),
            String::new(),
            false,
            500,
        )
        .unwrap();
        let expected_private_key = generated.private_key.clone();

        persist_vault_mutation(&state, &path, |vault| {
            vault.ssh_keys.push(generated);
            Ok(())
        })
        .unwrap();
        *state.vault.lock().unwrap() = None;
        let (_, _, _, data) = load_vault(&path, password).unwrap();

        assert_eq!(data.ssh_keys.len(), 1);
        assert_eq!(data.ssh_keys[0].private_key, expected_private_key);
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn stored_ssh_pair_must_be_ed25519_and_match() {
        let first = generate_ed25519_ssh_key(
            "first".into(),
            "First".into(),
            String::new(),
            false,
            1,
        )
        .unwrap();
        let second = generate_ed25519_ssh_key(
            "second".into(),
            "Second".into(),
            String::new(),
            false,
            1,
        )
        .unwrap();

        assert!(
            normalize_ed25519_ssh_key(
                "stored".into(),
                "Stored".into(),
                &first.public_key,
                &first.private_key,
                String::new(),
                false,
                2,
            )
            .is_ok()
        );
        assert!(
            normalize_ed25519_ssh_key(
                "mismatch".into(),
                "Mismatch".into(),
                &first.public_key,
                &second.private_key,
                String::new(),
                false,
                2,
            )
            .unwrap_err()
            .contains("does not match")
        );
    }

    #[test]
    fn smoke_journey_create_save_lock_unlock_and_read() {
        let directory = persistence_test_directory("smoke-create-unlock");
        let path = directory.join(VAULT_FILE);
        let password = "initial master password";
        let state = persisted_smoke_state(&path, password, Vec::new());
        let mut entry = persistence_test_entry("stored secret");
        entry.updated_at = 0;
        entry.password_changed_at = 0;
        entry.password_strength_score = evaluate_password_strength(&entry).unwrap();
        let now = current_time_millis().unwrap();

        persist_vault_mutation(&state, &path, |vault| {
            update_entry_timestamps(&mut entry, None, now);
            vault.entries.push(entry);
            Ok(())
        })
        .unwrap();
        *state.vault.lock().unwrap() = None;
        assert!(with_vault(&state, |_| Ok(())).is_err());

        let (key, salt, kdf, data) = load_vault(&path, password).unwrap();
        *state.vault.lock().unwrap() = Some(UnlockedVault {
            revision: 0,
            key,
            salt,
            kdf,
            entries: data.entries,
            ssh_keys: data.ssh_keys,
            preferences: data.preferences,
        });
        let stored_password = with_vault(&state, |vault| {
            vault
                .entries
                .iter()
                .find(|candidate| candidate.id == "persistence-entry")
                .map(|candidate| candidate.password.clone())
                .ok_or_else(|| "Password entry not found".to_string())
        })
        .unwrap();

        assert_eq!(stored_password, "stored secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn smoke_journey_export_change_restore_and_recover_entries() {
        let directory = persistence_test_directory("smoke-backup-restore");
        let active_path = directory.join(VAULT_FILE);
        let backup_path = directory.join("smoke.passman");
        let password = "initial master password";
        let state = persisted_smoke_state(
            &active_path,
            password,
            vec![persistence_test_entry("recoverable secret")],
        );

        let exported = with_vault(&state, |vault| Ok(vault.clone())).unwrap();
        write_vault_with_kdf(
            &backup_path,
            &exported.salt,
            &exported.key,
            &exported.kdf,
            &exported.entries,
            &exported.ssh_keys,
            &exported.preferences,
        )
        .unwrap();
        persist_vault_mutation(&state, &active_path, |vault| {
            vault.entries[0].password = "changed secret".into();
            Ok(())
        })
        .unwrap();

        let (key, salt, kdf, data) = load_vault(&backup_path, password).unwrap();
        mutate_vault(
            &state,
            |candidate| persist(&active_path, candidate),
            move |candidate| {
                candidate.key = key;
                candidate.salt = salt;
                candidate.kdf = kdf;
                candidate.entries = data.entries;
                candidate.ssh_keys = data.ssh_keys;
                candidate.preferences = data.preferences;
                Ok(())
            },
        )
        .unwrap();
        let (_, _, _, restored) = load_vault(&active_path, password).unwrap();

        assert_eq!(restored.entries[0].password, "recoverable secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn smoke_journey_master_password_change_rejects_old_and_accepts_new() {
        let directory = persistence_test_directory("smoke-password-change");
        let path = directory.join(VAULT_FILE);
        let current_password = "initial master password";
        let new_password = "replacement master password";
        let state = persisted_smoke_state(
            &path,
            current_password,
            vec![persistence_test_entry("preserved secret")],
        );

        let (expected_revision, mut candidate) = begin_vault_mutation(&state).unwrap();
        let (_, _, _, data) = load_vault(&path, current_password).unwrap();
        let salt = fresh_salt();
        let key = derive_key(new_password, &salt).unwrap();
        candidate.key = key;
        candidate.salt = salt;
        candidate.kdf = CURRENT_KDF;
        candidate.entries = data.entries;
        candidate.ssh_keys = data.ssh_keys;
        candidate.preferences = data.preferences;
        persist(&path, &candidate).unwrap();
        commit_vault_mutation(&state, expected_revision, candidate).unwrap();
        *state.vault.lock().unwrap() = None;

        assert!(load_vault(&path, current_password).is_err());
        let (_, _, _, unlocked) = load_vault(&path, new_password).unwrap();
        assert_eq!(unlocked.entries[0].password, "preserved secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn smoke_journey_reset_rejects_wrong_confirmation_then_removes_vault() {
        let directory = persistence_test_directory("smoke-reset");
        let path = directory.join(VAULT_FILE);
        let state = persisted_smoke_state(&path, "initial master password", Vec::new());

        assert!(validate_recovery_reset_phrase("reset vault").is_err());
        assert!(path.exists());
        validate_recovery_reset_phrase(RECOVERY_RESET_PHRASE).unwrap();
        remove_vault_and_clear_state(&path, &state).unwrap();

        assert!(!path.exists());
        assert!(state.vault.lock().unwrap().is_none());
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn kdf_upgrade_rejects_metadata_or_key_that_differs_from_active_state() {
        let state = mutation_test_state();
        let guard = state.vault.lock().unwrap();
        let active = guard.as_ref().unwrap();
        assert!(
            ensure_loaded_vault_matches_active(
                active,
                active.key.as_ref(),
                &active.salt,
                &active.kdf,
            )
            .is_ok()
        );

        let different_key = [9_u8; KEY_LEN];
        assert!(
            ensure_loaded_vault_matches_active(
                active,
                &different_key,
                &active.salt,
                &active.kdf,
            )
            .is_err()
        );
        let mut different_kdf = active.kdf;
        different_kdf.iterations += 1;
        assert!(
            ensure_loaded_vault_matches_active(
                active,
                active.key.as_ref(),
                &active.salt,
                &different_kdf,
            )
            .is_err()
        );
    }

    #[test]
    fn vault_mutation_releases_state_lock_during_persistence_and_increments_revision() {
        let state = mutation_test_state();

        let result = mutate_vault(
            &state,
            |_| {
                assert!(state.vault.try_lock().is_ok());
                Ok(())
            },
            |candidate| {
                candidate.preferences.password_age_limit_days = 120;
                Ok("saved")
            },
        )
        .unwrap();

        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().unwrap();
        assert_eq!(result, "saved");
        assert_eq!(vault.revision, 1);
        assert_eq!(vault.preferences.password_age_limit_days, 120);
    }

    #[test]
    fn failed_persistence_does_not_commit_candidate_state() {
        let state = mutation_test_state();

        let error = mutate_vault(
            &state,
            |_| Err("simulated persistence failure".into()),
            |candidate| {
                candidate.preferences.password_age_limit_days = 120;
                Ok(())
            },
        )
        .unwrap_err();

        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().unwrap();
        assert_eq!(error, "simulated persistence failure");
        assert_eq!(vault.revision, 0);
        assert_eq!(
            vault.preferences.password_age_limit_days,
            crate::models::DEFAULT_PASSWORD_AGE_LIMIT_DAYS
        );
    }

    #[test]
    fn stale_vault_mutation_is_rejected_without_replacing_active_state() {
        let state = mutation_test_state();

        let error = mutate_vault(
            &state,
            |_| {
                state.vault.lock().unwrap().as_mut().unwrap().revision += 1;
                Ok(())
            },
            |candidate| {
                candidate.preferences.password_age_limit_days = 120;
                Ok(())
            },
        )
        .unwrap_err();

        let guard = state.vault.lock().unwrap();
        let vault = guard.as_ref().unwrap();
        assert_eq!(error, "Vault changed while saving; retry the operation");
        assert_eq!(vault.revision, 1);
        assert_eq!(
            vault.preferences.password_age_limit_days,
            crate::models::DEFAULT_PASSWORD_AGE_LIMIT_DAYS
        );
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
            password_age_tracking_started_at: 0,
            password_strength_score: u8::MAX,
        }];
        let key = [7_u8; KEY_LEN];
        let preferences = VaultPreferences::default();
        let (nonce, ciphertext) = seal(&key, &entries, &[], &preferences).unwrap();
        assert_eq!(
            open(&key, &nonce, &ciphertext).unwrap().entries[0].password,
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
        previous.password_age_tracking_started_at = 400;
        let mut metadata_edit = previous.clone();
        metadata_edit.title = "Renamed".into();
        update_entry_timestamps(&mut metadata_edit, Some(&previous), 500);
        assert_eq!(metadata_edit.updated_at, 500);
        assert_eq!(metadata_edit.password_changed_at, 0);
        assert_eq!(metadata_edit.password_age_tracking_started_at, 400);

        let mut password_edit = previous.clone();
        password_edit.password = "new secret".into();
        update_entry_timestamps(&mut password_edit, Some(&previous), 500);
        assert_eq!(password_edit.password_changed_at, 500);
        assert_eq!(password_edit.password_age_tracking_started_at, 0);

        let mut new_entry = persistence_test_entry("new secret");
        update_entry_timestamps(&mut new_entry, None, 700);
        assert_eq!(new_entry.password_changed_at, 700);
    }

    #[test]
    fn legacy_age_tracking_records_migration_time_once() {
        let mut entries = vec![persistence_test_entry("legacy secret")];
        entries[0].password_changed_at = 0;

        assert!(initialize_legacy_password_age_tracking(&mut entries, 500));
        assert_eq!(entries[0].password_age_tracking_started_at, 500);
        assert!(!initialize_legacy_password_age_tracking(&mut entries, 700));
        assert_eq!(entries[0].password_age_tracking_started_at, 500);
    }

    #[test]
    fn vault_preferences_enforce_password_age_bounds() {
        assert!(
            VaultPreferences {
                password_age_limit_days: 29,
            }
            .validate()
            .is_err()
        );
        assert!(
            VaultPreferences {
                password_age_limit_days: 3_651,
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            VaultPreferences {
                password_age_limit_days: 180,
            }
            .validate()
            .unwrap()
            .password_age_limit_days,
            180
        );
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
            password_age_tracking_started_at: 0,
            password_strength_score: u8::MAX,
        }];

        write_vault(&path, &salt, &key, &entries).unwrap();
        let (_, loaded_salt, loaded_kdf, loaded_data) =
            load_vault(&path, "a secure test password").unwrap();

        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded_kdf, CURRENT_KDF);
        assert_eq!(loaded_data.entries[0].password, "secret");
        assert_eq!(loaded_data.preferences, VaultPreferences::default());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_v1_vault_uses_legacy_kdf_parameters() {
        let salt = fresh_salt();
        let key = derive_key("legacy vault password", &salt).unwrap();
        let entries = vec![persistence_test_entry("legacy secret")];
        let (nonce, ciphertext) = seal_legacy_entries(&key, &entries).unwrap();
        let legacy_file = VaultFile {
            version: 1,
            kdf: None,
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        let data = serde_json::to_vec(&legacy_file).unwrap();

        let (_, loaded_salt, loaded_kdf, loaded_data) =
            load_vault_data(&data, "legacy vault password").unwrap();

        assert_eq!(loaded_salt, salt);
        assert_eq!(loaded_kdf, CURRENT_KDF);
        assert_eq!(loaded_data.entries[0].password, "legacy secret");
        assert_eq!(loaded_data.preferences, VaultPreferences::default());
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
            &[],
            &VaultPreferences::default(),
        )
        .unwrap();

        let current_file: VaultFile =
            serde_json::from_slice(&fs::read(&current_path).unwrap()).unwrap();
        let (_, _, loaded_alternate_kdf, loaded_data) =
            load_vault(&alternate_path, "alternate parameters password").unwrap();
        assert_eq!(current_file.kdf, Some(CURRENT_KDF));
        assert_eq!(loaded_alternate_kdf, alternate_kdf);
        assert_eq!(loaded_data.entries[0].password, "parameterized secret");
        remove_persistence_test_directory(&directory);
    }

    #[test]
    fn unsafe_or_unsupported_kdf_metadata_is_rejected() {
        let salt = fresh_salt();
        let key = derive_key("metadata validation password", &salt).unwrap();
        let entries = vec![persistence_test_entry("secret")];
        let (nonce, ciphertext) =
            seal(&key, &entries, &[], &VaultPreferences::default()).unwrap();
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
            password_age_tracking_started_at: 0,
            password_strength_score: u8::MAX,
        }];
        write_vault(&path, &old_salt, &old_key, &entries).unwrap();

        let new_salt = fresh_salt();
        let new_key = derive_key("new secure password", &new_salt).unwrap();
        write_vault(&path, &new_salt, &new_key, &entries).unwrap();

        assert_ne!(new_salt, old_salt);
        assert!(load_vault(&path, "old secure password").is_err());
        assert_eq!(
            load_vault(&path, "new secure password").unwrap().3.entries[0].password,
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

        let (_, _, _, data) = load_vault(&path, "persistence test password").unwrap();
        assert_eq!(data.entries[0].password, "new secret");
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

        let (_, _, _, data) = load_vault(&path, "interrupted test password").unwrap();
        assert_eq!(data.entries[0].password, "active secret");
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
