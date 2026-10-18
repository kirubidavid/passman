use crate::{
    crypto::{derive_key_with_kdf, open, seal},
    models::{
        CURRENT_KDF, CURRENT_VAULT_VERSION, Entry, KEY_LEN, KdfParameters, LEGACY_V1_KDF,
        NONCE_LEN, SALT_LEN, UnlockedVault, VAULT_FILE, VaultData, VaultFile,
        VaultPreferences,
    },
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use tauri::Manager;
use zeroize::Zeroizing;

const TEMP_FILE_ATTEMPTS: usize = 16;

pub(crate) fn vault_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| format!("Could not create vault directory: {e}"))?;
    Ok(dir.join(VAULT_FILE))
}

fn create_unique_temp_file(path: &Path) -> Result<(PathBuf, File), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = path
        .file_name()
        .ok_or_else(|| "Vault destination has no file name".to_string())?;
    for _ in 0..TEMP_FILE_ATTEMPTS {
        let mut temp_name = OsString::from(".");
        temp_name.push(filename);
        temp_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            OsRng.next_u64()
        ));
        let temp_path = parent.join(temp_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Could not create temporary vault file: {error}")),
        }
    }
    Err("Could not allocate a unique temporary vault file".into())
}

fn cleanup_failed_temp(temp_path: &Path, primary_error: String) -> String {
    match fs::remove_file(temp_path) {
        Ok(()) => primary_error,
        Err(error) if error.kind() == io::ErrorKind::NotFound => primary_error,
        Err(error) => {
            format!("{primary_error}; could not remove temporary vault file: {error}")
        }
    }
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("Could not synchronize vault directory metadata: {error}"))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

pub(crate) fn atomic_write_with(
    path: &Path,
    data: &[u8],
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<(), String> {
    let (temp_path, mut temp_file) = create_unique_temp_file(path)?;
    let write_result = temp_file
        .write_all(data)
        .and_then(|()| temp_file.flush())
        .and_then(|()| temp_file.sync_all());
    drop(temp_file);
    if let Err(error) = write_result {
        return Err(cleanup_failed_temp(
            &temp_path,
            format!("Could not write temporary vault file: {error}"),
        ));
    }
    if let Err(error) = replace(&temp_path, path) {
        return Err(cleanup_failed_temp(
            &temp_path,
            format!("Could not replace vault file: {error}"),
        ));
    }
    if let Err(error) = sync_parent_directory(path) {
        eprintln!("Passman warning: {error}");
    }
    Ok(())
}

pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    atomic_write_with(path, data, |from, to| fs::rename(from, to))
}

pub(crate) fn write_vault(
    path: &PathBuf,
    salt: &[u8; SALT_LEN],
    key: &[u8; KEY_LEN],
    entries: &[Entry],
) -> Result<(), String> {
    write_vault_with_kdf(
        path,
        salt,
        key,
        &CURRENT_KDF,
        entries,
        &VaultPreferences::default(),
    )
}

pub(crate) fn write_vault_with_kdf(
    path: &PathBuf,
    salt: &[u8; SALT_LEN],
    key: &[u8; KEY_LEN],
    kdf: &KdfParameters,
    entries: &[Entry],
    preferences: &VaultPreferences,
) -> Result<(), String> {
    let preferences = preferences.validate()?;
    let (nonce, ciphertext) = seal(key, entries, &preferences)?;
    let file = VaultFile {
        version: CURRENT_VAULT_VERSION,
        kdf: Some(*kdf),
        salt: BASE64.encode(salt),
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    };
    let data =
        serde_json::to_vec(&file).map_err(|e| format!("Could not encode vault file: {e}"))?;
    atomic_write(path, &data)
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    let bytes = BASE64
        .decode(value)
        .map_err(|_| format!("Invalid vault {field}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("Invalid vault {field}"))
}

pub(crate) fn load_vault(
    path: &PathBuf,
    password: &str,
) -> Result<
    (
        Zeroizing<[u8; KEY_LEN]>,
        [u8; SALT_LEN],
        KdfParameters,
        VaultData,
    ),
    String,
> {
    let data = fs::read(path).map_err(|e| format!("Could not read vault: {e}"))?;
    load_vault_data(&data, password)
}

pub(crate) fn load_vault_data(
    data: &[u8],
    password: &str,
) -> Result<
    (
        Zeroizing<[u8; KEY_LEN]>,
        [u8; SALT_LEN],
        KdfParameters,
        VaultData,
    ),
    String,
> {
    if data.len() > 64 * 1024 * 1024 {
        return Err("Vault file is larger than the supported limit".into());
    }
    let file: VaultFile =
        serde_json::from_slice(data).map_err(|_| "Vault file is invalid".to_string())?;
    let kdf = match file.version {
        1 => LEGACY_V1_KDF,
        CURRENT_VAULT_VERSION => file
            .kdf
            .ok_or_else(|| "Vault KDF parameters are missing".to_string())?,
        _ => return Err("This vault version is not supported".into()),
    };
    let salt = decode_fixed::<SALT_LEN>(&file.salt, "salt")?;
    let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
    let ciphertext = BASE64
        .decode(file.ciphertext)
        .map_err(|_| "Invalid vault ciphertext".to_string())?;
    let key = derive_key_with_kdf(password, &salt, &kdf)?;
    let data = open(&key, &nonce, &ciphertext)?;
    Ok((key, salt, kdf, data))
}

pub(crate) fn persist(path: &PathBuf, vault: &UnlockedVault) -> Result<(), String> {
    write_vault_with_kdf(
        path,
        &vault.salt,
        &vault.key,
        &vault.kdf,
        &vault.entries,
        &vault.preferences,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{derive_key, fresh_salt},
        models::KdfAlgorithm,
    };

    fn test_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "passman-persistence-{name}-{}-{}",
            std::process::id(),
            OsRng.next_u64()
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }

    fn remove_test_directory(directory: &Path) {
        for entry in fs::read_dir(directory).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    fn entry(id: &str, title: &str, password: &str) -> Entry {
        Entry {
            id: id.into(),
            title: title.into(),
            username: "person@example.com".into(),
            password: password.into(),
            website: "https://example.com".into(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
            password_changed_at: 1,
            password_strength_score: u8::MAX,
        }
    }

    #[test]
    fn encrypted_vault_persists_crud_lifecycle() {
        let directory = test_directory("crud");
        let path = directory.join(VAULT_FILE);
        let salt = fresh_salt();
        let key = derive_key("persistence lifecycle password", &salt).unwrap();
        let mut vault = UnlockedVault {
            key,
            salt,
            kdf: CURRENT_KDF,
            entries: Vec::new(),
            preferences: VaultPreferences {
                password_age_limit_days: 120,
            },
        };
        persist(&path, &vault).unwrap();

        vault
            .entries
            .push(entry("mail", "Personal Mail", "initial secret"));
        persist(&path, &vault).unwrap();
        let (_, _, _, created) =
            load_vault(&path, "persistence lifecycle password").unwrap();
        assert_eq!(created.entries.len(), 1);
        assert_eq!(created.entries[0].title, "Personal Mail");
        assert_eq!(created.preferences.password_age_limit_days, 120);

        vault.entries[0].title = "Updated Mail".into();
        vault.entries[0].password = "updated secret".into();
        persist(&path, &vault).unwrap();
        let (_, _, _, updated) =
            load_vault(&path, "persistence lifecycle password").unwrap();
        assert_eq!(updated.entries[0].title, "Updated Mail");
        assert_eq!(updated.entries[0].password, "updated secret");
        assert_eq!(updated.preferences.password_age_limit_days, 120);

        vault.entries.clear();
        persist(&path, &vault).unwrap();
        let (_, _, _, deleted) =
            load_vault(&path, "persistence lifecycle password").unwrap();
        assert!(deleted.entries.is_empty());
        assert_eq!(deleted.preferences.password_age_limit_days, 120);
        remove_test_directory(&directory);
    }

    #[test]
    fn malformed_and_incomplete_vault_files_are_rejected() {
        assert_eq!(
            load_vault_data(b"{not-json", "irrelevant").unwrap_err(),
            "Vault file is invalid"
        );

        let missing_kdf = br#"{
            "version": 2,
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "ciphertext": "AA=="
        }"#;
        assert_eq!(
            load_vault_data(missing_kdf, "irrelevant").unwrap_err(),
            "Vault KDF parameters are missing"
        );
    }

    #[test]
    fn corrupted_ciphertext_and_wrong_password_fail_authentication() {
        let salt = fresh_salt();
        let key = derive_key("correct persistence password", &salt).unwrap();
        let entries = vec![entry("mail", "Mail", "secret")];
        let (nonce, ciphertext) =
            seal(&key, &entries, &VaultPreferences::default()).unwrap();
        let mut file = VaultFile {
            version: CURRENT_VAULT_VERSION,
            kdf: Some(CURRENT_KDF),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(&ciphertext),
        };
        let valid_data = serde_json::to_vec(&file).unwrap();

        assert!(load_vault_data(&valid_data, "wrong persistence password").is_err());

        let mut corrupted = ciphertext;
        corrupted[0] ^= 0xff;
        file.ciphertext = BASE64.encode(corrupted);
        assert!(load_vault_data(
            &serde_json::to_vec(&file).unwrap(),
            "correct persistence password"
        )
        .is_err());
    }

    #[test]
    fn invalid_envelope_fields_and_unsafe_kdf_costs_are_rejected() {
        let salt = fresh_salt();
        let key = derive_key("envelope validation password", &salt).unwrap();
        let entries = vec![entry("mail", "Mail", "secret")];
        let (nonce, ciphertext) =
            seal(&key, &entries, &VaultPreferences::default()).unwrap();
        let mut file = VaultFile {
            version: CURRENT_VAULT_VERSION,
            kdf: Some(CURRENT_KDF),
            salt: "not-base64".into(),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        };
        assert_eq!(
            load_vault_data(
                &serde_json::to_vec(&file).unwrap(),
                "envelope validation password"
            )
            .unwrap_err(),
            "Invalid vault salt"
        );

        file.salt = BASE64.encode(salt);
        file.kdf = Some(KdfParameters {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 262_145,
            ..CURRENT_KDF
        });
        assert!(load_vault_data(
            &serde_json::to_vec(&file).unwrap(),
            "envelope validation password"
        )
        .unwrap_err()
        .contains("safety limits"));
    }
}
