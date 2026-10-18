use serde::Deserializer;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

pub(crate) const VAULT_FILE: &str = "vault.json";
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const MAX_ENTRIES: usize = 100_000;
pub(crate) const CURRENT_VAULT_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum KdfAlgorithm {
    Argon2id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KdfParameters {
    pub(crate) algorithm: KdfAlgorithm,
    pub(crate) version: u32,
    pub(crate) memory_kib: u32,
    pub(crate) iterations: u32,
    pub(crate) parallelism: u32,
    pub(crate) output_length: u32,
}

pub(crate) const CURRENT_KDF: KdfParameters = KdfParameters {
    algorithm: KdfAlgorithm::Argon2id,
    version: 0x13,
    memory_kib: 19_456,
    iterations: 2,
    parallelism: 1,
    output_length: KEY_LEN as u32,
};

pub(crate) const LEGACY_V1_KDF: KdfParameters = CURRENT_KDF;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultFile {
    pub(crate) version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kdf: Option<KdfParameters>,
    pub(crate) salt: String,
    pub(crate) nonce: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) website: String,
    pub(crate) notes: String,
    #[serde(default, deserialize_with = "deserialize_totp_secret")]
    pub(crate) totp_secret: Option<String>,
    #[serde(default)]
    pub(crate) favorite: bool,
    pub(crate) updated_at: u64,
    #[serde(default)]
    pub(crate) password_changed_at: u64,
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
pub(crate) struct EntrySummary {
    id: String,
    title: String,
    username: String,
    website: String,
    has_totp: bool,
    favorite: bool,
    updated_at: u64,
    password_changed_at: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EntryDetails {
    id: String,
    title: String,
    username: String,
    password: String,
    website: String,
    notes: String,
    favorite: bool,
    updated_at: u64,
    password_changed_at: u64,
    has_totp: bool,
}

fn password_changed_at(entry: &Entry) -> u64 {
    if entry.password_changed_at == 0 {
        entry.updated_at
    } else {
        entry.password_changed_at
    }
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
            password_changed_at: password_changed_at(entry),
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
            has_totp: entry.totp_secret.is_some(),
            favorite: entry.favorite,
            updated_at: entry.updated_at,
            password_changed_at: password_changed_at(entry),
        }
    }
}

#[derive(Default)]
pub(crate) struct AppState {
    pub(crate) vault: Mutex<Option<UnlockedVault>>,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Ok(vault) = self.vault.get_mut() {
            *vault = None;
        }
    }
}

pub(crate) struct UnlockedVault {
    pub(crate) key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) kdf: KdfParameters,
    pub(crate) entries: Vec<Entry>,
}
