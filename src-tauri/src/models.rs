use serde::Deserializer;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Mutex};
use zeroize::{Zeroize, Zeroizing};
use zxcvbn::zxcvbn;

pub(crate) const VAULT_FILE: &str = "vault.json";
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const MAX_ENTRIES: usize = 100_000;
pub(crate) const CURRENT_VAULT_VERSION: u8 = 2;
pub(crate) const DEFAULT_PASSWORD_AGE_LIMIT_DAYS: u32 = 90;
pub(crate) const MIN_PASSWORD_AGE_LIMIT_DAYS: u32 = 30;
pub(crate) const MAX_PASSWORD_AGE_LIMIT_DAYS: u32 = 3_650;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, zeroize::Zeroize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultPreferences {
    pub(crate) password_age_limit_days: u32,
}

impl Default for VaultPreferences {
    fn default() -> Self {
        Self {
            password_age_limit_days: DEFAULT_PASSWORD_AGE_LIMIT_DAYS,
        }
    }
}

impl VaultPreferences {
    pub(crate) fn validate(self) -> Result<Self, String> {
        if !(MIN_PASSWORD_AGE_LIMIT_DAYS..=MAX_PASSWORD_AGE_LIMIT_DAYS)
            .contains(&self.password_age_limit_days)
        {
            return Err(format!(
                "Password age must be between {MIN_PASSWORD_AGE_LIMIT_DAYS} and {MAX_PASSWORD_AGE_LIMIT_DAYS} days"
            ));
        }
        Ok(self)
    }
}

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
    #[serde(default)]
    pub(crate) password_age_tracking_started_at: u64,
    #[serde(default = "unknown_password_strength_score")]
    pub(crate) password_strength_score: u8,
}

fn unknown_password_strength_score() -> u8 {
    u8::MAX
}

#[derive(Debug, Serialize, Deserialize, zeroize::Zeroize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultData {
    pub(crate) entries: Vec<Entry>,
    #[serde(default)]
    pub(crate) preferences: VaultPreferences,
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
    password_age_tracking_started_at: u64,
    password_strength_score: u8,
    duplicate_password: bool,
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
    password_age_tracking_started_at: u64,
    has_totp: bool,
    password_strength_score: u8,
    duplicate_password: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultSnapshot {
    pub(crate) entries: Vec<EntrySummary>,
    pub(crate) preferences: VaultPreferences,
}

impl VaultSnapshot {
    pub(crate) fn from_vault(vault: &UnlockedVault) -> Self {
        Self {
            entries: summarize_entries(&vault.entries),
            preferences: vault.preferences,
        }
    }

    pub(crate) fn from_data(data: &VaultData) -> Self {
        Self {
            entries: summarize_entries(&data.entries),
            preferences: data.preferences,
        }
    }
}

pub(crate) fn initialize_legacy_password_age_tracking(
    entries: &mut [Entry],
    tracking_started_at: u64,
) -> bool {
    let mut changed = false;
    for entry in entries {
        if entry.password_changed_at == 0 && entry.password_age_tracking_started_at == 0 {
            entry.password_age_tracking_started_at = tracking_started_at;
            changed = true;
        }
    }
    changed
}

pub(crate) fn evaluate_password_strength(entry: &Entry) -> Result<u8, String> {
    let password_sample = Zeroizing::new(entry.password.chars().take(256).collect::<String>());
    zxcvbn(
        password_sample.as_str(),
        &[
            entry.title.as_str(),
            entry.username.as_str(),
            entry.website.as_str(),
        ],
    )
    .map(|estimate| estimate.score())
    .map_err(|_| "Could not evaluate password strength".to_string())
}

fn entry_summary(
    entry: &Entry,
    password_strength_score: u8,
    duplicate_password: bool,
) -> EntrySummary {
    EntrySummary {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        website: entry.website.clone(),
        has_totp: entry.totp_secret.is_some(),
        favorite: entry.favorite,
        updated_at: entry.updated_at,
        password_changed_at: entry.password_changed_at,
        password_age_tracking_started_at: entry.password_age_tracking_started_at,
        password_strength_score,
        duplicate_password,
    }
}

pub(crate) fn summarize_entries(entries: &[Entry]) -> Vec<EntrySummary> {
    let mut password_counts = HashMap::with_capacity(entries.len());
    for entry in entries {
        *password_counts.entry(entry.password.as_str()).or_insert(0_usize) += 1;
    }
    entries
        .iter()
        .map(|entry| {
            entry_summary(
                entry,
                entry.password_strength_score,
                password_counts
                    .get(entry.password.as_str())
                    .is_some_and(|count| *count > 1),
            )
        })
        .collect()
}

pub(crate) fn entry_details(entries: &[Entry], entry: &Entry) -> EntryDetails {
    let duplicate_password = entries
        .iter()
        .filter(|candidate| candidate.password == entry.password)
        .take(2)
        .count()
        > 1;
    EntryDetails {
        id: entry.id.clone(),
        title: entry.title.clone(),
        username: entry.username.clone(),
        password: entry.password.clone(),
        website: entry.website.clone(),
        notes: entry.notes.clone(),
        favorite: entry.favorite,
        updated_at: entry.updated_at,
        password_changed_at: entry.password_changed_at,
        password_age_tracking_started_at: entry.password_age_tracking_started_at,
        has_totp: entry.totp_secret.is_some(),
        password_strength_score: entry.password_strength_score,
        duplicate_password,
    }
}

#[derive(Default)]
pub(crate) struct AppState {
    pub(crate) vault: Mutex<Option<UnlockedVault>>,
    pub(crate) mutation: Mutex<()>,
}

impl Drop for AppState {
    fn drop(&mut self) {
        if let Ok(vault) = self.vault.get_mut() {
            *vault = None;
        }
    }
}

#[derive(Clone)]
pub(crate) struct UnlockedVault {
    pub(crate) revision: u64,
    pub(crate) key: Zeroizing<[u8; KEY_LEN]>,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) kdf: KdfParameters,
    pub(crate) entries: Vec<Entry>,
    pub(crate) preferences: VaultPreferences,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, password: &str) -> Entry {
        let mut entry = Entry {
            id: id.into(),
            title: format!("Account {id}"),
            username: format!("user-{id}"),
            password: password.into(),
            website: String::new(),
            notes: String::new(),
            totp_secret: None,
            favorite: false,
            updated_at: 1,
            password_changed_at: 1,
            password_age_tracking_started_at: 0,
            password_strength_score: u8::MAX,
        };
        entry.password_strength_score = evaluate_password_strength(&entry).unwrap();
        entry
    }

    #[test]
    fn summaries_detect_weak_and_duplicate_passwords_without_serializing_secrets() {
        let duplicate = "password123";
        let entries = vec![
            entry("one", duplicate),
            entry("two", duplicate),
            entry("three", "v7$Qm2!zL9@xR4#pT8"),
        ];

        let summaries = summarize_entries(&entries);

        assert!(summaries[0].duplicate_password);
        assert!(summaries[1].duplicate_password);
        assert!(!summaries[2].duplicate_password);
        assert!(summaries[0].password_strength_score <= 2);
        assert!(summaries[2].password_strength_score >= 3);
        assert!(!serde_json::to_string(&summaries).unwrap().contains(duplicate));
    }

    #[test]
    fn legacy_summary_preserves_unknown_age_and_tracking_start() {
        let mut legacy = entry("legacy", "legacy secret");
        legacy.password_changed_at = 0;
        legacy.password_age_tracking_started_at = 500;

        let summaries = summarize_entries(&[legacy]);
        let encoded = serde_json::to_value(&summaries[0]).unwrap();

        assert_eq!(encoded["passwordChangedAt"], 0);
        assert_eq!(encoded["passwordAgeTrackingStartedAt"], 500);
    }
}
