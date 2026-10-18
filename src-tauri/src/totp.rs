use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha1::Sha1;
use zeroize::Zeroizing;

pub(crate) fn decode_totp_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, String> {
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

pub(crate) fn decode_normalized_totp_secret(
    normalized: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .or_else(|_| BASE32.decode(normalized.as_bytes()))
        .map_err(|_| "Authenticator secret must use Base32 characters (A–Z and 2–7)".to_string())?;
    if !(10..=64).contains(&decoded.len()) {
        return Err("Authenticator secret must decode to 10–64 bytes".into());
    }
    Ok(Zeroizing::new(decoded))
}

pub(crate) fn totp_code(secret: &[u8], unix_seconds: u64) -> Result<String, String> {
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
pub(crate) struct TotpResult {
    pub(crate) code: String,
    pub(crate) seconds_remaining: u8,
}
