//! Byte and text helpers for Commonveil's cryptography (`src/crypto/encoding.js`).
//!
//! Commonveil stores keys and ciphertexts in standard base64 with padding (not the URL-safe form
//! the protocol uses), so this has its own decoder that accepts exactly what the JavaScript
//! `fromB64` accepts: the standard alphabet, correct padding, and (like `atob`) leftover bits in
//! the last character ignored.
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};

use crate::bytes::b64u;
use crate::error::{Error, Result};

const B64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

pub fn to_b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Decode standard base64. The length must be a multiple of four with only the padding the
/// value needs, the same rule as the JavaScript regular expression.
pub fn from_b64(text: &str) -> Result<Vec<u8>> {
    let ok_chars = text.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=');
    if !ok_chars || !text.len().is_multiple_of(4) {
        return Err(Error::new("BAD_FORMAT", "Invalid base64 value"));
    }
    B64.decode(text).map_err(|_| Error::new("BAD_FORMAT", "Invalid base64 value"))
}

/// Decode and check the length in one go.
pub fn from_b64_len(text: &str, len: usize, what: &str) -> Result<Vec<u8>> {
    match from_b64(text) {
        Ok(b) if b.len() == len => Ok(b),
        _ => Err(Error::new("BAD_FORMAT", format!("Invalid {what}"))),
    }
}

pub fn to_b64url(bytes: &[u8]) -> String {
    b64u(bytes)
}

/// A random URL-safe identifier (16 bytes unless told otherwise).
pub fn random_id(byte_len: usize) -> String {
    crate::bytes::random_b64u(byte_len)
}

pub fn sha256_b64(text: &str) -> String {
    to_b64(&crate::bytes::sha256(text.as_bytes()))
}

// ---------- time ----------
//
// Commonveil's statements carry `issued_at` as `Date.prototype.toISOString()` text. Rust's clock
// isn't available in a browser's WebAssembly, so callers pass the time in (milliseconds since
// 1970) and these convert between the two forms exactly as JavaScript does.

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// `new Date(ms).toISOString()` for years 0 to 9999.
pub fn iso_from_ms(ms: i64) -> Result<String> {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return Err(Error::new("BAD_TIME", "Invalid time"));
    }
    Ok(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600_000,
        rem / 60_000 % 60,
        rem / 1000 % 60,
        rem % 1000
    ))
}

/// Milliseconds for an ISO time in the form `toISOString()` writes (`YYYY-MM-DDTHH:MM:SS.sssZ`,
/// fraction optional). Anything else is refused rather than guessed at.
pub fn ms_from_iso(text: &str) -> Result<i64> {
    let bad = || Error::new("BAD_TIME", "Invalid time");
    let b = text.as_bytes();
    let num = |from: usize, to: usize| -> Result<i64> {
        let s = text.get(from..to).ok_or_else(bad)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        s.parse().map_err(|_| bad())
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || *b.last().unwrap() != b'Z' {
        return Err(bad());
    }
    let (y, mo, d, h, mi, s) = (num(0, 4)?, num(5, 7)?, num(8, 10)?, num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let frac = match b.len() {
        20 => 0,
        24 if b[19] == b'.' => num(20, 23)?,
        _ => return Err(bad()),
    };
    let month_days = [31, if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if !(1..=12).contains(&mo) || d < 1 || d > month_days[(mo - 1) as usize] || h > 23 || mi > 59 || s > 59 {
        return Err(bad());
    }
    Ok(days_from_civil(y, mo, d) * 86_400_000 + h * 3_600_000 + mi * 60_000 + s * 1000 + frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_atob() {
        assert_eq!(from_b64("").unwrap(), b"");
        assert_eq!(from_b64("AB==").unwrap(), from_b64("AA==").unwrap());
        assert!(from_b64("AA").is_err());
        assert!(from_b64("AA=A").is_err());
        assert!(from_b64("A-_=").is_err());
        assert_eq!(to_b64(b"hi?"), "aGk/");
    }

    #[test]
    fn iso_round_trip() {
        assert_eq!(iso_from_ms(0).unwrap(), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_from_ms(1_731_628_800_123).unwrap(), "2024-11-15T00:00:00.123Z");
        assert_eq!(iso_from_ms(951_782_400_000).unwrap(), "2000-02-29T00:00:00.000Z");
        for ms in [0, 1, 951_782_400_000, 1_763_200_000_999, 4_102_444_800_000] {
            assert_eq!(ms_from_iso(&iso_from_ms(ms).unwrap()).unwrap(), ms);
        }
        assert_eq!(ms_from_iso("2026-11-15T10:00:00Z").unwrap(), ms_from_iso("2026-11-15T10:00:00.000Z").unwrap());
        assert!(ms_from_iso("2026-02-29T00:00:00.000Z").is_err());
        assert!(ms_from_iso("2026-11-15 10:00:00.000Z").is_err());
        assert!(ms_from_iso("2026-11-15T10:00:00.000+01:00").is_err());
    }
}
