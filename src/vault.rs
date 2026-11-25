//! Zero-knowledge vault.
//!
//! Sealed blob layout (version 1):
//!
//! ```text
//! magic "SYV1" (4) | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE | salt (16) | nonce (12) | ciphertext+tag
//! ```
//!
//! The key is derived from the master password with Argon2id and used with
//! AES-256-GCM. The whole header is authenticated as associated data, so the
//! KDF parameters cannot be tampered with. The master password is never
//! written to disk and derived keys are zeroed after use.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SYV1";
/// Same format, written before the project was renamed from Hostdeck.
const LEGACY_MAGIC: &[u8; 4] = b"HDV1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 12 + SALT_LEN + NONCE_LEN;

/// Argon2id cost: 256 MiB memory, 3 passes, 1 lane (about 0.4 s on an M-series
/// Mac). This is four times the memory of RFC 9106's second recommended
/// setting, which makes GPU guessing proportionally more expensive. Older vaults
/// keep the cost stored in their header and are upgraded on the next save.
const M_COST: u32 = 256 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;

fn derive_key(password: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("bad KDF params: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

pub fn seal(password: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    seal_with(password, plaintext, M_COST, T_COST, P_COST)
}

fn seal_with(password: &str, plaintext: &[u8], m: u32, t: u32, p: u32) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&m.to_le_bytes());
    header.extend_from_slice(&t.to_le_bytes());
    header.extend_from_slice(&p.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let key = derive_key(password, &salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("bad key length"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &header })
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(password: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < HEADER_LEN || (&blob[..4] != MAGIC && &blob[..4] != LEGACY_MAGIC) {
        return Err(anyhow!("not a Shellyard vault, or the file is truncated"));
    }
    let u32_at = |i: usize| u32::from_le_bytes(blob[i..i + 4].try_into().unwrap());
    let (m, t, p) = (u32_at(4), u32_at(8), u32_at(12));
    // Refuse absurd parameters so a crafted file cannot exhaust memory.
    if m > 1024 * 1024 || t > 64 || p > 16 {
        return Err(anyhow!("vault uses unsupported key-derivation parameters"));
    }
    let header = &blob[..HEADER_LEN];
    let salt = &blob[16..16 + SALT_LEN];
    let nonce = &blob[16 + SALT_LEN..HEADER_LEN];
    let ciphertext = &blob[HEADER_LEN..];

    let key = derive_key(password, salt, m, t, p)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| anyhow!("bad key length"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: header })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("wrong master password or corrupted vault"))
}

/// Shortest master password accepted for a new vault or a password change.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// A rough strength estimate for a new master password, in bits of guessing
/// work. It is deliberately pessimistic: repeats, sequences and very common
/// passwords score low.
pub fn password_bits(pw: &str) -> f64 {
    const COMMON: &[&str] = &[
        "password", "passw0rd", "qwerty", "123456", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
        "master", "shellyard", "abc123", "111111", "sunshine", "football", "baseball", "trustno1", "secret",
    ];
    let lower = pw.to_lowercase();
    if COMMON.iter().any(|c| lower.contains(c)) && lower.chars().count() < 20 {
        return 10.0;
    }
    let (mut lo, mut up, mut dig, mut sym, mut other) = (false, false, false, false, false);
    for c in pw.chars() {
        match c {
            'a'..='z' => lo = true,
            'A'..='Z' => up = true,
            '0'..='9' => dig = true,
            c if c.is_ascii() => sym = true,
            _ => other = true,
        }
    }
    let pool = [(lo, 26.0), (up, 26.0), (dig, 10.0), (sym, 33.0), (other, 100.0)]
        .iter()
        .filter(|(on, _)| *on)
        .map(|(_, n)| n)
        .sum::<f64>()
        .max(1.0);
    // Count only characters that are not a repeat of, or one step from, the previous one.
    let chars: Vec<char> = pw.chars().collect();
    let mut effective = 0.0;
    for (i, c) in chars.iter().enumerate() {
        let predictable = i > 0 && {
            let d = *c as i64 - chars[i - 1] as i64;
            d.abs() <= 1
        };
        effective += if predictable { 0.25 } else { 1.0 };
    }
    effective * pool.log2()
}

/// `Err(reason)` if `pw` is too weak to protect a vault.
pub fn check_new_password(pw: &str) -> Result<(), String> {
    if pw.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("Use at least {MIN_PASSWORD_CHARS} characters. A few unrelated words work well."));
    }
    if password_bits(pw) < 60.0 {
        return Err("This password is easy to guess. Make it longer or less predictable.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_are_rejected() {
        for pw in ["short", "aaaaaaaaaaaaaaaa", "abcdefghijklmnop", "Password123456", "qwerty12345678", "123456789012"] {
            assert!(check_new_password(pw).is_err(), "{pw} should be rejected");
        }
        for pw in ["correct horse battery staple", "vY7#qL2!mZ9p", "tiltas-obuolys-vakaras-42"] {
            assert!(check_new_password(pw).is_ok(), "{pw} should be accepted");
        }
    }

    #[test]
    fn new_vaults_use_current_cost_and_old_cost_still_opens() {
        let blob = seal("pw", b"x").unwrap();
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), M_COST);
        // A vault sealed with the earlier 64 MiB cost must still open.
        let old = seal_with("pw", b"old", 64 * 1024, 3, 1).unwrap();
        assert_eq!(open("pw", &old).unwrap().as_slice(), b"old");
    }

    #[test]
    fn legacy_magic_still_opens() {
        let mut blob = seal_with("pw", b"old", 1024, 1, 1).unwrap();
        blob[..4].copy_from_slice(LEGACY_MAGIC); // the header is AAD, so re-seal under the old magic
        assert!(open("pw", &blob).is_err(), "changing the magic must break authentication");
        let mut header = blob[..HEADER_LEN].to_vec();
        let salt = &blob[16..16 + SALT_LEN];
        let nonce = &blob[16 + SALT_LEN..HEADER_LEN];
        let key = derive_key("pw", salt, 1024, 1, 1).unwrap();
        let ct = Aes256Gcm::new_from_slice(key.as_ref())
            .unwrap()
            .encrypt(Nonce::from_slice(nonce), Payload { msg: b"old", aad: &header })
            .unwrap();
        header.extend_from_slice(&ct);
        assert_eq!(open("pw", &header).unwrap().as_slice(), b"old");
    }

    /// Random and mutated input must give an error, never a panic.
    #[test]
    fn fuzz_open_never_panics() {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        // Cheap KDF cost so hundreds of attempts run quickly.
        let good = seal_with("pw", b"payload", 1024, 1, 1).unwrap();
        for i in 0..400 {
            let blob: Vec<u8> = if i % 2 == 0 {
                let n = rng.gen_range(0..120);
                (0..n).map(|_| rng.gen()).collect()
            } else {
                let mut b = good.clone();
                let at = rng.gen_range(0..b.len());
                b[at] ^= 1 << rng.gen_range(0..8);
                b.truncate(rng.gen_range(at.max(1)..=b.len()));
                b
            };
            // Skip blobs whose (mutated) cost would make a test run take minutes.
            if blob.len() >= 16 && &blob[..4] == MAGIC {
                let m = u32::from_le_bytes(blob[4..8].try_into().unwrap());
                let t = u32::from_le_bytes(blob[8..12].try_into().unwrap());
                if m > 4096 || t > 2 {
                    continue;
                }
            }
            assert!(open("pw", &blob).is_err());
        }
    }

    #[test]
    fn roundtrip() {
        let blob = seal("correct horse", b"hosts-json").unwrap();
        assert_eq!(open("correct horse", &blob).unwrap().as_slice(), b"hosts-json");
    }

    #[test]
    fn wrong_password_fails() {
        let blob = seal("right", b"secret").unwrap();
        assert!(open("wrong", &blob).is_err());
    }

    #[test]
    fn fresh_salt_and_nonce_each_seal() {
        let a = seal("pw", b"same").unwrap();
        let b = seal("pw", b"same").unwrap();
        assert_ne!(a[16..HEADER_LEN], b[16..HEADER_LEN]);
    }

    #[test]
    fn tampered_header_fails() {
        let mut blob = seal("pw", b"data").unwrap();
        blob[8] ^= 1; // flip a bit in t_cost
        assert!(open("pw", &blob).is_err());
    }
}

#[cfg(test)]
mod bench {
    /// `cargo test --release kdf_timing -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn kdf_timing() {
        for (m, t, p) in [(64 * 1024, 3, 1), (64 * 1024, 3, 4), (128 * 1024, 3, 1), (256 * 1024, 3, 1), (256 * 1024, 2, 4)] {
            let start = std::time::Instant::now();
            super::derive_key("password", &[0u8; 16], m, t, p).unwrap();
            println!("m={} MiB t={t} p={p}: {:?}", m / 1024, start.elapsed());
        }
    }
}
