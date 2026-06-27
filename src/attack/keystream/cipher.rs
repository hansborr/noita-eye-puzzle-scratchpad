use std::fmt;

/// Adds two reduced residues modulo `n` (caller ensures `n >= 1`).
const fn add_mod(a: usize, b: usize, n: usize) -> usize {
    (a + b) % n
}

/// Subtracts `b` from `a` modulo `n` without `usize` underflow
/// (caller ensures `n >= 1`).
const fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    (a + n - (b % n)) % n
}

/// Reads `slice[idx]` as a residue modulo `n`, or `0` if out of range
/// (caller ensures `n >= 1`).
fn byte_at(slice: &[u8], idx: usize, n: usize) -> usize {
    usize::from(slice.get(idx).copied().unwrap_or(0)) % n
}

/// The keystream cipher families this module can encrypt, decrypt, and crack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeystreamFamily {
    /// Periodic additive keystream (`c_i = p_i + k_{i mod L}`).
    Vigenere,
    /// Periodic subtractive involution (`c_i = k_{i mod L} - p_i`).
    Beaufort,
    /// Autokey whose keystream is `primer ++ plaintext`.
    PlaintextAutokey,
    /// Autokey whose keystream is `primer ++ ciphertext`.
    CiphertextAutokey,
}

impl KeystreamFamily {
    /// All four families, in a stable order (the CLI default set).
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::Vigenere,
            Self::Beaufort,
            Self::PlaintextAutokey,
            Self::CiphertextAutokey,
        ]
    }

    /// Stable lowercase name (used in tables and candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vigenere => "vigenere",
            Self::Beaufort => "beaufort",
            Self::PlaintextAutokey => "autokey-pt",
            Self::CiphertextAutokey => "autokey-ct",
        }
    }
}

impl fmt::Display for KeystreamFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Combines a plaintext residue and keystream residue into a ciphertext residue
/// for `family` (caller ensures `n >= 1`).
fn encrypt_combine(family: KeystreamFamily, p: usize, k: usize, n: usize) -> usize {
    match family {
        KeystreamFamily::Beaufort => sub_mod(k, p, n),
        _ => add_mod(p, k, n),
    }
}

/// Combines a ciphertext residue and keystream residue into a plaintext residue
/// for `family` (caller ensures `n >= 1`).
fn decrypt_combine(family: KeystreamFamily, c: usize, k: usize, n: usize) -> usize {
    match family {
        KeystreamFamily::Beaufort => sub_mod(k, c, n),
        _ => sub_mod(c, k, n),
    }
}

/// The keystream residue at position `i` during encryption (caller ensures
/// `l >= 1` and `n >= 1`). Autokey families read the already-built prefix.
fn encrypt_key_value(
    family: KeystreamFamily,
    i: usize,
    l: usize,
    key: &[u8],
    plaintext: &[u8],
    cipher_so_far: &[u8],
    n: usize,
) -> usize {
    match family {
        KeystreamFamily::Vigenere | KeystreamFamily::Beaufort => byte_at(key, i % l, n),
        KeystreamFamily::PlaintextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(plaintext, i - l, n)
            }
        }
        KeystreamFamily::CiphertextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(cipher_so_far, i - l, n)
            }
        }
    }
}

/// The keystream residue at position `i` during decryption (caller ensures
/// `l >= 1` and `n >= 1`). Plaintext-autokey reads the already-recovered prefix.
fn decrypt_key_value(
    family: KeystreamFamily,
    i: usize,
    l: usize,
    key: &[u8],
    recovered: &[usize],
    ciphertext: &[u8],
    n: usize,
) -> usize {
    match family {
        KeystreamFamily::Vigenere | KeystreamFamily::Beaufort => byte_at(key, i % l, n),
        KeystreamFamily::PlaintextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                recovered.get(i - l).copied().unwrap_or(0)
            }
        }
        KeystreamFamily::CiphertextAutokey => {
            if i < l {
                byte_at(key, i, n)
            } else {
                byte_at(ciphertext, i - l, n)
            }
        }
    }
}

/// Encrypts `plaintext` (letter indices `< N`) under `key` for `family`.
///
/// An empty `key` is treated as a no-op (the plaintext is returned reduced
/// modulo `N`), so a degenerate call never panics. `alphabet_size` is clamped to
/// at least `1`.
#[must_use]
pub fn encrypt(
    family: KeystreamFamily,
    plaintext: &[u8],
    key: &[u8],
    alphabet_size: usize,
) -> Vec<u8> {
    let n = alphabet_size.max(1);
    let l = key.len();
    let mut out: Vec<u8> = Vec::with_capacity(plaintext.len());
    if l == 0 {
        out.extend(plaintext.iter().map(|&p| (usize::from(p) % n) as u8));
        return out;
    }
    for i in 0..plaintext.len() {
        let p = byte_at(plaintext, i, n);
        let k = encrypt_key_value(family, i, l, key, plaintext, &out, n);
        out.push(encrypt_combine(family, p, k, n) as u8);
    }
    out
}

/// Decrypts `ciphertext` (letter indices `< N`) under `key` for `family`,
/// writing recovered residues into `out` (reused to avoid per-call allocation in
/// the search hot loop). Caller ensures `n >= 1`.
pub(super) fn decrypt_into(
    family: KeystreamFamily,
    ciphertext: &[u8],
    key: &[u8],
    n: usize,
    out: &mut Vec<usize>,
) {
    out.clear();
    let l = key.len();
    if l == 0 {
        out.extend(ciphertext.iter().map(|&c| usize::from(c) % n));
        return;
    }
    for i in 0..ciphertext.len() {
        let c = byte_at(ciphertext, i, n);
        let k = decrypt_key_value(family, i, l, key, out, ciphertext, n);
        out.push(decrypt_combine(family, c, k, n));
    }
}

/// Decrypts `ciphertext` under `key` for `family`, returning letter indices.
///
/// An empty `key` is a no-op (mirroring [`encrypt`]); `alphabet_size` is clamped
/// to at least `1`. For any key, `encrypt(decrypt(c, k), k) == c` is an algebraic
/// identity (the round-trip gate), so the discriminating signal lives in the
/// matched-null and held-out gates, not the round trip.
#[must_use]
pub fn decrypt(
    family: KeystreamFamily,
    ciphertext: &[u8],
    key: &[u8],
    alphabet_size: usize,
) -> Vec<u8> {
    let n = alphabet_size.max(1);
    let mut out: Vec<usize> = Vec::with_capacity(ciphertext.len());
    decrypt_into(family, ciphertext, key, n, &mut out);
    out.iter().map(|&v| v as u8).collect()
}
