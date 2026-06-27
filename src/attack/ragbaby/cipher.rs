use std::fmt;

/// Letter index of `J` (folded to `I` for bases ≤ 25).
const LETTER_J: usize = 9;

/// Letter index of `V` (folded to `U` for base 24).
const LETTER_V: usize = 21;

/// The ACA-family key-numbering convention for a Ragbaby cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Numbering {
    /// Standard ACA numbering: the `k`-th letter (1-indexed) of word `w`
    /// (1-indexed) gets `N = w + (k - 1)`.
    Std,
    /// Each word numbered `1, 2, 3, …` independently of its word index.
    PerWord,
    /// A single counter incrementing across the whole text, never reset.
    Continuous,
}

impl Numbering {
    /// All numbering conventions, in a stable order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Std, Self::PerWord, Self::Continuous]
    }

    /// Stable lowercase name (used in tables and candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Std => "std",
            Self::PerWord => "perword",
            Self::Continuous => "continuous",
        }
    }

    /// A stable per-numbering tag decorrelating the per-convention null streams.
    pub(super) const fn tag(self) -> u64 {
        match self {
            Self::Std => 0x5354_4400,
            Self::PerWord => 0x5057_4400,
            Self::Continuous => 0x434f_4e00,
        }
    }
}

impl fmt::Display for Numbering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The shift sign of a Ragbaby cipher (`+1` adds the key number, `-1` subtracts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    /// `c = K[(pos(p) + N) mod base]`.
    Plus,
    /// `c = K[(pos(p) - N) mod base]`.
    Minus,
}

impl Sign {
    /// The numeric sign value (`+1` or `-1`).
    #[must_use]
    pub const fn value(self) -> i64 {
        match self {
            Self::Plus => 1,
            Self::Minus => -1,
        }
    }

    /// Stable lowercase name (used in candidate-record filenames).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Plus => "plus",
            Self::Minus => "minus",
        }
    }

    /// Compact signed label (`"+1"` / `"-1"`) for tables.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plus => "+1",
            Self::Minus => "-1",
        }
    }

    /// A stable per-sign tag decorrelating the per-sign null streams.
    pub(super) const fn tag(self) -> u64 {
        match self {
            Self::Plus => 0x2b31_0000,
            Self::Minus => 0x2d31_0000,
        }
    }
}

/// Returns the real `A..Z` letter indices that form the keyed alphabet for `base`.
///
/// Base 26 keeps all of `A..Z`; base 25 drops `J`; base 24 drops `J` and `V`. Any
/// other base falls back to the first `min(base, 26)` letters (never panics).
#[must_use]
pub fn keep_for_base(base: usize) -> Vec<usize> {
    match base {
        25 => (0..26).filter(|&i| i != LETTER_J).collect(),
        24 => (0..26)
            .filter(|&i| i != LETTER_J && i != LETTER_V)
            .collect(),
        b if b >= 26 => (0..26).collect(),
        b => (0..b).collect(),
    }
}

/// Folds a real letter index into the kept alphabet for `base` (`J -> I` for
/// bases ≤ 25, `V -> U` for base 24); all other letters pass through unchanged.
#[must_use]
pub fn fold_idx(letter: usize, base: usize) -> usize {
    if base <= 25 && letter == LETTER_J {
        return LETTER_J - 1; // J -> I
    }
    if base <= 24 && letter == LETTER_V {
        return LETTER_V - 1; // V -> U
    }
    letter
}

/// Computes the per-letter key numbers `N_i` for the letters of `text`, in letter
/// order, under `numbering`. Letters are maximal runs of ASCII alphabetic
/// characters; every other character is a word separator.
#[must_use]
pub fn key_numbers(text: &str, numbering: Numbering) -> Vec<usize> {
    let mut nums = Vec::new();
    let mut word_idx = 0usize;
    let mut within = 0usize;
    let mut continuous = 0usize;
    let mut in_word = false;
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            if !in_word {
                word_idx += 1;
                within = 0;
                in_word = true;
            }
            continuous += 1;
            let number = match numbering {
                Numbering::Std => word_idx + within,
                Numbering::PerWord => within + 1,
                Numbering::Continuous => continuous,
            };
            nums.push(number);
            within += 1;
        } else {
            in_word = false;
        }
    }
    nums
}

/// Prepares `text` for a Ragbaby attack at `base` under `numbering`, returning the
/// folded real-letter-index stream and the matching key-number stream (already
/// reduced modulo `base`). The two vectors have equal length (one entry per ASCII
/// letter); word structure is preserved by [`key_numbers`].
#[must_use]
pub fn prepare(text: &str, numbering: Numbering, base: usize) -> (Vec<usize>, Vec<usize>) {
    let divisor = base.max(1);
    let nums: Vec<usize> = key_numbers(text, numbering)
        .into_iter()
        .map(|number| number % divisor)
        .collect();
    let letters: Vec<usize> = text
        .chars()
        .filter(char::is_ascii_alphabetic)
        .map(|ch| fold_idx(usize::from(ch.to_ascii_uppercase() as u8 - b'A'), base))
        .collect();
    (letters, nums)
}

/// Adds two residues modulo `n` without overflow (returns `0` when `n == 0`).
fn add_mod(a: usize, b: usize, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (a % n + b % n) % n
}

/// Subtracts `b` from `a` modulo `n` without underflow (returns `0` when
/// `n == 0`).
fn sub_mod(a: usize, b: usize, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    (a % n + n - b % n) % n
}

/// The shifted position for one letter: a forward shift (`forward == true`) adds
/// the key number along the keyed alphabet, a backward shift subtracts it.
fn shift_position(position: usize, number: usize, forward: bool, base: usize) -> usize {
    if forward {
        add_mod(position, number, base)
    } else {
        sub_mod(position, number, base)
    }
}

/// Builds the inverse map `inv[real_letter] = position in key` into `inv`
/// (size-26; entries for absent letters are left at `0`, never read for kept
/// letters).
fn fill_inverse(key: &[usize], inv: &mut [usize; 26]) {
    for slot in inv.iter_mut() {
        *slot = 0;
    }
    for (position, &letter) in key.iter().enumerate() {
        if let Some(slot) = inv.get_mut(letter) {
            *slot = position;
        }
    }
}

/// Encrypts a folded real-letter-index plaintext stream under keyed alphabet
/// `key`, returning the ciphertext letter-index stream.
///
/// `nums` are the per-letter key numbers (any residue; reduced internally). The
/// streams must be the same length; a short `nums` reads missing entries as `0`.
#[must_use]
pub fn encrypt_indices(
    plain: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
) -> Vec<usize> {
    let mut inv = [0usize; 26];
    fill_inverse(key, &mut inv);
    let mut out = Vec::with_capacity(plain.len());
    for (i, &letter) in plain.iter().enumerate() {
        let position = inv.get(letter).copied().unwrap_or(0);
        let number = nums.get(i).copied().unwrap_or(0);
        // Encrypt adds the key number for sign +1, subtracts it for sign -1.
        let cipher_pos = shift_position(position, number, sign >= 0, base);
        out.push(key.get(cipher_pos).copied().unwrap_or(0));
    }
    out
}

/// Decrypts a folded real-letter-index ciphertext stream under keyed alphabet
/// `key`, returning the plaintext letter-index stream (mirror of
/// [`encrypt_indices`]).
#[must_use]
pub fn decrypt_indices(
    cipher: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
) -> Vec<usize> {
    let mut inv = [0usize; 26];
    let mut out = Vec::with_capacity(cipher.len());
    decrypt_into(cipher, nums, key, sign, base, &mut inv, &mut out);
    out
}

/// Decrypts into reused buffers (the search hot path): fills `inv` from `key`,
/// clears `out`, and writes the recovered plaintext letter indices.
pub(super) fn decrypt_into(
    cipher: &[usize],
    nums: &[usize],
    key: &[usize],
    sign: i64,
    base: usize,
    inv: &mut [usize; 26],
    out: &mut Vec<usize>,
) {
    fill_inverse(key, inv);
    out.clear();
    for (i, &letter) in cipher.iter().enumerate() {
        let position = inv.get(letter).copied().unwrap_or(0);
        let number = nums.get(i).copied().unwrap_or(0);
        // Decrypt subtracts the key number for sign +1, adds it for sign -1.
        let plain_pos = shift_position(position, number, sign < 0, base);
        out.push(key.get(plain_pos).copied().unwrap_or(0));
    }
}

/// Parses a keyed-alphabet string (ASCII letters) into its real-letter-index
/// permutation, or returns `None` on a non-letter character.
fn keyed_alphabet_indices(keyed_alphabet: &str) -> Option<Vec<usize>> {
    keyed_alphabet
        .chars()
        .map(|ch| {
            ch.is_ascii_alphabetic()
                .then(|| usize::from(ch.to_ascii_uppercase() as u8 - b'A'))
        })
        .collect()
}

/// Transcodes a full text (letters shifted, non-letters preserved) under keyed
/// alphabet `keyed_alphabet`, with `step` the signed position delta applied to
/// each letter's key number (encrypt uses `+sign`, decrypt uses `-sign`).
fn transcode_str(
    text: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    step: i64,
    base: usize,
) -> String {
    let Some(key) = keyed_alphabet_indices(keyed_alphabet) else {
        return text.to_owned();
    };
    let mut inv = [None; 26];
    for (position, &letter) in key.iter().enumerate() {
        if let Some(slot) = inv.get_mut(letter) {
            *slot = Some(position);
        }
    }
    let nums = key_numbers(text, numbering);
    let mut out = String::with_capacity(text.len());
    let mut letter_index = 0usize;
    for ch in text.chars() {
        if !ch.is_ascii_alphabetic() {
            out.push(ch);
            continue;
        }
        let folded = fold_idx(usize::from(ch.to_ascii_uppercase() as u8 - b'A'), base);
        let number = nums.get(letter_index).copied().unwrap_or(0);
        letter_index += 1;
        match inv.get(folded).copied().flatten() {
            Some(position) => {
                let shifted = shift_position(position, number, step >= 0, base);
                let letter = key.get(shifted).copied().unwrap_or(0);
                out.push((b'A' + letter as u8) as char);
            }
            None => out.push(ch),
        }
    }
    out
}

/// Encrypts `plaintext` (letters shifted, non-letters preserved) under the keyed
/// alphabet string `keyed_alphabet`. This is the string-form convention pinned by
/// the worked example (`"THE CAT"` → `"OJH YED"`).
#[must_use]
pub fn encrypt_str(
    plaintext: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    sign: Sign,
    base: usize,
) -> String {
    transcode_str(plaintext, keyed_alphabet, numbering, sign.value(), base)
}

/// Decrypts `ciphertext` under the keyed alphabet string `keyed_alphabet` (mirror
/// of [`encrypt_str`]).
#[must_use]
pub fn decrypt_str(
    ciphertext: &str,
    keyed_alphabet: &str,
    numbering: Numbering,
    sign: Sign,
    base: usize,
) -> String {
    transcode_str(ciphertext, keyed_alphabet, numbering, -sign.value(), base)
}
