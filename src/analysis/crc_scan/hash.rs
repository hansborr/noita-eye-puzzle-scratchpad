//! Pre-committed `u32` digest family for the stored-word scanner.
//!
//! The variant list is intentionally finite and documented here because the
//! false-alarm calculation multiplies by this exact family size.

/// Named CRC/hash variants tested by `crcscan`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashVariant {
    /// `CRC-32/ISO-HDLC` (`zip`/`PNG`): poly `0x04c11db7`, reflected.
    Crc32IsoHdlc,
    /// `CRC-32/BZIP2`: poly `0x04c11db7`, non-reflected.
    Crc32Bzip2,
    /// `CRC-32/MPEG-2`: poly `0x04c11db7`, non-reflected, `xorout=0`.
    Crc32Mpeg2,
    /// `CRC-32/POSIX` (`cksum` catalogue parameters).
    Crc32Posix,
    /// `CRC-32/JAMCRC`: reflected ISO core with `xorout=0`.
    Crc32Jamcrc,
    /// `CRC-32/XFER`: non-reflected poly `0x000000af`.
    Crc32Xfer,
    /// `CRC-32C` (`Castagnoli`): poly `0x1edc6f41`, reflected.
    Crc32C,
    /// `CRC-32D` (`BASE91-D`): poly `0xa833982b`, reflected.
    Crc32D,
    /// `CRC-32Q` (`AIXM`): poly `0x814141ab`, non-reflected.
    Crc32Q,
    /// `Adler-32`.
    Adler32,
    /// `FNV-1` 32-bit.
    Fnv1,
    /// `FNV-1a` 32-bit.
    Fnv1a,
    /// `djb2` 32-bit wrapping hash.
    Djb2,
    /// `sdbm` 32-bit wrapping hash.
    Sdbm,
}

/// The fixed digest family scanned by `crcscan`.
pub const HASH_VARIANTS: [HashVariant; 14] = [
    HashVariant::Crc32IsoHdlc,
    HashVariant::Crc32Bzip2,
    HashVariant::Crc32Mpeg2,
    HashVariant::Crc32Posix,
    HashVariant::Crc32Jamcrc,
    HashVariant::Crc32Xfer,
    HashVariant::Crc32C,
    HashVariant::Crc32D,
    HashVariant::Crc32Q,
    HashVariant::Adler32,
    HashVariant::Fnv1,
    HashVariant::Fnv1a,
    HashVariant::Djb2,
    HashVariant::Sdbm,
];

/// Output byte order applied to each computed digest before target comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutputByteOrder {
    /// Compare the digest as computed by the named variant.
    AsComputed,
    /// Compare `digest.swap_bytes()`.
    ByteReversed,
}

impl OutputByteOrder {
    /// Both output byte orders tested for every digest variant.
    pub const ALL: [Self; 2] = [Self::AsComputed, Self::ByteReversed];

    /// Applies this output-byte-order transform to `value`.
    #[must_use]
    pub const fn apply(self, value: u32) -> u32 {
        match self {
            Self::AsComputed => value,
            Self::ByteReversed => value.swap_bytes(),
        }
    }

    /// Stable report label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AsComputed => "as-computed",
            Self::ByteReversed => "byte-reversed",
        }
    }
}

impl std::fmt::Display for OutputByteOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl HashVariant {
    /// Stable report label for this digest variant.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Crc32IsoHdlc => "CRC-32/ISO-HDLC",
            Self::Crc32Bzip2 => "CRC-32/BZIP2",
            Self::Crc32Mpeg2 => "CRC-32/MPEG-2",
            Self::Crc32Posix => "CRC-32/POSIX",
            Self::Crc32Jamcrc => "CRC-32/JAMCRC",
            Self::Crc32Xfer => "CRC-32/XFER",
            Self::Crc32C => "CRC-32C",
            Self::Crc32D => "CRC-32D",
            Self::Crc32Q => "CRC-32Q",
            Self::Adler32 => "Adler-32",
            Self::Fnv1 => "FNV-1",
            Self::Fnv1a => "FNV-1a",
            Self::Djb2 => "djb2",
            Self::Sdbm => "sdbm",
        }
    }

    /// Computes this variant over `bytes`.
    #[must_use]
    pub fn digest(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Crc32IsoHdlc => crc32(
                bytes,
                Crc32Params::new(0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, true, true),
            ),
            Self::Crc32Bzip2 => crc32(
                bytes,
                Crc32Params::new(0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, false, false),
            ),
            Self::Crc32Mpeg2 => crc32(
                bytes,
                Crc32Params::new(0x04c1_1db7, 0xffff_ffff, 0x0000_0000, false, false),
            ),
            Self::Crc32Posix => crc32(
                bytes,
                Crc32Params::new(0x04c1_1db7, 0x0000_0000, 0xffff_ffff, false, false),
            ),
            Self::Crc32Jamcrc => crc32(
                bytes,
                Crc32Params::new(0x04c1_1db7, 0xffff_ffff, 0x0000_0000, true, true),
            ),
            Self::Crc32Xfer => crc32(
                bytes,
                Crc32Params::new(0x0000_00af, 0x0000_0000, 0x0000_0000, false, false),
            ),
            Self::Crc32C => crc32(
                bytes,
                Crc32Params::new(0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, true, true),
            ),
            Self::Crc32D => crc32(
                bytes,
                Crc32Params::new(0xa833_982b, 0xffff_ffff, 0xffff_ffff, true, true),
            ),
            Self::Crc32Q => crc32(
                bytes,
                Crc32Params::new(0x8141_41ab, 0x0000_0000, 0x0000_0000, false, false),
            ),
            Self::Adler32 => adler32(bytes),
            Self::Fnv1 => fnv1(bytes),
            Self::Fnv1a => fnv1a(bytes),
            Self::Djb2 => djb2(bytes),
            Self::Sdbm => sdbm(bytes),
        }
    }
}

impl std::fmt::Display for HashVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Copy)]
struct Crc32Params {
    poly: u32,
    init: u32,
    xorout: u32,
    refin: bool,
    refout: bool,
}

impl Crc32Params {
    const fn new(poly: u32, init: u32, xorout: u32, refin: bool, refout: bool) -> Self {
        Self {
            poly,
            init,
            xorout,
            refin,
            refout,
        }
    }
}

fn crc32(bytes: &[u8], params: Crc32Params) -> u32 {
    let mut crc = params.init;
    for byte in bytes {
        let input = if params.refin {
            byte.reverse_bits()
        } else {
            *byte
        };
        crc ^= u32::from(input) << 24;
        for _bit in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ params.poly;
            } else {
                crc <<= 1;
            }
        }
    }
    if params.refout {
        crc = crc.reverse_bits();
    }
    crc ^ params.xorout
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + u32::from(*byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn fnv1(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash = hash.wrapping_mul(0x0100_0193);
        hash ^= u32::from(*byte);
    }
    hash
}

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn djb2(bytes: &[u8]) -> u32 {
    let mut hash = 5_381u32;
    for byte in bytes {
        hash = hash.wrapping_mul(33).wrapping_add(u32::from(*byte));
    }
    hash
}

fn sdbm(bytes: &[u8]) -> u32 {
    let mut hash = 0u32;
    for byte in bytes {
        hash = u32::from(*byte)
            .wrapping_add(hash << 6)
            .wrapping_add(hash << 16)
            .wrapping_sub(hash);
    }
    hash
}
