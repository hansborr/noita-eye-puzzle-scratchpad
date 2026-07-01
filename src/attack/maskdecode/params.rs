//! The sweep-grid axes ([`MaskKind`], [`BitOrder`], [`Polarity`],
//! [`ReadDirection`]) and the [`CellParams`] cell coordinate they form.

/// The XOR mask applied to the direction bits before the ASCII readout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskKind {
    /// `b_i = 0`: the direction bits are read as-is.
    Static,
    /// `b_i = i mod 2`: the conv-alt reading (orientation flips every step).
    Alternating,
}

impl MaskKind {
    /// The mask bit at stream index `index`.
    #[must_use]
    pub const fn bit(self, index: usize) -> bool {
        matches!(self, Self::Alternating) && index % 2 == 1
    }

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Alternating => "alternating",
        }
    }
}

/// Bit order used to assemble each `width`-bit chunk value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitOrder {
    /// The first stream bit of a chunk is the value's most significant bit.
    MsbFirst,
    /// The first stream bit of a chunk is the value's least significant bit.
    LsbFirst,
}

impl BitOrder {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MsbFirst => "MSB",
            Self::LsbFirst => "LSB",
        }
    }
}

/// Polarity of the masked bit stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    /// Bits are read as produced by the mask.
    Plain,
    /// Every bit is complemented (this also covers alternating phase `b_0=1`).
    Complemented,
}

impl Polarity {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Complemented => "complemented",
        }
    }
}

/// Reading direction of the direction-bit stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadDirection {
    /// Bits in ciphertext order.
    Forward,
    /// The bit stream is reversed before masking. Combined with the polarity
    /// axis this also covers reading the reversed ciphertext's own walk (whose
    /// direction bits are the complemented reversal of the forward bits).
    Reversed,
}

impl ReadDirection {
    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Forward => "fwd",
            Self::Reversed => "rev",
        }
    }
}

/// One readout cell in the sweep grid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellParams {
    /// XOR mask over the direction bits.
    pub mask: MaskKind,
    /// ASCII chunk width in bits.
    pub width: usize,
    /// Number of leading masked bits skipped before the first full chunk
    /// (`0..width`). A non-zero offset leaves a partial head chunk.
    pub offset: usize,
    /// Bit order within each chunk.
    pub order: BitOrder,
    /// Polarity of the masked stream.
    pub polarity: Polarity,
    /// Reading direction of the bit stream.
    pub direction: ReadDirection,
}

impl CellParams {
    /// Compact display label, e.g. `mask=alternating w=7 off=6 MSB fwd plain`.
    #[must_use]
    pub fn label(&self) -> String {
        format!(
            "mask={} w={} off={} {} {} {}",
            self.mask.label(),
            self.width,
            self.offset,
            self.order.label(),
            self.direction.label(),
            self.polarity.label()
        )
    }

    /// Canonical tie-break key: forward before reversed, `MSB` before `LSB`,
    /// plain before complemented, static before alternating, then width and
    /// offset ascending. This lists the forward member of a mirror-twin pair
    /// of verified cells first.
    pub(crate) fn canonical_key(&self) -> (u8, u8, u8, u8, usize, usize) {
        (
            match self.direction {
                ReadDirection::Forward => 0,
                ReadDirection::Reversed => 1,
            },
            match self.order {
                BitOrder::MsbFirst => 0,
                BitOrder::LsbFirst => 1,
            },
            match self.polarity {
                Polarity::Plain => 0,
                Polarity::Complemented => 1,
            },
            match self.mask {
                MaskKind::Static => 0,
                MaskKind::Alternating => 1,
            },
            self.width,
            self.offset,
        )
    }
}
