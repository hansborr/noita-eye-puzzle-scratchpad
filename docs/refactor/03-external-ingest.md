# 03 — External-ciphertext ingest

> One-line: add the missing front door — a pure parser plus a thin I/O wrapper
> that load an arbitrary external ciphertext (string / file) into the crate's
> `Glyph` sequence type — so the workbench can be pointed at any sample (the
> eyes, validation fixtures, the committed practice corpus
> `research/data/practice-puzzles/` — e.g. puzzle `one`, a 5-digit-stream
> sample, and puzzle `three`, a letter+space sample), not just the embedded
> `corpus`. The CLI owns stdin reading.
> Status: not started · Depends on: 01 (golden-master safety net) · Blocks: 04
> (solve pipeline) · Size: S

## Goal & why it matters

Today the only data source the engine can see is the compiled-in `corpus`
(`src/corpus.rs:163` `MESSAGES`). There is no way to feed an external ciphertext
in. The overview's reframe (`docs/refactor/00-OVERVIEW.md:18-58`) names this as
smell row "No data ingest" (line 57): *"the only non-test `fs` use writes
candidate records (no `stdin` path at all); nothing loads an external
ciphertext."* This still holds after the wave-1 GAK-attack work: `gak_attack`'s
Unit 2c (`run_gak_attack_eyes`, `src/gak_attack.rs:4725`) now *does* run against
the eye corpus, but it loads it from the **embedded** `corpus`
(`orders::corpus_grids()`), not from any external file or stdin — the crate has
no external-ciphertext *read* path (the only
`fs::read_to_string` in `src/` is a test reading back a candidate record it just
wrote). The committed sample `research/data/practice-puzzles/one` (puzzle `one`,
formerly `/tmp/gak_cipher_example`) — an **external** base-5 digit string (266
symbols over `{0,1,2,3,4}`, every transition ±1 mod 5: a walk on the pentagon
C5), **hypothesized to be decryptable to English** but whose ground-truth
cleartext we do **not** currently have — was never even *loadable*, let alone
usable as a digit-stream demo / round-trip test input. Recovering its English is
a *goal/hypothesis*, never an established decode.

This brief builds the one-way-in that the overview specifies under
"`Sequence` ingest — one way in (brief 03)" (`00-OVERVIEW.md:87-97`). It factors
the parse from the I/O so the **library never reads global stdin**: a pure
`parse_sequence(text, layer)` is the unit-testable core, and a thin
`load_sequence(input, layer)` wrapper reads a path/string and delegates to it.

```rust
/// Pure parse — no I/O. The unit-testable core.
pub fn parse_sequence(text: &str, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;
/// I/O wrapper: reads a path/file (or forwards a string), then delegates.
pub fn load_sequence(input: Input<'_>, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;
pub enum Input<'a> { Str(&'a str), Path(&'a Path) }
```

`Input` carries **no `Stdin` variant** — reading stdin is the CLI's job
(`main.rs` reads stdin to a `String`, then calls `parse_sequence`). It is
deliberately small (Size S) and self-contained: a pure parser, an I/O wrapper, an
error enum, and a thin CLI wiring on the existing `stats` subcommand. Brief 04
(solve pipeline) reuses `parse_sequence`/`load_sequence` to point `solve` at the
same external ciphertexts, so this must land first (it is on the `02 → 03 → 04`
engine track, `00-OVERVIEW.md:166-178`).

## Current state (grounded, with file:line)

**The sequence type.** A `Glyph` is `pub struct Glyph(pub u16)`
(`src/glyph.rs:140`) — an opaque index into an `Alphabet`
(`src/glyph.rs:151-204`), exactly as `AGENTS.md:52` describes. The owned
sequence type is `pub struct Sequence { pub glyphs: Vec<Glyph> }`
(`src/glyph.rs:207-211`). The closest existing parser is
`Sequence::parse(text, alphabet) -> Result<Self, char>` (`src/glyph.rs:219-231`):
it skips whitespace and maps each char through `alphabet.glyph(c)`, returning the
first unknown `char` on failure. It has **no concept of a delimiter digit**, **no
file/stdin source**, and a bare-`char` error type.

**The glyph layers this must support.** Two are the **eye layers** (below); the
third is an **additive general path** for the external practice corpus
(`research/data/practice-puzzles/`), added without disturbing the eye layers.

1. *Rendered orientation layer (base-5 + delimiter) — eye layer.* Digits `0..=4`
   are the five displayed orientations and `5` is a non-rendered row delimiter
   (`AGENTS.md:52-56`, `src/glyph.rs:71-99` `RenderedSymbol`). The corpus stores
   this layer as raw digit strings (`src/corpus.rs:72-73`, `:169`). Parsing into
   glyphs **drops the `5` delimiter** and maps each orientation digit `d` to
   `Glyph(d)` via `Orientation::glyph` (`src/glyph.rs:64-68`,
   `src/corpus.rs:130-137` `Message::sequence`). The committed sample
   `research/data/practice-puzzles/one` (puzzle `one`, formerly
   `/tmp/gak_cipher_example`) is exactly such a digit string (digits `0..=4`,
   no `5`) — the loadable 5-digit demo. It is **external**, hypothesized to be
   decryptable to English, never an asserted decode.

2. *83-symbol honeycomb reading layer — eye layer.* The reading layer groups
   orientation digits into base-5 trigrams; each *raw* trigram has a value in `0..=124`
   (`src/trigram.rs:28-33`, `:42-64` `TrigramValue`), but the **accepted eye
   reading alphabet is the contiguous `0..=82`** (`src/ciphers.rs:20-21`
   "values `0..=82`", `EYE_READING_ALPHABET_SIZE = 83`; matching
   `src/orders.rs:24` `READING_LAYER_ALPHABET_SIZE = 83`). This is the alphabet
   the attack consumes: `cipher_attack`/`solve` **reject any value `>= 83`**
   (`src/cipher_attack.rs:471-475` → `ValueOutsideEyeAlphabet`). At this layer a
   glyph index *is* a reading-layer symbol: `glyph_messages_from_values` maps
   `value` → `Glyph(u16::from(value.get()))` (`src/orders.rs:962-977`). So
   "loading the honeycomb layer" means parsing **accepted** reading-layer
   tokens `0..=82` directly into `Glyph(value)` — the same alphabet solve uses,
   **not** the raw `0..=124` trigram range. Loading raw `0..=124` trigram
   values would be a *separate, out-of-scope layer* (see Out of scope); keeping
   the two distinct is a transcription-risk safeguard (`AGENTS.md:47-48`).

3. *General cipher-alphabet layer (additive; for the practice corpus, not the
   eyes).* The practice puzzles use **arbitrary cipher alphabets** — letters
   `{A..Z}` (`research/data/practice-puzzles/three`–`seven`), the 12-letter
   `{A..L}` set (`two`), or digit sets — and the letter puzzles **preserve word
   boundaries and punctuation**. Today the crate has no parser for these: the
   closest, `Sequence::parse` (`src/glyph.rs:219-231`), needs a prebuilt
   `Alphabet` and treats *any* non-whitespace char outside it as a hard error
   (the bare-`char` failure), so a space or `.` in a letter puzzle would be
   rejected. `Alphabet::from_chars` (`src/glyph.rs:165`) can build the cipher
   alphabet and `Alphabet::glyph` (`src/glyph.rs:195`) looks up a char, but
   nothing yet treats spaces/punctuation as **transparent pass-through** rather
   than `InvalidToken`. This brief adds that path (the `CipherAlphabet` layer
   below), purely additive: the two eye layers stay exactly as the round-2 fix
   left them. (e.g. puzzle `three`, `research/data/practice-puzzles/three`, a
   letter+space sample — external, hypothesized English, never an asserted
   decode.)

**The current CLI front door.** `StatsArgs` is a single positional
`sequence: String` field (`src/main.rs:107-110`). `run_stats`
(`src/main.rs:1058-1069`) calls the local free function
`parse_rendered_sequence(text) -> Result<Sequence, char>`
(`src/main.rs:1071-1085`), which:

- skips whitespace and `5` (`src/main.rs:1074`),
- rejects non-decimal chars (`src/main.rs:1077-1079`),
- maps each digit through `Orientation::from_digit(..).glyph()`
  (`src/main.rs:1080-1082`),
- on error prints `"unknown rendered digit {c:?}; expected 0-5, with 5 as
  delimiter"` (`src/main.rs:1065`).

This is the *rendered-layer* parser, duplicated inline in the CLI; it is the
pattern the brief says to "generalize". `report::print_report(label, &seq)`
(`src/report.rs:5402`) is what consumes the resulting `Sequence`; it is shared
with `run_demo` (`src/main.rs:650-661`).

**There is no existing `IngestError`, `load_sequence`, or `Input` symbol** in the
crate (`grep` over `src/` returns nothing), and **`thiserror` is not a
dependency** (not in `Cargo.toml`), so error `Display` is hand-written, matching
the prevailing style (`src/report.rs` `format_*_error` functions). `clap` is
`4.5.4` with the `derive` feature (`Cargo.toml:24`).

**House-rule baseline.** `unwrap`/`panic`/`indexing_slicing` are forbidden in
lib/CLI (`AGENTS.md:27-30`); every public item must be documented
(`AGENTS.md:31-32`); `make verify` must stay green at every commit
(`AGENTS.md:23-25`, `00-OVERVIEW.md:196-198`). No reported statistic or decode
may change (`00-OVERVIEW.md:192-195`).

## Target design (concrete API / types / layout)

Add a new module `src/ingest.rs` (registered as `pub mod ingest;` in
`src/lib.rs`, alphabetically between `honeycomb` and `isomorph`,
`src/lib.rs:86-87`). Keeping it a sibling top-level module matches the current
flat layout; brief 07B later relocates it under `core/` per `00-OVERVIEW.md:149`
(`core/ … sequence/ingest …`). Do **not** pre-empt brief 07B's move.

```rust
//! src/ingest.rs

use std::io;
use std::path::Path;

use crate::glyph::{Alphabet, Glyph, Orientation};

/// Where an external ciphertext is read from. There is **no `Stdin` variant** —
/// reading stdin is the CLI's job (`main.rs` reads it to a `String`, then calls
/// `parse_sequence`); the library never touches global stdin.
pub enum Input<'a> {
    /// An in-memory string (e.g. a CLI argument).
    Str(&'a str),
    /// A filesystem path read in full.
    Path(&'a Path),
}

/// The configured set of **transparent symbols** for the `CipherAlphabet` path:
/// chars that are passed through (their positions recorded) rather than treated
/// as cipher symbols. Default membership: space, `.`, `,`, `?`, `!`, `#`, and
/// newline. These are *plumbing* (word boundaries / punctuation), never a
/// decode; the 29-letter `crate::language` bigram model scores **letters only**
/// (`normalize_text` already strips non-letters, `src/language.rs:192-213`), so
/// transparent symbols are skipped for scoring but kept for readability.
pub struct TransparentSet { /* configured char membership */ }

/// One transparent (pass-through) char and the position it occupied in the
/// original input, recorded **separately from the cipher-symbol stream** so the
/// pipeline (brief 04) can reinsert it into `rendered_text` at its position.
pub struct TransparentMark {
    /// The verbatim char (e.g. `' '`, `'.'`, `'\n'`).
    pub ch: char,
    /// Its index in the original char stream (for position-faithful reinsert).
    pub position: usize,
}

/// Which glyph layer the external tokens are expressed in.
///
/// The first two variants are the **eye layers** and stay exactly as the
/// round-2 fix left them (rendered digits `0..=4`; accepted honeycomb reading
/// `0..=82`). [`CipherAlphabet`] is the **additive** general path for the
/// external practice corpus — it does not touch the eye layers.
pub enum SequenceLayer<'a> {
    /// Rendered orientation digits `0..=4`; digit `5` is the row delimiter and
    /// is dropped. Maps digit `d` to `Glyph(d)`. (Eye layer — e.g. puzzle `one`,
    /// `research/data/practice-puzzles/one`, the loadable 5-digit demo.)
    RenderedOrientation,
    /// Whitespace/comma-separated **accepted eye-reading-layer** symbols
    /// `0..=82` — the same alphabet `cipher_attack`/`solve` consume
    /// (`EYE_READING_ALPHABET_SIZE = 83`, `src/ciphers.rs:20-21`). Maps value
    /// `v` to `Glyph(v)`. This loads *accepted* reading-layer symbols, **not**
    /// the raw base-5 trigram range `0..=124`: values `83..=124` are rejected
    /// (`InvalidToken`), exactly as `cipher_attack` rejects them
    /// (`src/cipher_attack.rs:471-475` → `ValueOutsideEyeAlphabet`). Raw
    /// `0..=124` trigram ingest, if ever wanted, would be a **separate,
    /// out-of-scope layer** (see Out of scope) — never conflate the two.
    /// (Eye layer.)
    HoneycombReading,
    /// **General cipher-alphabet path (additive; for the practice corpus, not
    /// the eyes).** Ingests an arbitrary cipher alphabet built from
    /// `alphabet` via `Alphabet::from_chars` (`src/glyph.rs:165`), mapping each
    /// cipher char to its `Glyph(i)` index. A **configured set of transparent
    /// symbols** (space, `.`, `,`, `?`, `!`, `#`, newline) is treated as
    /// **pass-through**: such chars are *not* cipher symbols and *never*
    /// `InvalidToken` — their positions are recorded (see below) and they are
    /// excluded from the returned `Vec<Glyph>` cipher-symbol stream. Any char
    /// that is neither in `alphabet` nor in `transparent` is `InvalidToken`.
    /// (e.g. puzzle `three`, `research/data/practice-puzzles/three`, a
    /// letter+space sample.)
    CipherAlphabet {
        /// The cipher alphabet (e.g. `"ABCDEFGHIJKLMNOPQRSTUVWXYZ"`), parsed by
        /// `Alphabet::from_chars` (`src/glyph.rs:165`).
        alphabet: &'a Alphabet,
        /// Chars passed through verbatim (positions recorded, not cipher
        /// symbols): by default space, `.`, `,`, `?`, `!`, `#`, and newline.
        transparent: &'a TransparentSet,
    },
}

/// A parsed external ciphertext: the cipher-symbol stream and (for the
/// `CipherAlphabet` path) the transparent symbols recorded **separately**.
pub struct ParsedSequence {
    /// The cipher symbols, in order — the stream the cipher/codec/mapping and
    /// the language scorer operate on. Transparent symbols are **not** here.
    pub glyphs: Vec<Glyph>,
    /// Transparent (pass-through) chars with their original positions, kept
    /// apart from `glyphs` so the pipeline (brief 04) can reinsert them into
    /// `rendered_text` at their positions. Empty for the two eye layers.
    pub transparent: Vec<TransparentMark>,
}

/// Failure to ingest an external ciphertext into a glyph sequence.
#[derive(Debug)]
pub enum IngestError {
    /// Reading the path failed (`load_sequence(Input::Path(..))` only; the
    /// library has no stdin path, so this is the sole I/O source).
    Io(io::Error),
    /// A token was not valid for the requested layer (records a layer label,
    /// the offending token text, and its 0-based token index). The label is an
    /// owned discriminant, not a borrowed `SequenceLayer`, so `IngestError`
    /// carries no lifetime.
    InvalidToken { layer: LayerKind, token: String, index: usize },
    /// The input yielded no **cipher** glyphs after parsing (an all-transparent
    /// `CipherAlphabet` input, or empty/all-whitespace for the eye layers).
    Empty,
}

/// Owned discriminant of [`SequenceLayer`] for error reporting (no borrow).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayerKind { RenderedOrientation, HoneycombReading, CipherAlphabet }
```

The pure parser is the core; `load_sequence` is the thin I/O wrapper over it:

```rust
/// Parses an external ciphertext string under the given layer. **Pure —
/// performs no I/O.** This is the unit-testable core; every parsing test
/// targets this function.
///
/// `RenderedOrientation` ignores ASCII whitespace and drops digit `5`;
/// `HoneycombReading` splits on whitespace and commas and parses **accepted
/// eye-reading-layer** symbols `0..=82` (the alphabet `cipher_attack`/`solve`
/// consume), rejecting `83..=124` and non-numeric tokens as `InvalidToken`.
/// `CipherAlphabet` maps each char through `alphabet`, **passes through** the
/// configured transparent symbols (recording their positions in
/// `ParsedSequence::transparent`), and rejects any other char as
/// `InvalidToken`. The two eye layers return an empty `transparent` vec.
///
/// # Errors
/// Returns [`IngestError`] on an out-of-range/non-numeric/unknown token
/// (`InvalidToken`) or an input that yields no cipher glyphs (`Empty`). Never
/// returns `Io` (no I/O).
pub fn parse_sequence(text: &str, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;

/// Loads an external ciphertext under the given layer.
///
/// I/O wrapper around [`parse_sequence`]: `Input::Path` reads the file in full
/// (I/O errors → [`IngestError::Io`]) then parses; `Input::Str` forwards to
/// [`parse_sequence`] directly. The library reads no stdin — the CLI reads stdin
/// to a `String` and calls [`parse_sequence`] itself.
///
/// # Errors
/// Returns [`IngestError`] on path-read I/O failure (`Io`), an
/// out-of-range/non-numeric/unknown token (`InvalidToken`), or an input that
/// yields no cipher glyphs (`Empty`).
pub fn load_sequence(input: Input<'_>, layer: SequenceLayer<'_>) -> Result<ParsedSequence, IngestError>;
```

Design notes that keep this consistent and honest:

- **Signature: a layer selector that *carries* an `&Alphabet` only where it
  applies (reconciled with the overview).** The overview *originally* sketched
  `load_sequence(input: Input, alphabet: &Alphabet)`; it has since been
  reconciled to this layer-based shape (`00-OVERVIEW.md:107-110`, plus the
  "Documented deviations" note). For the **two eye layers** the mapping is
  **positional, not character-table-based**: rendered digit `d → Glyph(d)`
  (`src/glyph.rs:64-68`) and trigram value `v → Glyph(v)` (`src/orders.rs:973`).
  An `Alphabet` (`src/glyph.rs:151`) is a char↔glyph table and does not model
  "skip the `5` delimiter" or "tokens are multi-digit accepted reading-layer
  numbers `0..=82` (rejecting `83..=124`)". So those two variants stay
  alphabet-free. The **`CipherAlphabet` variant is the one place an `&Alphabet`
  belongs** — it *is* a char↔glyph table over an arbitrary cipher alphabet
  (built by `Alphabet::from_chars`, `src/glyph.rs:165`, looked up by
  `Alphabet::glyph`, `src/glyph.rs:195`) — so the selector carries it as
  variant data rather than as a universal parameter. This keeps the eye layers
  exactly as the round-2 fix left them while the general path is purely
  additive. The variant-data shape (not a top-level `alphabet` arg) is the
  minimal honest fit, and the overview and brief 04 reflect it.
- **No panics.** All parsing returns `Result`; never index a slice or `unwrap`.
  `Orientation::from_digit` (`src/glyph.rs:45-56`) and `TrigramValue::new`
  (`src/trigram.rs:51-57`) already return `Result`/`Err`; thread their errors
  into `IngestError::InvalidToken`. Read I/O errors map to `IngestError::Io`.
  Note `TrigramValue::new` only bounds the **raw** trigram range `0..=124`; the
  `HoneycombReading` layer must additionally reject `83..=124` (a value `>= 83`,
  i.e. `>= EYE_READING_ALPHABET_SIZE`) as `InvalidToken`, mirroring
  `cipher_attack`'s `ValueOutsideEyeAlphabet` check (`src/cipher_attack.rs:471-475`),
  so ingest accepts exactly the alphabet solve consumes.
- **Transparent symbols are preserved, separate from the cipher stream (the
  `CipherAlphabet` path).** The letter puzzles keep word boundaries and
  punctuation — a strong crib — so a char that is a configured transparent
  symbol (space, `.`, `,`, `?`, `!`, `#`, newline) is **passed through, not
  rejected**: it is recorded as a `TransparentMark { ch, position }` in
  `ParsedSequence::transparent`, kept **apart from** the `glyphs` cipher-symbol
  stream. The cipher/codec/mapping operate **only** on `glyphs`; the pipeline
  (brief 04) reinserts each `TransparentMark` into `rendered_text` at its
  recorded position, so the human-readable candidate keeps its spacing and
  punctuation. The **language scorer handles letters only** — the 29-letter
  `crate::language` bigram model already strips non-letters in `normalize_text`/
  `normalize_text_into` (`src/language.rs:192-213`), so transparent symbols are
  skipped for scoring but kept for readability. This is plumbing — passthrough is
  *not* a decode, and word boundaries are merely available as cribs (word-pattern
  scoring is a later enhancement, not designed here). The two **eye layers**
  (`RenderedOrientation`, `HoneycombReading`) have no transparent symbols and
  return an empty `transparent` vec; this note is additive and does not touch
  them.
- **`Display` for `IngestError`** is hand-written (no new dependency), mirroring
  `report.rs` style and satisfying `00-OVERVIEW.md:123` ("each error enum gets a
  `Display`"). Implement `std::error::Error` too (with `source()` returning the
  inner `io::Error` for the `Io` variant) so it composes with brief 06.
- **`ParsedSequence` (a `Vec<Glyph>` + transparent marks), not `Sequence`.** The
  overview's API and brief 04's `SolveRequest.ciphertext: &'a [Glyph]`
  (`00-OVERVIEW.md:131`) both speak `[Glyph]`; `ParsedSequence::glyphs` *is* that
  `Vec<Glyph>` cipher stream, with `ParsedSequence::transparent` carried
  alongside it (empty for the eye layers). The CLI can wrap `glyphs` in
  `Sequence { glyphs }` (`src/glyph.rs:207-211`) for `report::print_report`
  (`src/report.rs:5402`); `stats` ignores the transparent marks (the solve
  pipeline, brief 04, consumes them).

CLI wiring (generalize `StatsArgs`, `src/main.rs:107-110`):

```rust
#[derive(Debug, Args)]
struct StatsArgs {
    /// Rendered orientation sequence (digits 0-4, optional delimiter 5).
    /// Optional: omit to read from --input-file or stdin.
    sequence: Option<String>,
    /// Read the ciphertext from this file instead of the positional argument.
    #[arg(long = "input-file", conflicts_with = "sequence")]
    input_file: Option<std::path::PathBuf>,
    /// Treat the input as accepted honeycomb reading-layer values (0-82, the
    /// alphabet solve consumes) rather than rendered orientation digits.
    #[arg(long = "honeycomb", default_value_t = false)]
    honeycomb: bool,
    /// Treat the input as a general cipher alphabet (these chars, in order, are
    /// the cipher symbols; e.g. ABCDEFGHIJKLMNOPQRSTUVWXYZ for a letter puzzle).
    /// Spaces/punctuation (`. , ? ! #`, newline) pass through as transparent
    /// symbols. For the practice corpus, not the eyes; conflicts with
    /// --honeycomb.
    #[arg(long = "alphabet", conflicts_with = "honeycomb")]
    alphabet: Option<String>,
}
```

Resolution order in `run_stats` (the round-2 source resolver, unchanged):
positional `sequence` (→ `parse_sequence(&s, layer)`) → `--input-file` (→
`load_sequence(Input::Path(&p), layer)`) → **stdin read by the CLI** when neither
is given (`io::Read::read_to_string` into a `String`, then
`parse_sequence(&text, layer)`). The resolver is **layer-agnostic** — it picks
the *source*, then feeds the pure `parse_sequence` a `layer` chosen from the
flags: `--alphabet S` builds `Alphabet::from_chars(S)` (`src/glyph.rs:165`) plus
the default `TransparentSet` and selects
`SequenceLayer::CipherAlphabet { .. }` (e.g.
`--alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ --input-file research/data/practice-puzzles/three`);
else `--honeycomb` selects `HoneycombReading`; else `RenderedOrientation`. The
stdin read lives entirely in `main.rs`; the library never sees stdin. **Corpus
stays the default source for `demo`** (`run_demo`, `src/main.rs:650-661`) — this
brief does not touch `demo`.

## Implementation steps (ordered, each independently committable & green)

**Step 1 — `src/ingest.rs` with `parse_sequence` (`RenderedOrientation` only) +
unit tests.** Create the module, `Input` (`{Str, Path}` — **no `Stdin`**),
`SequenceLayer` (start with `RenderedOrientation`; the `HoneycombReading` and
additive `CipherAlphabet` variants land in Steps 2 / 2b), `ParsedSequence`,
`IngestError`, its `Display`/`Error` impls, the pure `parse_sequence(text,
layer)`, and the `load_sequence` wrapper. Implement `RenderedOrientation` *inside
`parse_sequence`*: iterate `chars`, skip `char::is_whitespace`, drop `'5'`, map
`'0'..='4'` via `Orientation::from_digit` → `Orientation::glyph`, else
`InvalidToken`. `load_sequence` is the I/O wrapper: `Input::Str(s)` →
`parse_sequence(s, layer)`; `Input::Path(p)` → `std::fs::read_to_string(p)`
mapped to `Io`, then `parse_sequence(&text, layer)`. (No stdin branch — the
library has no stdin path; the read helper is Path-only.) Register `pub mod
ingest;` in `src/lib.rs:86-87` and add a module-doc bullet near
`src/lib.rs:37-38`. Unit tests target **`parse_sequence`** (relaxed lints in
`#[cfg(test)]` per `clippy.toml`):
- `parse_sequence("012 345\n01", RenderedOrientation)` drops `5`/whitespace →
  glyphs `[0,1,2,3,4,0,1]`;
- non-digit / digit `>5` → `InvalidToken` with the right `index`;
- empty / all-whitespace input → `Empty`.
*Green:* `make verify`.

**Step 2 — add `HoneycombReading` to `parse_sequence` + tests.** Split the text
on whitespace and `,`; for each non-empty token parse `u8`, then reject any value
`>= EYE_READING_ALPHABET_SIZE` (i.e. `>= 83`) — the **accepted eye-reading
alphabet `0..=82`** the attack consumes, mirroring `cipher_attack`'s
`ValueOutsideEyeAlphabet` check (`src/cipher_attack.rs:471-475`) — then
`Glyph(u16::from(value))`. (`TrigramValue::new`, `src/trigram.rs:51`, only bounds
the raw `0..=124` trigram range, so it alone is **not** sufficient; the `>= 83`
reject is the load-bearing boundary.) Non-numeric or `>= 83` → `InvalidToken`.
Tests (on `parse_sequence`): `"0 12 82"` → `Glyph(0/12/82)`; `"83"` (the first
raw-but-unaccepted trigram value), `"125"`, and `"x"` → `InvalidToken`;
trailing/duplicate separators tolerated. *Green:* `make verify`.

**Step 2b — add the `CipherAlphabet` path to `parse_sequence` + transparent
symbols + tests (additive; for the practice corpus).** Add the
`TransparentSet`/`TransparentMark`/`ParsedSequence`/`LayerKind` types and switch
`parse_sequence` to return `ParsedSequence` (the two eye layers fill
`transparent` with an empty vec — behavior unchanged). Implement
`CipherAlphabet { alphabet, transparent }` *inside `parse_sequence`*: walk the
chars (track a `position`/`index`); if the char is in `transparent`, push a
`TransparentMark { ch, position }` and **continue** (do NOT push a glyph, do NOT
error); else look it up via `Alphabet::glyph` (`src/glyph.rs:195`) and push the
`Glyph`; else `InvalidToken { layer: LayerKind::CipherAlphabet, .. }`. The
default `TransparentSet` is space, `.`, `,`, `?`, `!`, `#`, and newline. The
cipher alphabet is built by the caller via `Alphabet::from_chars`
(`src/glyph.rs:165`). Tests (on `parse_sequence`): with `alphabet =
from_chars("ABCDEFGHIJKLMNOPQRSTUVWXYZ")` and the default transparent set,
`"AB CD."` → glyphs `[A,B,C,D]` and `transparent` recording the space at
position 2 and `.` at position 5; a char outside both (e.g. a digit) →
`InvalidToken`; an all-transparent input (e.g. `"  "`) → `Empty` (no cipher
glyphs). Keep the eye layers' empty-`transparent` behavior asserted. *Green:*
`make verify`.

**Step 3 — golden-master parity test for the rendered path (behavior-preserving
proof).** Add a test asserting that, for the nine corpus digit strings
(`corpus::MESSAGES[i].digits`, `src/corpus.rs:169`+),
`parse_sequence(digits, SequenceLayer::RenderedOrientation)?.glyphs` equals
`corpus::messages()[i].sequence().unwrap().glyphs` (`src/corpus.rs:130-137`).
This pins that ingest reproduces the corpus parser byte-for-byte, satisfying the
behavior-preserving rule (`00-OVERVIEW.md:192-195`). Being on the pure parser, it
needs no I/O. *Green:* `make verify`.

**Step 4 — wire the CLI (incl. CLI-owned stdin read).** Generalize `StatsArgs`
(`src/main.rs:107-110`) to the shape above; rewrite `run_stats`
(`src/main.rs:1058-1069`) to resolve the source and pick the layer from the
flags (`--alphabet S` → `CipherAlphabet { alphabet: from_chars(S)?, transparent:
&default }`; else `--honeycomb` → `HoneycombReading`; else
`RenderedOrientation`):
- positional `sequence` → `ingest::parse_sequence(&s, layer)`;
- `--input-file` → `ingest::load_sequence(Input::Path(&p), layer)`;
- neither → **`main.rs` reads stdin itself** (`io::Read::read_to_string` from
  `io::stdin()` into a `String`, mapping the I/O error to the same failure path)
  then `ingest::parse_sequence(&text, layer)`.

Then wrap the resulting `ParsedSequence::glyphs` in `Sequence { glyphs }` and
call `report::print_report("input", &seq)` unchanged (`stats` ignores the
transparent marks — the solve pipeline, brief 04, consumes them). On
`Err(IngestError)` (or the stdin read error, or an `Alphabet::from_chars`
failure on a malformed `--alphabet`), print the `Display` to stderr and return
`ExitCode::FAILURE`.
**Delete the now-dead `parse_rendered_sequence`** (`src/main.rs:1071-1085`).
Update the `noita_eye_puzzle` import list (`src/main.rs:10-15`) to bring in
`ingest`; the `glyph::Sequence` import stays for the wrapper. Stdin reading is the
CLI's responsibility — the library exposes no stdin path. *Green:* `make verify`;
manual smoke (see Verification).

**Step 5 — docs touch-ups.** Update `00-OVERVIEW.md:87-97` (and a note in brief
04 once it exists) to the final `load_sequence(input, layer)` signature if Step 1
deviated. Add a one-line `## Commands`-adjacent example to `AGENTS.md` only if it
adds value (optional). *Green:* `make verify` + `make check` before the final
push (`codespell`/`shellcheck` run there).

Each step compiles, tests, and lints independently; no step leaves the tree red.

## Files to create / change / delete

- **Create** `src/ingest.rs` — `Input` (`{Str, Path}`, no `Stdin`),
  `SequenceLayer` (the two eye layers + the additive `CipherAlphabet { alphabet,
  transparent }`), `TransparentSet`/`TransparentMark`/`ParsedSequence`/`LayerKind`,
  `IngestError` (+`Display`/`Error`), the pure `parse_sequence`, the
  `load_sequence` I/O wrapper (Path-only read helper), unit tests on
  `parse_sequence` (incl. the `CipherAlphabet` transparent-passthrough cases) +
  golden-master parity test.
- **Change** `src/lib.rs` — add `pub mod ingest;` (`:86-87`) and a module-doc
  bullet (`:37-38` neighborhood).
- **Change** `src/main.rs` — generalize `StatsArgs` (`:107-110`, adding
  `--alphabet`); rewrite `run_stats` (`:1058-1069`) to read stdin itself and call
  `parse_sequence` (the CLI owns the stdin read); **delete**
  `parse_rendered_sequence` (`:1071-1085`); update imports (`:10-15`).
- **Change** `docs/refactor/00-OVERVIEW.md` — reconcile the `load_sequence`
  signature in §"`Sequence` ingest" (`:87-97`) if it deviated.
- **No change** to `src/corpus.rs`, `src/glyph.rs`, `src/trigram.rs`,
  `src/orders.rs`, `src/report.rs` — ingest reuses their existing public APIs
  (`Orientation::from_digit/glyph`, `TrigramValue::new`, `Alphabet::from_chars`
  (`:165`)/`Alphabet::glyph` (`:195`) for the `CipherAlphabet` path, `Glyph`,
  `Sequence`, `print_report`). No new external dependency (no `thiserror`);
  nothing for `cargo-machete`/`cargo-deny` to flag.

## Success criteria

- `parse_sequence("…digits…", RenderedOrientation)?.glyphs` reproduces the
  corpus rendered parse for all nine messages (Step 3 test passes).
- `load_sequence(Input::Path(Path::new("research/data/practice-puzzles/one")),
  RenderedOrientation)?.glyphs` returns a non-empty `Vec<Glyph>` whose length
  equals the count of `0..=4` digits in that file — the committed external
  ±1-C5 5-digit sample (puzzle `one`, formerly `/tmp/gak_cipher_example`;
  hypothesized to be decryptable to English; cleartext not held) is now
  *loadable* as a digit-stream demo / round-trip input.
- The `CipherAlphabet` path ingests a letter+space sample (e.g.
  `research/data/practice-puzzles/three`) under
  `--alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ`: `ParsedSequence::glyphs` holds only
  the cipher letters and `ParsedSequence::transparent` records the spaces /
  punctuation at their positions, none of which is an `InvalidToken` (additive;
  loadable, not decoded — the English remains a hypothesis).
- The CLI reads stdin to EOF and parses it via `parse_sequence` (`echo "0120" |
  noita-eye stats`); the library itself exposes no stdin path.
- `HoneycombReading` maps **accepted** reading-layer tokens `0..=82` to
  `Glyph(value)` and rejects `83..=124` and non-numeric tokens with
  `InvalidToken` (via `parse_sequence`) — exactly the alphabet
  `cipher_attack`/`solve` accept, never the raw `0..=124` trigram range. (Both
  eye layers stay exactly as the round-2 fix left them.)
- All failure paths return `IngestError` (or, for the CLI stdin read, its I/O
  error mapped to the same exit path) — **no panic, no `unwrap`, no
  `indexing_slicing`** in `src/ingest.rs` or the CLI changes (clippy `-D` clean).
- `stats` works four ways: `noita-eye stats "0120 5 34"`,
  `noita-eye stats --input-file research/data/practice-puzzles/one`,
  `noita-eye stats --alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ --input-file research/data/practice-puzzles/three`,
  and `echo "0120" | noita-eye stats`. `demo` output is byte-for-byte unchanged.
- `make verify` green at each commit; `make check` green before push.

## Verification (exactly how to prove it)

- **`make verify`** after every step (fmt-check + clippy `-D` + tests + rustdoc
  `-D` + cargo-deny, `AGENTS.md:15`).
- **Golden-master / behavior-preserving diff:** the Step 3 corpus-parity test is
  the in-tree proof that ingest equals `Message::sequence`. Additionally confirm
  `demo` is untouched: `cargo run --locked -- demo > /tmp/demo_after.txt` and
  `git stash`-compare against `main`'s `demo` output (must be identical) — this
  is the `00-OVERVIEW.md:192-195` no-statistic-changes check for this brief.
- **Manual smoke (the actual front-door proof):**
  ```sh
  cargo run --locked -- stats "20101 5 322"
  cargo run --locked -- stats --input-file research/data/practice-puzzles/one
  cargo run --locked -- stats --alphabet ABCDEFGHIJKLMNOPQRSTUVWXYZ \
      --input-file research/data/practice-puzzles/three      # letter+space; spaces/. pass through
  printf '0 12 82\n'  | cargo run --locked -- stats --honeycomb   # accepted 0..=82
  printf '83\n'        | cargo run --locked -- stats --honeycomb   # FAILURE: outside eye alphabet
  printf 'bad\n'       | cargo run --locked -- stats   # exits FAILURE, prints IngestError
  ```
  Expect a `report::print_report` block on success and a single
  `IngestError`-`Display` line + non-zero exit on malformed input.
- **New tests** (in `src/ingest.rs#[cfg(test)]`) target the pure `parse_sequence`
  for: rendered parse + delimiter drop, honeycomb parse + accepted-`0..=82` bound
  (`"83"`/`"125"` rejected), the `CipherAlphabet` path (cipher letters →
  `glyphs`, transparent space/punctuation → `transparent` marks at the right
  positions, an out-of-alphabet non-transparent char → `InvalidToken`, an
  all-transparent input → `Empty`), `InvalidToken`, `Empty`, and the nine-message
  corpus parity. The one `load_sequence` test exercises the `Io` variant via
  `Input::Path` on a nonexistent path. No test touches stdin (the library has no
  stdin path); stdin is covered only by the manual CLI smoke below.
- **`make check`** before the final push (adds `cargo-machete`, `codespell`,
  `shellcheck`, release build — `AGENTS.md:16`).

## Risks & honesty caveats

- **Loadable ≠ decoded.** This brief makes external ciphertext *ingestible*; it
  performs **no** cryptanalysis and emits **no** plaintext. The claim ceiling is
  unchanged (`00-OVERVIEW.md:205-210`): the eyes remain *deterministic,
  engine-generated, strikingly structured data of unknown meaning; unsolved.*
  Nothing here may be reported as a step toward a decode beyond "we can now point
  the tools at a sample."
- **Layer ambiguity is a transcription risk.** Mixing the rendered (`0..=4`+`5`),
  accepted honeycomb-reading (`0..=82`), and general `CipherAlphabet` layers
  silently would corrupt analysis (`AGENTS.md:47-48`). The explicit
  `SequenceLayer`/`--honeycomb`/`--alphabet` flags and the
  `InvalidToken { layer, … }` error keep the layer choice loud, never inferred.
  The honeycomb layer deliberately accepts only the eye alphabet `0..=82`
  (rejecting `83..=124`), so a stray raw-trigram value can never be silently
  mistaken for an accepted reading-layer symbol; raw `0..=124` trigram ingest,
  were it ever wanted, is a **separate, out-of-scope layer** (below), kept
  distinct so the two are never conflated. The `CipherAlphabet` path is **only**
  reachable via an explicit `--alphabet` (it conflicts with `--honeycomb`), so it
  can never silently capture eye input; it is additive and leaves the two eye
  layers exactly as the round-2 fix left them.
- **Transparent-symbol passthrough is plumbing, not a decode.** Recording a
  space or `.` position (the `CipherAlphabet` path) carries **no** claim about
  meaning; it only preserves word boundaries / punctuation for readability and as
  cribs. Recovering any practice puzzle's English (incl. the letter+space samples)
  remains a GOAL/HYPOTHESIS — no cleartext is committed and the eyes stay the
  primary end goal and sole honest-negative.
- **Signature shape vs the overview** (a `SequenceLayer` selector — carrying an
  `&Alphabet` only in the `CipherAlphabet` variant — instead of a top-level
  `&Alphabet` parameter) is a deliberate, documented choice (see Target design);
  the implementing agent must update `00-OVERVIEW.md:87-97` and brief 04's
  cross-reference, per the overview's "update every brief's cross-references if a
  name changes" rule (`00-OVERVIEW.md:9-14`).
- **Stdin lives in the CLI, not the library.** `parse_sequence` is pure and fully
  unit-testable; `Input` has no `Stdin` variant, so there is no library stdin path
  to block a test harness. Stdin is read in `main.rs` and is covered only by the
  manual CLI smoke. Unit tests target `parse_sequence` (with one `load_sequence`
  `Input::Path` test for the `Io` variant).
- **No new dependency** is introduced; if the agent reaches for `thiserror` or an
  arg-file crate, that must be justified against `deny.toml` + `cargo-machete`
  (`AGENTS.md:35-38`) — the hand-written `Display` avoids the need.

## Out of scope / non-goals

- **No mapping search, no scoring, no solve** — that is brief 04
  (`00-OVERVIEW.md:126-137`). This brief stops at producing a `ParsedSequence`
  (the cipher `glyphs` + recorded transparent marks); reinserting transparent
  symbols into `rendered_text` and scoring letters is brief 04's job.
- **No `Cipher` trait / `AnyCipher`** — brief 02.
- **No new subcommand.** Only `stats` is wired here; brief 04's `solve` reuses
  `load_sequence`.
- **No word-pattern / known-word scoring.** Word boundaries (the recorded
  transparent spaces) are merely *available* as cribs; using them is a later
  enhancement, not designed here.
- **No module relocation** into `core/` — brief 07B (`00-OVERVIEW.md:143-160`)
  owns the layout move; `src/ingest.rs` stays top-level for now.
- **No changes to `demo`, `corpus`, or any statistic/experiment** — behavior must
  stay byte-for-byte identical (`00-OVERVIEW.md:192-195`).
- **No support for additional input layers** (e.g. raw base-7 storage symbols,
  `StorageSymbol` `-1`, `src/glyph.rs:101-136`) beyond the rendered, accepted
  honeycomb-reading (`0..=82`), and general `CipherAlphabet` layers named here.
- **No raw `0..=124` trigram-value ingest.** The `HoneycombReading` layer loads
  only the **accepted** eye reading alphabet `0..=82` (the alphabet
  `cipher_attack`/`solve` consume, `EYE_READING_ALPHABET_SIZE = 83`). Ingesting
  the wider raw base-5 trigram range `0..=124` (values `83..=124` that never
  appear in the accepted order) would be a **separate, distinct layer** and is
  not designed here — kept explicitly out of scope so the accepted-symbol and
  raw-trigram alphabets are never conflated (transcription-risk rule,
  `AGENTS.md:47-48`).
