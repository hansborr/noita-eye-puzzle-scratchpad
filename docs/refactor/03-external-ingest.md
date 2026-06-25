# 03 — External-ciphertext ingest

> One-line: add the missing front door — load an arbitrary external ciphertext
> (string / file / stdin) into the crate's `Glyph` sequence type — so the
> workbench can be pointed at any sample (the eyes, validation fixtures, the
> `/tmp/gak_cipher_example` sample), not just the embedded `corpus`.
> Status: not started · Depends on: 01 (golden-master safety net) · Blocks: 04
> (solve pipeline) · Size: S

## Goal & why it matters

Today the only data source the engine can see is the compiled-in `corpus`
(`src/corpus.rs:163` `MESSAGES`). There is no way to feed an external ciphertext
in. The overview's reframe (`docs/refactor/00-OVERVIEW.md:18-54`) names this as
smell row "No data ingest" (line 53): *"only `fs`/`stdin` use is writing
candidate records; nothing loads an external ciphertext."* The sample cipher
`/tmp/gak_cipher_example` (a base-5 digit string that contains a real English
message) was never even *loadable*, let alone crackable.

This brief builds the one-way-in that the overview specifies under
"`Sequence` ingest — one way in (brief 03)" (`00-OVERVIEW.md:83-93`):

```rust
pub fn load_sequence(input: Input, alphabet: &Alphabet) -> Result<Vec<Glyph>, IngestError>;
pub enum Input<'a> { Str(&'a str), Path(&'a Path), Stdin }
```

It is deliberately small (Size S) and self-contained: a parsing function, an
error enum, and a thin CLI wiring on the existing `stats` subcommand. Brief 04
(solve pipeline) reuses `load_sequence` to point `solve` at the same external
ciphertexts, so this must land first (it is on the `02 → 03 → 04` engine track,
`00-OVERVIEW.md:167-177`).

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

**The two glyph layers this must support.**

1. *Rendered orientation layer (base-5 + delimiter).* Digits `0..=4` are the five
   displayed orientations and `5` is a non-rendered row delimiter
   (`AGENTS.md:52-56`, `src/glyph.rs:71-99` `RenderedSymbol`). The corpus stores
   this layer as raw digit strings (`src/corpus.rs:72-73`, `:169`). Parsing into
   glyphs **drops the `5` delimiter** and maps each orientation digit `d` to
   `Glyph(d)` via `Orientation::glyph` (`src/glyph.rs:64-68`,
   `src/corpus.rs:130-137` `Message::sequence`). The `/tmp/gak_cipher_example`
   sample is exactly such a digit string (digits `0..=4`, no `5`).

2. *83-symbol honeycomb reading layer.* The reading layer groups orientation
   digits into base-5 trigrams; each trigram has a value in `0..=124`
   (`src/trigram.rs:28-33`, `:42-64` `TrigramValue`), of which **83 distinct
   values appear in the accepted order** (`src/orders.rs:24`
   `READING_LAYER_ALPHABET_SIZE = 83`). At this layer a glyph index *is* a
   trigram value: `glyph_messages_from_values` maps `value` → `Glyph(u16::from(value.get()))`
   (`src/orders.rs:962-977`). So "loading the honeycomb layer" means parsing
   tokens in `0..=124` (or `0..=82`) directly into `Glyph(value)`.

**The current CLI front door.** `StatsArgs` is a single positional
`sequence: String` field (`src/main.rs:107-110`). `run_stats` calls the local
free function `parse_rendered_sequence(text) -> Result<Sequence, char>`
(`src/main.rs:1052-1079`), which:

- skips whitespace and `5` (`src/main.rs:1068`),
- rejects non-decimal chars (`src/main.rs:1071-1073`),
- maps each digit through `Orientation::from_digit(..).glyph()`
  (`src/main.rs:1074-1077`),
- on error prints `"unknown rendered digit {c:?}; expected 0-5, with 5 as
  delimiter"` (`src/main.rs:1059`).

This is the *rendered-layer* parser, duplicated inline in the CLI; it is the
pattern the brief says to "generalize". `report::print_report(label, &seq)`
(`src/report.rs:5394`) is what consumes the resulting `Sequence`; it is shared
with `run_demo` (`src/main.rs:644-655`).

**There is no existing `IngestError`, `load_sequence`, or `Input` symbol** in the
crate (`grep` over `src/` returns nothing), and **`thiserror` is not a
dependency** (not in `Cargo.toml`), so error `Display` is hand-written, matching
the prevailing style (`src/report.rs` `format_*_error` functions). `clap` is
`4.5.4` with the `derive` feature (`Cargo.toml:24`).

**House-rule baseline.** `unwrap`/`panic`/`indexing_slicing` are forbidden in
lib/CLI (`AGENTS.md:27-30`); every public item must be documented
(`AGENTS.md:31-32`); `make verify` must stay green at every commit
(`AGENTS.md:23-25`, `00-OVERVIEW.md:191-196`). No reported statistic or decode
may change (`00-OVERVIEW.md:188-190`).

## Target design (concrete API / types / layout)

Add a new module `src/ingest.rs` (registered as `pub mod ingest;` in
`src/lib.rs`, alphabetically between `honeycomb` and `isomorph`,
`src/lib.rs:86-87`). Keeping it a sibling top-level module matches the current
flat layout; brief 07 later relocates it under `core/` per `00-OVERVIEW.md:144`
(`core/ … sequence/ingest …`). Do **not** pre-empt brief 07's move.

```rust
//! src/ingest.rs

use std::io::{self, Read};
use std::path::Path;

use crate::glyph::{Glyph, Orientation};

/// Where an external ciphertext is read from.
pub enum Input<'a> {
    /// An in-memory string (e.g. a CLI argument).
    Str(&'a str),
    /// A filesystem path read in full.
    Path(&'a Path),
    /// Standard input, read to EOF.
    Stdin,
}

/// Which glyph layer the external tokens are expressed in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SequenceLayer {
    /// Rendered orientation digits `0..=4`; digit `5` is the row delimiter and
    /// is dropped. Maps digit `d` to `Glyph(d)`. (`/tmp/gak_cipher_example`.)
    RenderedOrientation,
    /// Whitespace/comma-separated base-5 trigram values `0..=124` (the 83-symbol
    /// reading layer). Maps value `v` to `Glyph(v)`.
    HoneycombReading,
}

/// Failure to ingest an external ciphertext into a glyph sequence.
#[derive(Debug)]
pub enum IngestError {
    /// Reading the path or stdin failed.
    Io(io::Error),
    /// A token was not valid for the requested layer (records the layer, the
    /// offending token text, and its 0-based token index).
    InvalidToken { layer: SequenceLayer, token: String, index: usize },
    /// The input contained no glyph tokens after parsing.
    Empty,
}
```

The free function the overview names, plus a small read helper:

```rust
/// Loads an external ciphertext into a glyph vector under the given layer.
///
/// `RenderedOrientation` ignores ASCII whitespace and drops digit `5`;
/// `HoneycombReading` splits on whitespace and commas and parses base-5 trigram
/// values `0..=124`.
///
/// # Errors
/// Returns [`IngestError`] on I/O failure, an out-of-range/non-numeric token, or
/// an input that yields no glyphs.
pub fn load_sequence(input: Input<'_>, layer: SequenceLayer) -> Result<Vec<Glyph>, IngestError>;
```

Design notes that keep this consistent and honest:

- **Signature deviation from the overview, stated explicitly.** The overview's
  proposed signature is `load_sequence(input: Input, alphabet: &Alphabet)`
  (`00-OVERVIEW.md:87`). For the two layers in scope, the mapping is
  **positional, not character-table-based**: rendered digit `d → Glyph(d)`
  (`src/glyph.rs:64-68`) and trigram value `v → Glyph(v)`
  (`src/orders.rs:973`). An `Alphabet` (`src/glyph.rs:151`) is a
  char↔glyph table and does not model "skip the `5` delimiter" or "tokens are
  multi-digit numbers `0..=124`". Passing `SequenceLayer` instead is the minimal
  honest fit. If the implementing agent prefers to keep the `alphabet` parameter,
  it must construct the layer's `Alphabet` internally and still strip the
  delimiter — but `SequenceLayer` is the recommended shape. **Either way, update
  the cross-reference in `00-OVERVIEW.md:83-93` and in brief 04 so the briefs
  stay mutually consistent.**
- **No panics.** All parsing returns `Result`; never index a slice or `unwrap`.
  `Orientation::from_digit` (`src/glyph.rs:45-56`) and `TrigramValue::new`
  (`src/trigram.rs:51-57`) already return `Result`/`Err`; thread their errors
  into `IngestError::InvalidToken`. Read I/O errors map to `IngestError::Io`.
- **`Display` for `IngestError`** is hand-written (no new dependency), mirroring
  `report.rs` style and satisfying `00-OVERVIEW.md:119` ("each error enum gets a
  `Display`"). Implement `std::error::Error` too (with `source()` returning the
  inner `io::Error` for the `Io` variant) so it composes with brief 06.
- **`Vec<Glyph>` return, not `Sequence`.** The overview's API and brief 04's
  `SolveRequest.ciphertext: &'a [Glyph]` (`00-OVERVIEW.md:128`) both speak
  `[Glyph]`. The CLI can wrap the result in `Sequence { glyphs }`
  (`src/glyph.rs:207-211`) for `report::print_report` (`src/report.rs:5394`).

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
    /// Treat the input as base-5 honeycomb reading-layer values (0-124)
    /// rather than rendered orientation digits.
    #[arg(long = "honeycomb", default_value_t = false)]
    honeycomb: bool,
}
```

Resolution order in `run_stats`: positional `sequence` → `--input-file` →
stdin (when neither is given). `layer` = `HoneycombReading` if `--honeycomb`
else `RenderedOrientation`. **Corpus stays the default source for `demo`**
(`run_demo`, `src/main.rs:644-655`) — this brief does not touch `demo`.

## Implementation steps (ordered, each independently committable & green)

**Step 1 — `src/ingest.rs` with `RenderedOrientation` only + unit tests.**
Create the module, `Input`, `SequenceLayer` (RenderedOrientation variant first
or both up front), `IngestError`, its `Display`/`Error` impls, and
`load_sequence`. Implement `RenderedOrientation`: iterate `chars`, skip
`char::is_whitespace`, drop `'5'`, map `'0'..='4'` via `Orientation::from_digit`
→ `Orientation::glyph`, else `InvalidToken`. Read helper turns `Input` into a
`String` (`Str` clones; `Path` → `std::fs::read_to_string` mapped to `Io`;
`Stdin` → `io::Read::read_to_string` mapped to `Io`). Register `pub mod ingest;`
in `src/lib.rs:86-87` and add a module-doc bullet near `src/lib.rs:37-38`. Unit
tests (relaxed lints in `#[cfg(test)]` per `clippy.toml`):
- `RenderedOrientation` of `"012 345\n01"` drops `5`/whitespace → glyphs
  `[0,1,2,3,4,0,1]`;
- non-digit / digit `>5` → `InvalidToken` with the right `index`;
- empty / all-whitespace input → `Empty`.
*Green:* `make verify`.

**Step 2 — add `HoneycombReading` + tests.** Split the read string on whitespace
and `,`; for each non-empty token parse `u8`, then `TrigramValue::new`
(`src/trigram.rs:51`) to bound to `0..=124`, then `Glyph(u16::from(value))`.
Non-numeric or `>124` → `InvalidToken`. Tests: `"0 12 124"` → `Glyph(0/12/124)`;
`"125"` and `"x"` → `InvalidToken`; trailing/duplicate separators tolerated.
*Green:* `make verify`.

**Step 3 — golden-master parity test for the rendered path (behavior-preserving
proof).** Add a test asserting that, for the nine corpus digit strings
(`corpus::MESSAGES[i].digits`, `src/corpus.rs:169`+),
`load_sequence(Input::Str(digits), SequenceLayer::RenderedOrientation)` equals
`corpus::messages()[i].sequence().unwrap().glyphs` (`src/corpus.rs:130-137`).
This pins that ingest reproduces the corpus parser byte-for-byte, satisfying the
behavior-preserving rule (`00-OVERVIEW.md:188-190`). *Green:* `make verify`.

**Step 4 — wire the CLI.** Generalize `StatsArgs` (`src/main.rs:107-110`) to the
shape above; rewrite `run_stats` (`src/main.rs:1052-1063`) to resolve
positional→file→stdin, pick the layer from `--honeycomb`, call
`ingest::load_sequence`, wrap the `Vec<Glyph>` in `Sequence { glyphs }`, and call
`report::print_report("input", &seq)` unchanged. On `Err(IngestError)`, print its
`Display` to stderr and return `ExitCode::FAILURE`. **Delete the now-dead
`parse_rendered_sequence`** (`src/main.rs:1065-1079`). Update the `noita_eye_puzzle`
import list (`src/main.rs:10-15`) to bring in `ingest`; the
`glyph::Sequence` import stays for the wrapper. *Green:* `make verify`; manual
smoke (see Verification).

**Step 5 — docs touch-ups.** Update `00-OVERVIEW.md:83-93` (and a note in brief
04 once it exists) to the final `load_sequence(input, layer)` signature if Step 1
deviated. Add a one-line `## Commands`-adjacent example to `AGENTS.md` only if it
adds value (optional). *Green:* `make verify` + `make check` before the final
push (`codespell`/`shellcheck` run there).

Each step compiles, tests, and lints independently; no step leaves the tree red.

## Files to create / change / delete

- **Create** `src/ingest.rs` — `Input`, `SequenceLayer`, `IngestError`
  (+`Display`/`Error`), `load_sequence`, read helper, unit + golden-master tests.
- **Change** `src/lib.rs` — add `pub mod ingest;` (`:86-87`) and a module-doc
  bullet (`:37-38` neighborhood).
- **Change** `src/main.rs` — generalize `StatsArgs` (`:107-110`); rewrite
  `run_stats` (`:1052-1063`); **delete** `parse_rendered_sequence` (`:1065-1079`);
  update imports (`:10-15`).
- **Change** `docs/refactor/00-OVERVIEW.md` — reconcile the `load_sequence`
  signature in §"`Sequence` ingest" (`:83-93`) if it deviated.
- **No change** to `src/corpus.rs`, `src/glyph.rs`, `src/trigram.rs`,
  `src/orders.rs`, `src/report.rs` — ingest reuses their existing public APIs
  (`Orientation::from_digit/glyph`, `TrigramValue::new`, `Glyph`, `Sequence`,
  `print_report`). No new external dependency (no `thiserror`); nothing for
  `cargo-machete`/`cargo-deny` to flag.

## Success criteria

- `load_sequence(Input::Str("…digits…"), RenderedOrientation)` reproduces the
  corpus rendered parse for all nine messages (Step 3 test passes).
- `load_sequence(Input::Path(Path::new("/tmp/gak_cipher_example")),
  RenderedOrientation)` returns a non-empty `Vec<Glyph>` whose length equals the
  count of `0..=4` digits in that file (the sample is now *loadable*).
- `load_sequence(Input::Stdin, …)` reads stdin to EOF and parses it.
- `HoneycombReading` round-trips `0..=124` tokens to `Glyph(value)` and rejects
  `>124`/non-numeric with `InvalidToken`.
- All failure paths return `IngestError` — **no panic, no `unwrap`, no
  `indexing_slicing`** in `src/ingest.rs` or the CLI changes (clippy `-D` clean).
- `stats` works three ways: `noita-eye stats "0120 5 34"`,
  `noita-eye stats --input-file /tmp/gak_cipher_example`, and
  `echo "0120" | noita-eye stats`. `demo` output is byte-for-byte unchanged.
- `make verify` green at each commit; `make check` green before push.

## Verification (exactly how to prove it)

- **`make verify`** after every step (fmt-check + clippy `-D` + tests + rustdoc
  `-D` + cargo-deny, `AGENTS.md:15`).
- **Golden-master / behavior-preserving diff:** the Step 3 corpus-parity test is
  the in-tree proof that ingest equals `Message::sequence`. Additionally confirm
  `demo` is untouched: `cargo run --locked -- demo > /tmp/demo_after.txt` and
  `git stash`-compare against `main`'s `demo` output (must be identical) — this
  is the `00-OVERVIEW.md:188-190` no-statistic-changes check for this brief.
- **Manual smoke (the actual front-door proof):**
  ```sh
  cargo run --locked -- stats "20101 5 322"
  cargo run --locked -- stats --input-file /tmp/gak_cipher_example
  printf '0 12 124\n' | cargo run --locked -- stats --honeycomb
  printf 'bad\n'       | cargo run --locked -- stats   # exits FAILURE, prints IngestError
  ```
  Expect a `report::print_report` block on success and a single
  `IngestError`-`Display` line + non-zero exit on malformed input.
- **New tests** (in `src/ingest.rs#[cfg(test)]`) cover: rendered parse + delimiter
  drop, honeycomb parse + bound, every `IngestError` variant (`Io` via a
  nonexistent path, `InvalidToken`, `Empty`), and the nine-message corpus parity.
- **`make check`** before the final push (adds `cargo-machete`, `codespell`,
  `shellcheck`, release build — `AGENTS.md:16`).

## Risks & honesty caveats

- **Loadable ≠ decoded.** This brief makes external ciphertext *ingestible*; it
  performs **no** cryptanalysis and emits **no** plaintext. The claim ceiling is
  unchanged (`00-OVERVIEW.md:198-206`): the eyes remain *deterministic,
  engine-generated, strikingly structured data of unknown meaning; unsolved.*
  Nothing here may be reported as a step toward a decode beyond "we can now point
  the tools at a sample."
- **Layer ambiguity is a transcription risk.** Mixing the rendered (`0..=4`+`5`)
  and honeycomb (`0..=124`) layers silently would corrupt analysis
  (`AGENTS.md:47-48`). The explicit `SequenceLayer`/`--honeycomb` flag and the
  `InvalidToken { layer, … }` error keep the layer choice loud, never inferred.
- **Signature deviation from the overview** (dropping `&Alphabet` for
  `SequenceLayer`) is a deliberate, documented choice (see Target design); the
  implementing agent must update `00-OVERVIEW.md:83-93` and brief 04's
  cross-reference, per the overview's "update every brief's cross-references if a
  name changes" rule (`00-OVERVIEW.md:9-14`).
- **Stdin in tests:** do not exercise `Input::Stdin` from a unit test (it would
  block on the test harness); cover stdin only via the manual CLI smoke. Unit
  tests use `Input::Str` and `Input::Path` (temp file or the read helper) only.
- **No new dependency** is introduced; if the agent reaches for `thiserror` or an
  arg-file crate, that must be justified against `deny.toml` + `cargo-machete`
  (`AGENTS.md:35-38`) — the hand-written `Display` avoids the need.

## Out of scope / non-goals

- **No mapping search, no scoring, no solve** — that is brief 04
  (`00-OVERVIEW.md:122-137`). This brief stops at producing `Vec<Glyph>`.
- **No `Cipher` trait / `AnyCipher`** — brief 02.
- **No new subcommand.** Only `stats` is wired here; brief 04's `solve` reuses
  `load_sequence`.
- **No module relocation** into `core/` — brief 07 (`00-OVERVIEW.md:139-156`)
  owns the layout move; `src/ingest.rs` stays top-level for now.
- **No changes to `demo`, `corpus`, or any statistic/experiment** — behavior must
  stay byte-for-byte identical (`00-OVERVIEW.md:188-190`).
- **No support for additional input layers** (e.g. raw base-7 storage symbols,
  `StorageSymbol` `-1`, `src/glyph.rs:101-136`) beyond the rendered and honeycomb
  layers named here.
