# 07 — Bridge: mapping the findings onto this Rust workbench

This research folder lives inside the existing `noita-eye-puzzle` Rust crate
(`../src`). This document connects the code-investigation plan
([05-code-investigations.md](05-code-investigations.md)) to the code that already
exists, so the next coding session has a concrete build order instead of a blank
page. Nothing here changes the crate — it is a plan.

## Why the fit is good

The crate's stated ethos (`../AGENTS.md`) is *"trustworthy cryptanalysis:
primitives that constrain the hypothesis space, not premature claims."* The
research independently converged on the same conclusion from the opposite
direction: the community's headline results are largely artifacts of a reading
order chosen because it looked clean, and the missing ingredient across the
whole corpus is null distributions (see Experiments 1, 2, 7). The crate is
already built to host exactly that kind of work, and two of its existing rules
map straight onto the research's main warnings:

| Existing crate rule (`AGENTS.md`)                         | Research finding it anticipates                                              |
| -------------------------------------------------------- | --------------------------------------------------------------------------- |
| "Never present unverified numbers as findings."          | The whole corpus rests on order-selected stats with no family-wise correction. |
| "Transcription is the risk… cross-check real data."      | Experiment 0: four independent transcriptions must be diffed before trusting any. |
| `Glyph` is an opaque `u16`, not a closed enum yet.        | The rendered 0–4 + delimiter-5 inventory is **confirmed** → add a closed `Orientation` type, but keep `Glyph`/`Alphabet` generic (see below). |

## What already exists (and is reusable as-is)

- `src/glyph.rs` — `Glyph(u16)` / `Alphabet` / `Sequence`. The parsing and
  alphabet model are directly reusable.
- `src/analysis.rs` — `frequencies`, `shannon_entropy`, index of coincidence,
  n-grams. These are the primitives Experiments 3, 4, 5, 6 need.
- `src/corpus.rs` — the verified Experiment-0 corpus (since implemented),
  cross-checked byte-for-byte against the four transcriptions.
- `src/main.rs` — thin CLI; grows into subcommands as modules land.

## What the research does (and does not) settle for the crate

`AGENTS.md` says to promote `Glyph` from `u16` to a closed `enum` "once the
inventory is settled." The research settles only part of that: the *rendered
orientation alphabet* is fixed — exactly 5 displayed orientations → digits 0–4,
plus 5 = row delimiter (never rendered) [confirmed]. That alone does not
justify promoting `Glyph` itself to a closed enum, because the code also has to
represent the storage layer (base-7 symbols −1..5, where 5 = newline), the
trigram reading values (0–124), and the possibility of future transcription
corrections. Recommendation: add a closed `Orientation` enum (0–4) + an explicit
delimiter marker for the rendered layer, but keep `Glyph`/`Alphabet` generic
until the corpus and the two-layer model are actually implemented. The deeper point
is that the crate should encode *two* layers, which the current single `Alphabet`
does not capture:

- **Storage/engine layer:** base-7 over 64-bit integers emitting −1..5 (5 = newline).
- **Reading layer:** base-5 trigrams of the rendered 0–4 glyphs → 0–124.

These must stay distinct types in code (the research flags conflating them as a
common error). Suggest a `glyph::Orientation` enum (0–4) + an explicit `Delimiter`
marker, and a separate `trigram` module for the 0–124 reading layer. **Caveat:**
the *direction* each digit denotes (1=up, 2=right, …) is `[unverifiable]` from any
text source — keep digit identities, do not bake pixel-direction semantics
into the type.

## Build order (experiment → module)

Priorities mirror §"What would actually move the needle" in
[05-code-investigations.md](05-code-investigations.md).

### Tier 1 — prerequisites and the decisive tests

1. **`corpus::ingest` (Experiment 0)** — *since implemented.* Fetches the four
   transcriptions, normalizes each to (a) raw 0–4 string with delimiter removed and
   (b) per-message base-5 trigram sequence, with a cross-validation test
   that fails on any byte-level disagreement. Each message's in-game source is
   recorded alongside the data (the crate insists on this). Now that this passes,
   the numbers the crate prints are meaningful.
   - Inputs are in `data/code-testable.json` and `data/sources.json` here, plus:
     `ngraham20/NoitaCryptographyResearch` (`eye/eyes.json`),
     `Doctor-Ned/NoitaEyeGlyphResearch` (`data.csv`),
     `ToboterXP/EyeGlyphs` (`noitaGlyphs.txt`),
     Xkeeper0 PHP transcoder gist.

2. **`analysis::null` + `reading_order` (Experiment 1)** — the decisive test, *since
   implemented.* It implements the 36 standard reading orders (and optionally
   Toboter's ~86k space), then a null-distribution harness: generate many random
   grids of identical dimensions and measure how often *some* order yields a
   contiguous range. This is the family-wise correction the community's
   `(83/125)^1036` omits.
   - **Reproducibility note:** vetted crates are allowed now, but keep null-run
     randomness on the tiny in-crate deterministic PRNG unless there is a measured
     reason to change it. Seed it from a CLI flag so null runs are reproducible;
     this fits the "no hidden nondeterminism" ethos and keeps `--locked` honest.

3. **`generator` (Experiment 2)** — implement the documented base-7 / 64-bit
   generator and reproduce the wiki worked example
   (`acf686745634505c` → the 22-value sequence) as a test. Then feed random
   64-bit ints and known plaintexts through the same pipeline and run the Tier-2
   stats on the output. Constrain the null to the real structure — match the
   per-message `[u32,u32]` block count, output lengths, delimiter layout, and the
   "no internal −1" property; unconstrained random base-7 noise is only a separate
   negative control, not the null. If structure-matched random inputs *also* produce
   near-contiguous ranges / pseudo-isomorphs, the "encoding" reading weakens — a
   major correction.

### Tier 2 — signal characterization (mostly reuses `analysis.rs`)

4. **Experiment 3** — divisibility + trigram-count assertions as tests
   (`{297,309,354,306,411,372,357,360,342}`, sum 1036). Trivial; also encodes the
   "count eyes, not delimiters" caveat so it can't regress.
5. **Experiment 4** — add chi-square goodness-of-fit to `analysis.rs`; run
   frequency/entropy/IoC on the real corpus across multiple orders to quantify
   how order-dependent flatness is.
6. **Experiment 6** — add adjacency + recurrence-distance histograms. Use
   "adjacent-equal == 0" as an independent reading-order discriminator (cross-check
   on Experiment 1's winner).
7. **Experiment 5** — Kasiski / autocorrelation / IoC-by-period; Caesar +
   short-Vigenère brute scored against English and Finnish n-gram models (add
   small corpora under `data/`).

### Tier 3 — structure and candidate ciphers (research frontier)

8. **Experiment 7** — isomorph detection with a shuffle-based null (the null is
   the genuinely missing contribution; the detection itself exists upstream).
9. **Experiment 8** — base-N / grouping reinterpretation; estimate internal state
   count *independently* (don't assume 83).
10. **Experiment 11** — the solved ciphers as positive-control fixtures
    matched to each tool: monoalphabetic ciphers (e.g. Common Glyphs →
    "SEEK THE END") for the frequency/substitution path; *generated*
    polyalphabetic/autokey fixtures with known keys for the isomorph/chaining path.
    The solved Noita puzzles are domain context, not drop-in tooling controls —
    the Cessation Cipher in particular is a multi-step image/key puzzle the
    frequency/IoC pipeline will not recover. If the *matched* controls fail, a null
    on the eyes is meaningless. Highest-value calibration step.
11. **Experiment 12** — candidate cipher implementations (incrementing-wheel,
    Chaocipher/Hutton, S_83 deck). Frontier, not verification.

### Out of pure-crate scope (document, don't force into Rust)

- **Experiment 9** (seed-invariance) needs the game or its world-gen PRNG; the crate
  can still *store* cross-seed transcriptions and diff them.
- **Experiment 10** (sprite-state clustering) is image work; better as a small
  Python side-tool than inside the core Rust crate.

## First three commits, concretely

1. Settle the glyph model: `Orientation` enum (0–4) + delimiter, plus a `trigram`
   reading-layer type; keep storage vs reading layers distinct, and keep
   `Glyph`/`Alphabet` generic. Update `AGENTS.md` to note the *rendered* orientation
   alphabet is settled (5 orientations + delimiter) while the full type model is not.
2. `corpus::ingest` + the four-way cross-validation test (Experiment 0) — since
   implemented; the sample was replaced with the real, verified corpus once it
   parsed.
3. The reading-order + null-distribution harness (Experiment 1) behind a
   `noita-eye nulltest` subcommand — since implemented. This is the result most
   likely to confirm or deflate the community's headline claim.

## Honest framing to carry into the code

The strongest defensible statement (per the verification verdicts in
[03-confirmed-vs-speculation.md](03-confirmed-vs-speculation.md)) is: *"The Eye
Messages are deterministic, engine-generated, structured data of unknown meaning;
they are unsolved, and there is no primary developer source confirming they encode
recoverable plaintext."* The crate should never print stronger than that.
