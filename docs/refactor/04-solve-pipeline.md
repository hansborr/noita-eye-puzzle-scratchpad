# 04 — Solve pipeline + mapping search

> One-line: build the unified `solve` engine — enumerate cipher families × keys × symbol→letter mappings, score with `crate::language`, round-trip-verify, rank, and (Phase 2) *search* the mapping with hill-climb / annealing — the component whose absence let a real English message slip through uncracked.
> Status: not started · Depends on: 02 (`Cipher`/`AnyCipher`), 03 (`load_sequence`/`Input`) · Blocks: — · Size: L

## Goal & why it matters

The workbench can *constrain* the hypothesis space (25 experiments) and can *score* a candidate plaintext (`crate::language`), but it has **no component that searches the space**. `cipher_attack.rs` decrypts and language-scores, but only over a fixed handful of **declared** symbol→letter mappings — `cipher_attack.rs:483-556` enumerate exactly two mapping kinds (`MappingKind::Modulo`, `MappingKind::FrequencyRankCdf`) and the module's own header says so verbatim: *"Every mapping here is a declared guess"* (`cipher_attack.rs:13`). There is no hill-climb, no annealing, no mapping search anywhere in the crate.

The concrete failure this fixes: the sample at `/tmp/gak_cipher_example` is a 266-symbol stream over a 5-symbol alphabet (verified: only digits `0`–`4` appear). A 5-symbol substitution mapping is small enough that a hill-climb on a bigram language score recovers it routinely — yet the workbench never tried, because the only search loops it has (`search_caesar` … `search_deck`, `cipher_attack.rs:623-793`) iterate over **keys** under a **frozen** mapping, never over the mapping itself. Brief 04 builds the missing search.

This is the highest-reward Tier-1 item and the single biggest step toward the end goal (reading the eyes). It is also the highest **claim-discipline** risk in the project: a search-and-score engine must never present a scored candidate as a decode. Round-trip verification is mandatory, every emitted candidate is a labelled HYPOTHESIS auto-logged to `research/gak-threads/candidates/`, and the matched-null control must stay flat (the same search on shuffled ciphertext must not win). The claim ceiling is unchanged: *deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved.*

## Current state (grounded, with file:line)

**The scorer to reuse** — `crate::language` is a real, calibrated bigram model:
- `LanguageModel::score_indices(&self, indices: &[usize]) -> Result<LanguageScore, LanguageError>` (`language.rs:271-298`) is the objective. It returns `LanguageScore { symbols, unigram_mean_log_likelihood, bigram_mean_log_likelihood }` (`language.rs:217-228`); the bigram mean is what every existing search maximizes.
- `LanguageAlphabet::normalize_text` / `normalize_text_into` (`language.rs:192-213`) and `LanguageAlphabet::index`/`symbol` (`language.rs:166-178`) convert between text and indices — used to build synthetic positive-control plaintext.
- `english_model()` / `finnish_model()` (`language.rs:424-434`), both over the shared 29-symbol `DEFAULT_LANGUAGE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖ"` (`language.rs:26`). Noita is Finnish; weight Finnish at least as heavily as English (README directive, `research/gak-threads/candidates/README.md:69-71`).
- The held-out calibration test (`language.rs:584-617`) confirms the model separates English from Finnish — i.e. it is a usable objective, not decoration.

**The harness to extend/reuse** — `cipher_attack.rs`:
- `run_cipher_attack(config) -> Result<CipherAttackReport, CipherAttackError>` (`cipher_attack.rs:398-421`) is the existing top-level: for each `CipherFamily` (`cipher_attack.rs:193-205`, five families) it runs `search_cipher` (`cipher_attack.rs:608-621`) plus a matched within-message shuffle null (`null_samples`, `cipher_attack.rs:582-600`).
- The per-family search loops (`search_caesar` `:623`, `search_incrementing_wheel` `:646`, `search_vigenere` `:675`, `search_chaocipher` `:716`, `search_deck` `:753`) iterate keys, decrypt with the free functions from `ciphers.rs`, then call `score_candidate` (`cipher_attack.rs:850-856`). The decode→mapping→score chain is `decrypt_messages` (`:839`) → `map_messages` (`:858`, the declared-mapping step) → `weighted_language_score` (`:981`). **This whole chain freezes the mapping and never searches it.**
- The matched-null pattern to copy: `shuffled_messages` (`:1122`, Fisher-Yates per message via `null::fisher_yates`), `summarize_null` (`:1018`, computes mean/q95/max/empirical-p), and the per-cipher seed tag `mix_seed(config.seed, cipher.seed_tag() ^ 0x6e75_6c6c)` (`:589`). Reuse these shapes verbatim so the new null is calibrated identically.
- **The positive-control precedent to mirror**: `run_positive_controls` (`:1168-1203`) plants a known English plaintext (`POSITIVE_CONTROL_TEXT`, `:48`) under Caesar shift 17 and Vigenère `[3,11]`, then asserts `recover_plant` recovers the exact key and beats the null by `POSITIVE_CONTROL_MIN_MARGIN = 0.10` (`:47`, `:1236-1268`). Phase 1 and Phase 2 each need an analogous positive control.
- Error type `CipherAttackError` (`cipher_attack.rs:55-165`) is a hand-written enum with `Display` + `std::error::Error` — match this style for `SolveError`.

**The cipher dispatch (from brief 02)** — `AnyCipher` is the heterogeneous enum the overview specifies (`00-OVERVIEW.md:78-81`). It does not exist yet; brief 02 adds it to `crate::ciphers` wrapping the existing keys (`CaesarKey` `ciphers.rs:375`, `VigenereKey` `:412`, `IncrementingWheelKey` `:460`, `ChaocipherKey` `:511`, `DeckCipherKey` `:585`, `GakKey` `:956`) and the existing `*_encrypt`/`*_decrypt` free functions (`ciphers.rs:1101-1372`). `EYE_READING_ALPHABET_SIZE = 83` (`ciphers.rs:21`). **If brief 02 lands a different name/shape, follow brief 02 and update this brief's cross-references; do not invent a parallel dispatch.** Until 02 is green, Phase 1 may temporarily dispatch over the existing `CipherFamily` + free functions (the exact pattern `search_cipher` already uses, `cipher_attack.rs:614-620`) behind a thin internal adapter, then swap to `AnyCipher`.

**The ingest front door (from brief 03)** — `load_sequence(input: Input, alphabet: &Alphabet) -> Result<Vec<Glyph>, IngestError>` and `enum Input { Str, Path, Stdin }` (`00-OVERVIEW.md:86-89`). Today the only parse path is `Sequence::parse(text, alphabet)` (`glyph.rs:219-231`, skips whitespace, errors on the first unknown char) and the embedded `corpus`. `Glyph(pub u16)` (`glyph.rs:140`); `Alphabet::from_chars` (`glyph.rs:165`). The CLI is `clap`-based with one `Command` variant per experiment (`main.rs:34-104`) dispatched in a flat `match` (`main.rs:615-640`); add a `Solve` variant beside them.

**The candidate-logging convention (load-bearing, must reuse)** — `research/gak-threads/candidates/`:
- `README.md` is the binding protocol: every record carries the claim ceiling verbatim (`README.md:10-13`), the kill order (held-out + matched-null, Thread-3 consistency, then *speculative* cleartext only — `README.md:36-52`), the HYPOTHESIS-not-decode label, and **any candidate cleartext in English OR Finnish must be written verbatim with scores and caveats even if failing** (`README.md:69-71`). The expected record is "NO candidate surfaced" (`README.md:20-24`, `:72`).
- The machine-writer to imitate: `write_eyes_candidate_record` (`gak_attack.rs:5923-5940`, creates the dir, writes the body, maps IO errors to a `CandidateRecordWrite { path }` variant) and `render_eyes_candidate_record` (`:5945`, pure string builder, unit-testable without the filesystem). Filenames are a **stable label derived from config/seed, never a wall-clock** (`eyes_record_filename`, `:5878-5883`; rationale `README.md:62-64`). The speculative-cleartext gate `eyes_speculative_cleartext` (`:5753-5794`) and its matched mapping-null `eyes_mapping_null` (`:5821-5872`) are the existing pattern for scoring an implied plaintext behind a null under a HYPOTHESIZED mapping — reuse this discipline.

**Candidate beam search to reuse for the GAK family** — `gak_attack.rs` carries a bounded beam over hidden-state branches (`beam_recover_column`, `gak_attack.rs:3513-3573`; `run_marginalization_attack`, `:3631`). It is **structural recovery, not cleartext**, and it is synthetic/eyes-internal. Phase 2 *may* reuse it as the GAK-family mapping recovery, but only behind the same round-trip + null + HYPOTHESIS gates as every other family; it is not a shortcut around them. **Coordinate with brief 07, which splits `gak_attack.rs` (7,967 lines) — sequence on the same branch or agree the split point.**

## Target design (concrete API / types / layout)

New module `crate::attack::solve` (a new file `src/solve.rs` registered in `lib.rs`; physical move into `src/attack/` is brief 07's job — keep it a flat `pub mod solve;` for now to avoid colliding with 07).

```rust
// crate::solve  (later crate::attack::solve)

/// A symbol→language-index mapping: maps each cipher-alphabet symbol (0..cipher_alphabet_size)
/// to a language-alphabet index (0..language_alphabet.len()).
pub struct Mapping { table: Vec<usize> }      // len == cipher alphabet size
impl Mapping {
    pub fn identity(cipher_alphabet_size: usize) -> Mapping;          // i -> i (when sizes allow)
    pub fn apply(&self, ct: &[Glyph]) -> Result<Vec<usize>, SolveError>;
    pub fn table(&self) -> &[usize];
}

/// What to search: cipher families × key/param ranges × symbol→letter mappings.
pub struct HypothesisSpace {
    pub families: Vec<CipherFamilySpec>,   // which ciphers + their key ranges (reuse cipher_attack's loops)
    pub mappings: MappingStrategy,         // Phase 1: Fixed set; Phase 2: Search
    pub language: LanguageChoice,          // English, Finnish, or Both (score under each, keep best)
    pub cipher_alphabet_size: usize,       // e.g. 5 for the /tmp sample, 83 for the eyes
}

pub enum MappingStrategy {
    /// Phase 1: a declared, fixed set of mappings (reuse cipher_attack's Modulo / FrequencyRankCdf,
    /// plus Identity). No search — round-trips and scores only.
    Fixed(Vec<Mapping>),
    /// Phase 2: hill-climb / simulated annealing over symbol→letter, language score as objective.
    Search(MappingSearch),
}

pub struct MappingSearch {
    pub restarts: usize,        // random restarts
    pub iterations: usize,      // proposals per restart
    pub anneal: Option<AnnealSchedule>,   // None => pure hill-climb (accept only improvements)
    pub seed: u64,              // drives SplitMix64; same seed => same search (reproducible)
}

pub struct SolveRequest<'a> {
    pub ciphertext: &'a [Glyph],
    pub space: HypothesisSpace,
    pub english: &'a LanguageModel,
    pub finnish: &'a LanguageModel,
}

pub struct Candidate {
    pub cipher: AnyCipher,        // the winning cipher + key (brief 02). Phase-1 fallback: CipherFamily + key label.
    pub mapping: Mapping,
    pub language: LanguageKind,   // reuse cipher_attack::LanguageKind
    pub plaintext: String,        // implied text under `mapping`, for verbatim logging
    pub score: f64,               // bigram_mean_log_likelihood of the winning (cipher,key,mapping)
    pub round_trip_ok: bool,      // MUST be true for an emitted candidate
    pub null_mean: f64,           // matched-null mean (search rerun on shuffled ciphertext)
    pub beats_null: bool,         // score > matched-null best; informational, never a "decode"
}

pub fn solve(req: &SolveRequest) -> Result<Vec<Candidate>, SolveError>;   // ranked desc by score
```

**Round-trip verification (mandatory, the discipline gate).** A `Candidate` is admissible only if re-encrypting the implied plaintext reproduces the ciphertext exactly. Concretely: given the winning `(AnyCipher, key)` and the recovered plaintext-as-glyphs, `cipher.encrypt(pt) == ciphertext` byte-for-byte. For a pure substitution mapping over a deterministic cipher this is mechanical; `round_trip_ok` records it and **`solve` filters out any candidate where it is false**. This makes "a score is not a decode" structurally enforced, not just documented.

**`solve` algorithm (both phases share the skeleton):**
1. For each `CipherFamilySpec`, enumerate keys exactly as `cipher_attack`'s `search_*` loops do (reuse those loops; do not reimplement keyspaces). Decrypt the ciphertext to symbols.
2. Resolve the mapping: `Fixed(set)` scores each declared mapping (Phase 1); `Search(cfg)` runs the hill-climb/anneal (Phase 2) to *find* a mapping that maximizes `LanguageModel::score_indices`.
3. Score the mapped indices with `score_indices` under the chosen language(s); keep the per-(cipher,key) best.
4. **Round-trip-verify** the best; drop it if it fails.
5. Run the **matched null**: rerun the identical Phase-1/Phase-2 procedure on a Fisher-Yates-shuffled ciphertext (`null::fisher_yates`, same seed-tag discipline as `cipher_attack.rs:589`); record `null_mean` and `beats_null`.
6. Collect, sort by `score` desc, return.
7. **Auto-log**: write a candidate record to `research/gak-threads/candidates/` for the top candidate(s), using a writer that mirrors `write_eyes_candidate_record` (stable seed-derived filename, claim ceiling verbatim, HYPOTHESIS label, English+Finnish scores+caveats, matched-null verdict). Expected record on the eyes is still "NO candidate surfaced — decode remains blocked."

**`MappingSearch` (Phase 2).** State = a `Mapping` (a `Vec<usize>` of length `cipher_alphabet_size`). Objective = `score_indices(mapping.apply(decrypted)).bigram_mean_log_likelihood`. Proposal = swap two symbols' targets (or repoint one symbol). Acceptance = improvement (hill-climb) or Metropolis (annealing, if `anneal` is `Some`). `restarts` random starts from `shuffled_permutation` (`null.rs:159`) reduce local-optimum risk; the best mapping over all restarts wins. All randomness from `SplitMix64` seeded by `cfg.seed` so the search is **bit-for-bit reproducible** (the property the whole crate's nulls rely on, `null.rs:27-36`).

**CLI (Phase 1 deliverable).** Add `Command::Solve(SolveArgs)` to `main.rs` (`main.rs:34-104`), dispatched in the flat `match` (`main.rs:615-640`). `SolveArgs` carries the ciphertext source (a positional string, or `--file <path>`, or `--stdin` — wired to brief 03's `load_sequence`/`Input`), `--alphabet` (the transcription chars, e.g. `01234` for the sample; default to the eye layer), `--seed`, family selection, and a `--mapping-search` flag that flips `MappingStrategy::Fixed` → `Search` (Phase 2). Keep `main.rs` thin: a `run_solve(req)` library entry returns the ranked `Vec<Candidate>` and a renderer prints it; logic stays in the library (`main.rs:3-5`).

## Implementation steps (ordered, each independently committable & green)

> **Hand-off note: Phase 1 (steps 1–5) and Phase 2 (steps 6–8) are cleanly separable and can go to different agents.** Phase 1 builds the enumerate→score→round-trip→rank→CLI skeleton over a *fixed* mapping set and is independently valuable. Phase 2 adds the *search* (the new capability) on top of Phase 1's `solve` skeleton. Steps 9–10 (auto-logging + eyes wiring) sit on top of Phase 2; the eyes case may stay a `Fixed`/`Search` honest-negative.

**Phase 1 — enumerate / decrypt / score / round-trip / rank + CLI.**
1. **`Mapping` + `SolveError` + `Candidate` skeleton.** New `src/solve.rs`: `Mapping` (identity/apply/table), `SolveError` (hand-written enum with `Display` + `std::error::Error`, mirroring `CipherAttackError`, with at least `Language`, `Cipher`, `Ingest`, `RoundTripFailed`, `EmptyHypothesisSpace`, `CandidateRecordWrite` variants and `From` impls), `Candidate`, `HypothesisSpace`, `SolveRequest`, `MappingStrategy::Fixed`. Document every public item. Unit-test `Mapping::apply` and identity. *(Green: compiles, `make verify`.)*
2. **`solve` over `Fixed` mappings, single family.** Implement the step-1–4 skeleton for one family (Caesar), reusing `cipher_attack`'s key loop and `score_candidate`/`weighted_language_score` shapes (extract the reusable parts; do **not** fork the scorer). Round-trip-verify and drop failures. Return ranked candidates. *(Green: a synthetic test plants a Caesar-encrypted English message over a small alphabet and `solve` returns it as the top, round-trip-valid candidate.)*
3. **All families + `AnyCipher`.** Generalize step 2 across every `CipherFamilySpec`. Prefer brief 02's `AnyCipher`; if 02 is not yet merged, dispatch over `CipherFamily` + the existing free functions behind a private adapter and leave a `// TODO(brief-02): swap to AnyCipher` marker. *(Green: per-family round-trip on synthetic plants.)*
4. **Matched-null control (Phase-1 form).** Add the Fisher-Yates shuffle rerun and `null_mean`/`beats_null`, copying `cipher_attack::shuffled_messages` + `summarize_null` discipline and seed tags. *(Green: on shuffled ciphertext the fixed-mapping search does not beat the real result; deterministic for a fixed seed.)*
5. **CLI `solve` subcommand + ingest.** Add `Command::Solve(SolveArgs)`, `run_solve`, and a renderer; wire the ciphertext source to brief 03's `load_sequence`/`Input`. *(Green: `cargo run -- solve --file /tmp/gak_cipher_example --alphabet 01234` runs end-to-end; `make verify`.)*

**Phase 2 — mapping search (the new capability).**
6. **`MappingSearch` hill-climb.** Add `MappingStrategy::Search`, `MappingSearch`, the swap-proposal hill-climb with random restarts, all driven by `SplitMix64(cfg.seed)`. Wire it into `solve` as an alternative to `Fixed`. *(Green: a `restarts=N` hill-climb recovers a planted small-alphabet substitution on synthetic ground truth; bit-for-bit reproducible for a fixed seed.)*
7. **Simulated annealing schedule.** Add `AnnealSchedule` + Metropolis acceptance as an opt-in on `MappingSearch`. *(Green: anneal recovers the same plant; reproducible.)*
8. **Matched-null control for the search (the load-bearing guard).** Rerun the *identical search* (same restarts/iterations/seed) on a Fisher-Yates-shuffled ciphertext. Assert the shuffled-ciphertext best does **not** beat the real best by the search's margin. *(Green: a test asserts the matched null stays flat under search — search on noise does not manufacture a winner.)*

**Phase 2 capstone — auto-logging + positive controls + eyes wiring.**
9. **Auto-log every emitted candidate.** Add `write_solve_candidate_record` + a pure `render_solve_candidate_record`, mirroring `write_eyes_candidate_record`/`render_eyes_candidate_record`: stable seed-derived filename (no clock), claim ceiling verbatim, HYPOTHESIS-not-decode label, English **and** Finnish scores + caveats, matched-null verdict, round-trip status. Render is unit-tested without the filesystem. *(Green: a candidate run writes a well-formed record into a temp `candidates_dir`; render test passes.)*
10. **Positive controls + the /tmp sample + eyes honest-negative.** Add (a) a synthetic positive control recovering a planted small-alphabet substitution+cipher (mirrors `run_positive_controls`); (b) a test that `solve` on the `/tmp/gak_cipher_example` digit stream surfaces a high-scoring, round-trip-valid English plaintext (the message the old tooling missed); (c) the eyes path over the 83-symbol layer, expected to produce an honest negative whose record says "decode remains blocked." *(Green: all three; `make check`.)*

## Files to create / change / delete

**Create**
- `src/solve.rs` — the engine (`Mapping`, `HypothesisSpace`, `MappingStrategy`, `MappingSearch`, `SolveRequest`, `Candidate`, `SolveError`, `solve`, the candidate-record writer/renderer).
- A small fixtures helper in `solve.rs` `#[cfg(test)]` for synthetic plants (encrypt a known plaintext under a known mapping+key), and a checked-in copy or test-only inclusion of the `/tmp/gak_cipher_example` stream for the regression test (do **not** depend on `/tmp` at test time — embed the 266-symbol string as a test constant with its provenance noted).

**Change**
- `src/lib.rs` — add `pub mod solve;` (`lib.rs:72-103` block).
- `src/main.rs` — add `Command::Solve(SolveArgs)` (`main.rs:34-104`), the dispatch arm (`main.rs:615-640`), `SolveArgs`, `run_solve`, and a renderer; import `solve` and brief 03's ingest.
- `src/ciphers.rs` — only if brief 02 has not already exposed `AnyCipher`/`encrypt`/`decrypt`; coordinate, don't duplicate.
- `research/gak-threads/candidates/README.md` — extend the "Files" section to note `solve-*.md` records alongside `eyes-*.md` (the protocol itself already covers them).

**Delete** — none. `cipher_attack.rs` stays (it is the declared-mapping Experiment 12 harness); `solve.rs` is the new search engine. Do not remove or rewrite `cipher_attack`'s reported statistics — they are behavior-locked.

## Success criteria

- **Positive control (synthetic):** `solve` recovers a planted plaintext on a synthetic fixture — known cipher + known small-alphabet symbol→letter mapping — returning it as the top, round-trip-valid candidate (Phase 1 for the fixed-mapping case; Phase 2 for the searched-mapping case).
- **Positive control (the real gap):** `solve` surfaces a high-scoring, **round-trip-valid English** plaintext from the `/tmp/gak_cipher_example` digit stream — the message the old tooling missed. This is the proof the capability gap is closed.
- **Matched-null stays flat:** the identical search on a Fisher-Yates-shuffled ciphertext does **not** beat the real result by the search margin. (Asserted as a test, both Phase 1 and Phase 2.)
- **Round-trip is mandatory:** no `Candidate` with `round_trip_ok == false` is ever emitted; a test asserts `solve` filters them.
- **Auto-logging:** every emitted candidate is written to `research/gak-threads/candidates/` as a labelled HYPOTHESIS with English+Finnish scores, caveats, matched-null verdict, and the verbatim claim ceiling; filenames are stable/seed-derived (no clock).
- **Eyes honest-negative preserved:** running `solve` over the 83-symbol eye layer produces no surviving candidate and a record that says the decode remains blocked — the standing conclusion is unchanged.
- **Determinism:** every search and null is bit-for-bit reproducible for a fixed seed.
- **`make verify` green at every step; `make check` green before the final push.** House invariants hold: no `unsafe`, no `unwrap`/`panic`/`indexing_slicing`/`unused_results` in library/CLI code, every public item documented, `--locked`.

## Verification (exactly how to prove it)

- `make verify` after every step; `make check` before the final push.
- **Golden master (brief 01):** confirm `run_cipher_attack`, the null calibrations, and the corpus base-7 cross-check are byte-for-byte unchanged — `solve.rs` must not perturb any existing reported number. Diff the golden-master outputs.
- **New tests in `solve.rs`:**
  - synthetic plant → top round-trip-valid candidate (fixed mapping, then searched mapping);
  - `/tmp` sample → high-scoring round-trip-valid English plaintext (embedded constant, provenance noted);
  - matched-null-stays-flat (search on shuffle does not win), Phase 1 and Phase 2;
  - round-trip filter drops a deliberately non-invertible candidate;
  - determinism: two runs with the same seed produce identical `Vec<Candidate>`;
  - record renderer emits the claim ceiling + HYPOTHESIS label + both language scores (pure-string test, no filesystem).
- **CLI smoke:** `cargo run --locked -- solve --file /tmp/gak_cipher_example --alphabet 01234 --mapping-search` runs end-to-end and prints a ranked, labelled-HYPOTHESIS result; `cargo run --locked -- solve` over the eye layer prints the honest negative.

## Risks & honesty caveats

- **A score is not a decode — this is the crown-jewel risk.** Round-trip verification is the structural guard; it is mandatory and non-negotiable. Every emitted candidate is a labelled HYPOTHESIS, logged per `research/gak-threads/candidates/README.md`. The claim ceiling (`README.md:10-13`) is reproduced verbatim in every record. The eyes' strongest defensible statement remains *unsolved; decode blocked on the unknown symbol→meaning mapping*.
- **The 83-symbol eye layer vs the 5-symbol sample.** The `/tmp` sample is crackable precisely because its alphabet is tiny (5 symbols → a small mapping search space). The eye layer is 83 symbols with very little text; the same search is **not** expected to crack it, and the matched-null + held-out gates exist to keep an over-fit from masquerading as a solution. Do not let a high score on 83 symbols with no held-out validation be reported as a candidate — `README.md:54-58` (the trap) is binding.
- **Determinism is a correctness property, not a nicety.** All randomness flows through `SplitMix64` seeded explicitly; never read the clock (records must be reproducible, `README.md:62-64`). The modulo bias note in `null.rs:59-71` is intentional and must not be "fixed" in a way that changes existing streams.
- **Finnish first.** Noita is Finnish; score and log Finnish at least as prominently as English (`README.md:69-71`). A candidate must be logged even if low-confidence or failing.
- **Brief-02 / brief-07 coupling.** `AnyCipher` comes from 02; the `gak_attack.rs` split is brief 07. If 02's `AnyCipher` differs from the overview sketch, follow 02 and update cross-references here. Coordinate the `gak_attack.rs` beam-search reuse with 07 on a shared branch (`00-OVERVIEW.md:181-182`).
- **No big-bang.** Each step lands green on its own; if a step cannot be made independently green it is mis-scoped — re-split it.

## Out of scope / non-goals

- Inventing or endorsing a symbol→letter mapping for the **eyes** as a finding. The mapping is always a HYPOTHESIS; the eyes' honest negative is the expected, fully-reportable outcome.
- New cipher families. `solve` searches over the existing families behind `AnyCipher`; adding ciphers is separate work.
- Changing any reported statistic or decode anywhere in the crate (behavior-preserving is mandatory; brief 01 pins it).
- The physical move of `solve.rs` into `src/attack/` and the `gak_attack.rs` god-file split — those are brief 07. Keep `solve` a flat `pub mod` here.
- The null/experiment-harness dedup (`run_null_test`, brief 05). `solve` reuses `null::fisher_yates`/`SplitMix64`/`add_one_p_value` directly; it does not depend on brief 05's harness landing first.
- A clap-subcommand registry refactor (brief 08); `solve` adds one ordinary `Command` variant in the existing flat `match`.
