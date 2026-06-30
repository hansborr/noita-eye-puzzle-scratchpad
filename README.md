# noita-eye-puzzle

Noita is a Finnish roguelite, and the "eye glyphs" are one of its long-running
mysteries: sequences of eye symbols hidden in the world that look like they
encode something, and that nobody has conclusively cracked.

This is a Rust workbench for analyzing those sequences. The goal is deliberately
modest: build cryptanalysis tools that *narrow down what the puzzle could be*,
and that can tell a real signal apart from a coincidence. Every statistic here is
paired with a null model or a positive control, so a negative result means
something and a positive one can be trusted.

If you're coming from the Noita community: this builds on the transcriptions and
reverse-engineering the community has already done. It doesn't claim to have
solved anything — it's a toolkit and a careful record of what's been ruled out.
The library and a nine-experiment investigation are complete, tested,
independently reviewed, and gate-green.

## The honest current state

> The eye data is deterministic, engine-generated, strikingly structured data
> of unknown meaning. Under the honeycomb reading order (`standard36-u012-d012`)
> it shows no recoverable simple-cipher signal; the structural battery
> disfavors monoalphabetic and fixed-keystream additive ciphers and favors
> a plaintext-dependent (self-modifying) permutation direction — but decodes
> nothing. The puzzle is unsolved: no primary developer source confirms it
> encodes recoverable plaintext, and the 83-symbol→meaning mapping is not present
> in the game's storage layer.

Nothing in this repo prints anything stronger than that.

## The data is real

`src/data/corpus.rs` holds the nine eye messages with their provenance. A test
re-derives the engine's base-7 decode from Xkeeper0's `[u32, u32]` integer pairs
and checks it equals the ngraham20 transcription byte-for-byte for all nine
messages — so the two independent community transcriptions agree. Transcription
error is the single biggest risk in this kind of work, so the corpus is
cross-checked rather than trusted. Raw inputs are vendored under
`research/data/eye-messages/`.

It's well established (and already documented by the community) that the messages
are hardcoded constants — the world seed only randomizes *where* the eyes
appear, not what they say — and that the game's storage layer holds opaque
integers with no symbol→meaning table. That second point shapes what this
workbench can and can't do: the mapping that would actually turn glyphs into
letters isn't in the game files, so it can't be datamined or recovered by
cryptanalysis alone. It would have to come from in-game lore or a developer
source.

## Two glyph layers

Two representations of the data are kept strictly distinct — conflating them is
the classic way to manufacture a false signal:

- the storage / engine layer — how the game stores the messages: base-7 over
  64-bit integers, symbols `−1..5` with `5` as a row delimiter;
- the reading layer — base-5 trigrams of the rendered orientations `0..4`,
  giving values `0..124`, of which 83 are actually used.

## Running it

```sh
cargo run -- demo              # the headline analysis on the verified nine-message corpus
cargo run -- stats <sequence>  # frequency / entropy / IoC for rendered digits 0–4
cargo run -- orders            # reading-order audit
cargo run -- --help            # every subcommand and flag
```

The binary (`noita-eye`) exposes the whole structural battery, the null tests,
the positive controls, and the cipher-attack/solve pipelines as subcommands.
`cargo run -- --help` (or `cargo run -- <subcommand> --help`) lists them all.

## Results

Every experiment pairs a measurement with a null model or a positive control. For
the eyes the cipher and decryption results are uniformly negative; for the
known-answer controls they're positive — the tools provably fire on real
signal, and the eyes don't light them up. The full experiment-by-experiment
detail, with all the numbers, lives in `CHANGELOG.md` and under `research/`. The
highlights:

- **Structured, but not a simple cipher.** Per-symbol frequency is flat
  (reproducing the community's IoC ≈ 1.066), which rules out monoalphabetic
  substitution. No period, lag, isomorph structure, alphabet-chaining, or
  candidate cipher (Caesar, Vigenère, incrementing-wheel, Chaocipher, S₈₃ deck)
  decrypts above chance.
- **One real positive structural result.** Under the honeycomb reading order the
  trigram values are bounded and contiguous (0–82) — a 0/1000 result across five
  seeds whose analytic look-elsewhere-corrected bound stays astronomically small
  (~1e-182), so it survives the degrees-of-freedom correction analytically. And
  no trigram is ever immediately repeated: a genuine "forbidden-successor"
  constraint (add-one p ≈ 2e-4), not a side effect of flat frequencies.
- **The cipher family is narrowing.** Taken together, the structural battery
  disfavors monoalphabetic, fixed-keystream additive, incrementing-wheel, and
  single global-transposition mechanisms, and favors a plaintext-dependent,
  self-modifying (autokey/Alberti-like) direction. This narrows *what kind of
  cipher* the eyes could be — it does not decode them.
- **The controls fire.** Solved monoalphabetic and polyalphabetic ciphers,
  English-vs-Finnish discrimination, and a planted-signal test are all recovered
  by the same harness — which is exactly what makes the eye negatives meaningful.

The one real blocker is the unknown 83-symbol→meaning mapping. As noted
above, it isn't in the game's storage layer, so it can't be datamined or
recovered by cryptanalysis alone — it would need an in-game or developer source.
Until then, decode attempts here are designed negatives, and this repo never
reports anything stronger than "structured data of unknown meaning."

## Layout

Source lives under `src/`, grouped by role. Modules are re-exported flat from the
crate root (see `src/lib.rs`), so a path like `src/analysis/orders.rs` is the
module `orders`.

| Directory      | Role                                                                    |
| -------------- | ----------------------------------------------------------------------- |
| `core/`        | glyph alphabet, the base-5 reading layer, external-ciphertext front door |
| `data/`        | the verified nine-message corpus + the engine base-7 decoder            |
| `analysis/`    | encoding-agnostic statistics and structural analyses                    |
| `nulls/`       | matched-null distributions and the DoF-calibrated null driver           |
| `ciphers/`     | candidate-cipher primitives (with round-trip-tested inverses)           |
| `attack/`      | cipher attacks, language models, and the solve/keystream/ragbaby pipelines |
| `experiments/` | the structural-battery experiment drivers                               |
| `report/`      | CLI report rendering and domain-error formatting                        |

See `ARCHITECTURE.md` for the as-built design and the full module map.

## Reusable pieces

Beyond the eye puzzle, the workbench is built to be pointed at other
sequence-analysis questions:

- a matched-null + DoF-calibrated null harness for asking "is this structure
  real or just noise?" of any symbol stream, with the look-elsewhere correction
  built in;
- cipher crackers with controls — `solve`, `keystream`, and `ragbaby` each
  ship a matched null, a held-out fold, and a positive control, so a negative is
  trustworthy. Point them at your own ciphertext through the `ingest` front door;
- the verified corpus + engine decoder as a clean, provenance-checked source
  for the nine messages.

## Building and contributing

```sh
make verify   # the correctness gate: fmt-check + clippy(-D) + filesize + tests + rustdoc(-D) + cargo-deny
make check    # verify + blob-size + suppressions + cargo-machete + codespell + shellcheck + test-scripts + release build
make test-scripts  # run scripts/tests/*.sh shell smoke tests
make setup    # install the git pre-commit hook
```

`make verify` must be green before every commit; the pre-commit hook enforces it.
The crate forbids `unsafe`, bans panics and unwraps in library and CLI code,
documents every public item, and runs clippy `pedantic` as `-D warnings`; the
supply chain is gated by `cargo-deny` and `cargo machete`. `make check` also
runs the staged blob-size guard, suppression register audit, shellcheck, and the
shell smoke tests in `scripts/tests/`. See `CONTRIBUTING.md` and `AGENTS.md` for
the full working agreement.

## Further reading

- `research/README.md` — the research write-ups and sources.
- `research/03-confirmed-vs-speculation.md` — a skeptic's scorecard of what's
  actually established versus still speculative.
- `ARCHITECTURE.md` — the as-built design and module map.
- `CHANGELOG.md` — the experiment-by-experiment history.

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
