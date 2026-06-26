# HANDOFF — practice-puzzle cryptanalysis (letter-puzzle keystream slice)

Written 2026-06-25 by the `exploration`-branch agent, mid-task, after coordinating
with the `refactor/engine-spine` campaign. Read this before resuming so you inherit
the findings and the **conflict-free boundary** rather than re-deriving or colliding.

> Status of this file: working handoff, committed-or-not at the maintainer's
> discretion. It lives under `research/data/practice-puzzles/` (codespell-skipped,
> so cipher tokens here are safe). Move/relocate as you see fit.

---

## 1. The task & the binding directives

Goal: **solve what we can under `research/data/practice-puzzles/`**, which is the
solve-engine credibility ladder (external ciphers believed decryptable to English;
the eyes stay the sole honest-negative). Maintainer decisions made this session:

1. **Build the capability in Rust now, iterate in-repo** — not throwaway scripts.
2. **Engine-first: no decode counts until it is reproducible via the `solve` CLI.**
   Every successful attack must land as a tested Rust engine family.
3. **Coordinate to avoid overlap** with the `refactor/engine-spine` agent.

Honesty discipline (unchanged, binding): a high n-gram score on gibberish is **not**
a decode. Require independent confirmation (dictionary-word coverage + the engine's
gates) before calling anything English. Honest-negative is an acceptable outcome.
Any recovered English/Finnish candidate is a **HYPOTHESIS** and must be logged to
`research/gak-threads/candidates/` and committed for human review (standing rule).

---

## 2. Coordination boundary — DO NOT CROSS

The `refactor/engine-spine` campaign (worktree `/home/node/persist/noita-eye-puzzle`)
**owns the digit-puzzle attack surface and the scoring corpus**:

- `src/codec.rs` — `AnyCodec { Identity, FixedGrouping(GroupingCodec), Delta(DeltaCodec) }`,
  the transduction layer that widens small alphabets so **one / two / six** can host
  English. **Brief 04a.** Phase 1 (the module + 4th gate: codec round-trip +
  alphabet-size sanity) is **already merged into `exploration`** (commit `2ee2e9b`).
- Phase 2 of 04a (still in flight on engine-spine as of this writing): the **codec
  search** (`CodecStrategy::Search` — currently returns `CodecSearchUnavailable` in
  `solve.rs`) **and the enlarged language corpus samples / n-gram scoring**.

**Therefore: do not touch `src/codec.rs`, the digit puzzles (one/two/six), the
language corpus, or the codec search.** That is engine-spine's territory.

**Your clean, non-overlapping slice:** the **polyalphabetic KEYSTREAM cracking of the
letter puzzles `three` / `four` / `five` / `seven`** (Vigenère / Beaufort / autokey /
running-key key-search). Recon confirmed the briefs explicitly do **not** add general
keystream ciphers, and the remaining campaign tasks (04a → 08 → 07B) don't either.

**Before resuming: merge/rebase the latest `refactor/engine-spine`** so you inherit
the real `codec.rs`, the bigger corpus, and n-gram scoring. Building your own corpus
or scoring would both duplicate work and collide. The keystream cracker is useless on
the current 3.1 KB-bigram scorer (see §4) — it depends on the upgraded scorer.

---

## 3. Cryptanalytic findings (validated in scratchpad — the research is done)

Per-puzzle diagnostics (letters-only stream; English IoC reference ≈ 0.0667,
uniform-random floor ≈ 1/alphabet):

| File | n | alphabet | IoC | verdict |
| --- | --- | --- | --- | --- |
| `three` | 139 | 24 ltrs | 0.0385 | non-periodic polyalphabetic |
| `four`  | 121 | 24 ltrs | 0.0435 | non-periodic polyalphabetic |
| `five`  | 274 | 25 ltrs | 0.0392 | non-periodic polyalphabetic; **repeat clue** |
| `seven` | 152 | 26 ltrs | 0.0362 | non-periodic polyalphabetic; **`#` clue** |

**The README's "likely mode: letter substitution" is REFUTED for these four.** IoC at
the random floor rules out monoalphabetic (IoC is invariant under mono substitution);
`seven` additionally has **six distinct single-letter words** (B,E,H,K,R,U) —
impossible under mono.

Rigorously **ruled out** (with a proper 2.7 M-quadgram English model: English ≈ −4.0,
random ≈ −7.7 mean log10/quadgram):
- Monoalphabetic substitution.
- **Periodic Vigenère / Beaufort, key length ≤ 45** (chi-square per column → decrypts
  are high-frequency-letter *soup*, not words: column overfit on tiny samples).
- **Plaintext-autokey & ciphertext-autokey**, primer length ≤ 12, greedy per-residue
  hill-climb, Vigenère & Beaufort directions (best q ≈ −6.6, gibberish).
- **Progressive / Trithemius / Alberti-periodic**, per-letter and per-word advance.

**Still live / untested (your starting hypotheses, roughly in priority order):**
1. **Running-key** (key = an English text). Consistent with flat IoC + no period.
   *Caveat:* `five`'s exact repeat (below) argues against pure running-key.
2. **Autokey with a longer word-primer**, attacked properly (multi-restart simulated
   annealing, not the greedy column pass I ran — greedy gets stuck in local optima).
3. **Alberti with explicit index markers** — `seven` uses `#` *mid-word*
   (`KB#K`, `B#TV`, `OG#PJ`…): prime suspect for the disk-rotation index. Treat `#`
   as a re-key signal, not a letter.
4. **Finnish plaintext** (Noita is Finnish; my model is English-only). Re-run the
   whole battery against a Finnish n-gram model before declaring honest-negative.
5. Quagmire I–IV, Porta, running-key-Beaufort — lower priority.

**`five`'s strong structural clue:** the 10-letter ciphertext word **`UXECHTINIT`
repeats exactly** (line 3 end `...DQED UXECHTINIT?` and line 5 start
`UXECHTINIT EMAC...`), at **letter gap 40**; Kasiski shows gap-40 recurring **24×**.
An exact 10-gram repeat in a polyalphabetic cipher ⇒ same plaintext **and** same
keystream at both spots. This **favors** periodic-Vigenère with period dividing 40
(but ≤20 is ruled out → only 40 itself survives: ~7 letters/column on 274 chars,
borderline-solvable with a *strong* scorer) **or** autokey whose plaintext repeats;
it **disfavors** running-key. → Worth a focused fixed-length-40 key search on `five`
with quadgram scoring as the first concrete experiment.

---

## 4. Why the engine can't do this yet (the gap to close)

As merged (`2ee2e9b`): `solve` families are **Identity / Caesar / Transposition**;
scoring is **bigram** built from a **3.1 KB** sample
(`research/data/lang/english.txt`). The engine's own tests note the anneal margin
stays ~0 on real letter puzzles. **Bigram-on-3KB cannot crack a 26-letter
substitution from ~200 chars, let alone a keystream cipher.** This is exactly why you
must rebase onto engine-spine's n-gram + corpus upgrade first.

Engine seams (from recon; verify line numbers after rebase, they will drift):
- `src/ciphers.rs`: `Cipher` trait (assoc. `Key`) + closed `AnyCipher` enum
  (`…, Caesar(CaesarKey), Vigenere(VigenereKey), …`). Shared additive helper
  `translate_additive(values, alphabet_size, shift_at: impl FnMut(usize)->…, Direction)`.
  **Vigenère already exists.** Beaufort = same but `Direction::Decrypt`-style subtract.
  Autokey/running-key are NEW variants (autokey needs key = primer ++ plaintext
  feedback; running-key needs a key stream argument). Add enum variant + encrypt/
  decrypt free fns + `AnyCipher::{encrypt,decrypt,name}` match arms.
- `src/solve.rs`: `search_mapping(...)` hill-climbs/anneals the symbol→letter
  **Mapping** (Metropolis `accept(delta,temp)`, `temperature_at(...)`, seeded
  `SplitMix64`, multi-restart). **Mirror this for a KEY search**: maintain key state
  as `Vec<u8>`, reuse `accept`/`temperature_at`/seeding. For autokey, exploit that the
  primer's residue chains are independent given primer length.
- `score_transduced` currently reads `.bigram_mean_log_likelihood` (solve.rs ~530).
  Switch to the n-gram score once landed.
- Gates (keep all): crypto round-trip; `beats_null` with `SEARCH_BEATS_NULL_MARGIN`
  (0.15); held-out fold > null_mean. `candidate_survives()` requires all.
- CLI (`src/main.rs`): extend `SolveFamilyArg` (Vigenere/Beaufort/Autokey/RunningKey),
  add a family generator + key-length-range flags; `--restarts/--iterations/
  --anneal-temp` already exist and are reusable.

**File-size ratchet:** `solve.rs` pinned 2112, `ciphers.rs` 3673, `main.rs` 1413,
`language.rs` 618. Put the key-search in a **new module** (e.g. `src/key_search.rs`,
≤600 lines) to avoid bumping `solve.rs`. Any pin bump needs a reason in the same
commit. `make verify` (fmt-check, clippy -D, filesize, test, rustdoc -D, deny) must be
green before every commit. Forbidden: unsafe; unwrap/panic/indexing/unused_results/
missing_docs (warn→-D in CI) — use `#[allow(..., reason="…")]` only when unavoidable.

---

## 5. Scratchpad assets (ephemeral — reproduce, don't rely on)

Were in `/tmp/.../scratchpad/` (may be GC'd). Reproduce the quadgram corpus with:
```sh
# 3.5 MB public-domain English corpus (P&P, Alice, Sherlock, Moby-Dick, 2 Cities)
for u in GITenberg/Pride-and-Prejudice_1342/master/1342.txt \
         GITenberg/Alice-s-Adventures-in-Wonderland_11/master/11.txt \
         GITenberg/The-Adventures-of-Sherlock-Holmes_1661/master/1661.txt \
         GITenberg/Moby-Dick--or-The-Whale_2701/master/2701.txt \
         GITenberg/A-Tale-of-Two-Cities_98/master/98.txt; do
  curl -sL "https://raw.githubusercontent.com/$u" >> corpus_raw.txt; done
# words_alpha.txt (≈370k words, for dictionary-coverage verification):
curl -sL https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt -o words.txt
```
For the in-repo engine, prefer engine-spine's committed corpus over these.

---

## 6. Recommended first moves on resume

1. `git merge refactor/engine-spine` (get codec + corpus + n-gram). Confirm
   `make verify` green.
2. Stand up the n-gram scorer path in `solve` (or confirm engine-spine landed it).
3. Add **Beaufort + autokey** AnyCipher variants + a **key-search module**; unit-test
   with planted ciphertext (round-trip + recovery), mirroring `hillclimb_surfaces_
   planted_*` fixtures.
4. First real experiment: **fixed-length-40 Vigenère/autokey key search on `five`**
   (the repeat clue), then the autokey-anneal + running-key + Finnish battery on all
   four. Treat `seven`'s `#` as an Alberti index.
5. Whatever surfaces is a HYPOTHESIS → gates + dictionary check → log to
   `research/gak-threads/candidates/`. Honest-negative is fine and likely for some.

---

## 7. Pointers

- Eye-puzzle state & the autokey/Alberti survivors: `research/` + memory
  `noita-eye-puzzle-state`, `noita-eye-wiki-gak-convergence`.
- Codec design intent: `docs/refactor/04a-codec-transduction.md`.
- Solve pipeline design: `docs/refactor/04-solve-pipeline.md`.
- Campaign state: memory `refactor-campaign-state`.
- Candidate-logging rule: memory `candidate-cleartext-logging`.
