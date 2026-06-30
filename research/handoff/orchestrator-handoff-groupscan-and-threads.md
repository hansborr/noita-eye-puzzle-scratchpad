# Handoff: finish `groupscan`, then pull the new research threads

**Created:** 2026-06-29 · **Branch:** `exploration` · **Last code commit:**
`1fcc417` (`feat(groupscan): D4/A4/S4 hidden-group element-order discriminator`),
then a clean merge of `re-search` (research docs only, no code conflict) on top.

This document is written for a **fresh agent with no prior context**. It is
self-contained: everything the in-flight work needs is embedded here (do not rely
on any scratchpad — it does not survive the context reset).

---

## 0. Your operating model (read first — this is a hard constraint)

You are an **orchestrator**. You **do not implement, and you do not read diffs or
long logs yourself.** Your context window stays clean so you can run the whole
program end-to-end. Concretely:

- **Implementation → `codex` (heavily).** For each build/fix task, write a precise
  spec to a prompt file and run `codex exec` to do the work (see §6 for mechanics).
  Codex reads `AGENTS.md`/`CLAUDE.md` itself; keep prompts about *the task*, not
  the stack.
- **Reading codex's result → a one-line tail or a Claude subagent.** After codex
  finishes, do **not** read the full log or the diff. Either glance at the *last
  few lines* of its log (its own summary) or — preferred for anything non-trivial
  — spawn a short-lived **Claude subagent** ("read `/tmp/codex-X.log` and
  `git show <sha> --stat`; report in ≤8 lines what changed, whether the gate
  passed, and anything that looks wrong") and act on its summary.
- **Review → `codex review` or a Claude subagent**, again summarised back to you.
  Relay P0/P1 findings verbatim; delegate the *fix* back to codex.
- **You hold the plan, the task list, and the decisions.** Use `TaskCreate`/
  `TaskUpdate` to track the queue below. You decide ordering, when something is
  "done", and when to escalate to the user.
- **Subagent budget:** keep concurrent Claude subagents low (a couple at a time).
  Lean on codex for the heavy lifting; use Claude subagents for *reviews and
  summaries*, not implementation.

**Serialization:** codex takes temporary ownership of the worktree write-lock.
Run **one codex at a time** on the main worktree; do not edit/commit while it
runs. For genuinely parallel builds, give each codex its own `git worktree`
(the Agent tool's `isolation: "worktree"` or a manual worktree) — but serial is
simpler and usually fine here.

---

## 1. Non-negotiable repo discipline (applies to every task below)

These come from `AGENTS.md` (the source of truth — codex will read it; you must
hold agents to it):

- **Build instruments, not throwaway scripts.** Every result worth reporting must
  be produced by a **file-driven, self-validating Rust CLI instrument**: accepts
  arbitrary input (`--input-file`/`--stdin` + `--alphabet` via `cli::shared`),
  ships a **planted positive control** + a **matched null**, and is exercised by
  tests through the *same library functions the CLI calls*. A `#[cfg(test)]`-only
  check or an analysis hardwired to the eye corpus is a regression test, not a
  tool. No Python/throwaway scripts as the deliverable.
- **Toolkit, both targets.** Each instrument must be useful on **both** the eye
  corpus **and** the practice puzzles (`research/data/practice-puzzles/`). Design
  inputs/alphabets generically; default to a sensible target but never hardwire.
- **Honesty ceiling (binding).** A file-driven attack emits a **candidate, never
  a "decode."** A high n-gram/structure score is not a recovery. Label
  guessed/assumed choices as such; a bounded search states its limits and what it
  dropped. The matched null must be **transition-appropriate** (order-1 Markov for
  transition-structured streams; **never** Fisher-Yates for those — it manufactures
  fake significance). Cross-cutting lessons live in
  `research/attack-methodology.md`.
- **The gate.** `make verify` = fmt-check + clippy(`-D warnings`) + filesize
  (600-line cap, ratchet in `scripts/file-size-allowlist.txt`) + tests + rustdoc
  (`-D`) + cargo-deny. The pre-commit hook runs it (~2 min). `clippy::indexing_slicing`
  is an error — use `.get()`/destructuring, never `[i]`. Binary name: `noita-eye`.
- **Commit completed work** with these trailers (codex should include them, or you
  add them when committing):
  ```
  Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01FQGUMGrPofuiRdNY7yHLoP
  ```
  Foreground `git commit` times out on the 2-min hook — commit with
  `run_in_background=true` (write the message to a file, `git commit -q -F file`),
  or let codex commit.

---

## 2. IN-FLIGHT TASK — finish the `groupscan` codex fixes (do this first)

**What `groupscan` is:** a new instrument (`src/analysis/group_order/` +
`groupscan` CLI subcommand, committed at `1fcc417`) that discriminates the hidden
deck group `H` in the `C3 × H` hidden-state Group-Autokey reading of practice
puzzle `two`. `C3` is the transparent rotor (`r = symbol % 3`, visible); `H ⊆ S4`
acts on a 4-card deck (`q = symbol // 3`). The mod-3 rotor is forced; `H` is not —
`D4`/`A4`/`S4` all reproduce the mod-3 law identically. As subgroups of `S4` they
have disjoint giveaway cycle types: **D4 has no 3-cycle, A4 has no 4-cycle, S4 has
both**, so one observed 3-cycle rules out D4, one 4-cycle rules out A4. Element
orders are read off the deck channel: a repeated plaintext span relates its two
occurrences by a fixed group element `C`, and under the top-card readout
`q[b+s] = C(q[a+s])`, so the induced permutation's cycle type = the order of an
element of `H`. It reuses `translate_isomorph`'s difference-channel anchors.

**Status:** committed, gate-green, `groupscan --self-test` passes. A codex review
returned **no P0** and **confirmed the core math + that the difference-channel↔
visible-position indexing has no off-by-one**. It found 3 P1 + 2 P2 that are **not
yet applied**. Hand these to codex as one focused fix task.

### Provisional result on real `two` (must be re-confirmed — see fix #3)

`cargo run -- groupscan --input-file research/data/practice-puzzles/two
--alphabet ABCDEFGHIJKL` currently reports **NoDeckSignal**: all 16 difference-
channel anchors (incl. the length-68 @231/351) give a consistent deck-channel
prefix of only ~4–6 before colliding (≈ chance for a 4-value channel); matched
null mean 0.01. **Interpretation (provisional):** under the top-card reading the
crib anchors are *eps-only* (rotor-only) repeats — the rotor/high-bit plaintext
repeats but the deck/low-2-bit plaintext does not — **or** the readout is not
top-card. Either way it would mean the length-68 span is a constant-*eps* span,
not a constant-full-plaintext span, which **weakens the crib-recovery lead**.
**Do not treat this as load-bearing until fix #3 lands and the run is repeated.**

### The fixes to delegate to codex (verbatim from the review)

Give codex this list with file:line; have it apply all five in one commit, then
re-run the gate and re-run real `two`.

1. **[P1] Gate the verdict on the matched null.** `group_scan` computes `null` but
   `verdict_from(&observed_cycle_lengths, real_consistent)` never uses it, and the
   CLI prints unconditional "rules out"/"is S4". A chance consistent permutation
   can become a group exclusion. **Fix:** add `SIGNIFICANCE_P = 0.05`; compute
   `significant = real_consistent > 0 && null.p_value < SIGNIFICANCE_P`; verdict
   returns `NoDeckSignal` when `!significant`. Reword the `NoDeckSignal` doc/CLI to
   "no **significant** deck-channel signal (vs the deck-decoupled null)".
   **Also bump the self-test's `scan_control` null-trials 16 → 64** so a planted
   `real_consistent ≈ 3` clears `p < 0.05` (min p = 1/(trials+1); 16 → 0.059 would
   FAIL, 64 → 0.015 OK). The CLI default (200) is already fine.
   (`mod.rs` ~:292/:405; `groupscan.rs:123`.)

2. **[P1] `read_context` tie-break is wrong.** It prioritises any `Some` over a
   longer clean-but-undetermined run, biasing toward false-positive cycle types.
   **Fix:** scan **all** start offsets `0..length` (remove the `MAX_LEADING_TRIM`
   const + its doc); tie-break = **longest `prefix_len` wins**, with `Some` only
   breaking *equal-prefix* ties:
   ```
   better = outcome.prefix_len > best.prefix_len
       || (outcome.prefix_len == best.prefix_len
           && outcome.permutation.is_some() && best.permutation.is_none());
   ```
   (`scan.rs:128`, completion rule at `:182`.)

3. **[P1] Hard-coded `0..=4` leading trim → `NoDeckSignal` false-negative** for
   long binary anchors that over-extend the constant-context region by >4 leading
   positions. **Subsumed by fix #2** (all-offset scan removes the bound).
   **CRITICAL:** after fixes land, **re-run real `two`** (`groupscan --input-file
   … --alphabet ABCDEFGHIJKL`). If a long clean run now appears, the NoDeckSignal
   was a false negative and that is itself a finding — report it. If it still
   reports NoDeckSignal, the negative is robust and load-bearing.
   (`scan.rs:101`/`:122`.)

4. **[P2] eps-only self-test can pass vacuously** if no anchor is found.
   **Fix:** `null_rejected &&= null_report.anchors_examined > 0` (ideally also
   assert a long anchor was read and rejected as non-permuting). (`control.rs` ~:360.)

5. **[P2] non-TopCard docs too categorical.** **Fix:** soften "does not yield a
   bijection / collides quickly" → "*generically* not a clean group action; a
   finite consistency gate can still be fooled by degenerate cases (a context
   fixing the marked card, low coverage, chance consistency)".
   (`mod.rs:31`, `scan.rs:80`.)

### After the fixes

- Re-run `cargo test --lib group_order`, `groupscan --self-test`, and real `two`.
- Record the (re-confirmed) result in
  `research/data/practice-puzzles/CODEC-RESULTS.md` — append a section after the
  existing "transparent rotor channel and crib anchors (`isoscan`)" section
  describing the `groupscan` discriminator and the real-`two` verdict, with the
  reproduce command. Update the README pointer
  (`research/data/practice-puzzles/README.md`) and the project memory note
  (`practice-puzzles-one-two-analysis.md`). Honesty framing: structural
  discriminator over the hidden group, never a decode.
- Commit the fixes: `fix(groupscan): gate verdict on null, all-offset run
  selection, harden self-test (codex P1/P2)`.

---

## 3. DECISION GATE — the crib-anchored deck-key recovery (was "task 3")

The original plan was: discriminator first (done), **then** crib-anchored deck-key
recovery over `two`'s length-68 constant-plaintext span (anchor 231/351). **The
groupscan result reshapes this.** Resolve it based on §2's re-confirmed outcome:

- **If real `two` still reports NoDeckSignal** (likely): the length-68 span is
  *not* a constant-full-plaintext span at the deck level, so a deck-key recovery
  seeded by it stands on little. **Recommend to the user** either (a) shelve the
  crib recovery, or (b) first resolve the *readout-convention* question — is real
  `two` top-card (`deck[0]`) or position-of-marked-card (`deck⁻¹[0]`)? The
  synthetic solver (`src/attack/gak_attack/hidden_state_solver/`, recovers
  synthetic ~100%) assumes top-card; real `two` is an honest negative, so the
  convention may differ. A small instrument that tests both readouts' deck-channel
  co-repetition would settle it and is high-value toolkit.
- **If the re-run surfaces a real deck signal:** proceed with the crib recovery as
  originally scoped (recover the local deck permutation over the constant span),
  file-driven + self-validated, candidate-not-decode.

Bring the user a one-paragraph recommendation before building the recovery — it is
a genuine fork, not a default.

---

## 4. NEW THREADS from the `re-search` merge (build as toolkit, ranked)

Source: `research/findings/community-docs-firsthand-digest.md` (six community docs
read firsthand 2026-06-29) + the user's relayed agent suggestions. Each is a
codex-ready instrument brief. **All must follow §1** (file-driven, positive
control + matched null, both targets where applicable, candidate-not-decode).
**Honest umbrella caveat (state it in every write-up):** none of these is a path
to plaintext — the blocker remains the external key/mapping. They sharpen and
*discriminate* the structural hypothesis space. The one slim exception is #1.

### Thread A — Stored-word CRC/hash scanner (highest novelty; build first)

**Why:** The repo confirmed this session that `0xacf68674` (the 2nd u32 of eye
message 0's first stored pair `[0x5634505c, 0xacf68674]`, `src/data/generator.rs:34`)
equals **CRC-32/BZIP2("lumikki") byte-reversed** (poly `0x04C11DB7`,
init/xorout `0xffffffff`, non-reflected; note: *not* plain CRC-32, the community
label was imprecise). "lumikki" = Finnish *Snow White* — a plausible Nolla Easter
egg. If intentional, the **message content was chosen so its packing hashes to a
lore word** → the closest thing yet to the missing *external mapping anchor*. This
is the only lead with a slim chance of breaking, not just sharpening, the problem.

**Build:** a scanner over **all stored u32s** (and the full 64-bit values:
high/low/whole) across the 9 messages (`ENGINE_MESSAGES`; ~283 unique nonzero u32,
150 `[u32,u32]` pairs), testing the common **CRC-32 variants × both byte orders**
against a **pre-committed wordlist** (English + Finnish + Noita lore: lumikki,
kolmisilmä, etc.). File-driven: accept an arbitrary `--wordlist` and arbitrary
stored-value input.
- **Positive control (mandatory):** must recover the `0xacf68674` →
  CRC-32/BZIP2("lumikki") byte-reversed match.
- **Matched null / the real payoff:** report the **expected false-alarm count**
  `N_words · variants · |dict| / 2³²`. Rough cut: ~283 words × ~18 configs × 10⁴
  dict ≈ 0.01 expected spurious → finding lumikki alone ≈ 100:1 against
  coincidence; against a 10⁵ multilingual dict ≈ 10:1 (suggestive). **The
  instrument's job is to pin that number with a defensible, pre-committed
  dictionary** and convert anecdote → calibrated significance.
- **Upside:** if other stored words hit lore terms, you may have found an embedded
  word-list = a candidate mapping anchor. Downside (confirms coincidence) is still
  a publishable rigorous negative.

### Thread B — Isomorph key-difference discriminator (bears on the central question)

**Why:** CodeWarrior0's theorem — isomorphs appear iff the keying sequences differ
by a **constant** (true of ciphertext-autokey / progressive-alphabet / Wadsworth) —
discriminates the two hypotheses the repo is stuck between: classical autokey
(constant key-difference) vs an S₈₃ deck/GAK cipher (varying, self-modifying
difference). **This is the natural successor to `groupscan`** and reuses the same
machinery (`translate_isomorph`/`isoscan`/`perfect_isomorphism`) — high toolkit
synergy, and it bears on the repo's load-bearing "non-commutative self-modifying"
conclusion, moving it from inference toward measurement.

**Build (extends `isoscan`/`perfectiso`):** for each isomorph pair, recover the
implied **per-position key-difference sequence** and classify it: **constant** →
autokey family; **structured/linear** → progressive; **irregular** →
deck-cipher/self-modifying.
- **Positive controls (easy to plant):** synthesize CTAK (constant-difference) vs
  deck-cipher (varying) ciphertexts with known isomorphs; confirm the
  discriminator separates them.
- **Matched null:** order-1 Markov / transition-preserving (not Fisher-Yates).
- Run on the eyes **and** on `two`/`one`. This directly cross-checks the groupscan
  finding (eps-only anchors ↔ what kind of key-difference structure).

### Thread C — Toboter arithmetic predicates + null significance (extend the battery)

**Why:** Toboter lists ~6 arithmetic predicates with self-reported probabilities
("no two-digit prime factor in any sum = 0.4%"; "Naugam GCD = 6.5%"; abab sums
4040/5656/4545; starting trigrams >26; **"only missing gap size is 1"**). The repo
already has a structural-property battery (`src/analysis/…`, the `structural`/
`chaining`/`perfectiso` instruments); these are **new predicates to add**.

**Build:** add each predicate to the battery with the repo's **SplitMix64 null** to
verify the claimed probabilities instead of taking "0.4%" on faith. **The honest
value-add is the meta-analysis:** these are a handful of survivors from many tried
coincidences, so a **multiple-comparisons correction** ("how many such 'surprising'
predicates would you expect given how many were tested?") is itself the finding.
The **"only missing gap size is 1"** fact is the most load-bearing — it's the
discriminator that rules out the `(char + N·pos) mod 83` family; make sure it's
captured cleanly.

### Thread D — Modular-form exclusion scanner (cheap; tightens the ledger)

**Why:** Lymm/Toboter ruled out modular forms (`c = (m·p + s·x) mod 83` → unique
`m=25, s=51`; `+f` needs alphabet ≥69; `×f` ≥61). Lower payoff (confirms dead
ends) but cheap. **Build:** a small **exhaustive parametric scanner** that
regenerates these exclusions independently, using the gap/isomorph structure as
the discriminant, and emits a tightened elimination ledger. File-driven so it runs
on any alphabet/stream.

### Reading-only leads (not builds — triage, don't implement)

Independent C++/JS engine ports for a binary cross-check; RmVw's Vigenère doc;
7Soldier's 2025 frequency analysis. These are *reading* to fold into the research
docs, not instruments. Delegate a *summarise-and-file* subagent if/when relevant;
don't spend codex on them.

**Suggested order:** finish §2 → resolve §3 with the user → **Thread A** (novelty +
slim breakthrough chance) → **Thread B** (synergy with groupscan, central question)
→ C → D. Re-rank if the user prefers.

---

## 5. Key context & authoritative pointers

- **`two` (the live practice puzzle):** ~698 letters A–L, read as `C3 × S4`
  hidden-state GAK; English via an expanding ~2-octal-symbols-per-letter codec.
  Synthetic solver recovers ~100% but **real `two` is an honest negative** —
  blocked on the joint (group-action sub-convention × codec digit→coset bijection ×
  key) search; the **codec** is the load-bearing unknown, not the ~23-bit key.
  Maintainer holds the cleartext (true known-answer target) — do not tune to it.
- **Existing toolkit to reuse (don't reinvent):** `isoscan`
  (`analysis::translate_isomorph`, exact-repeat / crib-anchor scanner, order-1
  Markov null), `groupscan` (`analysis::group_order`), the `gak` subcommand
  (`attack::gak_attack`, hidden-state solve/discriminate/self-test), the
  `structural`/`chaining`/`chaining-graph`/`perfectiso`/`isomorphimperf`/
  `leakceiling` battery, `SplitMix64` (`nulls::null` — the mandated PRNG; keep it,
  don't add a crates.io RNG). CLI plumbing patterns: `cli::shared`
  (`resolve_input_text`, `parse_cli_sequence`), `cli/commands/isoscan.rs` and
  `cli/commands/groupscan.rs` are the cleanest handler templates;
  `cli/args_analysis.rs` holds analysis-instrument args.
- **Authoritative in-repo docs:** `AGENTS.md` (golden rules),
  `research/attack-methodology.md` (process lessons),
  `research/data/practice-puzzles/{README,CODEC-RESULTS,KEYSTREAM-RESULTS}.md`,
  `research/findings/community-docs-firsthand-digest.md` (the new threads' source),
  `research/handoff/T12-cli-instrument-refactor.md` (the file-driven-instrument
  refactor precedent), `research/gak-threads/` (the GAK campaign).
- **Binary ground truth:** the eye messages are hardcoded constants in `noita.exe`
  (Ghidra-confirmed); seed only randomizes placement; transcription validated
  byte-for-byte. Stored values live in `src/data/generator.rs` / `corpus.rs`.

---

## 6. `codex` mechanics (you will drive this constantly)

Skill: `codex-cli`. Command shape (always bypass the broken sandbox, always close
stdin, always redirect to a log — never `| tail`, which looks like a hang):

```bash
# implementation / fixes (open-ended):
cat > /tmp/codex-<task>-prompt.txt <<'EOF'
<the task: concrete goal, file:line you know, "verify don't trust" hypotheses,
constraints, and which command must pass when done>
EOF
\codex -c sandbox_mode=danger-full-access -a never exec \
  < /tmp/codex-<task>-prompt.txt > /tmp/codex-<task>.log 2>&1   # run in background

# unprompted priority-tagged diff review:
\codex -c sandbox_mode=danger-full-access -a never review --commit <SHA> \
  < /dev/null > /tmp/codex-review.log 2>&1                      # run in background
```

- Use `\codex` (skip the alias). Run via Bash `run_in_background=true`; rely on the
  completion notification (runs take 10–30+ min); **never launch a second codex on
  the same worktree** because a log went quiet.
- For review-only `exec`, tell codex: "Do not modify files. Reading files and
  `git diff` is fine. Assume tests pass." (Do **not** say "run no commands" — that
  blocks its file reads.)
- After codex finishes: read **only the tail** of its log, or delegate a Claude
  subagent to summarise it — **do not ingest the full log/diff yourself.**
- Apply P0/P1 from any review; re-review after fixes.

---

## 7. Your immediate next actions

1. `TaskCreate` the queue: (a) groupscan codex fixes, (b) crib-recovery decision
   gate, (c) Thread A CRC scanner, (d) Thread B key-difference discriminator,
   (e) Threads C/D.
2. Delegate §2's five fixes to codex in one `exec`; on completion, have a Claude
   subagent confirm gate-green + re-run real `two` and report the verdict.
3. Surface §2's re-run result + §3's recommendation to the user before building
   the crib recovery.
4. Then proceed down §4 in order, one codex build at a time, each reviewed and
   committed before the next.
