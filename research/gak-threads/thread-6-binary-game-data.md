# Thread 6 — Binary / game-data re-examination (low priority, likely dead end)

**Priority:** Low. **Effort:** Low. **Mapping-independent:** n/a.
**Game-data/Ghidra helps:** This thread *is* the game-data/Ghidra angle.

**One-line:** We have the game files and a Ghidra project for `noita.exe`. This
thread records what they have already told us, the one residual lead, and an honest
assessment of why we don't expect more from them — so nobody re-treads it
expecting a breakthrough.

## What the binary already settled (2026-06-24 first-party Ghidra)

- The nine eye messages are **hardcoded `(low, high)` `u32` constants** assembled in
  `FUN_0061ed60`. The world seed only randomizes **placement** (`FUN_0061fe80`),
  not content. 150 pairs match the decompiled immediates **byte-for-byte**, which
  also re-validates the transcription in `corpus.rs`.
- The storage path has **no symbol→meaning table**. The base-7 decode and any
  meaning layer are *downstream* of where the constants live — they are not in the
  emit path we traced.
- Consequence already banked: the cross-seed-content question is **resolved**
  (content is seed-invariant by construction), and the absence of a decode table in
  the binary is a *fact about the storage layer*, not a reverse-engineering gap.

See the memory note `noita-eye-binary-confirmation` and `research/05` for the full
write-up.

## Why we don't expect more (the honest part)

The messages are **display constants**. They are not decrypted at runtime — the
game renders the eyes from the stored integers; it never needs the plaintext, so
the plaintext (and any cipher key) **need not exist anywhere in the shipped game**.
Petri could have encoded the messages once, offline, with pen-and-paper or a
throwaway script, and shipped only the resulting constants. If that is what
happened — and the binary evidence is consistent with it — then **no amount of
datamining recovers the key**, because the key was never shipped. This is exactly
why the cipher-structure threads (1–5) attack the ciphertext directly instead.

## The one residual lead (and why it's probably nothing)

The only untraced path is the **`data.wak` Lua** that consumes the decoded
integers further downstream. A diligent agent could:

1. Unpack `data.wak` and grep the Lua for anything that ingests the eye-message
   integers, a base-7/base-5 transform, an 83-entry table, or a string lookup keyed
   by the decoded values.
2. Check whether any Lua path maps decoded values → glyphs/letters/words (which
   would be a symbol→meaning table) versus merely → rendering coordinates.

**Expected outcome:** rendering only, no semantic table — consistent with "display
constants." Treat a negative here as *confirming* the dead end, not as failure.
Time-box it; do not let it expand.

## Where game data legitimately helps later

Post-hoc corroboration for Thread 4. *If* the GAK attack ever yields a candidate
plaintext, then in-game lore, the relationships among the nine messages, and known
Noita puzzle conventions become a way to sanity-check the recovered text. That is an
**output** check on a hypothesis, not an input to the decode — and it only matters
once Thread 4 produces something to check.

## Success / failure criteria

- **Success:** the `data.wak` Lua scan is documented as done, with the finding
  (almost certainly "rendering only, no semantic table"), closing the lead
  explicitly so it isn't reopened on a hunch.
- There is no realistic "breakthrough" branch here. If one appears (an actual
  decode table in the Lua), it would be enormous — but the prior is strongly
  against it.

## Pitfalls & honesty notes

- Don't let the availability of Ghidra create the illusion of progress. The binary
  has already given us what it can; this thread is about *closing* a lead cleanly,
  not opening a frontier.
- Keep the strongest-defensible-statement discipline: the binary confirms
  *deterministic, hardcoded, structured content of unknown meaning* — it does not
  confirm recoverable plaintext, and nothing here should be written as if it does.
