# T11 — External-anchor hunt (criteria + status now; search is standing)

**Tier:** 2 · **Size:** S (the one-pass deliverable) · **Type:** doc / research · **Status:** Todo
**Depends on:** none · **Conflicts with:** none
**Touches:** new `research/external-anchor-hunt.md`

## Goal
A standing, honest checklist of what an external anchor would look like and where
it could come from — because a verifiable external anchor, not more cryptanalysis,
is the only thing that can unblock a decode. The targets are **key material** (the
plaintext-letter→group-action assignment), a **method/cipher-family disclosure**,
or **known plaintext** (a crib) — not a "symbol-to-meaning table": no such fixed
mapping exists for a polyalphabetic cipher, and the letter→action assignment *is*
the key, so it would never be externally provided by construction (reframed per
maintainer (Lymm) feedback, 2026-07-06). Mostly non-computational: it scopes and
tracks the search, it does not invent a key or method.

## Scope (split — codex P2: don't let this become open-ended)
- **The one-pass deliverable (do this):** write the doc — define anchor *criteria*
  (what counts as a primary/verifiable anchor for key material, method, or known
  plaintext) + the *current repo status* of each candidate source (most are
  "absent / not found"). This is bounded and finishable.
- **Standing (not a single pass):** the *periodic external search* itself. Record a
  re-check cadence in the doc; do not block this task on exhausting the search.

## Why
The decode is blocked on missing key material (the letter→action assignment — this
is the thing to be recovered, not a fixed lookup table, since the cipher is
polyalphabetic), a method/cipher-family disclosure, or known plaintext, and the
binary work shows the storage layer holds only opaque constants (no in-binary key
table or method disclosure). Pure cryptanalysis of the ciphertext alone cannot
supply any of these. Writing down what *would* count as an anchor keeps the
project honest about its ceiling and gives a human collaborator a concrete list to
chase.

## Steps
1. Enumerate candidate anchor sources and their status, e.g.:
   - **Developer statements** (Nolla Games / Petri Purho / Olli Harjola AMAs,
     streams, ARG hints) — any confirmation that the eyes encode recoverable text,
     or that discloses the key, the method/cipher family, or a plaintext crib.
     *Partial anchor on file (intentionality only):* a relayed-verbatim Arvi quote
     (2021-10-15 Twitch stream, relayed by FuryForged) confirms the eye decorations
     carry an **intentional** message — "do contain a message… do have a meaning" —
     and are "very difficult" (~"square root of minus 1" hard). So intentionality /
     "there is a message" *is* dev-attested. It discloses no cipher, key, method, or
     plaintext, so it does **not** lift the ceiling: the recoverable-text
     confirmation stays absent. This is the one developer-statement source that is
     *not* wholly absent — treat it as an intentionality anchor, never as a
     solvability, key, or method confirmation.
   - **In-game lore / #silmä-novel track** — cribs from the game itself (a known
     word, a name, a number) that could pin known plaintext for even one symbol.
   - **Decompilation beyond `FUN_0061ed60`** — any code path that *consumes* the
     eye constants as meaning (vs. just placing them), a disclosed method, or a
     key/permutation table.
   - **Community wiki** — any newly-posted crib, key disclosure, or method write-up
     to corroborate.
2. For each: what it would let us assert, and the honesty bar to accept it (a
   single plausible crib is a hypothesis, not an anchor; a genuine key or method
   disclosure would be a real unblocker).
3. Record current status (most are "absent / not found") and a re-check cadence.
4. Cross-link to the candidate-logging directive: if an anchor ever yields candidate
   cleartext, it goes to `gak-threads/candidates/` as a hypothesis first.

## Definition of done
- [ ] `external-anchor-hunt.md` lists sources, what each would unblock, and status.
- [ ] No source is overstated; "absent" is stated where true; `make check` green.
- [ ] committed.

## Honesty guardrails
This is the single highest-leverage *unblocker* and therefore the single biggest
overclaim risk. An anchor must be a primary/verifiable source, not a plausible
coincidence. Until one exists, the decode stays blocked and the claim ceiling holds
verbatim. Do not let "we're hunting for an anchor" drift into "we expect a decode."

## Pointers
- Memory: the canonical state names this as "the one genuine open item."
- `research/02-theories-and-encoding.md` (~:149: Arvi 2021 attests intentional
  *meaning*, not solvability; no primary developer confirmation of recoverable plaintext)
- Binary confirmation: messages are hardcoded constants; no in-binary key table or
  method disclosure (and no fixed symbol-to-meaning table would exist regardless —
  the cipher is polyalphabetic).
- `research/gak-threads/candidates/README.md` (candidate-logging discipline)
