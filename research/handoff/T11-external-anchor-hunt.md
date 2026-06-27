# T11 — External-anchor hunt (criteria + status now; search is standing)

**Tier:** 2 · **Size:** S (the one-pass deliverable) · **Type:** doc / research · **Status:** TODO
**Depends on:** none · **Conflicts with:** none
**Touches:** new `research/external-anchor-hunt.md`

## Goal
A standing, honest checklist of what a **symbol→meaning anchor** would look like and
where it could come from — because that anchor, not more cryptanalysis, is the only
thing that can unblock a decode. Mostly **non-computational**: it scopes and tracks
the search, it does not invent a mapping.

## Scope (split — codex P2: don't let this become open-ended)
- **The one-pass deliverable (do this):** write the doc — define anchor *criteria*
  (what counts as a primary/verifiable anchor) + the *current repo status* of each
  candidate source (most are "absent / not found"). This is bounded and finishable.
- **Standing (not a single pass):** the *periodic external search* itself. Record a
  re-check cadence in the doc; do not block this task on exhausting the search.

## Why
The decode is blocked on the unknown 83-symbol→meaning mapping, and the binary work
shows the storage layer holds only opaque constants (no in-binary table). Pure
cryptanalysis cannot supply the mapping. Writing down what *would* count as an anchor
keeps the project honest about its ceiling and gives a human collaborator a concrete
list to chase.

## Steps
1. Enumerate candidate anchor sources and their status, e.g.:
   - **Developer statements** (Nolla Games / Petri Purho / Olli Harjola AMAs,
     streams, ARG hints) — any confirmation that the eyes encode recoverable text.
   - **In-game lore / #silmä-novel track** — cribs from the game itself (a known
     word, a name, a number) that could pin even one symbol.
   - **Decompilation beyond `FUN_0061ed60`** — any code path that *consumes* the
     eye constants as meaning (vs. just placing them), or a lookup table.
   - **Community wiki** — any newly-posted crib or partial mapping to corroborate.
2. For each: what it would let us assert, and the honesty bar to accept it (a single
   plausible crib is a HYPOTHESIS, not an anchor).
3. Record current status (most are "absent / not found") and a re-check cadence.
4. Cross-link to the candidate-logging directive: if an anchor ever yields candidate
   cleartext, it goes to `gak-threads/candidates/` as a HYPOTHESIS first.

## Definition of done
- [ ] `external-anchor-hunt.md` lists sources, what each would unblock, and status.
- [ ] No source is overstated; "absent" is stated where true; `make check` green.
- [ ] `docs/deslop-audit` merged in; committed.

## Honesty guardrails
This is the single highest-leverage *unblocker* and therefore the single biggest
overclaim risk. An anchor must be a primary/verifiable source, not a plausible
coincidence. Until one exists, the decode stays BLOCKED and the claim ceiling holds
verbatim. Do not let "we're hunting for an anchor" drift into "we expect a decode."

## Pointers
- Memory: the canonical state names this as "the one genuine open item."
- `research/02-theories-and-encoding.md` (~:147: no primary developer confirmation)
- Binary confirmation: messages are hardcoded constants; no symbol→meaning table.
- `research/gak-threads/candidates/README.md` (candidate-logging discipline)
