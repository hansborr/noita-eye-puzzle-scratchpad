# Pre-publication cleanup — overview

A maintainability/readability audit of this crate ahead of making it **public**.
Produced 2026-06-26 by one synthesizing agent over four parallel code
investigations plus an independent `codex` second opinion. Every finding below
was cross-checked against the source; file:line citations are first-hand.

> **Reconciled 2026-06-26 after the `exploration` merge.** That merge added two
> new analysis files (`analysis/isomorph_imperfection.rs`, `analysis/leak_ceiling.rs`
> — the G2/G3 threads) and nothing else that reports 02–04 cite. All pre-merge
> line citations below were re-verified and remain **exact**; the only updates
> were to fold the two new files into reports 02–04 and bump the affected counts.

> **These `docs/deslop/` files are themselves internal scaffolding.** They are a
> work-plan to hand to cleanup agents — like `docs/refactor/`, they should be
> archived or deleted before the repo goes public (see report 01).

## Headline: this is a disciplined codebase, not a sloppy one

The honest verdict is reassuring. On the axes that usually expose "embarrassing"
code, this repo is already strong:

- **2** non-test `unwrap`/`expect` in the entire library (both deliberate, in
  stats code); **0** `panic!`/`todo!`/`unimplemented!` in library/CLI paths.
- **13** `#[allow]` total, every one carrying a `reason = "..."`.
- **0** `TODO`/`FIXME`/`HACK`, **0** commented-out code blocks, **0**
  `dead_code` allows, **306** named constants.
- A strong lint wall (`clippy` pedantic, `unsafe` forbidden, `-D warnings` in
  CI), a **file-size ratchet**, and an **exemplary golden-master test harness**
  (byte-exact `.stdout` fixtures with a documented regeneration guard).
- A genuinely good README that leads with the *strongest defensible claim*
  rather than overclaiming, and a research dossier with explicit
  `[confirmed]/[likely]/[speculative]` tagging.

**Do not let a cleanup agent "fix" the scientific rigor.** Terms like *honest
negative*, *claim ceiling*, *HYPOTHESIS not a decode* are legitimate domain
discipline and are the repo's main credibility asset. Keep them verbatim.

## What actually needs work — four themes

The smells cluster into four reports, each independently executable:

| # | Report | Theme | Risk | Effort |
|---|--------|-------|------|--------|
| **01** | `01-publish-blockers.md` | Legal/privacy/staleness gates that must clear before *any* public push | low (delete/edit/add) | small |
| **02** | `02-file-decomposition.md` | 35 files over the 600-line budget; several 1.5k–3.7k lines | low–medium (behavior-preserving moves) | large |
| **03** | `03-duplication-and-readability.md` | Copy-paste clusters, deep nesting, magic-number inconsistency, AI-chatter in source | medium | medium |
| **04** | `04-structure-and-api.md` | `#[path]`-flattened `lib.rs`, public-API identity, `main.rs` CLI split | medium (one breaking path change) | medium |

## Recommended execution order

1. **Report 01 first, and on its own.** These are the items that would actually
   embarrass or legally expose. They are quick (add two LICENSE files, delete a
   leaked session URL, scrub local paths, fix stale README paths, archive the
   AI-ops docs). Do this before sharing the repo with anyone — including before
   handing the other reports out, since the other reports cite internal docs
   that 01 may relocate.
2. **Report 04's `#[path]` decision** before report 02's big splits — the
   nested-module conversion changes where files live, so settle the directory
   model first to avoid re-doing splits.
3. **Report 02** (decomposition) is the bulk of the work and the most
   mechanical. The P0 sub-items are *test-module extraction* — zero public-API
   churn, large line wins. Do those first; they de-risk everything else.
4. **Report 03** (duplication/readability) can proceed in parallel with 02 on
   disjoint files, but the cipher-macro and null-helper dedups touch files that
   02 also splits — coordinate or sequence them.

## Binding constraints for every cleanup agent

- **Behavior-preserving.** The golden-master fixtures (`tests/golden/*.stdout`)
  must stay byte-identical. `make verify` (and ideally `make check`) green before
  every commit. The file-size ratchet (`scripts/check-file-size.sh`) will fail CI
  if a split doesn't also update `scripts/file-size-allowlist.txt`.
- **No public-path churn without a decision.** The campaign deliberately froze
  `crate::*` module paths. Report 04 proposes *unfreezing* them for publish — but
  that is a deliberate, one-time breaking change, not something to do casually
  mid-split.
- `--locked` everywhere; document lockfile changes deliberately.

## Provenance of this audit

Five independent passes, all reconciled here:
- File decomposition map (line-range seams for the 33 oversized files).
- Code-level readability (long/nested functions, duplication, magic numbers,
  naming, comments).
- Public-share hygiene (docs, licensing, internal-process leakage).
- Structure & API surface (`#[path]` layout, `pub` surface, CLI, build config).
- `codex` second opinion (cross-cutting; corroborated all four and added the
  concrete duplication sites).
