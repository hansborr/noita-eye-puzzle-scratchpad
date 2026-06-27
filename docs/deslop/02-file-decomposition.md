# Report 02 — File decomposition (god-file split map)

`scripts/file-size-allowlist.txt` pins **35** `.rs` files over the 600-line
default budget; several are 1.5k–3.7k lines. The ratchet *tolerates* them, but a
visitor to a public repo sees god-files. This report is a line-range split map a
cleanup agent can execute behavior-preserving.

> **+2 since the `exploration` merge.** The merge added `analysis/isomorph_imperfection.rs`
> (1527) and `analysis/leak_ceiling.rs` (1235), already pinned in the allowlist.
> Both follow the codebase's uniform shape exactly, so they slot into the same
> render-extract + test-extract playbook — mapped in their own section below. The
> 12-largest and remaining-21 tables (= 33 files) are unchanged and re-verified.

## Two facts drive almost every split

The codebase has a deliberately **uniform module shape** (a consequence of "brief
05 harness + brief 06 colocated report render"):

```
header/consts → config/error → result structs → impl Report + a swarm of
append_*/render_* fns → compute → nulls/controls → #[cfg(test)] mod tests
```

So two mechanical, low-risk moves recur everywhere and give most of the wins:

1. **Extract the `append_*`/`render_*` block into a sibling `*_report.rs`.** Pure
   string formatting, no algorithmic risk, 250–600 lines per file. (Brief 06
   *colocated* this render code; pulling it back out is the planned inverse.)
2. **Extract the inline `#[cfg(test)] mod tests` into a `#[path]` sibling.** These
   modules use `super::*` (private items), so they must stay a *child module* via
   `#[cfg(test)] #[path = "..._tests.rs"] mod tests;` — they **cannot** move to
   `tests/` (which sees only the public API). The module path is unchanged, so
   there is **zero public-API churn**. This alone reclaims thousands of lines.

The one exception is `solve`'s 8 `include_str!` pipeline tests, which mostly
drive the *public* `solve`/`log_solve_run` surface and could go to `tests/`.

### Mechanics caveat for the executing agent
The ratchet pins each path, so every split must **(a)** lower or delete the
shrunk file's pin **and (b)** add allowlist entries for any new sibling still
>600. Run `make verify` after each split (golden fixtures must stay byte-exact).
Coordinate with **report 04**: if the `#[path]`-flatten is converted to nested
`mod` trees first, the target sibling filenames below live inside real
directories instead of `#[path]` includes.

---

## Prioritized ROI table (do the P0 free wins first)

| Pri | File(s) | Action | Effort | Drop |
|---|---|---|---|---|
| **P0** | `attack/solve/mod.rs` | Extract `mod tests` (`#[path]` sibling); code is already a clean 258-line orchestrator | trivial | 2304 → ~258 |
| **P0** | `attack/gak_attack/mod.rs` | Extract `mod tests` (~1714) + `report.rs` (~457) | trivial+low | 2681 → ~510 |
| **P0** | `analysis/chaining_graph.rs` | Extract `*_tests.rs` (~1103, 60% of file) | trivial | 1830 → ~727 |
| **P0** | `ciphers/mod.rs` (tests) | Extract `tests.rs` (~999 pure-unit) | trivial | 3673 → ~2674 |
| **P1** | `ciphers/mod.rs` (code) | `error.rs`/`keys.rs`/`math.rs` (or per-cipher-family) | medium | →≤600 each |
| **P1** | `main.rs` | `cli/` tree: args + dispatch + commands/* (see report 04) | medium | 2107 → shim |
| **P1** | `gak_attack/eyes.rs` | `report.rs`+`record.rs` (free, ~910) then `heldout.rs`+`speculative.rs` | medium | 2316 → ≤~770 |
| **P1** | `conditional_structure.rs` | `report.rs` (~600) + `transition.rs` + `nulls.rs` | medium | →≤600 each |
| **P1** | `cipher_attack.rs`, `perfect_isomorphism.rs`, `pyry_conditions.rs`, `dof_null.rs` | `*_report.rs` + 1–2 compute modules (+ tests for dof_null) | medium | →≤600 |
| **P1** | `ragbaby.rs` + `keystream.rs` | matched pair: `cipher`/`search`/`record` + `tests` | medium | →≤600 each |
| **P2** | `gak_attack/solver.rs` | `gctak.rs`/`deck.rs`/`sweep.rs` (cohesive; real cross-ref work) | medium-high | →≤~780 |
| **P2** | the 21 mid-size analysis/null/experiment files | uniform `*_report.rs` + `*_tests.rs` sibling extraction (mechanical) | low each | most →≤600 |
| **P2** | `pipeline_null.rs`, `language.rs`, `ingest.rs`, `generator.rs` | single small extraction each (barely over 600) | trivial | →≤600 |
| **P2** | `isomorph_imperfection.rs`, `leak_ceiling.rs` (G2/G3 merge) | uniform `*_report.rs` + `*_tests.rs` + one compute split each (mapped below) | low each | →≤600 each |

**Honestly hard-to-split (split by *stage*, don't force sub-600):** `eyes.rs`
held-out core (`774-1538`, one algorithm), `gak_attack/solver.rs` (cohesive
multi-stage attack), `gak_attack/marginalization.rs` (cohesive, no test ballast),
and the `Cipher`/`AnyCipher` dispatch core in `ciphers`.

---

## The 12 largest, mapped

### 1. `src/ciphers/mod.rs` — 3673 (the cipher zoo; pure-unit tests)
- `1-35` header + consts
- `36-376` `CipherError` enum + `Display`/`impl`/`Error` (~340-line error taxonomy)
- `380-1158` **key types** (`Identity`, `TranspositionKey`, `CaesarKey`,
  `VigenereKey`, `IncrementingWheelKey`, `ChaocipherKey`, `DeckCipherKey`,
  `AglGakKey`/`AglMultiplierSubgroup`/`CosetReadout`,
  `GakKey`/`GakKeyOptions`/`GakSubgroupConstraint`) — struct + constructor each
- `1159-1530` free `*_encrypt`/`*_decrypt` fns, one pair per cipher
- `1531-1851` `Cipher` trait + per-cipher unit structs + `AnyCipher` enum + impl
  (the dispatch core)
- `1852-2404` validation + group/modular math (`validate_*`, parity, `agl_*`,
  `mul_inverse_mod`, `quadratic_residues_mod`, `pow_mod`, `is_prime`)
- `2405-2672` cipher mechanics (`translate_chaocipher`, deck ops)
- `2674-3673` `mod tests` (~999, 46 tests, pure unit)

**Split:** `ciphers/error.rs` ←`36-376`; `ciphers/keys.rs` ←`380-1158`;
`ciphers/math.rs` ←`1852-2672`; keep `mod.rs` = trait + unit structs + `AnyCipher`
+ free dispatch (`1159-1851`). Aggressive alt: one file per family
(`caesar.rs`/`vigenere.rs`/`chaocipher.rs`/`deck.rs`/`agl_gak.rs`/`gak.rs`).
**Test note:** extract `ciphers/tests.rs` (~999) — P0 free win, independent of the
code-split. (See report 03: the 9 trait impls + a 14×-duplicated comment here are
a macro opportunity.)

### 2. `src/attack/gak_attack/mod.rs` — 2681 (GCTAK go/no-go gate)
- `76-93` submodule decls + re-exports (note `#[cfg(test)] mod known_answer;` at
  `82-83` — a precedent for test-only siblings)
- `94-289` consts + config/outcome structs
- `290-747` `GakAttackReport` + `impl Report` + 7 `append_gak_attack_*` (~457 render)
- `748-965` orchestration (`run_gak_attack`, `retry_selected_exemplar`, …)
- `967-2681` `mod tests` (~1714, 50 tests, synthetic)

**Split:** `gak_attack/report.rs` ←`290-747`; keep `mod.rs` = wiring+config+
orchestration. **Test extraction `mod_tests.rs` (~1714)** alone drops it 2681→~967
— P0.

### 3. `src/attack/gak_attack/eyes.rs` — 2316 (real eye corpus; **no inline tests**)
Highest honesty-risk file; all 2316 lines are code, so splits are real moves.
- `91-175` config + small result structs
- `176-455` `EyesAttackReport` + `impl Report` + render
- `455-773` orchestration (`run_gak_attack_eyes`, `finalize_eyes_run`, …)
- `774-1538` **held-out attack core** (`eyes_message_evidence`,
  `eyes_matched_null_tail`, `eyes_held_out_positive_control`) — ~765, one algorithm
- `1538-1860` **speculative/HYPOTHESIS layer** (`eyes_speculative_cleartext`,
  `eyes_hypothesis_mapping`, `eyes_mapping_null`)
- `1861-2316` candidate-record writing + `render_eyes_candidate_record`

**Split:** keep `eyes/mod.rs` = config+orchestration+consts; `eyes/report.rs`
←`176-455`; `eyes/record.rs` ←`1861-2316`; `eyes/heldout.rs` ←`774-1538` (the hard
one; one algorithm); **`eyes/speculative.rs` ←`1538-1860` — high claim-discipline
value** (isolates the caveated HYPOTHESIS code from the gated attack core).

### 4. `src/attack/solve/mod.rs` — 2304 (the cleanest case; ~89% tests)
Already pre-split into `codec_search`/`eval`/`record`/`search`/`types`.
- `55-257` orchestrator (`solve`, `run_codec_search`, `candidate_survives`, …) —
  **already ~203 lines, under budget**
- `259-2304` `mod tests` (~2045, 29 tests; **8 `include_str!`** pipeline tests at
  `345-357,552,612,675,702`)

**Split: test extraction only.** Move `259-2304` → `solve/tests.rs` (mod.rs →
~258). Optionally split `tests_unit.rs` (validation/survival) vs
`tests_pipeline.rs` (the 8 corpus tests). The 8 are integration-style on the
public surface and *could* go to `tests/solve_pipeline.rs` — default to the
`#[path]` sibling unless a private-coupling check comes back clean.

### 5. `src/main.rs` — 2107 (**no tests**) — see report 04 for the full CLI plan
- `37-967` clap defs: `Cli`, `Command` enum (`43-132`), ~32 `*Args` + `From` impls
- `969-1121` dispatch infra (`RunOutcome`, `emit`, generic `dispatch<C,R,E>`, `main`)
- `1122-1239` simple `run_*` handlers
- `1240-1660` solve command machinery
- `1661-1860` `run_profile`, `run_keystream`
- `1863-2107` ragbaby command

**Split into a `cli/` tree:** `cli/args.rs` ←`37-967` (split args_analysis/
args_attack if still >600); `cli/dispatch.rs` ←`969-1121`;
`cli/commands/{solve,keystream,ragbaby,misc}.rs`; `main.rs` → small
`mod cli; fn main()` shim. (Binaries *can* have bin-private submodules — this
doesn't touch the library API.)

### 6. `src/attack/gak_attack/solver.rs` — 1993 (**no tests**; cohesive algorithm)
- `35-310` GCTAK solve core; `310-740` chain-link recovery; `741-817`
  `SmallUnionFind`; `819-1018` deck fixture; `1019-1330` deck-attack substrate;
  `1330-1700` hidden-state mechanics; `1701-1993` outcome/report/sweep.

**Split:** `solver/gctak.rs` ←`35-817`; `solver/deck.rs` ←`819-1700`;
`solver/sweep.rs` ←`1701-1993`. Clean seams (3 sub-algorithms) but touches
`pub(crate)` cross-refs — lower urgency than render/test extractions. **P2.**

### 7. `src/analysis/perfect_isomorphism.rs` — 2056
`320-657` render; `769-1330` catalog building + significance + break
classification; `1332-1908` null + regression checks + fixtures; `1916-2056` tests.
**Split:** `perfect_isomorphism/{report,catalog,regression}.rs`; keep mod.rs.

### 8. `src/experiments/conditional_structure.rs` — 2283
`485-1083` `impl Report` + ~20 `append_conditional_*` (**~600, the largest single
render block in the repo**); `1199-1656` transition-count compute; `1656-2057`
nulls+controls; `2066-2283` tests.
**Split:** `conditional_structure/{report,transition,nulls}.rs`; keep mod.rs.

### 9. `src/nulls/dof_null.rs` — 1786
`382-650` render; `850-1343` cell prep + grouping + calibration; `1344-1786` tests
(~442, sizable).
**Split:** `dof_null/{report,cells}.rs`; **extract `dof_null/tests.rs` (~442)**.

### 10. `src/experiments/pyry_conditions.rs` — 1767
`418-697` render; `756-1135` condition predicates; `1135-1625` generated-family +
cipher fixtures; `1626-1767` tests.
**Split:** `pyry_conditions/{report,predicates,fixtures}.rs`; keep mod.rs.

### 11. `src/attack/ragbaby.rs` — 1736 (single file, no dir yet)
`216-485` cipher core; `485-732` SA optimizer; `732-1068` scoring + matched-null
gate; `1068-1342` control sweep + record writer; `1343-1736` tests (~393).
**Split:** convert to `ragbaby/` dir — `cipher.rs`/`search.rs`/`record.rs` +
**`tests.rs` (~393)**. `keystream.rs` (1360) is the same shape (see report 03's
near-clone finding) — **split the two together** for consistency.

### 12. `src/attack/cipher_attack.rs` — 1720
`394-666` render; `826-1424` per-family search + scoring/mapping; `1424-1572`
positive controls; `1572-1720` tests.
**Split:** `cipher_attack/{report,search,controls}.rs`; keep mod.rs.

---

## The 2 files added by the `exploration` (G2/G3) merge, mapped

Both are textbook uniform-shape and **mechanical** to split (clean seams; not in
the "honestly hard-to-split" set). Each needs three moves — a `*_report.rs`
render extraction, a `*_tests.rs` sibling, and one compute split — because the
render+test extraction alone leaves the core over 600.

### 13. `src/analysis/isomorph_imperfection.rs` — 1527 (G2 forward falsifier)
- `1-20` module doc; `22-86` imports + consts (window grids, tags, MOTIF fixture)
- `90-171` `IsomorphImperfectionConfig` + `IsomorphImperfectionError`
- `175-314` result structs (`ScanCounts`/`NullOutcome`/`StutterCandidate`/
  `LooseCandidate`/`EpsilonFitRow`/`FamilyFit`/`IsomorphImperfectionReport`)
- `316-601` `impl Report` + 8 `append_*_section`/verdict render fns (~285)
- `602-648` `run_isomorph_imperfection` orchestration
- `650-1218` break-localization + matched-null detector core (`scan_*`,
  `localize_pair`, `classify_break`, `internal_profile`, benign-region helpers,
  `matched_nulls`, `collect_loose_candidates`, `locate_stutter_candidate`) — the
  **honesty-critical** word-boundary-discount / loose-vs-robust logic
- `1220-1363` generative imperfect-family calibration (`generate_family`,
  `run_family_fit`, `epsilon_row`, `best_fit_epsilon`, `ensure_positive_control`)
- `1365-1527` `mod tests` (~162)

**Split:** keep `isomorph_imperfection/mod.rs` = consts + config/error + structs +
`run_*`; `isomorph_imperfection/report.rs` ←`316-601`; **extract
`isomorph_imperfection/tests.rs` ←`1365-1527` (~162, P0 free win)**;
`isomorph_imperfection/detector.rs` ←`650-1218` (break-localization + matched null
— isolate the honesty-critical core); `isomorph_imperfection/family.rs`
←`1220-1363` (generative calibration). **Notes:** reuses `crate::null`
(`mix_seed`/`usize_band`/`fisher_yates`) — no util-dup; its `run_*` preamble is a
member of report 03's fix #2 (and carries the `Vec<&'static str>` annotation drift).

### 14. `src/analysis/leak_ceiling.rs` — 1235 (G3 information ceiling; **pure analytic, no RNG**)
- `1-29` module doc; `31-76` imports + consts (window/sensitivity grids,
  calibrated-geometry + `two`-calibration constants)
- `78-132` `LeakCeilingConfig` + `LeakCeilingError`
- `134-343` result structs (`OutDegreeSupply`/`ChainingSupply`/`IsomorphSupply`/
  `EmpiricalSupply`/`AnalyticDemand`/`CeilingEstimate`/`ScalingPoint`/
  `ScalingSweep`/`CalibrationControl`/`LeakCeilingReport`)
- `345-455` **pure combinatorics helpers** (`log2_factorial`/`harmonic`/
  `coupon_*`/`binomial_f64`/`odd_double_factorial`/`near_identity_neighborhood`/
  `coverage_*`) — ~110 standalone `pub fn`s, independently unit-testable
- `458-556` supply compute (`out_degree_supply`/`chaining_supply`/`isomorph_supply`)
- `557-629` `run_leak_ceiling` orchestration
- `631-759` demand/ceiling/calibration/scaling compute
- `761-1057` `impl Report` + 9 `append_*` render fns (~296)
- `1058-1235` `mod tests` (~177)

**Split:** keep `leak_ceiling/mod.rs` = consts + config/error + structs + compute
(`458-759`) + `run_*`; `leak_ceiling/report.rs` ←`761-1057`; **extract
`leak_ceiling/tests.rs` ←`1058-1235` (~177, P0 free win)**; `leak_ceiling/math.rs`
←`345-455` (the ~110 pure combinatorics — cleanest seam). **Notes:** shares only
the corpus-load *triple* of report 03's fix #2 (no `report_from_message_values`
tail); its `append_header` (`781`) joins the P2 header-reemission cluster.

---

## The remaining 21 allowlisted files (one-line notes)

All follow the same shape. "render-heavy" → the win is a `*_report.rs` extraction;
"test-heavy" → a `*_tests.rs` sibling is the win. `testsAt` = first `#[cfg(test)]`.

| File | Lines | testsAt | Note |
|---|---|---|---|
| `analysis/chaining_graph.rs` | 1830 | 727 | **~1103 test lines (60%)** — extract `*_tests.rs` → ~727 (P0). |
| `nulls/null.rs` | 1664 | 1203 | Shared null-harness core (others depend on it). render-extract + tests. |
| `experiments/controls.rs` | 1636 | 1405 | Exp-11 positive controls; render-heavy → `controls_report.rs`. |
| `experiments/modular_diff.rs` | 1600 | 1470 | render-heavy → `*_report.rs`. (Also has a duplicate `mix_seed` — report 03.) |
| `analysis/grouping.rs` | 1511 | 1366 | Exp-8 base-N grouping; render-heavy. |
| `attack/keystream.rs` | 1360 | 936 | **~424 test lines**; split like `ragbaby.rs` (cipher/search/record + tests). |
| `analysis/orders.rs` | 1340 | 1142 | Reading-layer order machinery; render + tests. |
| `experiments/periodicity.rs` | 1322 | 1215 | Exp-5A; render-heavy. |
| `nulls/perseus.rs` | 1316 | 1113 | Exp-7C; render + ~203 tests. |
| `analysis/honeycomb.rs` | 1292 | 1062 | 2-D lattice; render-heavy. (local `null_band` — report 03.) |
| `analysis/chaining.rs` | 1242 | 1110 | Exp-7B; render-heavy. |
| `nulls/tree_residual.rs` | 1226 | 910 | **~316 test lines**; render + tests. |
| `attack/agl_gak.rs` | 1208 | 1135 | Thread-2; mostly code → `*_report.rs` + compute split (~73 test lines). |
| `experiments/orientation_homogeneity.rs` | 1138 | 981 | render → `*_report.rs`. |
| `attack/codec.rs` | 1134 | 720 | **~414 test lines (37%)**; extract `codec_tests.rs`. |
| `attack/gak_attack/marginalization.rs` | 1026 | none | **no tests** — cohesive; split by stage only if needed. |
| `nulls/zero_adjacency_null.rs` | 848 | 716 | Exp-7D (the one POSITIVE result); render + ~132 tests. |
| `nulls/pipeline_null.rs` | 684 | 547 | small overflow — `*_report.rs` brings it <600. |
| `attack/gak_attack/generator.rs` | 647 | none | **no tests**; barely over — small extraction or leave. |
| `attack/language.rs` | 618 | 502 | barely over — extract ~116 test lines → <600. |
| `core/ingest.rs` | 610 | 393 | allowlist already says "trim under 600 next" — extract ~217 test lines, done. |
