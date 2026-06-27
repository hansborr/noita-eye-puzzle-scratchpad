# Reading-layer recon: canonical honeycomb trigram streams

Prerequisite emission for the GAK-threads work. This note records (a) exactly how
the codebase produces the base-5 trigram reading stream, (b) the per-message
value streams under the accepted order, (c) the validation against the community
wiki's dihedral-proof isomorph triple, and (d) the distinct-symbol counts.

Status discipline: the eyes remain deterministic, engine-generated, strikingly
structured data of unknown meaning; unsolved; no primary developer source
confirms recoverable plaintext. Nothing below claims otherwise. This is
mapping-independent structural work (symbol equality + group structure only).

## How the stream is produced (code path)

1. `corpus.rs` holds the nine verified rendered digit strings (digits `0..=4` are
   eye orientations, `5` is a non-rendered row delimiter; Experiment-0 verified
   byte-for-byte against the ngraham20 transcription and the Xkeeper0 base-7
   engine decode).
2. `orders::corpus_grids()` -> `GlyphGrid::from_message`: split each digit string
   on delimiter `5` into rendered rows. A trailing `5` does not create an extra
   row; an interior empty row is an error.
3. `orders::accepted_honeycomb_order()` = `ReadingOrder::HoneycombStandard { upper:
   IDENTITY, lower: IDENTITY }`, whose stable name is **`standard36-u012-d012`**.
4. `orders::read_corpus_message_values(&grids, order)` walks each grid in
   interlocking-triangle row-pair geometry (`read_honeycomb_row_pair`):
   for each top/bottom row pair, columns advance `+2` then `+1`, emitting
   - upper triangle `(upper[c], upper[c+1], lower[c])`, then
   - lower triangle `(lower[c], lower[c-1], upper[c])`.
   `honeycomb.rs::lattice_for_grid` is the same walk with physical coordinates;
   its `flattened_values()` equals `read_grid_values` (pinned by the in-crate test
   `lattice_flattening_reproduces_accepted_honeycomb_order`).
5. Each trigram value is base-5: `first*25 + second*5 + third` (`trigram.rs`),
   range `0..=124`. Under the accepted order the realized values are exactly the
   contiguous `0..=82` (83 distinct symbols; 83 is prime -- the basis of the
   transitivity restriction).
6. **Community display convention: char = value + 32.**

## Method of emission (two independent paths, byte-identical)

- **Path A (authoritative):** standalone cargo project
  `scratchpad/stream-emit/` path-depending on the workbench crate, calling the
  public API `read_corpus_message_values(corpus_grids(), accepted_honeycomb_order())`.
  Built/ran fully offline with an isolated `CARGO_TARGET_DIR` outside the project
  tree (the project build gate is untouched).
- **Path B (cross-check):** pure-Python re-implementation of the row-pair walk
  (`scratchpad/reimpl_honeycomb.py`) reading the digit strings directly out of
  `corpus.rs` (so the input is not taken on trust from Path A).
- Result: **IDENTICAL** value streams. Totals: 1036 trigrams; global range
  `0..82`; 83 distinct; contiguous. These match the pinned crate tests
  (`identity_honeycomb_reproduces_contiguous_anchor`,
  `accepted_honeycomb_message_lengths_are_distinct`).

## Validation against the wiki dihedral proof

Source: Lymm's eye-messages wiki (github.com/Lymm37/eye-messages/wiki), page
`Proof-that-the-eyes-cannot-be-a-dihedral-GAK-cipher` (content current to
2026-01-16). The proof cites three mutually-isomorphic
instances of the "main isomorph" it labels **msg1/msg2/msg3** (these are the
wiki's own labels for three stacked instances, NOT corpus messages 1/2/3):

```
msg1: OLPJ3P-O3QL
msg2: &-`=Q`_&Q?-
msg3: dN1D-15d-)N
```

Converting our emitted streams to display chars (value+32) and searching all nine
messages, **all three exact strings reproduce byte-for-byte**:

| wiki label | exact display string | located in our streams |
| ---------- | -------------------- | ---------------------- |
| msg1       | `OLPJ3P-O3QL`        | west1 @ offset 40      |
| msg2       | `` &-`=Q`_&Q?- ``    | east2 @ offset 45      |
| msg3       | `dN1D-15d-)N`        | west1 @ offset 70      |

All three share the single gap signature `[0,0,0,0,0,3,0,7,4,0,9]`, i.e. they are
the same isomorph stacked/aligned column-for-column. The proof's quoted column
block reads out verbatim from our streams: columns (4,6,9) give
`3-Q` / `Q_?` / `-5)`. So the proof's chaining data is reproduced exactly.

### Result: **reproduced.**

### Important clarification on "alignment"

The task's literal hypothesis was that the three strings sit at the *same absolute
offset* inside three separate messages. That is **not** how the wiki uses them.
The main isomorph (gap signature above) actually occurs as **four** instances in
the first three corpus messages under the accepted order:

```
west1 @ 40  OLPJ3P-O3QL   <- wiki msg1
west1 @ 70  dN1D-15d-)N   <- wiki msg3
east2 @ 45  &-`=Q`_&Q?-   <- wiki msg2
east2 @ 80  IhY47YaI72h   (a fourth instance the wiki did not cite)
```

The wiki picked three of these four. Two cited instances live in west1 (@40, @70)
and one in east2 (@45). They are "aligned" only as stacked isomorph rows (the
proof reads vertical columns across the three), which is exactly the sense the
proof needs. The offset spread (40/45/70) is a property of where the isomorph
recurs, not of the reading order. Our reading order matches the community's; the
mismatch with the literal "same-offset" phrasing is a labeling artifact, not a
data discrepancy.

## Robustness control (the match is specific, not generic)

`scratchpad/uniqueness.py`:
- Of the 36 standard honeycomb permutations (upper x lower trigram-digit perms),
  **exactly one** reproduces the wiki triple: `standard36-u012-d012` -- and it is
  also the unique 83-contiguous member.
- Per-message reversal, additive shifts mod 83 (`+1,+41,+82`), and all 119
  non-identity orientation-digit relabelings (`0..4` permutations) reproduce the
  triple **zero** times.

So the reproduction is highly specific to the accepted reading order.

## Per-message distinct-symbol counts

| id | key   | trigrams | distinct symbols |
| -- | ----- | -------- | ---------------- |
| 0  | east1 | 99       | 57               |
| 1  | west1 | 103      | 57               |
| 2  | east2 | 118      | 62               |
| 3  | west2 | 102      | 61               |
| 4  | east3 | 137      | 67               |
| 5  | west3 | 124      | 65               |
| 6  | east4 | 119      | 62               |
| 7  | west4 | 120      | 68               |
| 8  | east5 | 114      | 63               |

**Global distinct symbol count across all nine messages: 83** (contiguous
`0..=82`). Total trigrams: 1036.

## Canonical data artifact

`scratchpad/streams.json`:

```json
{"messages":[{"id":0,"key":"east1","values":[...],"display":"..."}, ...]}
```

plus `order_name` (`standard36-u012-d012`), `display_convention`
(`char = value + 32`), `wiki_validation` (result + offsets + isomorph
instances), `global_distinct_symbol_count` (83), `global_value_range`
(`[0,82]`), and per-message `distinct`.

Reproduce: build `scratchpad/stream-emit` (offline, isolated target dir) ->
`raw_streams.json`; run `scratchpad/validate.py` -> `streams.json`;
`scratchpad/reimpl_honeycomb.py` and `scratchpad/uniqueness.py` are the
independent cross-check and the specificity control.
