# Thread 6 notes — `data.wak` Lua/data scan

**Date:** 2026-06-24. **Verdict: lead CLOSED.**
**Outcome:** As predicted by `thread-6-binary-game-data.md`: the shipped game data
contains **rendering/world-gen assets only**, **no symbol→meaning decode table**,
and **no base-7/base-5 transform, no 83-entry table, and no eye-message integer
data** of any kind. This *confirms* the dead end; it is not a failure.

Strongest defensible statement is unchanged: the eyes are deterministic,
engine-generated, strikingly structured data of unknown meaning; unsolved; no
primary developer source confirms recoverable plaintext.

## What I extracted

- Archive: `data.wak` (42,467,033 bytes).
- No pre-existing unpacker was found under `ghidra-tools` or elsewhere, so I wrote
  a small Python unpacker (scratchpad `wak/unwak.py`).
- **`.wak` format, reverse-engineered and verified from the header:**
  - 16-byte header: `u32 reserved(0)`, `u32 num_files (14745)`,
    `u32 data_start (0x0c2ca3)`, `u32 reserved(0)`.
  - Then `num_files` records: `u32 abs_offset`, `u32 length`, `u32 path_len`,
    `path_len` ASCII bytes (path includes the `data/` prefix).
  - Integrity cross-checks that passed: the header table ends **exactly** at
    `data_start` (0x0c2ca3); offsets are contiguous and absolute
    (`data/credits.txt` @0xc2ca3 len 2739 → `data/debug_keys.txt` @0xc3757);
    all 14,745 files extracted with `bad=0` and correct byte lengths;
    `credits.txt` and PNG/XML files decode as valid content.
- Extracted to scratchpad `wak/extracted/` (85 MB): 9030 png, 4325 xml, 1077 lua,
  162 txt, 97 plz, plus minor others. ~5,566 Lua/XML/CSV/TXT text files scanned.

## What I searched (and the results)

1. **Eye-message digit content (the decisive test).** Searched the *raw* `data.wak`
   and the whole extracted tree for distinctive ≥30-char substrings of the verified
   `corpus.rs` orientation-digit strings, including the all-message **shared prefix**
   (`...0132233040411302321143130330040240...`) and a message-0-unique run
   (`1135310221044000200104040144142033`).
   **Result: zero hits** in raw and extracted. The message content is **not stored
   in `data.wak`** as a data table. This is consistent with the prior first-party
   Ghidra finding that the nine messages are hardcoded `(low, high)` `u32` constants
   inside `noita.exe` (`FUN_0061ed60`) — not in shipped data files.

2. **Transform / decode-table terms.** `grep -i` across all text assets for
   `base 7|base 5|base_7|base_5|trigram|decode|decrypt|cipher|ciphertext|plaintext`.
   **Only hit:** `data/scripts/streaming_integration/event_utilities.lua` — an
   unrelated comment about Twitch chat messages being "decoded to ascii 1-255".
   No base-7/base-5 logic, no 83-entry table, no decode keyed by message values.

3. **Glyph / rune / secret / message / orb terms.** All hits are ordinary gameplay:
   spell **runestones** (`runestone_*`), decorative `runes.xml`, and biome "secret"
   rooms (`alchemist_secret`, `temple_altar_secret`, `snowcave_secret_chamber`,
   etc.). None ingests eye-message integers or maps decoded values → letters/words.

4. **Files/paths named `eye`.** Two distinct, unrelated systems:
   - **World-gen brush PNGs** `data/biome_impl/caves/eye.png` and `eye_0[1-5].png`
     are tiny **9×5** material stamps used by `<CaveStructure>` in
     `data/biome/hills.xml`, `hills2.xml`, `forest.xml` to carve cave shapes. These
     are decoration in the EDR, **not** the message-glyph walls and carry no text.
   - **Gameplay eyes:** `evil_eye` item, `eyespot_*` trip-vision buildings, boss
     eyes (`boss_fish/eye.lua`, etc.), `eye_check.lua`/`eyespot_check.lua`. Read
     `eye_check.lua` and `eyespot_check.lua` in full — pure entity/component
     gameplay logic, no message data.

5. **Binary blobs that text-grep could miss.** The 97 `.plz` files are world-gen
   "spliced" pixel-scene terrain blobs (`biome_impl/spliced/moon|lavalake/*.plz`),
   confirmed by path and pixel-data header — not message data. No compiled Lua
   bytecode (`\x1bLua`) present; all `.lua` are plain source.

## Why this is a confirmation, not a gap

The messages are **display constants** rendered from integers stored in the
executable; the game never needs the plaintext at runtime, so neither the plaintext
nor any cipher key need exist in the shipped game. The absence of a `data.wak`
decode table is exactly what "display constants" predicts. Per Thread 6's prior:
treat this negative as *closing* the lead.

## Verdict

**Lead CLOSED.** The `data.wak` Lua/data scan is done. No semantic
symbol→meaning table, no base-7/base-5 transform, no 83-entry table, and no
eye-message integer content exist in the shipped game data. Do not reopen on a
hunch. (Caveat preserved: this rules out a decode table *in `data.wak`*; it does
not, and cannot, establish that recoverable plaintext exists anywhere.)

## Reproduction

- Unpacker + manifest + logs: scratchpad
  `…/scratchpad/wak/` (`unwak.py`, `manifest.tsv`, `unwak.err`),
  extracted tree under `…/scratchpad/wak/extracted/`.
- The `corpus.rs` digit strings used as search needles are the verified
  Experiment-0 transcription (rendered orientation layer).
