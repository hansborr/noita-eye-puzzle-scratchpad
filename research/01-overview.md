# Noita Eye Messages — Overview

## What the puzzle is

The Eye Messages (also called the "eye glyph puzzle") are a set of nine messages, each rendered as a dense grid of small eye-shaped glyphs, that appear in Noita's East and West Parallel Worlds. The community widely treats them as an intentionally encoded cipher that has remained unsolved for years. [confirmed] (https://noita.wiki.gg/wiki/Eye_Messages, https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0)

A few framing cautions are worth stating up front, because popular write-ups overstate them:

- "Eye Messages" is a community-coined label, not a name confirmed by Nolla Games / Petri Purho. No located developer source names this feature or designates it a "puzzle." [confirmed] (https://noita.wiki.gg/wiki/Eye_Messages, https://en.wikipedia.org/wiki/Noita_(video_game))
- The Noita Wiki states the messages "are known to contain information, but have yet to be solved." That "known to contain information" assertion is itself a community inference from a statistical argument (see below), not a developer confirmation. [disputed — as to "known"] (https://noita.wiki.gg/wiki/Eye_Messages)
- The frequently repeated claim that "the developers confirmed it is solvable" has no primary source. It traces to an unsourced one-line intro on a 2022 Hacker News submission and is echoed by AI-generated pages (Grokipedia); no dev quote, Discord screenshot, or dated statement backs it. [disputed] (https://news.ycombinator.com/item?id=33929442, https://hn.svelte.dev/item/33929442, https://en.wikipedia.org/wiki/Noita_(video_game))

What *is* strongly supported about intentionality is indirect: the messages are deterministic, seed-based, and engine-generated (not random noise, not stray assets), and a specific statistical structure makes pure coincidence extremely unlikely (detailed in the Status section). The reverse-engineered generator function (see "How they are stored") proves deliberate authorship. None of this amounts to a dev statement that the eyes encode a recoverable plaintext message. [likely] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages)

## Where the messages appear

There are nine messages total: five in the East Parallel World, four in the West. Internally they are placed in alternating order (East, West, East, West, …). Every East message has a West counterpart in a mirrored location except the last East message, which has no Western counterpart (there is no "West 5"). The reason for the missing counterpart is unknown; one community speculation is that the West-5 slot may be a trigger/event location that fires only if the puzzle is solved — this is unverified. [confirmed for the structure; speculative for the "trigger" explanation] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages, https://github.com/ngraham20/NoitaCryptographyResearch)

The primary research doc numbers the messages 0–8: Message 0 = East 1, Message 1 = West 1, Message 2 = East 2, … Message 7 = West 4, Message 8 = East 5 (the one with no West counterpart). [confirmed] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0)

### Spawn conditions

The messages do not appear unconditionally. The verified spawn conditions are: [confirmed] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages)

1. The run must be mod-free: the `mods_have_been_active_during_this_run` flag must not be set. If any mod has been enabled at any point during the run, the eyes will not generate (the condition resets when the game is closed). This independently corroborated flag can be reset by save-editing `world_state.xml`.
2. The player must have triggered the "Entered East/West" parallel-world message; the eyes will not render before that, even where they would otherwise be visible.
3. The eyes only spawn in caves whose background is `background_cave_02.png`.

### Locations are seed-deterministic, not fixed coordinates

There are no universal coordinates; spawn locations are a deterministic function of the world seed, with East/West counterparts mirrored across the X axis. A given seed always produces the same locations. [confirmed] (https://noita.wiki.gg/wiki/Eye_Messages, https://gitlab.com/realgonzogames/lymms-binoculars)

The wiki publishes a worked example for seed 1249563923: [supported — transcribed from the wiki; not independently re-verified in-game] (https://noita.wiki.gg/wiki/Eye_Messages)

| Message | East (X, Y) | West (X, Y) |
|---|---|---|
| 1 | 22064, -6079 | -49616, -6079 |
| 2 | 52272, 14400 | -19408, 14400 |
| 3 | 52784, -5055 | -18896, -5055 |
| 4 | 52784, 6208 | -18896, 6208 |
| 5 | 36400, 2624 | (no counterpart) |

Coordinates can in principle shift if Nolla alters world generation between game versions (true of any seed-derived Noita data). To find the eyes for an arbitrary seed, use Lymm's Binoculars (a Python script that outputs coordinates from a seed) or its web port; an older method used a Cheat Engine Lua script that prints generated eye coordinates but must be re-patched after each Noita update. [confirmed] (https://gitlab.com/realgonzogames/lymms-binoculars, https://chillie-ilya.github.io/lymms-binoculars-web/, https://noita.fandom.com/wiki/Eye_Messages)

## The glyph states / symbols

Each individual eye is drawn in one of five distinct orientations, encoded as digits 0–4. A sixth value, 5, is a structural control code that starts a new row of eyes and is never displayed as a glyph (it acts as a line/row delimiter). [confirmed] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://github.com/ngraham20/NoitaCryptographyResearch)

The commonly cited direction-per-digit legend is:

- 0 = neutral / center
- 1 = up
- 2 = right
- 3 = down
- 4 = left

This specific direction-to-digit mapping should be treated cautiously. [disputed / unverifiable as to the exact directions] In the primary Google Doc and on the Noita Wiki, the orientation-to-value correspondence is presented only as an image (a sprite table), never as retrievable text, so no text/primary source pins each pixel direction to its digit. At least one independent analysis (Klausis Krypto Kolumne / Cipherbrain) explicitly warns that the eye-symbol-to-number assignment is non-obvious and differs from the naïve pictures. What *is* firmly established is that there are exactly five orientations mapped to 0–4 (plus 5 as a non-displayed delimiter); the exact assignment of which orientation is which digit is best treated as an arbitrary-but-conventional labeling. Importantly, the canonical 0–4 numbering "was learned from data mining the game's executable" and is "the unique numbering that produces a complete range of 0–82" under the base-5 trigram reading — so the numbering is grounded in the binary, even if the directional pictures are only shown as images. [confirmed for "five orientations + delimiter," "from datamining"; disputed/unverifiable for the exact direction legend] (https://noita.wiki.gg/wiki/Eye_Messages, https://noita.fandom.com/wiki/Eye_Messages, https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA, https://scienceblogs.de/klausis-krypto-kolumne/unsolved-the-noita-eye-messages/)

### Visual layout

Glyphs are packed in rows of at most 39 eyes, with every second row offset so it interlocks (honeycomb-style) between its neighbors. The "39 per row" figure is an observed maximum across the nine transcribed messages, not a documented hardcoded engine constant. The offset/interlock packing is a directly observable, reproducible visual property. [confirmed for the interlock; likely for the precise "39" cap] (https://noita.wiki.gg/wiki/Eye_Messages, https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0)

## How they are stored (and why they can't be unpacked normally)

The eye-spawning code is built directly into the game engine; it is not a Lua script and cannot be extracted from the data archive (`data.wak`), and the glyph graphics are generated on the fly rather than stored as sprites. This means standard asset unpackers cannot retrieve eye content. [confirmed] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://en.wikipedia.org/wiki/Noita_(video_game))

The content was nevertheless recovered by reverse engineering, not normal datamining. The reverse engineer Ninji (@_ninji / wuffs.org — not "ghidraninja"/stacksmashing) disassembled a Noita build (community sources cite the Feb 3, 2021 build) and published a Ghidra project (community-cited as ~60 MB) plus a decompiled view of the message-generating function. A save file from FuryForged is credited as part of the workflow. The exact ~60 MB figure and the live Ghidra artifact could not be independently re-verified in this research; the attribution is consistently and specifically stated across community sources. [likely] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://wuffs.org/blog/reversing-games-with-hashcat)

A practical nuance: "the eyes cannot be datamined" is true only of the asset archive. The underlying content is recoverable from the binary via reverse engineering. There are two layers of encoding, which are often conflated:

- **Engine-internal storage / decode (base-7).** Xkeeper0's PHP transcoder (a primary artifact reproducing the engine math) stores each of the 9 messages as arrays of `[u32, u32]` pairs, combines each pair into a 64-bit integer (`a = n0 + n1·2³²`), divides by 7 once, then repeatedly emits `(a mod 7) − 1` while dividing by 7 — yielding values in the range −1..5 where 5 = newline. The Fandom wiki gives a confirmed worked example: hex `acf686745634505c` = 12463296853015023708, whose base-7 expansion (minus 1 per digit) reproduces the engine's stated eye-orientation output exactly. [confirmed] (https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw, https://noita.fandom.com/wiki/Eye_Messages)
- **Human reading of rendered glyphs (base-5).** The visible five orientations are read in groups of three (trigrams) as base-5 numbers (see below).

Both are correct at different layers. The popular "base-5 only" framing describes the rendered glyphs; the engine's own generation uses base-7 over 64-bit integers. The occasionally repeated phrasing "written originally in hexadecimal and converted to 0–5 values" is loose but essentially accurate as a description of the binary→glyph pipeline (the radix of conversion is 7, not 5). [confirmed] (https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw, https://noita.fandom.com/wiki/Eye_Messages)

## Agreed transcription and notation

The community has converged on a stable transcription. Each message is recorded as a string of digits 0–4 for eye orientations, with 5 as a row delimiter. This is the format used in the canonical research datasets (e.g. `eyes.json` in ngraham20/NoitaCryptographyResearch, and Doctor-Ned/SirCapybar's `data.csv`). Multiple independent transcriptions agree byte-for-byte (e.g. East 1 begins `50 66 5 48 62 13 75 29 24 …` in decimal trigrams across at least three independent sources). [confirmed] (https://github.com/ngraham20/NoitaCryptographyResearch, https://github.com/Doctor-Ned/NoitaEyeGlyphResearch)

### Reading model (trigrams)

The accepted reading model groups eyes into trigrams — three eyes read as a 3-digit base-5 number (`000`–`444` = decimal 0–124), computed as `d0·25 + d1·5 + d2`. Reproducible structural facts (independently recomputed from the raw data in this dossier): [confirmed]

- After stripping delimiters, every message's eye count is divisible by three — counts are East 1–5 = 297, 354, 411, 357, 342 and West 1–4 = 309, 306, 372, 360, all `% 3 == 0`. (https://github.com/ngraham20/NoitaCryptographyResearch, https://noita.wiki.gg/wiki/Eye_Messages)
- The total trigram count across all nine messages is exactly 1036, which matches the exponent in the wiki's probability figure. (https://noita.wiki.gg/wiki/Eye_Messages)
- Splitting on the delimiter yields rows of 39 with the bottom two rows differing by at most 1 (e.g. East 1 rows: 39,39,39,39,39,39,32,31). (https://github.com/ngraham20/NoitaCryptographyResearch)

### The 0–82 result and its key caveat

The headline structural finding: under one specific reading order, the 1036 trigram values form an unbroken range 0–82 — exactly 83 distinct values, none missing, none above 82, out of the 125 possible. [confirmed, but order-dependent] (https://noita.wiki.gg/wiki/Eye_Messages, https://github.com/Doctor-Ned/NoitaEyeGlyphResearch)

The critical caveat, which casual summaries omit: this result is not a property of the raw data in any obvious reading order. Independent recomputation shows that reading trigrams horizontally line-by-line yields ~114 distinct values spanning 0–122 (with gaps), and column-major yields all 125 values. The contiguous 0–82 set appears only under a particular interlocking-triangle traversal — "1 of 36 standard reading orders" per the wiki. Toboter scripted a brute force of ~86,000 reading-order variants and reportedly found no other order matching its statistical significance. So the 0–82 finding is real and statistically striking, but it is order-conditional: all downstream cryptanalysis is computed on this one chosen traversal. **[Lymm]** Contiguity was not chosen in advance as a validation criterion — it emerged while researchers were testing reading orders and stood out as significant; the order is retained because of independently significant downstream structure (isomorphs, forbidden-successor patterns), not because of circular reasoning from contiguity back to itself. Substitution-equivalent alternative reading orders change no computed statistic — every statistic here is substitution-invariant or conditioned on the fixed digit sequence. [confirmed for the order-dependence; likely for the ~86,000 brute-force result; look-elsewhere framing per Lymm 2026-07-06] (https://noita.wiki.gg/wiki/Eye_Messages, https://github.com/ToboterXP/EyeGlyphs)

Some analysts (e.g. Perseus on Steam) push back that the specific 0–82 order has not been *proven* correct; the strongest defensible statement is that at least one of a small symmetric set of reading orders is correct. [likely] (https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/)

### Display conventions

Decoded values 0–82 are often displayed in researcher repos as 83 Elder Futhark runes, or alternatively as decimal, ASCII, or alchemical-symbol renderings. These are arbitrary display mappings chosen by researchers — the game stores eye orientations (0–4), not runes, and no runes appear in-game. [confirmed] (https://github.com/ngraham20/NoitaCryptographyResearch)

## Current solved/unsolved status

The Eye Messages are unsolved. No public, method-backed decryption to plaintext exists as of the sources surveyed for this dossier (mid-2026); the Noita Wiki still lists them as unsolved. The wiki, the canonical research doc, the Steam guides, and the GitHub research repos all agree. The wiki explicitly warns that "anyone claiming to have solved the eyes without presenting a method should not be believed." [confirmed] (https://noita.wiki.gg/wiki/Eye_Messages, https://steamcommunity.com/sharedfiles/filedetails/?id=3281214266)

What the cryptanalysis establishes (working hypotheses, not proofs):

- **Simple monoalphabetic substitution is ruled out** — trigram frequency is flat/uniform, IoC ≈ 1.066, non-monoalphabetic. [confirmed] (https://github.com/ngraham20/NoitaCryptographyResearch, https://noita.wiki.gg/wiki/Eye_Messages)
- The cipher is believed polyalphabetic, aperiodic, with each ciphertext symbol conditionally dependent on the previous one, and roughly ~83 internal states. The "~83 states" figure is the softest of these claims — the source itself is hedged ("no fewer than 20 … probably at least ~88 … so likely 83") and 83 equals the alphabet size, raising a circularity concern; it is also now superseded rather than merely disputed. Under the surviving cipher-family theories (GAK on a near-S₈₃ state group; see `research/gak-threads/`), the state space is understood to be S₈₃-scale (83! ≈ 10¹²⁴), not ~83 states — the old figure reflects the earlier, pre-GAK custom-Alberti-era framing. [likely for polyalphabetic/aperiodic; disputed and superseded for the precise "83 states"] (https://noita.wiki.gg/wiki/Eye_Messages)
- Reported fingerprints — "no ciphertext symbol twice in a row," a "~2× expected" recurrence at distance 4, and cross-message isomorphs — hold only on the correctly-reordered ciphertext. On the raw stored order, independent recomputation finds 17 adjacent-equal trigrams and no distance-4 spike, confirming these properties are conditional on the inferred reading order. [disputed as stated; the properties are real only post-reorder] (https://noita.wiki.gg/wiki/Eye_Messages, https://github.com/ngraham20/NoitaCryptographyResearch)
- Many classical attacks are documented dead ends: Vigenère/Caesar, Trifid (called "useless here"), diamond, Polybius, periodic ciphers, and 3D/octahedron projections. The isomorph-based "alphabet chaining" attack notably fails for unclear reasons, which is the main reason researchers are stuck; the live (unproven) directions are non-commutative / plaintext-driven permutation models (wheel/incrementing cipher, Chaocipher/Hutton, S₈₃ permutation, autokey-Alberti). [confirmed for the dead ends; likely for the live directions] (https://github.com/SirCapybar/NoitaEyeGlyphResearch, https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/, https://noita.wiki.gg/wiki/Eye_Messages)

Two notable false-solution episodes were publicly debunked: the PAM5 / 3D-octahedron theory (debunked video, Dec 2022) and the FuryForged "mysterious emails" ARG (early 2023). Loud "I solved it" claims that withhold a method (e.g. the Steam user feed4fun, who said "no i wont tell you, kbye") are uniformly dismissed. [likely for the debunks; confirmed for the dismissals] (https://www.youtube.com/watch?v=TdHYTu99GZ4, https://www.youtube.com/watch?v=hXEzoSyQlU4, https://steamcommunity.com/app/881100/discussions/0/4852155152090234980/)

### Context: other Noita ciphers

For contrast, Nolla do design solvable ciphers. Several other Noita symbol systems are solved — Common Glyphs map 1:1 to English (e.g. "SEEK THE END", "BRING THE TREASURE HERE"), Orb-Room glyphs map to a Finnish creation myth, and the separate Cessation Cipher Quest decodes to "SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE." These prove Nolla build solvable multi-step ciphers but are distinct from the Eye Messages and should not be cited as evidence the eyes themselves are solvable. Developer denials recorded on the wiki concern the Orb-Room symbol (denied by Arvi, Antti, and Olli). On the eyes, **exactly one** dev statement exists: in a 2021-10-15 Twitch stream (video recording: youtube.com/watch?v=ItzQh6K3hP8; relayed verbatim by FuryForged) Arvi confirmed *"the eye decorations do contain a message… They actually do have a meaning,"* and rated their difficulty ~*"square root of minus 1… probably very difficult."* This relayed-verbatim quote confirms the eyes carry an intentional, "very difficult" message, but it discloses **no** cipher, key, or method — so the eyes' unsolved status and the claim ceiling are unchanged, it does **not** make the eyes solvable, and the "do not cite [other solved Nolla ciphers] as evidence the eyes are solvable" caution stands. [likely — verbatim but relayed/maintainer-supplied] (https://www.youtube.com/watch?v=ItzQh6K3hP8, https://discord.com/channels/453998283174576133/817530812454010910/899514286290898985, https://noita.wiki.gg/wiki/Mysteries_and_Oddities)
