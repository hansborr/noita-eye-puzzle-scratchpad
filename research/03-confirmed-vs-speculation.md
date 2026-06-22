# Confirmed vs. Speculation: The Noita Eye Messages

This document sorts every significant claim about the Noita "Eye Messages" puzzle into four evidence tiers — **[confirmed]** (primary evidence: game files, decompiled engine code, reproducible in-game observation, or independently reproduced computation), **[likely]** (multiple consistent sources but a verification gap), **[speculative]** (community inference without primary backing), and **[disputed]** (sources conflict or a popular claim fails when checked). Adversarial verification verdicts are quoted directly. The guiding principle: the puzzle's *structure* is well-substantiated; its *meaning*, its *intentionality as a developer-authored solvable cipher*, and several specific cryptographic "properties" are far softer than community write-ups imply.

---

## 1. What the puzzle is

**The "Eye Messages" are 9 grids of eye-glyphs found in the East/West Parallel Worlds, believed to encode information, unsolved for years.** [confirmed — with two overstated words]

- 9 messages total: 5 East, 4 West, placed internally in alternating E, W, E, W… order; every East message except the last (East 5 / "Message 8") has a West counterpart. The "missing West 5" is real and unexplained. [confirmed] (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages, https://github.com/ngraham20/NoitaCryptographyResearch)
- The puzzle is currently **unsolved** with no public, method-backed plaintext. [confirmed] (https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict (on "officially the Eye Messages … considered to encode information"): MIXED.** "The factual scaffolding (9 messages, 4 west / 5 east, Parallel Worlds, currently unsolved, deliberately generated) is well-supported. The framing words ('officially,' 'encode information' stated as established fact) are not backed by any primary developer source and rest on community consensus/statistical inference. … Calling it 'official' is unsubstantiated. … The wiki's exact phrase is 'They are known to contain information' … However, this 'known to contain information' assertion is itself a community inference, NOT a developer confirmation."

> **Verdict (on the 9-message E/W placement detail): SUPPORTED.** "Every element of the claim is confirmed verbatim against the cited primary source and independently corroborated by two further sources. … the claim is not just a fair paraphrase; it is a near-verbatim restatement of the primary document, including the numbering nuance."

**Hidden assumption flagged:** "Eye Messages" is a community-coined label. No located Nolla/Petri Purho statement names the feature, calls it a puzzle, or confirms it encodes a message.

---

## 2. CONFIRMED — primary evidence or independently reproduced

### Encoding mechanics

- **Each eye has one of five orientations encoded as digits 0–4; the digit "5" creates a new line and is not displayed.** [confirmed] The verbatim sentence appears in the primary Google Doc and is mirrored on the wiki; the five-orientation/base-5 structure is internally consistent with the trigram math. (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict: SUPPORTED.** "VERBATIM QUOTE IS REAL. … FIVE ORIENTATIONS / DIGITS 0-4 IS CORROBORATED AND INTERNALLY CONSISTENT … THIS IS PRIMARY-GROUNDED, NOT MERELY REPEATED LORE … the number strings and the encoding scheme … originate from reverse-engineering of the actual game binary." Caveats: the conversion-table image and Ninji's Ghidra decompilation were not opened directly; the *meaning* remains unsolved — "the claim is only about the low-level encoding."

- **Glyphs are arranged in rows (≈39 per row max) with every second row offset to interlock.** [confirmed for the offset/interlock; [likely] for the exact "39" cap] Independently reproduced: stripping the delimiter, East 1 splits into rows [39,39,39,39,39,39,32,31]; West 1 into [39,39,39,39,39,39,38,37] — bottom two rows differ by ≤1. (computation on eyes.json; https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict: MIXED.** "'Every second/other row is offset to interlock/mesh between neighbors' — WELL SUPPORTED … a directly observable, reproducible visual property. … 'At most 39 individual eyes in each row' — SUPPORTED ONLY AS AN OBSERVED MAXIMUM, NOT A PROVEN HARD LIMIT … I found NO primary evidence that 39 is a hardcoded engine constant."

### Quantitative structure (independently reproduced in code)

- **Every message's eye count is divisible by 3.** Counts {East1:297, West1:309, East2:354, West2:306, East3:411, West3:372, East4:357, West4:360, East5:342} — all ÷3. [confirmed] Important qualifier: divisibility holds for *eye* counts, **not** for the raw stored string lengths (which include delimiters). (computation; https://noita.wiki.gg/wiki/Eye_Messages)

- **Total trigram count across all 9 messages is exactly 1036.** Reproduced from two independent transcriptions (ngraham20 eyes.json; Doctor-Ned/SirCapybar data.csv): 99+118+137+119+114+103+102+124+120 = 1036. [confirmed] (computation; https://github.com/ngraham20/NoitaCryptographyResearch, https://github.com/Doctor-Ned/NoitaEyeGlyphResearch)

> **Verdict (trigram divisibility/attribution): MIXED.** "CORE NUMERIC CLAIM: SUPPORTED by primary data. I independently reproduced this … ALL NINE are divisible by 3. … IMPORTANT QUALIFIER the claim missed: the raw stored string LENGTHS (including delimiters) are … mostly NOT divisible by 3." The The_Duck1 attribution for the trigram idea is **NOT substantiated** — see §6.

- **The probability figure (83/125)^1036 is published as 5.8362007929568295e-185.** [confirmed that 1036 is real; [disputed] on the exact mantissa] The exponent equals the true trigram count. But high-precision recomputation gives ...6514e-185, not the wiki's ...68295e-185 (a float64 artifact). (https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict: MIXED.** "the trigram count of 1036 is solidly verified; the probability constant is published as claimed but its quoted mantissa is numerically slightly inaccurate. … the wiki does NOT show the per-message breakdown deriving 1036 — that number is asserted, not derived, on the page."

### Generation pipeline

- **The eye-spawning code is built into the engine (not a Lua script), cannot be extracted from the asset archive, and the graphics are generated on the fly (no sprites).** [confirmed] Backed independently by Ninji's Ghidra decompilation of a native generation function and by the fact that no eye assets exist in the otherwise-fully-unpackable data.wak. (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://en.wikipedia.org/wiki/Noita_(video_game))

> **Verdict: SUPPORTED.** "The spawn-code half of the claim is not merely repeated lore — it is backed by independent technical reverse engineering. … A decompiled NATIVE function in the engine binary is direct evidence the logic is compiled into the engine, not present as a Lua script." Caveat: "the 'graphics are generated on the fly / no sprites' half … rests more on community assertion than the spawn-code claim does."

- **The internal generation is base-7 over 64-bit integers.** Reproduced exactly: 0xacf686745634505c = 12463296853015023708 → repeated ÷7 → drop trailing 0 → subtract 1 → EyePositionNumeric `[2,0,1,0,1,3,2,2,3,3,0,4,0,4,1,1,3,0,2,3,2,1]`, an exact match to the wiki's stated output and to Xkeeper0's PHP transcoder (which divides by 7 and emits (a mod 7)−1, values −1..5, 5=newline). [confirmed] (https://noita.fandom.com/wiki/Eye_Messages, https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw)

  - **CRITICAL LAYER DISTINCTION:** the *engine's internal storage/decode* is base-7; the *human reading* of rendered glyphs is base-5 trigrams (000–444 = 0–124). Both are true at different layers. The popular "base-5 only" framing describes the rendered glyphs, not the binary. The one-source summary calling trigrams "base-83" is a fetch artifact and is **wrong** (83 = count of distinct values used, not a radix). [confirmed]

### Spawn conditions

- **Spawn requires: (1) `mods_have_been_active_during_this_run` unset; (2) the "Entered East/West" trigger; (3) background `background_cave_02.png`; (4) seed-deterministic locations.** [confirmed] Verbatim in the primary doc; the mods-flag condition is independently verifiable via the documented `world_state.xml` save-edit workaround. (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict: SUPPORTED.** "a real, retrievable primary source plus independent verification of the most consequential clause … The community is uniform on them; the open/unsolved part is the MEANING of the glyphs … not these spawn gating conditions."

- **Example seed 1249563923 coordinates** (East1 X:22064 Y:−6079; West1 X:−49616 Y:−6079; East5 X:36400 Y:2624 with no West cell) transcribe the wiki table exactly. [confirmed for transcription; not re-verified in-game]

> **Verdict: MIXED.** "COORDINATE VALUES — SUPPORTED (strong documentary match). … CHEAT-ENGINE WARNING — MISATTRIBUTED … The full current noita.wiki.gg page text I retrieved does NOT mention Cheat Engine at all … The … warning appears on the FANDOM mirror, a different page." Also not re-verified in a live game build.

### Cryptanalysis baselines

- **Simple monoalphabetic substitution is ruled out** by flat/non-monoalphabetic trigram frequency. [confirmed] Quotes verified verbatim in the ngraham20 README and the wiki/CodeWarrior0 material. (https://github.com/ngraham20/NoitaCryptographyResearch, https://noita.wiki.gg/wiki/Eye_Messages)

> **Verdict: SUPPORTED.** "I tried hard to refute this and could not. All three cited quotes were verified verbatim against their primary sources." Caveat: "the inference … is the community analysts' own conclusion, not a Nolla Games/Petri Purho statement nor a mathematically airtight proof."

- **The data.wak / .salakieli format facts** (WizardPak little-endian TOC; AES-128-**CTR**; key/IV PRNG seeds 0 / 1 / 2147483646 / file-index, each +0x165EC8F, Park-Miller MINSTD mult 16807 mod 2^31−1; literal passphrase keys for .salakieli) are confirmed across three independent implementations — and **correct several survey errors** (it is CTR not OFB; the seed is not "123"). [confirmed] (https://github.com/isJuhn/UnWak, https://gist.github.com/RidgeX/e159bb7df97b2e18209aea2804a79d7a, https://noita.wiki.gg/wiki/Technical:_File_Formats) — *Note: this concerns asset extraction generally; the eyes are NOT in data.wak, so this is context, not a route to the eye content.*

- **Other Noita symbol systems ARE solved** (Common Glyphs → English; Orb-Room glyphs → Finnish creation myth; the separate "Cessation Cipher Quest" → "SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE"). [confirmed] These prove Nolla designs *some* solvable ciphers — but are distinct from the eyes and do **not** establish the eyes are solvable. (https://steamcommunity.com/sharedfiles/filedetails/?id=3281214266, https://noita.wiki.gg/wiki/The_Cessation_Cipher_Quest)

---

## 3. LIKELY — consistent across sources, but a verification gap remains

- **The "1 of 36 reading orders yields an unbroken 0–82 set" anomaly, and Toboter's ~86,000-order brute force finding no equal alternative.** [likely] The statistical claim is real and the 1036/0–82 facts are reproduced — but it is **order-dependent and image-documented**, not derivable from the naive reading orders (see §6). (https://noita.wiki.gg/wiki/Eye_Messages)

- **Cipher characterized as polyalphabetic, aperiodic, ~83 internal states, cipher/key constant across messages, with isomorphs.** [likely as a working hypothesis; the "~83 states" is the weakest piece] (https://noita.wiki.gg/wiki/Eye_Messages, https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA)

> **Verdict: MIXED.** "as a description of 'what these named researchers hypothesize,' it is well-substantiated. … As a description of 'what the cipher actually is,' it is unproven, and one sub-claim (the specific '83 internal states') is weaker than the rest. … The '83' is not derived as 83; it is a guess pinned to a separate finding (the … 0–82 set) … even the lower bound '20' and central estimate '88' are statistical, not deductive."

- **Ninji reverse-engineered the Feb 3 2021 build; a ~60 MB Ghidra project and decompiled generation function exist.** [likely] Multiply-attributed and consistent with the reproducible base-7 algorithm, but the actual project file/function were not opened; Ninji's own site has no Noita project page. Ninji (@_ninji, wuffs.org) is distinct from "ghidraninja"/stacksmashing. (https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0, https://wuffs.org/blog/reversing-games-with-hashcat)

- **Eye CONTENT is recoverable in principle / "written originally in hexadecimal."** [likely] The Fandom worked example is reproducible (base-7), making the hex-source description **better-sourced than the survey credited** — but a separate Google-Doc-only claim that the content "was obtained" overstates: RE revealed the *generator and per-seed glyph sequences*, not a decrypted plaintext.

> **Verdict (on "content was obtained"): MIXED.** "reverse engineering revealed the GENERATION ALGORITHM and glyph-placement … and Cheat Engine reveals LOCATIONS … It did NOT yield a decrypted plaintext meaning. … the word CONTENT overstates what was achieved (glyph sequences/locations and the generator, not a solved/decrypted message)."

- **Content is seed-invariant (only placement varies by seed).** [likely] Consistent with Xkeeper0's single hard-coded message set and Lymm's coordinate-only tool, but **no primary byte-for-byte cross-seed invariance proof was located.** (https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw, https://gitlab.com/realgonzogames/lymms-binoculars)

- **No Nolla developer (Purho / Harjola / Teikari / Tiihonen) has ever made an eye-specific statement** about meaning, cipher, intent, or solvability. [likely — proving a negative] By contrast, the adjacent Cauldron (Arvi's 2021 "don't be too concerned") and Orb-Room symbol (denied by Arvi, Antti, Olli) *do* have dev remarks. (https://en.wikipedia.org/wiki/Noita_(video_game), https://noita.wiki.gg/wiki/Mysteries_and_Oddities)

- **PAM5 theory debunked; FuryForged "mysterious emails" ARG debunked.** [likely] Debunk status rests on video titles/snippets, not retrievable transcripts. (https://www.youtube.com/watch?v=TdHYTu99GZ4, https://www.youtube.com/watch?v=hXEzoSyQlU4)

---

## 4. SPECULATIVE — community inference without primary backing

- **Developer attitude / intentionality.** No verbatim dev quote calls the eyes an "intentional puzzle." Intentionality is *inferred* from the mod-gating, engine-hardcoding, statistical structure, and a Hempuli Roguelike Celebration talk that discussed Noita's secrets generally. [speculative] (https://www.youtube.com/watch?v=ItzQh6K3hP8)

- **The specific direction-per-digit mapping (0=center, 1=up, 2=right, 3=down, 4=left).** Presented only as an image in primary sources; no retrievable text pins each pixel-direction to its digit. [speculative]

> **Verdict: UNVERIFIABLE.** "No primary source pins each pixel-direction to its digit … THE WIKI MAPPING IS IMAGE-ONLY … NO AUTHORITATIVE SOURCE EXPLICITLY STATES THE 0=center,1=up,2=right,3=down,4=left ORDERING. … Cipherbrain … explicitly warns … 'the five eye symbols are represented by the numbers 0 to 4. The order is different from the two pictures.'" The digit→orientation legend is an arbitrary labeling convention; the puzzle is unsolved regardless.

- **The octahedron / 3D-projection family.** Popular (motivated by meditation-cube imagery) but produces inconsistent, only vaguely-glyph-like results; unsubstantiated. [speculative] (https://noita.wiki.gg/wiki/Eye_Messages)

- **Desert-ruin symbols (3 ovals, "¡!¡", a rhombus) as eye-puzzle hints.** Explicitly community speculation. [speculative] (https://noita.wiki.gg/wiki/Mysteries_and_Oddities)

- **Perseus's "key permutes after each character use" / plaintext-driven permutation, and the repo "incrementing wheel" model.** Live but unproven directions. [speculative] (https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/)

- **Ship date / first-discovery.** "Since 1.0 / since release" is consensus only; no patch note and no attributable first-discovery post located. The Sept 2019 Early Access vs Oct 2020 1.0 ambiguity is unresolved. [speculative] (https://store.steampowered.com/news/?appids=881100)

---

## 5. DISPUTED — sources conflict or a popular claim fails on inspection

- **"Developers confirmed the eye messages are solvable / encode meaningful content."** This is the single most over-circulated meta-claim, and it does not survive scrutiny. [disputed]

> **Verdict context:** It "traces solely to the unsourced one-line intro of a 2022 Hacker News submission, with no Discord screenshot, quote, or dated dev statement behind it." The HN text reads "The developers have confirmed that it is solvable…"; a fetch of the item found "No Discord message, quote, or developer link is provided to support this claim." The phrasing also surfaces in **Grokipedia (AI-generated, uncited)** and unsourced Fandom synthesis. Wikipedia, both wikis, the CodeWarrior0 doc, and Steam guides contain no such dev statement. (https://news.ycombinator.com/item?id=33929442, https://grokipedia.com/page/Noita_(video_game))

- **"~83 internal states."** [disputed] Internally muddled on the wiki ("at least ~88 … so likely 83," i.e. fewer than its own lower bound) and risks circularity because 83 = the glyph-value count. (https://noita.wiki.gg/wiki/Eye_Messages)

- **The "no symbol twice in a row" and "distance-4 recurrence spike" cipher properties.** [disputed] On the **raw stored order**, direct computation finds **17 adjacent-equal trigrams** (violating "no doubles") and distance-4 recurrences (10) **not elevated** vs distance 1 (17) or 3 (15). These properties hold only *after* assuming the correct reading order — which is itself only inferred. (computation on eyes.json; https://noita.wiki.gg/wiki/Eye_Messages)

- **"Eye Messages and Cauldron are *the two* major secrets."** [disputed] The wiki contradicts itself: the Eye Messages page says "two," while the Cauldron page says there are *three* mod-restricted secrets and calls Eye Messages "the only confirmed unsolved mystery." Epilogue 2 (2024) is widely read as having resolved the Cauldron.

> **Verdict: MIXED.** "The verbatim quotes the claim relies on are accurate … But the underlying assertion — that there are exactly 'two major secrets' — is editorial, internally inconsistent … and the Cauldron is now treated by the wiki as resolved/closed."

- **"Pyry" treated as a Nolla dev / insider signal.** [disputed] Pyry is a frequently-cited contributor but is **not** verifiably on the documented team (Purho, Harjola, Teikari). Treating Pyry's autokey-Alberti demo as a dev signal is unsupported. (https://noita.wiki.gg/wiki/Eye_Messages)

- **"PAM5 / base-83 radix / hex-origin is garbled lore."** [disputed → corrected] The survey's flag was **wrong**: the hex→base-7 generation is one of the best-substantiated primary facts; only the *base-83* radix phrasing is the error.

---

## 6. Dead ends (documented failed approaches)

All tried and reported as failures by named researchers:

- Monoalphabetic substitution / frequency analysis — flat distribution. [confirmed]
- Vigenère / Caesar (text and trigram), periodic ciphers — ruled out by non-periodicity. [confirmed]
- Trifid ("useless here" — SirCapybar), Polybius cube, diamond cipher. [likely]
- **Alphabet Chaining** (codewarrior0's isomorph exploit) — "has not been completely successful"; nobody can explain why it fails. This is the primary reason researchers are stuck. [confirmed/likely] (https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA)
- Chaocipher / Hutton / S83-symmetric-group permutation models — "similar in spirit" but non-matching. [likely]
- 3D/octahedron projection — inconsistent results. [confirmed]
- PAM5 theory — debunked. [likely]
- FuryForged "mysterious emails" ARG — debunked. [likely]
- Trigram-following correlation up to gap 50 — "little more than randomness," so distant trigrams don't influence each other. [confirmed quote] (https://noita.wiki.gg/wiki/Eye_Messages)
- Unmethoded "I solved it" claims (e.g., feed4fun: "no i wont tell you, kbye") — rejected per the community rule that anyone claiming a solution without a method should be disbelieved. [confirmed] (https://steamcommunity.com/app/881100/discussions/0/4852155152090234980/)

---

## 7. Likely over-fitting and hidden assumptions

These are the structural risks that the most confident community write-ups understate:

1. **Reading-order circularity (the central risk).** The headline "intentional, not noise" argument — 1 of 36 orders giving a contiguous 0–82 range — *presupposes* the trigram grouping, the base-5 model, and a selection criterion (contiguity) that is itself the thing being treated as significant. The winning traversal is shown via images and **could not be reproduced from the sources alone**; naive orders fail (horizontal → 114 distinct values, 0–122; column-major → all 125). Nearly every downstream cipher "property" is conditional on this unproven reorder. [confirmed that naive orders fail; the order-dependence is a genuine caveat] (computation; https://noita.wiki.gg/wiki/Eye_Messages)

2. **Generation-artifact possibility.** The hex→base-7 pipeline (÷7, then −1, yielding −1..5) sits oddly with a strict 5-glyph/base-5 framing. Some "structure" could be an encoding artifact of the base-7 generator rather than meaningful plaintext. The proper test — running random/known plaintexts through the documented generator and re-running the trigram/range/isomorph analyses — has not been done. [speculative but legitimate] (https://noita.wiki.gg/wiki/Eye_Messages)

3. **Circular state estimate.** "~83 internal states" likely just restates the alphabet size (83 used values), not an independent measurement. [disputed]

4. **Echo-chamber / single-corpus risk.** The entire technical corpus is a handful of analysts (Lymm, codewarrior0/CodeWarrior0, Toboter, Pyry) plus three GitHub repos and a few Google Docs. Independent reproduction beyond this group is thin; the two most precise failure logs live in gated Google Docs. Multiple transcriptions agree (good), but they may share provenance. [confirmed as a structural observation]

5. **"Plaintext/ciphertext corruption" as an unfalsifiable rescue.** The community openly hypothesizes corruption (wrong/transposed/missing letters) to explain why isomorph attacks fail — a hypothesis that can absorb almost any contrary evidence and is hard to falsify. [confirmed quote; flagged as epistemically weak] (https://noita.wiki.gg/wiki/Eye_Messages)

6. **Anti-datamining context.** Nolla actively trolls dataminers — the official `for_the_seekers_of_truest_of_knowledge` URL 302-redirects to a Rickroll, and a related hidden message decodes to "So long and thanks for all the fish!" This is primary evidence that any "dev confirmation" lore should be treated with caution. [confirmed] (https://noitagame.com/for_the_seekers_of_truest_of_knowledge/, https://tvtropes.org/pmwiki/pmwiki.php/Trivia/Noita)

---

## 8. Bottom line

- **Solidly established [confirmed]:** 9 messages (5E/4W, no West 5); 0–4 orientations + 5=newline; eye counts ÷3; 1036 trigrams; engine-generated (not Lua, not in data.wak); base-7 internal generation reproduced; spawn conditions; monoalphabetic substitution ruled out; the puzzle is unsolved.
- **Plausible but unproven [likely]:** the 0–82 reading-order anomaly; polyalphabetic/isomorph character; Ninji's Ghidra RE; seed-invariant content; absence of dev comment.
- **Not established [speculative]:** developer intentionality; the exact direction-per-digit mapping; octahedron and permutation-cipher models; ship date/first discovery.
- **Should be retired or heavily qualified [disputed]:** "developers confirmed it's solvable" (traces to one unsourced HN line + AI-generated Grokipedia); "~83 internal states" (circular); "no doubles / distance-4 spike" (false on raw order); "two major secrets" (self-contradictory, Cauldron now resolved); "Pyry is a dev."

The honest summary: the Eye Messages are a **deliberately generated, engine-hardcoded, structurally regular artifact that is genuinely unsolved**, and whose status as an *intentional, solvable cipher with recoverable plaintext* is a well-motivated community belief — **not** a fact backed by any primary developer statement.
