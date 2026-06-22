# Noita Eye Messages — Decoding Theories and Encoding Approaches

A critical catalog of every notable decoding theory and encoding approach applied to the Noita "Eye Messages" — the 9 engine-generated glyph grids (5 East, 4 West Parallel Worlds) that remain **unsolved** as of mid-2026. Each entry states what the approach produced and assesses it skeptically with a confidence tag. The puzzle is unsolved; treat any "solution" lacking a published method as false (the wiki's own rule: "anyone claiming to have solved the eyes without presenting a method should not be believed") [confirmed] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).

A structural note that governs everything below: there are at least **two distinct encoding layers**, and many theories conflate them.

- **Engine layer (generation):** hex pairs → 64-bit integer → repeated division by **7** → drop trailing 0 → subtract 1, yielding values −1..5 where 5 = newline. This is the engine's internal storage/decode and was reproduced from Xkeeper0's PHP transcoder and the Fandom worked example [confirmed] ([gist](https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw); [noita.fandom.com](https://noita.fandom.com/wiki/Eye_Messages)).
- **Reading layer (human):** the *rendered* glyphs have 5 orientations read as **base-5** trigrams (000–444 = 0–124). This is a separate step from generation [confirmed] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).

The "originally hexadecimal, base-7 division" pipeline is genuinely primary (reproduced) and is *not* the same as the base-5 trigram reading — a distinction the community sometimes blurs [confirmed].

---

## 1. Structural / reading-order theories

### 1.1 Base-5 trigram grouping (the foundation)
**Approach:** Pair offset rows, group eyes into triangles of three, read each as a 3-digit base-5 number (0–124).
**Produced:** A clean partition — every message's eye count is divisible by 3, totalling exactly **1036 trigrams** across all 9 messages [confirmed; independently reproduced in the dossier from three separate transcriptions]. The (83/125)^1036 = 5.836×10⁻¹⁸⁵ probability figure uses 1036 as its exponent [confirmed] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).
**Assessment:** The divisibility-by-3 and trigram count are objective, multiply-reproduced facts. The trigram *interpretation* (that three eyes form one symbol) is an inference, but a strong one given the divisibility. Attribution of the original idea to Reddit user "The_Duck1" appears in some summaries but is **not corroborated** by the directly-fetched wiki, which credits Lymm/Pyry/Toboter/CodeWarrior0 [disputed].

### 1.2 The "unbroken 0–82" reading order
**Approach:** Of 36 standard reading orders, find one where the 1036 trigram values span a contiguous 0–82 (83 distinct values).
**Produced:** Exactly one order yields the unbroken 0–82 set; Toboter's script tested ~86,000 orderings and found no other matching its statistical significance [confirmed per wiki] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).
**Assessment — the single most load-bearing and most over-stated claim.** Two genuine caveats:
- **Naive orders fail.** Horizontal line-by-line reading → 114 distinct values spanning 0–122; column-major → all 125 values. The 0–82 result requires one specific interlocking-triangle traversal, documented mainly via images [confirmed; reproduced]. So "0–82" is **order-dependent**, not an intrinsic property of the raw data.
- **Circularity risk.** The selection criterion (contiguity) presupposes the trigram model and the base-5 reading. The probability figure measures "how unlikely is contiguity by chance given this framing," not "is this framing correct." [likely a real signal, but the inference is not airtight.]
- **Perseus's dissent:** he argues the 0–82 order is treated "as if proven" but "hasn't been proven to be right," reframing it as "at least one of six symmetrical reading orders is correct" — a narrower claim than the wiki's "36 orders, one winner" [likely] ([Steam](https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/)).
**Net:** A real statistical anomaly that strongly suggests the data is structured/intentional, but the specific 0–82 order is a chosen, image-documented convention, not a proven fact [likely].

### 1.3 Glyph-orientation → digit mapping (0=center,1=up,2=right,3=down,4=left)
**Approach:** Assign each of the 5 eye orientations a digit.
**Produced:** The canonical numbering that yields the 0–82 range; CodeWarrior0 states this numbering "was learned from data mining the game's executable" and "is also the unique numbering that produces a complete range of 0–82" [confirmed for textual 0–4 coding] ([CodeWarrior0 doc](https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA/edit)).
**Assessment:** The 0–4 + "5=newline" coding is verbatim primary. The *specific* pixel-direction-per-digit (which orientation = "up", etc.) is shown only as an image; no retrievable text pins it down, and Cipherbrain explicitly warns "the order is different from the two pictures." Treat the exact direction labels as an arbitrary-but-consistent convention, **not** independently verified [speculative on the exact per-digit directions; confirmed that five orientations + a newline marker exist].

---

## 2. Classical substitution / frequency-based ciphers

### 2.1 Monoalphabetic substitution / frequency analysis
**Produced:** Nothing usable. "Frequency analysis has been tried on the trigrams, with no workable results, indicating that simple substitution isn't the answer"; the ciphertext frequency is "flat, and not monoalphabetic" (IoC ≈ 1.066, near random) [confirmed] ([ngraham20](https://github.com/ngraham20/NoitaCryptographyResearch); [noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).
**Assessment:** Soundly **ruled out** — but only for the narrow case it actually addresses: *one-to-one monoalphabetic substitution of ordinary natural-language plaintext, under the canonical trigram reading*. A flat distribution is incompatible with that. It does **not** rule out homophonic substitution, a codebook, null-padding, compression-then-encipherment, or a non-language payload — and it is contingent on the accepted reading order (see [03 §reading-order](03-confirmed-vs-speculation.md)). With those qualifications it is the most robust negative result in the corpus [confirmed].

### 2.2 Caesar / Vigenère / periodic ciphers
**Produced:** No solution. Period analysis shows the ciphertext is **not periodic**, ruling out classic Vigenère/Caesar over a fixed period. Implemented in SirCapybar's C# tooling (Vigenère, Caesar) and codewarrior0's `stat_period.py` without success [likely → confirmed for "tried and failed"] ([SirCapybar](https://github.com/SirCapybar/NoitaEyeGlyphResearch); [codewarrior0](https://github.com/codewarrior0/noita-eye-glyph-analyses)).
**Assessment:** Dead end as classically formulated. Aperiodicity is the key disqualifier [confirmed].

### 2.3 Polybius / Trifid / Diamond / cube ciphers
**Produced:** Nothing. SirCapybar's README explicitly calls the trifid cipher "useless here"; Polybius cube and a "diamond" cipher were implemented without result [likely] ([SirCapybar README](https://github.com/SirCapybar/NoitaEyeGlyphResearch/blob/master/README.md)).
**Assessment:** Documented dead ends [likely].

---

## 3. Polyalphabetic / dynamic-key family (the leading direction)

### 3.1 General polyalphabetic / autokey model
**Produced:** The dominant working hypothesis. Observed properties: flat frequency, aperiodic, **no ciphertext symbol twice in a row**, ciphertext coincidences at distance 4 at ~2× expected, isomorphs shared across messages. Conclusion: "the cipher is polyalphabetic. Each ciphertext character is dependent on something outside of a single plaintext character," and the analysis "slightly favors an auto-keyed cipher" [likely] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages); [CodeWarrior0 doc](https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA/edit)).
**Assessment — important caveat:** Several of these cipher *properties* (no doubled symbol; distance-4 spike) hold only **after** the special reading-order reorder. On the **raw stored order** the dossier found 17 adjacent-equal trigrams and **no** distance-4 elevation (distance 1 = 17, distance 3 = 15, distance 4 = 10) [disputed as stated; confirmed false on raw data]. So the cipher analysis assumes the reading-order problem is already solved — which is itself only inferred. The polyalphabetic conclusion is plausible but rests on a stacked set of assumptions.

### 3.2 ~83 internal states estimate
**Produced:** "No fewer than 20 internal states and statistically probably at least around 88, so it is likely 83 internal states" (Toboter) [disputed].
**Assessment:** Internally muddled (states "≥88" then concludes "83", i.e. *below* its own lower bound) and likely **circular** — 83 is exactly the number of distinct glyph values, so "#states = alphabet size" may be assumed rather than measured [disputed].

### 3.3 Isomorphs + "Alphabet Chaining"
**Produced:** Lymm found ~6 isomorphic segments across the first three messages; codewarrior0 applied the classical "alphabet chaining" attack — and it **failed** for reasons nobody could explain. This failure is the main reason researchers are stuck [likely] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).
**Assessment:** Significant. Alphabet chaining relies on commutativity; its failure implies a **non-commutative** mechanism (see 3.5). The community openly hypothesizes plaintext/ciphertext **corruption** (wrong/transposed/missing letters) as an alternative explanation for why perfect isomorphs don't appear — an unfalsifiable-leaning escape hatch worth flagging [confirmed that this is hypothesized; speculative as an actual explanation].

### 3.4 Wheel / Alberti / incrementing-ring cipher
**Produced:** Pyry demonstrated isomorphs using an **autokey Alberti** cipher (rings rotate by an amount depending on the previous plaintext character) — as an *illustration of how isomorphs form*, not a solution. ngraham20's "incrementing cipher" (83-glyph outer ring, gapped plaintext inner ring, rotate one step per char) is the repo's primary active model, **unproven** [confirmed as proposed; speculative as solution] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages); [ngraham20](https://github.com/ngraham20/NoitaCryptographyResearch)).
**Assessment:** The live frontier. Note "Pyry" is **not** a verified Nolla developer (known team: Purho, Harjola, Teikari); treating Pyry's demo as an insider signal is unsupported [disputed].

### 3.5 Chaocipher / Hutton / S₈₃ permutation (non-commutative models)
**Produced:** Perseus observed that ciphertext symbols in non-shared sections never reappear in later shared sections (p≈0.192% if random), hypothesizing the key **permutes/swaps** after each character use. simplesmiler tied this to plaintext-driven permutation ciphers (Chaocipher "similar in spirit" but non-matching). A Group-Autokey/deck cipher over the symmetric group **S₈₃** (83-card deck) is a leading model; a Tolkien text was used as known-plaintext for testing, producing garbage [likely as direction; speculative as solution] ([Steam](https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/); Lymm GAK notes).
**Assessment:** The most theoretically promising family — consistent with the alphabet-chaining failure (non-commutativity). Still **no readable plaintext** has emerged. simplesmiler's framing that the right cipher may need to be "invented" is honest about the difficulty [likely].

---

## 4. Numeric / symbolic remapping theories

### 4.1 Runic (Elder Futhark) mapping
**Produced:** The 83 distinct values are displayed as 83 Elder Futhark runes (forward wheel and exact reverse) in ngraham20's repo [confirmed as a display choice].
**Assessment:** This is an **arbitrary researcher display mapping**, not runes found in the game. No source claims these runes appear in-game. The "key text cipher" extension — that trigrams index words from an 83+-word reference text, possibly the orb-temple runic text — is unverified community speculation [speculative] ([noita.fandom.com via search](https://noita.fandom.com/wiki/Eye_Messages)).

### 4.2 Atomic-number theory (lead 82 / gold 79)
**Produced:** Tested **inert** — ngraham20's TASKS.md notes mapping values to atomic numbers (82 = lead, the puzzle's max value) "makes no difference" [confirmed as tested-and-failed] ([ngraham20 TASKS.md](https://github.com/ngraham20/NoitaCryptographyResearch)).
**Assessment:** Thematically tempting (alchemy is core to Noita; 82=lead is the max trigram value), but produced nothing. Dead end [confirmed].

### 4.3 ASCII / alchemical-symbol renderings
**Produced:** ngraham20 publishes East-1 in ASCII and alchemical-Unicode forms alongside decimal/runic; these are **format conversions of the 0–82 values**, not decryptions [confirmed as display formats].
**Assessment:** Useful for visualization; no decoding value on their own. Easy to mistake for "output" — they are not [confirmed].

---

## 5. Geometric / signal-processing theories

### 5.1 3D / octahedron projection
**Produced:** Mapping eye sets onto 3D shapes (most often an octahedron, echoing the meditation-cube shape) to form letters. Results are "inconsistent" or only "vaguely resemble the Noita glyphs" [confirmed as tried-and-inconsistent] ([noita.wiki.gg](https://noita.wiki.gg/wiki/Eye_Messages)).
**Assessment:** Popular but **unsubstantiated**; no consistent output. Inconsistent with the isomorph/alignment constraints [likely failed].

### 5.2 PAM5 (5-level pulse-amplitude modulation)
**Produced:** Mapped 5 orientations to telecom 5-level PAM signalling (lastCoyotes' `subsetmap3dPam5`). **Publicly debunked** in a dedicated video titled "[Debunked] PAM5…" [likely debunked; repo has 1 star] ([YouTube](https://www.youtube.com/watch?v=TdHYTu99GZ4); [lastCoyotes](https://github.com/lastCoyotes/eyeGlyphs)).
**Assessment:** Low-engagement, debunked. The "[Debunked]" tag is the author's own; full refutation text wasn't retrievable, hence [likely] rather than [confirmed].

### 5.3 Binary encoding
**Produced:** No notable result. Binary readings appear in general "various methods tried" summaries but no source documents a specific binary decode that produced structure [speculative].
**Assessment:** Not a developed theory; mentioned only as part of "everything has been tried." The 5-orientation alphabet doesn't map naturally to binary, and the base-5 trigram model dominates. Treat as a non-starter [speculative].

### 5.4 Morse code / "diamond" patterns
**Produced:** A Fandom-sourced summary references "a pattern on the diamonds that resemble what could be Morse code" — tied to desert-ruins symbols (3 ovals, "¡!¡", a rhombus/diamond) some believe hint at the Eye Messages [speculative] ([Fandom via search](https://noita.fandom.com/wiki/Eye_Messages); [Mysteries and Oddities](https://noita.wiki.gg/wiki/Mysteries_and_Oddities)).
**Assessment:** Thin and **community-speculative**. No developer confirmation that the diamond/desert symbols relate to the eyes at all; the "Morse" resemblance is an unworked observation, not a decode. The wiki explicitly frames the desert symbols as "Some people believe…" lore [speculative].

---

## 6. Generation/structural theories (not decodings, but relevant)

### 6.1 Seed / coordinate determinism
**Produced:** Eye-message **locations** are seed-deterministic (mirrored X across parallel worlds); Lymm's Binoculars computes per-seed coordinates without running the game [confirmed for locations] ([gitlab](https://gitlab.com/realgonzogames/lymms-binoculars)).
**Assessment:** Solid for *placement*. The popular claim that the *content* is byte-for-byte identical across all seeds is **likely but unproven** — no primary source demonstrates cross-seed content invariance; Xkeeper0's transcoder hard-codes one fixed message set, which is suggestive but not a proof [likely].

### 6.2 Hex → base-7 generation pipeline as artifact source
**Produced:** The reproduced base-7 division pipeline (§intro) raises the possibility that some "structure" (e.g. parts of the 0–82 range) is an **artifact of the encoding pipeline**, not meaningful plaintext [speculative but testable].
**Assessment:** A legitimate skeptical hypothesis: feeding random plaintext through the same hex→base-7→trigram pipeline and re-running the range/isomorph analyses would show whether the anomalies are signal or artifact. Not yet done in the corpus [speculative].

### 6.3 East/West counterpart relationship
**Produced:** Counterparts are mirrored in **location**, not content. They share large leading trigram blocks (East1/West1 share a 24-trigram run; East4/West4 share 20) but diverge; East2/West2 share only 2. **All nine messages share the same first two trigrams [66, 5]** [confirmed; reproduced via SequenceMatcher].
**Assessment:** A real, under-appreciated structural fingerprint. The shared [66,5] prefix and the family clustering are strong evidence of deliberate construction and a probable header/state-initialization, and constrain any valid cipher model [confirmed as a data property].

---

## 7. "Music" theory — flagged as a non-result
**Claimed category in the brief; assessed honestly:** No credible Eye-Messages-specific **music/pitch** decoding theory was found. Noita's musical systems (Musical Curiosities, note spells, melody murals) are **separate mechanics** with no documented link to the eye glyphs [confirmed that the music systems exist; speculative-to-absent that any eye-glyph music theory exists] ([Note spells](https://noita.wiki.gg/wiki/Note_spells)). Any "the eyes are music" claim should be treated as unsupported lore until a method appears.

---

## 8. Debunked "solutions" and ARGs (not theories — cautionary)
- **feed4fun "i solved the eyes"** (Steam, Sep 2024): no method given ("no i wont tell you, kbye") — dismissed [confirmed empty] ([Steam](https://steamcommunity.com/app/881100/discussions/0/4852155152090234980/)).
- **FuryForged "mysterious emails" ARG** (early 2023) and the "OMG solved" tweet: **debunked**, produced no public method [likely] ([YouTube debunk](https://www.youtube.com/watch?v=hXEzoSyQlU4); [X](https://x.com/FuryForged/status/1642192647493173255)).
**Assessment:** These are illustrations of the wiki's no-method-no-belief rule, not encoding theories.

---

## Cross-cutting critical observations

1. **The reading-order problem is upstream of everything.** Nearly all cipher properties (no doubled symbols, distance-4 spike, isomorphs) are **conditional on the inferred reading order**, which is itself only one of 36/86,000 candidates selected by a contiguity criterion. On raw data, several of these properties **fail** [disputed-as-stated]. The cryptanalysis assumes a problem that is not actually solved.

2. **No developer confirmation that the eyes encode recoverable plaintext.** The wiki's "known to contain information" is the wiki's **own statistical inference**, not a Nolla/Petri Purho quote. The widely-repeated "developers confirmed it's solvable" traces to an **unsourced 2022 Hacker News intro line**, with no Discord screenshot, quote, or dated statement behind it [confirmed: the meta-claim is unsourced] ([HN](https://news.ycombinator.com/item?id=33929442)). Documented dev statements exist only for the *Cauldron Room* (Arvi, 2021) and *Orb-Room symbol* (Arvi/Antti/Olli denials) — **not** the eyes [confirmed] ([Mysteries and Oddities](https://noita.wiki.gg/wiki/Mysteries_and_Oddities)).

3. **A separate Noita cipher IS solved** — "The Cessation Cipher Quest" decodes to "SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE" — proving Nolla designs solvable multi-step ciphers, but this is **distinct** from the eyes and is not evidence the eyes are solvable [confirmed; do not conflate] ([noita.wiki.gg](https://noita.wiki.gg/wiki/The_Cessation_Cipher_Quest)).

4. **Echo-chamber / over-fit risk.** The entire technical corpus rests on ~4–5 analysts (Lymm, codewarrior0, Toboter, Pyry, Perseus) and a handful of repos/Google Docs. Independent reproduction beyond this group of the *cipher* findings (as opposed to the structural counts, which the dossier reproduced) is thin [confirmed as a risk].

**Bottom line:** The strongest, reproducible findings are **structural** (1036 trigrams, divisibility by 3, the [66,5] shared prefix, seed-determined locations, engine-hardcoded generation). The 0–82 anomaly is a **likely** signal of intentional structure but is order-dependent and carries genuine circularity risk. The **leading cipher direction** is a non-commutative, plaintext-driven permutation cipher (S₈₃/chaocipher-flavored, autokey/wheel), which is **plausible but unproven**. Every concrete decode attempt — substitution, Vigenère, trifid, Polybius, atomic numbers, octahedron, PAM5, morse, binary — has **failed or been debunked**. The puzzle is genuinely unsolved.
