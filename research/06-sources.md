# Sources

57 unique sources collected and deduplicated by URL during the research workflow. Grouped by type; these are the raw references behind the findings — confidence tags in the other documents indicate how much weight each source can bear.

## language-model calibration samples

- `research/data/lang/english.txt` — Excerpt from Lewis Carroll, *Alice's Adventures in Wonderland*, Chapter I. First published in 1865, so the source work is public domain in the United States because it was published before 1929. Used only to train the bundled English n-gram language model; it is not eye-glyph evidence.
- `research/data/lang/finnish.txt` — Excerpt from Elias Lonnrot, *Kalevala*, First Poem / *Ensimmainen runo*. The expanded *Kalevala* was first published in 1849 and Lonnrot died in 1884, so the source work is public domain in the United States and in life-plus-70 jurisdictions. Used only to train the bundled Finnish n-gram language model; it is not eye-glyph evidence.

## ai-generated encyclopedia (unreliable for this claim)

- [Noita (video game) — Grokipedia](https://grokipedia.com/page/Noita_(video_game)) — Source of the 'developers have confirmed ... encode meaningful content' phrasing. AI-generated; no primary citation located for the dev-confirmation claim. Treat as unsourced synthesis.

## blog

- [dextercd/Noita-Wak-Extractor + 'Decrypting Noita's files' (Dexter Döpping, LinkedIn)](https://www.linkedin.com/pulse/decrypting-noitas-files-dexter-d%C3%B6pping) — Firsthand RE narrative: file/ent entropy 7.999, Ghidra+GDB, recreated AES, found secrets_secrets_secrets.png inside data.wak. Independently corroborates AES on data.wak. LinkedIn body not directly fetched here; corroborated via search.

## blog/secondary

- [Noita Eye Glyph Messages — techhenzy.com](https://techhenzy.com/noita-eye-glyph-messages/) — New secondary writeup; page only returned 'Loading...' on fetch. Indexed as containing the hex→base5 / EyePositionNumeric material; treat as derivative of the wiki.

## code/research repo

- [ngraham20/NoitaCryptographyResearch — README (raw)](https://raw.githubusercontent.com/ngraham20/NoitaCryptographyResearch/master/README.md) — Most valuable machine-readable dataset found: contains the full east1 message in five synchronized representations — base-5 'plain' trigrams, decimal (0-82), ASCII, runic (Elder Futhark, 83-glyph wheel), and alchemic symbols. I verified the base-5->decimal conversion matches exactly (99/99) and all values <=82. States simple substitution ruled out by frequency analysis; explores wheel/incrementing ciphers. Repo created 2021-10-06, last push 2021-11-03. Python/Rust/Lua.
- [SirCapybar/NoitaEyeGlyphResearch — README (raw)](https://raw.githubusercontent.com/SirCapybar/NoitaEyeGlyphResearch/master/README.md) — C# trigram analysis tooling (TrigramCollection/TrigramLineCollection/TrigramProvider/Statics): index of coincidence, frequency analysis, Vigenere/Caesar, diamond cipher, polybius cube, trifid ('useless here'). Links the same primary Google Doc + Sheet + author's personal notes doc (1CT4VW_A20peJBt49F93sQEbnrYogcnO_igvjAtzYpyo). Author 'sir.capybar', Discord eye room 'silma-houne'. Repo created 2021-07-03, last push 2023-09-01 — still 'unsolved for years now.'

## community tool/blog

- [jasper-r.github.io/noita-eye-shooter](https://jasper-r.github.io/noita-eye-shooter) — A 'joke' bubble-shooter prototype themed on the eyes; describes the messages as unsolved and notes a past claimant 'never showed the solution or proof they had solved it at all.' Not a decoder; no reading-order data.

## developer talk (video)

- [One of the devs (Hempuli) speaking about the secrets in Noita — YouTube](https://www.youtube.com/watch?v=ItzQh6K3hP8) — Arvi Teikari (Hempuli), Nolla Games, at Roguelike Celebration discussing Noita's unsolved mysteries. Strongest available developer-intent signal. Transcript not retrievable via fetch; no verbatim 'intentional puzzle' quote captured.

## devlog

- [Noita 1.0 Release Date — Nolla Games (itch.io devlog)](https://nollagames.itch.io/noita/devlog/180795/noita-10-release-date) — Primary dev devlog confirming the 1.0 date (15 Oct 2020). Does not mention eyes — useful only to anchor the timeline, not the eye-shipping claim.

## document

- [CodeWarrior0 — Noita Eye Glyphs: Analytical Overview (Google Doc)](https://docs.google.com/document/d/1QeagH8TklJsd8iribMtT5LIRL91laOUU_tFcVl7OOqA/edit) — **Read firsthand 2026-06-29** via the `/export?format=txt` endpoint (the earlier "needs browser" note was wrong: the doc is link-shared and exports as text). A LANAKI/Friedman-structured cryptanalysis of the 83-symbol/1036-letter base-5 trigram corpus: frequency flat & not monoalphabetic; ciphertext not periodic; same-position letters across messages likely enciphered by different alphabets; isomorph segments in the first three messages. Carries per-message IoC + unique-letter counts, a full Kasiski repeat census, three Kappa tests (validated against a Toboter periodic-homophonic positive control), the ciphertext-autokey "base-letter"/running-sum model with the `M+N=E+I` convergence constraint, and the isomorph-via-constant-key-difference theory. Emits no decode ("To be continued"). Full firsthand ingest in `findings/community-docs-firsthand-digest.md`.
- [Lymm — Eye Message Alignments and Gap Patterns (Google Doc)](https://docs.google.com/document/d/12sCi3OrTuy4PPcu3zUykue7suHvAPyK-uFKcm8Rp4Go) — Color-coded image of ciphertext alignments and gap patterns; alignments = letter groups at the same position across messages. Browser-only.
- [Toboter — Noita Eye Glyphs 'Progress' (Google Doc, header dated 28.12.2025)](https://docs.google.com/document/d/1XMNXktCoSabnFWZf9rJFoaKMzsA1bbv7x1Xh9tXkKYk/edit) — **Read firsthand 2026-06-29** via `/export?format=txt` (was previously mis-tagged "Browser-only" with a stale 2024-01-25 date; the live header reads 28.12.2025). The community's master collation: polyalphabetic; ciphertext-char depends on more than a single plaintext char; large shared sections; the ~86,000 reading-order test; the full GAK/6-group/S₈₃ apparatus. Plus ~20 granular named micro-observations not previously ingested (the CRC-32("lumikki")=`0xacf68674` claim, starting-trigrams >26, abab message-sums, several ruled-out modular forms, Lymm's pattern strings) and a long dead-end catalog. Full firsthand ingest in `findings/community-docs-firsthand-digest.md`.
- [Lymm (attrib.) — "Why 83?" (Google Doc)](https://docs.google.com/document/d/1H3dpTLw8oE5TGQLsjQEk4O9tT8B106N93AH1e5-ag2c/edit) — **Read firsthand 2026-06-29** via `/export`. Argues 83 is the largest *prime* modulus M<125 whose max value 82 writes as three base-5 digits that are distinct, nonzero, and not 4 — the six qualifying permutations of {1,2,3} giving moduli {39,43,59,67,83,87} — making the reading order recoverable without datamining. **Not** the same "6" as the repo's transitivity six-groups (those are permutation groups; these are moduli). Supplies the leading-trigram-digit histogram {317,312,310,97,0} (= the `25+25+25+8=83` decomposition, verified) and a `~10⁻³³` contiguity figure; closes with speculative numerological 83-hints. Ingest in `findings/community-docs-firsthand-digest.md`.
- ["83 Occurrences" (Google Doc; maintainer-labeled "Luc / 83 & 23")](https://docs.google.com/document/d/1lrPlAJH8jCa1mSDV2uGUiMEFxt-81lrgC3U_IRX_G9c/edit) — **Read firsthand 2026-06-29**. A numerology catalog of where the number 83 appears in Noita (83 liquids, 83 gun names, 83% modifier chance, Kolmi `1660=20·83`, 83×26 blood pool, blood `#830000`, blurhash base-83, …). Only its first line (83 distinct trigram values) is structural; the rest is coincidence-hunting → [speculation]. **Contains no "23" and no author "Luc"** — the maintainer's "83 & 23 connection" label is a mismatch (its only 83-paired numbers are 26 and 20).
- [defektu — "Noita – Community Tools / Decrypting Tools" (Google Doc, 2022-12-01)](https://docs.google.com/document/d/1oSY46-WCmytHvI-BtD0X2UkGX6jg9DFJ9oeFGsMKd1g/edit) — **Read firsthand 2026-06-29**. A date-sorted directory of generic decryption tools (AZdecrypt, CryptoCrack, CyberChef, quipqiup, dCode, Ciphey, CrypTool) plus ~25 named community eye/cauldron tools by author handle (tomster12's Eye Web Analyzer, ZeroPoint's LymmPatternScanner, Joanie's NoitaEyeCipherTools, …). Target URLs are hyperlinks not preserved in text export; resolve in-browser. Tool list captured in `findings/community-docs-firsthand-digest.md`.

## document (community progress doc copy)

- [Noita Eye Glyphs Progress — Course Hero](https://www.coursehero.com/file/226068863/Noita-Eye-Glyphs-Progress-pdf/) — HTTP 403 / login-walled. Title indicates it is the community Progress document. Not directly fetchable; corroborates existence of a structured progress doc.

## encyclopedia

- [Noita (video game) — Wikipedia](https://en.wikipedia.org/wiki/Noita_(video_game)) — Background on Noita, Nolla Games / Petri Purho, and the ongoing data-mine-resistant unsolved mystery.

## forum

- [An Esoteric Unsolved Puzzle: The Noita Eye Messages — Hacker News (Svelte mirror)](https://hn.svelte.dev/item/33929442) — Sole origin of the 'developers have confirmed that it is solvable' claim. Verbatim line: 'The developers have confirmed that it is solvable, but it would be great to get more... eyes... on possible solutions.' No primary dev citation given. This unsourced intro line is what snowballed into accepted lore.
- [Hacker News original item 33929442](https://news.ycombinator.com/item?id=33929442) — Canonical HN URL (returned HTTP 429 on direct fetch). Same 2022 submission; comments not retrievable here. Use the Svelte mirror for the body text.
- [Hacker News thread referencing the Noita eye messages](https://news.ycombinator.com/item?id=47532922) — Surfaced in search as a discussion calling the eye messages 'a great read'; rate-limited (HTTP 429) on fetch, not extracted. Low priority / corroborative only.
- [i solved the eyes :: Noita General Discussions — Steam](https://steamcommunity.com/app/881100/discussions/0/4852155152090234980/?l=english) — feed4fun, 2024-09-20: 'i solved the eyes... no i wont tell you, kbye.' No method; dismissed by community citing the wiki's 'should not be believed' line. No dev response.
- [Steam discussion: 'Eye Messages discovery(?)' — Perseus analysis](https://steamcommunity.com/app/881100/discussions/0/4700161534027181070/) — Perseus (Oct 2024): characters in non-shared sections never appear in later shared sections of size 2+ (chance ~0.192%, 0.227% adjusting for no doubles); hypothesis that a ciphertext char's key position swaps on use. Disputes that the 0-82 order is 'proven'; says all six symmetrical reading orders yield 83 distinct trigrams and at least one is correct. simplesmiler (Aug 2025) ties this to plaintext-driven alphabet permutation, chaocipher/Hutton, non-commutative permutation groups, possible S83.
- [Steam discussion: 'i solved the eyes'](https://steamcommunity.com/app/881100/discussions/0/4852155152090234980/) — Example of an empty solution claim ('no i wont tell you, kbye') — no method, no plaintext, dismissed by community. Useful as a concrete instance of the 'distrust methodless claims' disclaimer.

## github

- [codewarrior0/noita-eye-glyph-analyses](https://github.com/codewarrior0/noita-eye-glyph-analyses) — New find (not in survey). Python analysis suite: data.py, simple_freq.py, isomorphs.py, repeats.py, stat_period.py, superimp_positional.py, autokey_decrypt.py, autokey_superimp.py, gamelore.py, tests.py, docs/. Companion to CodeWarrior0's 'Analytical Overview' Google Doc. Investigates autokey + positional/isomorph structure. Strong cryptanalysis primary.
- [Lymm's Binoculars — Python seed->coordinate finder (GitLab)](https://gitlab.com/realgonzogames/lymms-binoculars) — README (raw at /-/raw/main/README.md) confirms: Python script that, given a seed, returns that seed's eye-message coordinates. 'All credit goes to Lymm.' numpy dependency. Web port by Chillie at chillie-ilya.github.io/lymms-binoculars-web/.
- [ngraham20/NoitaCryptographyResearch — repo root](https://github.com/ngraham20/NoitaCryptographyResearch) — C# tooling per survey but actual repo is Python 65% / Rust 31% / Lua 3%. Covers Eye and Cauldron ciphers; 83-symbol output; trigram decode to 0-82; wheel-cipher model. Status: unsolved.
- [SirCapybar / Doctor-Ned NoitaEyeGlyphResearch](https://github.com/SirCapybar/NoitaEyeGlyphResearch) — C# (100%) trigram cryptanalysis toolkit. Classes: TrigramCollection (one message), TrigramLineCollection (all 9), TrigramProvider, Statics. Implements index of coincidence, frequency analysis, Vigenere/Caesar (text + trigrams), diamond cipher, trifid ('useless here, btw'), polybius cube. Links three Google docs: 'Noita Eye Glyph Messages' (intro), 'Noita Eye Data' (sheet), 'Capybar#6875: Noita eye room research' (trials/errors). No solution; self-described 'unsolved for years now.'

## github gist (primary artifact: reproduces engine decode)

- [Noita eye transcoder (PHP) — Xkeeper0 GitHub Gist (raw)](https://gist.githubusercontent.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8/raw) — Full code retrieved verbatim (created 2021-04-29). U32_MAX=4294967296; 9 messages as [u32,u32] pair arrays; array_reverse; 64-bit combine; base-7 divide/modulo; emit (a%7)-1 in -1..5, 5=newline; output reversed. Message 0 = 14 pairs, first pair [0x5634505c,0xacf68674]. This is the canonical ground-truth ciphertext + engine decode procedure.

## github repo (cryptanalysis, source of 86k brute force)

- [ToboterXP/EyeGlyphs (GitHub, Python, GPL-3.0)](https://github.com/ToboterXP/EyeGlyphs) — Files incl. noitaGlyphs.txt, isomorphs.txt, cauldron data/, english_bigrams/trigrams/quadgrams, finnish_trigrams, essenceroom_visual.png, translateddiamond.png, alphabet/finnish/wheel/transposition hill-climbers. archive/eyeGlyphs-trigram order bruteforce.py = the ~86,000 reading-order test cited by wiki.gg.

## github repo (pam5 / 3d theory, low engagement)

- [lastCoyotes/eyeGlyphs (GitHub, Python)](https://github.com/lastCoyotes/eyeGlyphs) — Python, 1 star/7 commits. main.py + subsetmap3dPam5.txt. The 3D-projection/base-5/PAM5 family. Undocumented; associated PAM5 theory was publicly 'debunked'.

## github repo (python prototype)

- [Azertinv/cipher_bruteforcer (GitHub, Python)](https://github.com/Azertinv/cipher_bruteforcer) — Prototype for bruteforcing unknown ciphers (frequency, repeats, gapped pairs, isomorphic matching, rotational/substitution/Vigenere). README: 'results were positive so a rewrite in rust is underway' -> cipher_fuzzer.

## github repo (search-based cipher fuzzer)

- [Azertinv/cipher_fuzzer (GitHub, Rust)](https://github.com/Azertinv/cipher_fuzzer) — Rust 100%. Composes Shift/Scramble/Indexer/Repeater/Ciphertext-Autokeyer/Progressor; scores vs letter uniformity, index bounds, isomorph counts, periodic IoC. Successor to cipher_bruteforcer. No solution; notes local-minimum risk.

## github/technical

- [SirCapybar / NoitaEyeGlyphResearch README (GitHub)](https://github.com/SirCapybar/NoitaEyeGlyphResearch/blob/master/README.md) — C# tooling: Vigenere/Caesar (text+trigram), diamond, trifid, Polybius cube, IoC, frequency analysis. Verbatim 'trifid cypher (which is useless here, btw)'. Detailed trial/error log lives in the author's private Google Doc, not the repo. No raw glyph value tables in README.

## guide

- [Symbols, Glyphs, Cryptography — Noita Steam Guide (id 3281214266)](https://steamcommunity.com/sharedfiles/filedetails/?id=3281214266) — Solved vs unsolved catalog. Decoded examples: 'SEEKTHEEND', 'REFRESHIMG' (sic), 'BRING THE TREASURE HERE', 'NOT A MIMIC', 'we are watching you'; Orb-Room = Finnish creation myth. Eyes called 'the biggest unsolved mystery in Noita right now'. Lymm's rotated-magic-circle / stacked-zeros reading-direction idea.

## official site (primary; troll redirect)

- [noitagame.com/for_the_seekers_of_truest_of_knowledge (official Nolla)](https://noitagame.com/for_the_seekers_of_truest_of_knowledge/) — WebFetch returned HTTP 302 -> youtube.com/watch?v=oHg5SJYRHA0 (Rickroll). Direct primary evidence of Nolla's anti-datamining humor.

## personal blog (primary; re'er identity)

- [Ninji (wuffs.org) — game reverse-engineering blog](https://wuffs.org/blog/reversing-games-with-hashcat) — Confirms 'Ninji' = @_ninji, a game reverse-engineer (Splatoon etc.), the person who did the Noita Ghidra disassembly — distinct from 'ghidraninja'/stacksmashing.

## primary research doc

- [Noita Eye Messages (primary research Google Doc, maintained by @Xkeeper; RE by @Ninji; save from FuryForged)](https://docs.google.com/document/d/1s6gxrc1iLJ78iFfqC2d4qpB9_r_c5U5KwoHVYFFrjy0/edit) — The foundational primary source. Retrieved full text via /export?format=txt. Contains: full raw glyph sequences for all 9 messages (Message 0=East1 ... Message 8=East5), the 0-4 + '5=newline' coding, the engine-hardcoded/no-sprites/not-Lua claim verbatim, spawn conditions, the mod-flag bypass (hex patch offset 1af745; world_state.xml mods_have_been_active_during_this_run), the The_Duck1 trigram proposal, the 000-312 (=0-82) / 83-of-125 result, and ASCII (c+32) renderings. Last substantial update 2021-03-25. Companion Sheet (195Rtc8kj4b74LtIyakqGP-iHhm36vyT5i8w7H5JjOV8) just points back to this doc.

## repository

- [jpalacios84/noita-eye-puzzle — GitHub](https://github.com/jpalacios84/noita-eye-puzzle) — 'Attempts at unsolved puzzle (as of December 2022).' Jupyter notebooks, encoded_text*.txt, messages.csv, lymm_cipher.txt. README body not retrievable here; no dev-confirmation surfaced.
- [Lymm37/noita-telescope — GitHub](https://github.com/Lymm37/noita-telescope) — Lymm's web-based Noita seed analyzer; relevant to seed-deterministic eye placement / 'Why 83?' work attributed to Lymm.

## secondary doc (unverified)

- [Noita Eye Glyph Messages — Scribd (uploaded by glooko.pro, 13 pages)](https://www.scribd.com/document/911932819/Noita-Eye-Glyph-Messages) — Third-party explainer. A search snippet attributes to it the claim that messages are 'written originally in Hexadecimal' then algorithmically converted to 0-5 — a claim not supported by the authoritative primary doc. Body not retrievable (paywall/login). Treat as low-trust.

## social

- [FuryForged on X: 'OMG the Noita eyes have been solved! Video coming ASAP!'](https://x.com/FuryForged/status/1642192647493173255) — New. Primary FuryForged post (Apr 2023) tied to the ARG hype that was later debunked.
- [FuryForged — 'OMG the Noita eyes have been solved!' (X/Twitter, Apr 2023)](https://twitter.com/FuryForged/status/1642192647493173255) — High-profile 2023 hype tweet that did not result in a public, reproducible eye-message solution. Example of a popular 'solved' claim lacking a primary, verifiable method. FuryForged is independently credited with providing the save file used in the engine reverse-engineering.
- [Ninji (@_Ninji) — Noita reverse-engineering tweets](https://twitter.com/_Ninji/status/1252617459292659719) — Cited origin of the Ghidra reverse-engineering of the eye-generation function (~60 MB project). Not directly fetched/verified here (Twitter not accessible to WebFetch); the attribution and 60 MB figure are second-hand via Fandom and search index.

## spreadsheet

- [The Emerald Tablet — Noita Documents Directory (Google Sheet, by .gonzo.)](https://docs.google.com/spreadsheets/d/1Aih_3v9BMbVI-MQQgWP51HTTplgRwXi2jRKYgyhPMao/edit) — **Read firsthand 2026-06-29** via `/export?format=csv`. **Correction:** it does *not* hold raw per-message data (the prior "likely holds full per-message raw data" note was wrong); it is the community's master **link directory** — sectioned Name/Description/User/Date rows pointing to analysis docs, code/datasets/tools, hypotheses, Cauldron-Room work, and the Cessation Cipher. The raw data lives in the docs it links (e.g. "Raw Eye Messages Data" 2021-02-06, Nemare's decimal "Eye Values"). Highest-value uncatalogued leads it surfaces: independent C++ and JS ports of the datamined generation function; RmVw's "Eyes – Vigenère Theory"; 7Soldier's 2025 per-message frequency analysis; CodeWarrior0's "Isomorphism in Classical Ciphers". (Link targets are cell-hyperlinks not present in CSV export; resolve in-browser. Distinct from the SirCapybar-linked 'Noita Eye Data' sheet 195Rtc8kj4b...)

## technical_doc

- [Reversing data.wak — noita-player/noitadocs Wiki (GitHub)](https://github.com/noita-player/noitadocs/wiki/Reversing-data.wak) — Gives wak_header {unk0, unk1, file_list_size, unk2} (16 bytes), file_list_entry {offset, size, path_len, path}, the 0x165EC8F constant (j_get_16_bytes_random(...,0x165EC8F)), per-file seed = file index, and the note 'they AES encrypt the integer 123 (0x7b) when constructing WizardPak' (a constructed value, not the key seed). Hedges OFB vs CTR. Credits 'research server, feet crew discord' — does not name Ninji for this work.

## tool

- [Doctor-Ned/NoitaEyeGlyphResearch (SirCapybar) — GitHub](https://github.com/Doctor-Ned/NoitaEyeGlyphResearch) — Primary community transcription. data.csv holds raw 0-4 eye values for all 9 messages (East 1-5, West 1-4). I downloaded it and verified: divisibility by 3, total 1036 trigrams, unbroken 0-82 / 83 distinct values, and the East/West counterpart shared-block structure. TrigramProvider.cs documents the trigram glyph geometry (1 2 /6\ 7 8 over 3 /5 4\ 9) and 26 trigrams per line. C# library with Vigenere/Caesar/diamond/trifid/polybius/IoC tooling. Links to Google Docs data sheets.
- [isJuhn/UnWak — GitHub](https://github.com/isJuhn/UnWak) — Primary-grade C# implementation. WakTypes.cs: Constants wak_key_seed=0, wak_header_IV_seed=1, wak_filetable_IV_seed=2147483646. WakDecryptor.cs: GenerateIV adds 0x165ec8f, per-file IV uses file index i; little-endian reads of num_files@4, files_offset@8. Aes128CounterMode.cs implements AES-128 CTR (ECB+counter+XOR). WakRng.cs is Park-Miller/MINSTD (mult 16807, mod 0x7FFFFFFF, scale 4.656612875e-10 = 1/2^31). This is the strongest contradiction of the 'seed 123' and 'OFB' claims.
- [RidgeX — Noita .salakieli/.wak file unpacker (GitHub Gist)](https://gist.github.com/RidgeX/e159bb7df97b2e18209aea2804a79d7a) — Python unpacker for both formats. data.wak: AES.MODE_CTR, derive_key(0) master key, derive_key(index) per-entry IV, header decrypted with index 1, TOC '<II' (toc_count, toc_size) at header[4:12], entries '<III' (offset,size,filename_len)+name. .salakieli: literal passphrase key/IV pairs incl. 'KnowledgeIsTheHighestOfTheHighest'/'WhoWouldntGiveEverythingForTrueKnowledge'. Reconciles the encryption picture.
- [zatherz/wpak — GitHub](https://github.com/zatherz/wpak) — LuaJIT packer/unpacker on the LuaWAK lib. wak.lua read_toc parses {int offset, int length, int path_length, char path[]}; header read skips 4 bytes, reads num_files + toc_size, skips 4 (16-byte header). Notably this bundled wak.lua does not perform AES in the file I read — it reads the TOC as plaintext, suggesting it operates on already-extracted/repacked archives or relies on Noita's own unpack; the crypto lives in the separate LuaWAK/luawak repo, not the snippet I inspected. Commands: pack/unpack/list.

## video

- [[Debunked] Could these mysterious emails help SOLVE the Noita eye glyph puzzle? — YouTube](https://www.youtube.com/watch?v=hXEzoSyQlU4) — New. Debunk of the FuryForged 'mysterious emails' ARG (~Jan 11 2023). Transcript not fetchable.
- [[Debunked] PAM5 theory — YouTube](https://www.youtube.com/watch?v=TdHYTu99GZ4) — Dec 2022. '[Debunked]' in title by examiner. Maps 5 orientations to telecom PAM-5 levels. Only title retrievable; treat debunk as likely-but-not-fully-verified-from-primary.
- [The Eyes: Noita's Strangest Unsolved Mystery — YouTube](https://www.youtube.com/watch?v=q4o8Q252450) — New. Popular overview of the unsolved eye puzzle; useful for community-narrative context.
- [The Rise And Fall Of The Noita Eye Mystery ARG — YouTube](https://www.youtube.com/watch?v=hmOzG9dkPJQ) — New. Narrative retrospective on the FuryForged eye-mystery ARG. Transcript not fetchable; used for ARG framing only.

## wiki

- [Cauldron Room — The Noita Wiki](https://noita.wiki.gg/wiki/Cauldron_Room) — Source for the better-attributed 2021 'Arvi' remark to not be too concerned about the cauldron — the closest dev statement on the cauldron. (The eyes are no longer in total dev silence either: the same 2021 Arvi stream contains an eye-specific confirmation — see `findings/community-docs-firsthand-digest.md`.)
- [Eye Messages — Noita Wiki (Fandom)](https://noita.fandom.com/wiki/Eye_Messages) — Source (via search snippets; 403 on direct fetch) for the directional digit mapping (0 neutral,1 up,2 right,3 down,4 left;5=line break) and the engine-rendered/no-sprites/not-Lua/can't-extract claim. Mirrors the primary doc and noita.wiki.gg.
- [Eye Messages — The Noita Wiki (noita.wiki.gg)](https://noita.wiki.gg/wiki/Eye_Messages) — Primary community reference. Verbatim source for: 5 East/4 West; max 39 eyes/row + offset rows; base-5 trigrams 0-124; '36 possible standard reading orders, only one produces unbroken 0-82'; (83/125)^1036 = 5.8362007929568295e-185; spawn conditions incl. background_cave_02.png; seed 1249563923 coordinate table; cryptanalysis attributed to Toboter (polyalphabetic, ~83 internal states, key constant across messages) and CodeWarrior0 (flat frequency, aperiodic, no doubled letters, distance-4 anomaly).
- [Mysteries and Oddities — The Noita Wiki](https://noita.wiki.gg/wiki/Mysteries_and_Oddities) — Verbatim: 'Among the most popular unsolved mysteries are the Eye Messages and Cauldron Room.' Distinguishes the decorative three-eye motif (tutorial stones, Mestarien mestari robes) from the encrypted Eye Messages. Does not explicitly rank them as 'the two mod-free secrets.'
- [Technical: File Formats — The Noita Wiki (wiki.gg)](https://noita.wiki.gg/wiki/Technical:_File_Formats) — Current spec: WizardArchive {le u32 version; le u32 file_count; le u32 first_file; padding[4]; WakFile[]} and WakFile {le u32 offset; le u32 size; le u32 name_len; char name[]; char data[] @ offset}. Little-endian. Notes .salakieli = AES128-CTR. -wizard_unpak flag extracts assets. (This page's data.wak struct does not itself flag encryption; the gist/UnWak/Döpping establish that data.wak file contents are AES-128-CTR.)
- [Technical: Noita PRNG — The Noita Wiki](https://noita.wiki.gg/wiki/Technical:_Noita_PRNG) — Adjacent primary on how Noita's seed PRNG works; relevant to understanding how the hex pairs feeding the eye generator are derived. Not deeply inspected here.

## wiki (secondary, dev-behavior context)

- [Noita Trivia — TV Tropes](https://tvtropes.org/pmwiki/pmwiki.php/Trivia/Noita) — 34-orb ending loads a QR code -> noitagame.com 'seekers of truth' page -> Rickroll; hidden 'So long and thanks for all the fish!' message. Evidence Nolla trolls dataminers — context for skepticism toward 'dev confirmation' lore.

## wiki/primary-community

- [The Cessation Cipher Quest — The Noita Wiki](https://noita.wiki.gg/wiki/The_Cessation_Cipher_Quest) — New. A separate, fully solved Noita cipher ('Mr. Olli's Wild Ride'): 8 steps, six glyphs→digits, merged images, community-cracked 30-bit key, ASCII result 'SEEKING TRUTH, THE WISE FIND INSTEAD ITS PROFOUND ABSENCE'. No mention of Eye Messages. Proves Nolla design solvable ciphers but is not the eyes.
