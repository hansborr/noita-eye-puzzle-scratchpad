# crcscan default wordlist

`crcscan-default-wordlist.txt` is the bundled default dictionary for the
stored-u32 CRC/hash scanner. It is intentionally modest and static so the
false-alarm rate printed by `crcscan` is reproducible.

Provenance: hand-curated in-repository list assembled for this instrument from:

- Noita / Finnish-lore terms already under investigation (`lumikki`,
  `kolmisilma`, `sampo`, `hiisi`, `ukko`, wand/spell/alchemy terms).
- Common English words relevant to fairy-tale, puzzle, elemental, and game
  vocabulary.
- Common Finnish words transliterated to ASCII where needed.

The scanner reports the parsed dictionary size at runtime and uses that exact
line count in lambda. Blank lines and `#` comments are ignored by the loader;
the committed `.txt` file contains only one candidate word per line.
