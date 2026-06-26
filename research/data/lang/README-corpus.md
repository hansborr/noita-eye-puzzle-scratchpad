# Language corpora

Public-domain English text used to build language models for the solve engine.

## Files

- `english.txt` (3.1 KB) — small bigram-model sample used by the brief-04 solve
  pipeline / codec search. **Owned by the engine-spine track; do not alter** (its
  exact bytes pin reported scoring numbers).
- `finnish.txt` (2 KB) — small Finnish sample (Noita is a Finnish game).
- `english-corpus-large.txt` (~1.48 MB, ~1.12 M letters) — larger corpus for the
  **quadgram** language model behind the polyalphabetic *keystream* cracker
  (letter puzzles `three`/`four`/`five`/`seven`). Bigram-on-3 KB is far too weak
  to guide a key search; a quadgram model needs real volume.

## Provenance of `english-corpus-large.txt` (reproducible)

Concatenation of three public-domain works from the GITenberg mirror:

| Work                              | GITenberg id |
| --------------------------------- | ------------ |
| Pride and Prejudice (Jane Austen) | 1342         |
| Alice's Adventures in Wonderland  | 11           |
| The Adventures of Sherlock Holmes | 1661         |

Regenerate with:

```sh
OUT=research/data/lang/english-corpus-large.txt
: > "$OUT"
for u in GITenberg/Pride-and-Prejudice_1342/master/1342.txt \
         GITenberg/Alice-s-Adventures-in-Wonderland_11/master/11.txt \
         GITenberg/The-Adventures-of-Sherlock-Holmes_1661/master/1661.txt; do
  curl -sL "https://raw.githubusercontent.com/$u" >> "$OUT"
done
```

The model builder normalizes at load (keeps letters, folds case), so the raw
files (including each work's Project Gutenberg header/footer) are committed
verbatim for honest provenance rather than pre-stripped.
