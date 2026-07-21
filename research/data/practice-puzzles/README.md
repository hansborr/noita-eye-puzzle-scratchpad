# Practice puzzles

These external ciphertexts are the workbench's validation suite. Each is believed
to be decryptable to English, and some solutions can be checked independently.
They let us measure whether an attack recovers a planted or withheld answer
before applying the same method to the Noita eyes.

## Claim discipline

- A structural pattern or high language score is a **candidate**, not a decode.
- A negative applies only to the cipher family, conventions, bounds, language,
  and optimizer power that were actually tested.
- A fixed, non-fitted decoder with exact ciphertext replay can verify a decode.
  If the output table or relabeling was fitted to the same ciphertext, replay is
  only an implementation invariant.
- Withheld-plaintext confirmation can establish a practice-puzzle solve without
  publishing the ground truth. It does not imply recovery of the original key,
  generator, punctuation, or every encoding layer.

## Inventory and current status

| File | Size / alphabet | Verified structure | Status / interpretation |
| --- | --- | --- | --- |
| `one` | 266 digits, `0..4` | every transition is ±1 on C5 | **verified decode:** `Permutation Representation Destination`; alternating orientation + 7-bit ASCII; exact 266/266 replay |
| `two` | 698 symbols, `A..L` | every transition changes mod-3 block; long pattern-isomorphic repeats | **maintainer-confirmed plaintext:** full-symbol group-shadow attack plus monoalphabetic finish; original-generator round trip unavailable |
| `three` | 142 letters/punctuation | spaces and sentence structure preserved; flat whole/per-period IoC | bounded letter-cipher batteries negative; aperiodic/position-keyed family remains open |
| `four` | 128 letters/punctuation | spaces, punctuation, and lines preserved; flat whole/per-period IoC | bounded letter-cipher batteries negative; shortest and weakest-powered Ragbaby case |
| `five` | 281 letters/punctuation | spaces and sentence structure preserved; flat whole/per-period IoC | strongest calibrated letter-cipher negatives; weak running-key lead remains |
| `six` | 3 × 139 digits, `1..6` | three relabelings of one legal cube-face walk | **exact candidate:** `CUBE IS A GREAT TOY MODEL OF NON-COMMUTATIVITY.` via cube rolls → Morse; first-mark ambiguity remains |
| `seven` | 164 letters/`#`/punctuation | word structure preserved; flat whole/per-period IoC | bounded letter-cipher batteries negative; `#` as an Alberti index remains open |
| `deck-swap/` | 8 known-plaintext messages at 1–3 swaps | S83 GAK deck cipher with controlled top swaps | known-plaintext swap-recovery proving ground; see `../../handoff/gak-swap-recovery/` |

The fixture files are read-only research inputs. `one` and `two` are
byte-identical to the earlier temporary samples called `gak_cipher_example` and
`gak_example_two`.

## Where to read next

| Question | Canonical record |
| --- | --- |
| How were `one` and `two` solved, and what was the 3.1M-key search? | `CODEC-RESULTS.md` |
| What exactly supports the cube/Morse reading of `six`? | `SIX-RESULTS.md` |
| Which Vigenère/Beaufort/autokey bounds were searched? | `KEYSTREAM-RESULTS.md` |
| How strong is the general-Ragbaby negative? | `RAGBABY-RESULTS.md` |
| Which position-polynomial shifts were exhausted? | `POLYSHIFT-RESULTS.md` |
| What was frozen and confirmed for `two`? | `TWO-WITHHELD-CONFIRMATION-FREEZE.md` |
| What reusable mistakes did these attacks reveal? | `../../attack-methodology.md` |

For `two`, the detailed group-reconstruction and shadow-key mechanics are in
`../../handoff/two-cross-agent-recon.md`; the confirmed finishing result and its
claim ceiling are in
`../../findings/two-shadowfinish-substitution-candidate.md`.

## Letter-puzzle bounds at a glance

For `three`, `four`, `five`, and `seven`, the current evidence excludes only the
tested surfaces:

- monoalphabetic substitution and periodic polyalphabetic structure through
  period 40 by IoC/profile diagnostics;
- bounded simulated-annealing runs for Vigenère, Beaufort, plaintext-autokey,
  and ciphertext-autokey at key lengths 1..20, plus `five` at 40;
- keyword Ragbaby and the calibrated heuristic general-Ragbaby runs;
- long-primer ciphertext-autokey for lengths 1..60;
- degree-at-most-two position-polynomial additive/Beaufort shifts in the exact
  35,152-cell `polyshift` grid.

These are not blanket proofs against arbitrary long keys or every aperiodic
polyalphabetic cipher. The weak, non-surviving running-key signal on `five` and
`seven`'s `#` as a possible explicit index marker remain distinct open leads.

## Provenance

The maintainer gathered these samples on 2026-06-25 as external recovery tests.
The private plaintext for `two` remains uncommitted; only its post-freeze
confirmation status is recorded here.
