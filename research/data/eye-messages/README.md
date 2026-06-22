# Eye-message verification inputs

Vendored on 2026-06-22 for Experiment 0 and Experiment 3 reproducibility.

- `ng_eyes.json`: upstream rendered transcription from
  <https://github.com/ngraham20/NoitaCryptographyResearch>, file
  `eye/eyes.json`. Digits `0`-`4` are rendered eye orientations; `5` is a
  non-rendered row delimiter.
- `xk_eye.php`: upstream engine transcoder from
  <https://gist.github.com/Xkeeper0/a6eda18571ef889be291822c400cc6c8>. It holds
  the decompiled-engine `[low32, high32]` integer pairs and the base-7 decode.
- `eyes-ground-truth.json`: local verification fixture combining the nine
  rendered transcriptions, engine pairs, region labels, and counts. It records
  the source URLs above and is used as a human-readable audit fixture; tests
  independently compare the ngraham20 transcription against the Xkeeper0 engine
  decode.
