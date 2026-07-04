//! Avenue G repeated-span pattern-crib scan for practice puzzle `two`.
//!
//! The scan is intentionally narrower than the pairclass dictionary solver: it
//! tests only whether a candidate plaintext span from a corpus can induce one
//! consistent 26-to-4 coloring against the repeated anchor's class pattern. A
//! surviving span is a candidate crib, never a decode.

use super::plant::markov_resample;
use super::{MAX_CLASSES, PairclassError};
use crate::nulls::null::{SplitMix64, mix_seed, random_index_below};

const POSITIVE_TAG: u64 = 0x7061_6972_6372_6962;
const MATCHED_NULL_TAG: u64 = 0x7061_6972_6372_6e75;
const RANDOM_NEGATIVE_TAG: u64 = 0x7061_6972_6372_726e;

/// Default number of matched-null spans scanned before the real anchor.
pub const DEFAULT_PATTERN_CRIB_NULL_TRIALS: usize = 49;
/// Default number of random negative spans scanned before the real anchor.
pub const DEFAULT_PATTERN_CRIB_RANDOM_NEGATIVES: usize = 1;
/// Default maximum number of surviving spans retained for display.
pub const DEFAULT_PATTERN_CRIB_TOP: usize = 20;

/// Token-coordinate repeated span to crib against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternCribAnchor {
    /// Earlier occurrence start in the pair-token stream.
    pub first: usize,
    /// Later occurrence start in the pair-token stream.
    pub second: usize,
    /// Span length in pair tokens / plaintext letters.
    pub len: usize,
}

/// Runtime knobs for the repeated-span pattern-crib scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternCribConfig {
    /// Maximum real or control hits to retain in reports.
    pub max_hits: usize,
    /// Number of full-stream order-1 Markov resamples to cut null spans from.
    pub null_trials: usize,
    /// Number of independent uniform random negative spans to scan.
    pub random_negatives: usize,
    /// Deterministic seed for plants and nulls.
    pub seed: u64,
}

impl Default for PatternCribConfig {
    fn default() -> Self {
        Self {
            max_hits: DEFAULT_PATTERN_CRIB_TOP,
            null_trials: DEFAULT_PATTERN_CRIB_NULL_TRIALS,
            random_negatives: DEFAULT_PATTERN_CRIB_RANDOM_NEGATIVES,
            seed: super::DEFAULT_SEED,
        }
    }
}

/// One surviving candidate corpus span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribHit {
    /// Start offset in normalized letters, not bytes.
    pub letter_start: usize,
    /// Normalized lowercase letters of the surviving span.
    pub text: String,
    /// Number of distinct plaintext letters used by this span.
    pub distinct_letters: usize,
    /// Repeated positions beyond the first occurrence of each letter.
    pub repeated_positions: usize,
    /// Partial 26-to-4 coloring induced by the span.
    pub coloring: [Option<u8>; 26],
}

/// Result of scanning one corpus against one token pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribScan {
    /// Number of normalized letters in the scanned corpus.
    pub corpus_letters: usize,
    /// Number of fixed-length windows tested.
    pub windows_scanned: usize,
    /// Total surviving windows, even when only the first `max_hits` are stored.
    pub hit_count: usize,
    /// First retained hits in corpus order.
    pub hits: Vec<PatternCribHit>,
}

impl PatternCribScan {
    /// Returns whether some hits were omitted from [`Self::hits`].
    #[must_use]
    pub fn capped(&self) -> bool {
        self.hit_count > self.hits.len()
    }
}

/// Positive-control scan against a planted corpus span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribPositiveControl {
    /// Start offset of the planted span in normalized control-text letters.
    pub planted_start: usize,
    /// Planted normalized plaintext span.
    pub planted_text: String,
    /// Number of distinct letters in the planted span.
    pub distinct_letters: usize,
    /// Repeated positions in the planted span.
    pub repeated_positions: usize,
    /// Full scan of the control text against the planted class pattern.
    pub scan: PatternCribScan,
    /// Number of retained-or-counted hits equal to the planted span text.
    pub planted_hits: usize,
    /// Whether the planted span fired.
    pub fired: bool,
}

/// One quietness control against corpus material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribNegativeControl {
    /// Zero-based control trial index.
    pub trial: usize,
    /// Number of corpus spans that survived the negative pattern.
    pub hit_count: usize,
    /// First retained hit, if the negative was not quiet.
    pub first_hit: Option<PatternCribHit>,
}

/// Controls that must pass before the real anchor is scanned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribControls {
    /// Structured planted positive control.
    pub positive: PatternCribPositiveControl,
    /// Matched nulls: full-stream order-1 Markov resamples, sliced at the anchor.
    pub matched_nulls: Vec<PatternCribNegativeControl>,
    /// Uniform random negative token patterns.
    pub random_negatives: Vec<PatternCribNegativeControl>,
    /// Whether the positive fired and every negative stayed quiet.
    pub passed: bool,
}

/// Avenue G verdict vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatternCribVerdict {
    /// Controls failed, so the real stream was not scanned.
    ControlsFailed,
    /// Controls passed and at least one corpus span survived.
    Candidate,
    /// Controls passed and no corpus span survived.
    NoCandidate,
}

/// Full controls-first Avenue G run report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternCribRunReport {
    /// Anchor that supplied the observed class pattern.
    pub anchor: PatternCribAnchor,
    /// Observed token pattern at `anchor.first`.
    pub observed_pattern: Vec<u8>,
    /// Controls result.
    pub controls: PatternCribControls,
    /// Real scan, present only when controls passed.
    pub real_scan: Option<PatternCribScan>,
    /// Report verdict.
    pub verdict: PatternCribVerdict,
}

/// Tests whether `letters` can induce one consistent coloring for `pattern`.
///
/// Returns the induced partial coloring on success. The enforced condition is:
/// every repeated plaintext letter must carry the same observed class; therefore
/// any two different observed classes must be different plaintext letters.
#[must_use]
pub fn pattern_crib_span_fits(letters: &[u8], pattern: &[u8]) -> Option<[Option<u8>; 26]> {
    if letters.len() != pattern.len() || letters.is_empty() {
        return None;
    }
    let mut coloring = [None; 26];
    for (&letter, &class) in letters.iter().zip(pattern.iter()) {
        let slot = coloring.get_mut(usize::from(letter))?;
        match *slot {
            Some(prev) if prev != class => return None,
            Some(_) => {}
            None => *slot = Some(class),
        }
    }
    Some(coloring)
}

/// Scans `corpus_text` for spans compatible with `pattern`.
///
/// This is the same scanner used by the CLI for the planted positive, negative
/// controls, and real anchor scan.
///
/// # Errors
/// Returns [`PairclassError::EmptyInput`] when `pattern` is empty.
pub fn scan_pattern_crib_corpus(
    corpus_text: &str,
    pattern: &[u8],
    max_hits: usize,
) -> Result<PatternCribScan, PairclassError> {
    if pattern.is_empty() {
        return Err(PairclassError::EmptyInput);
    }
    let corpus = LetterCorpus::from_text(corpus_text);
    Ok(corpus.scan(pattern, max_hits, None))
}

/// Runs the controls-first Avenue G pattern-crib scan.
///
/// `tokens` is the full pairclass token stream. Matched nulls resample that full
/// stream and slice the same anchor position, so the null population is tied to
/// the actual stream before the real anchor is scanned.
///
/// # Errors
/// Returns [`PairclassError`] when the token stream, class count, anchor span,
/// positive-control text, or deterministic null sampler is invalid.
pub fn run_pattern_crib_scan(
    tokens: &[u8],
    n_classes: u8,
    anchor: PatternCribAnchor,
    corpus_text: &str,
    positive_text: &str,
    cfg: PatternCribConfig,
) -> Result<PatternCribRunReport, PairclassError> {
    validate_run(tokens, n_classes, anchor)?;
    let corpus = LetterCorpus::from_text(corpus_text);
    let positive_corpus = LetterCorpus::from_text(positive_text);
    let observed_pattern = token_span(tokens, anchor.first, anchor.len)?.to_vec();
    let positive = positive_control(&positive_corpus, n_classes, anchor.len, cfg)?;
    let matched_nulls = matched_null_controls(tokens, n_classes, anchor, &corpus, cfg)?;
    let random_negatives = random_negative_controls(n_classes, anchor.len, &corpus, cfg)?;
    let negatives_quiet = matched_nulls
        .iter()
        .chain(random_negatives.iter())
        .all(|trial| trial.hit_count == 0);
    let controls = PatternCribControls {
        passed: positive.fired && negatives_quiet,
        positive,
        matched_nulls,
        random_negatives,
    };
    if !controls.passed {
        return Ok(PatternCribRunReport {
            anchor,
            observed_pattern,
            controls,
            real_scan: None,
            verdict: PatternCribVerdict::ControlsFailed,
        });
    }
    let real_scan = corpus.scan(&observed_pattern, cfg.max_hits, None);
    let verdict = if real_scan.hit_count > 0 {
        PatternCribVerdict::Candidate
    } else {
        PatternCribVerdict::NoCandidate
    };
    Ok(PatternCribRunReport {
        anchor,
        observed_pattern,
        controls,
        real_scan: Some(real_scan),
        verdict,
    })
}

fn validate_run(
    tokens: &[u8],
    n_classes: u8,
    anchor: PatternCribAnchor,
) -> Result<(), PairclassError> {
    if tokens.is_empty() || anchor.len == 0 {
        return Err(PairclassError::EmptyInput);
    }
    if n_classes == 0 || n_classes > MAX_CLASSES {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(n_classes),
        });
    }
    if let Some(&bad) = tokens.iter().find(|&&token| token >= n_classes) {
        return Err(PairclassError::TooManyClasses {
            found: usize::from(bad) + 1,
        });
    }
    let first = token_span(tokens, anchor.first, anchor.len)?;
    let second = token_span(tokens, anchor.second, anchor.len)?;
    if first != second {
        return Err(PairclassError::NullModel(
            "pattern-crib anchor occurrences are not equal".to_owned(),
        ));
    }
    Ok(())
}

fn token_span(tokens: &[u8], start: usize, len: usize) -> Result<&[u8], PairclassError> {
    let Some(end) = start.checked_add(len) else {
        return Err(PairclassError::SpanOutOfRange);
    };
    tokens.get(start..end).ok_or(PairclassError::SpanOutOfRange)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LetterCorpus {
    letters: Vec<u8>,
}

impl LetterCorpus {
    fn from_text(text: &str) -> Self {
        let letters = text
            .chars()
            .filter_map(|ch| {
                let lower = ch.to_ascii_lowercase();
                lower.is_ascii_lowercase().then(|| lower as u8 - b'a')
            })
            .collect();
        Self { letters }
    }

    fn scan(&self, pattern: &[u8], max_hits: usize, needle: Option<&[u8]>) -> PatternCribScan {
        let span_len = pattern.len();
        let windows_scanned = self
            .letters
            .len()
            .checked_sub(span_len)
            .map_or(0, |remaining| remaining + 1);
        let mut hit_count = 0usize;
        let mut hits = Vec::new();
        for start in 0..windows_scanned {
            let Some(window) = self.letters.get(start..start + span_len) else {
                continue;
            };
            let Some(coloring) = pattern_crib_span_fits(window, pattern) else {
                continue;
            };
            hit_count += 1;
            if hits.len() < max_hits {
                hits.push(hit_from_window(start, window, coloring));
            }
        }
        let needle_hits = needle.map_or(0, |needle| self.needle_hits(pattern, needle));
        PatternCribScan {
            corpus_letters: self.letters.len(),
            windows_scanned,
            hit_count: hit_count.max(needle_hits),
            hits,
        }
    }

    fn needle_hits(&self, pattern: &[u8], needle: &[u8]) -> usize {
        if needle.len() != pattern.len() {
            return 0;
        }
        let span_len = pattern.len();
        let windows_scanned = self
            .letters
            .len()
            .checked_sub(span_len)
            .map_or(0, |remaining| remaining + 1);
        let mut hits = 0usize;
        for start in 0..windows_scanned {
            let Some(window) = self.letters.get(start..start + span_len) else {
                continue;
            };
            if window == needle && pattern_crib_span_fits(window, pattern).is_some() {
                hits += 1;
            }
        }
        hits
    }
}

fn hit_from_window(start: usize, window: &[u8], coloring: [Option<u8>; 26]) -> PatternCribHit {
    let distinct_letters = coloring.iter().filter(|slot| slot.is_some()).count();
    PatternCribHit {
        letter_start: start,
        text: letters_to_string(window),
        distinct_letters,
        repeated_positions: window.len().saturating_sub(distinct_letters),
        coloring,
    }
}

fn positive_control(
    corpus: &LetterCorpus,
    n_classes: u8,
    span_len: usize,
    cfg: PatternCribConfig,
) -> Result<PatternCribPositiveControl, PairclassError> {
    let planted_start = select_control_span(corpus, span_len, cfg.seed)?;
    let planted = corpus
        .letters
        .get(planted_start..planted_start + span_len)
        .ok_or(PairclassError::SpanOutOfRange)?;
    let coloring = random_coloring(n_classes, cfg.seed)?;
    let pattern: Vec<u8> = planted
        .iter()
        .map(|&letter| {
            coloring
                .get(usize::from(letter))
                .copied()
                .unwrap_or_default()
        })
        .collect();
    let planted_text = letters_to_string(planted);
    let scan = corpus.scan(&pattern, cfg.max_hits, Some(planted));
    let planted_hits = corpus.needle_hits(&pattern, planted);
    Ok(PatternCribPositiveControl {
        planted_start,
        planted_text,
        distinct_letters: distinct_letters(planted),
        repeated_positions: repeated_positions(planted),
        fired: planted_hits > 0,
        scan,
        planted_hits,
    })
}

fn select_control_span(
    corpus: &LetterCorpus,
    span_len: usize,
    seed: u64,
) -> Result<usize, PairclassError> {
    if span_len == 0 {
        return Err(PairclassError::EmptyInput);
    }
    let window_count = corpus
        .letters
        .len()
        .checked_sub(span_len)
        .map_or(0, |remaining| remaining + 1);
    if window_count == 0 {
        return Err(PairclassError::PlantTooShort {
            needed: span_len,
            have: corpus.letters.len(),
        });
    }
    let min_repeats = (span_len / 3).max(1);
    let mut rng = SplitMix64::new(mix_seed(seed, POSITIVE_TAG));
    let start0 = random_index_below(window_count, &mut rng)
        .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?;
    for offset in 0..window_count {
        let start = (start0 + offset) % window_count;
        let Some(window) = corpus.letters.get(start..start + span_len) else {
            continue;
        };
        if repeated_positions(window) >= min_repeats {
            return Ok(start);
        }
    }
    Err(PairclassError::NullModel(format!(
        "positive-control text has no {span_len}-letter span with at least {min_repeats} repeated positions"
    )))
}

fn random_coloring(n_classes: u8, seed: u64) -> Result<[u8; 26], PairclassError> {
    let mut rng = SplitMix64::new(mix_seed(seed, POSITIVE_TAG ^ 0x434f_4c4f_5249_4e47));
    let mut coloring = [0u8; 26];
    for slot in &mut coloring {
        *slot = random_index_below(usize::from(n_classes), &mut rng)
            .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?
            as u8;
    }
    Ok(coloring)
}

fn matched_null_controls(
    tokens: &[u8],
    n_classes: u8,
    anchor: PatternCribAnchor,
    corpus: &LetterCorpus,
    cfg: PatternCribConfig,
) -> Result<Vec<PatternCribNegativeControl>, PairclassError> {
    let mut trials = Vec::with_capacity(cfg.null_trials);
    for trial in 0..cfg.null_trials {
        let seed = mix_seed(cfg.seed.wrapping_add(trial as u64), MATCHED_NULL_TAG);
        let resampled = markov_resample(tokens, n_classes, seed)?;
        let pattern = token_span(&resampled, anchor.first, anchor.len)?;
        let scan = corpus.scan(pattern, 1, None);
        trials.push(PatternCribNegativeControl {
            trial,
            hit_count: scan.hit_count,
            first_hit: scan.hits.first().cloned(),
        });
    }
    Ok(trials)
}

fn random_negative_controls(
    n_classes: u8,
    span_len: usize,
    corpus: &LetterCorpus,
    cfg: PatternCribConfig,
) -> Result<Vec<PatternCribNegativeControl>, PairclassError> {
    let mut trials = Vec::with_capacity(cfg.random_negatives);
    for trial in 0..cfg.random_negatives {
        let mut rng = SplitMix64::new(mix_seed(
            cfg.seed.wrapping_add(trial as u64),
            RANDOM_NEGATIVE_TAG,
        ));
        let mut pattern = Vec::with_capacity(span_len);
        for _ in 0..span_len {
            let class = random_index_below(usize::from(n_classes), &mut rng)
                .map_err(|error| PairclassError::NullModel(format!("bad bound {}", error.bound)))?;
            pattern.push(class as u8);
        }
        let scan = corpus.scan(&pattern, 1, None);
        trials.push(PatternCribNegativeControl {
            trial,
            hit_count: scan.hit_count,
            first_hit: scan.hits.first().cloned(),
        });
    }
    Ok(trials)
}

fn distinct_letters(letters: &[u8]) -> usize {
    let mut seen = [false; 26];
    for &letter in letters {
        if let Some(slot) = seen.get_mut(usize::from(letter)) {
            *slot = true;
        }
    }
    seen.into_iter().filter(|seen| *seen).count()
}

fn repeated_positions(letters: &[u8]) -> usize {
    letters.len().saturating_sub(distinct_letters(letters))
}

fn letters_to_string(letters: &[u8]) -> String {
    letters
        .iter()
        .map(|&letter| char::from(b'a' + letter.min(25)))
        .collect()
}
