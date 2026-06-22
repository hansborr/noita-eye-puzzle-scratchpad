//! First-occurrence isomorph detection.
//!
//! An isomorph signature records only the equality pattern inside a window:
//! `A B C A B` and `X Y Z X Y` both become `0,1,2,0,1`. This is useful for
//! testing repeated relative-pattern segments without assuming any particular
//! symbol names.

use std::collections::BTreeMap;

/// Error returned when an isomorph detector configuration is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsomorphError {
    /// The requested window length was zero or longer than the sequence.
    InvalidWindow {
        /// Requested window length.
        window: usize,
        /// Number of symbols available in the sequence.
        sequence_len: usize,
    },
    /// The inclusive period-search range was empty.
    InvalidPeriodSearch {
        /// Lower inclusive period bound.
        min_period: usize,
        /// Upper inclusive period bound.
        max_period: usize,
    },
}

/// First-occurrence pattern signature for one window.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatternSignature {
    values: Vec<usize>,
}

impl PatternSignature {
    /// Builds the first-occurrence equality pattern for a window.
    #[must_use]
    pub fn from_window<T: Eq + Copy>(window: &[T]) -> Self {
        let mut assignments: Vec<(T, usize)> = Vec::new();
        let mut values = Vec::with_capacity(window.len());
        let mut next = 0usize;

        for symbol in window {
            let known = assignments
                .iter()
                .find(|(assigned_symbol, _signature)| assigned_symbol == symbol)
                .map(|(_assigned_symbol, signature)| *signature);
            if let Some(signature) = known {
                values.push(signature);
            } else {
                assignments.push((*symbol, next));
                values.push(next);
                next += 1;
            }
        }

        Self { values }
    }

    /// Returns `true` when the window represented by this signature contains
    /// at least one repeated symbol.
    #[must_use]
    pub fn has_repeated_symbol(&self) -> bool {
        let mut seen = Vec::new();
        for value in &self.values {
            if seen.contains(value) {
                return true;
            }
            seen.push(*value);
        }
        false
    }

    /// Renders the signature as comma-separated first-occurrence ordinals.
    #[must_use]
    pub fn render(&self) -> String {
        self.values
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// All starts where one repeated isomorph signature occurs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureGroup {
    /// The first-occurrence equality pattern.
    pub signature: PatternSignature,
    /// Zero-based window start positions where this signature occurs.
    pub occurrences: Vec<usize>,
}

/// Repeated-signature period signal from the isomorph detector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeriodSignal {
    /// Candidate period measured in symbol positions.
    pub period: usize,
    /// Number of repeated-signature occurrence pairs whose start-position
    /// distance is a positive multiple of this candidate period.
    pub matches: usize,
    /// Number of distinct signature shapes contributing at least one match.
    pub signature_kinds: usize,
}

/// One repeated isomorph signature surfaced for reporting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureSummary {
    /// First-occurrence pattern signature rendered as comma-separated ordinals.
    pub signature: String,
    /// Window start positions where this signature occurs.
    pub occurrences: Vec<usize>,
    /// Number of occurrence pairs whose start-position distance is a positive
    /// multiple of the checked period.
    pub expected_period_matches: usize,
}

/// Repeated first-occurrence signatures found in one sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsomorphDetection {
    /// Number of scanned windows whose signature contains at least one repeated
    /// symbol.
    pub informative_windows: usize,
    /// Repeated informative signatures and their occurrence starts.
    pub groups: Vec<SignatureGroup>,
    /// Nonzero period signals in the configured period-search range.
    pub period_signals: Vec<PeriodSignal>,
}

impl IsomorphDetection {
    /// Number of distinct informative signatures that repeat somewhere.
    #[must_use]
    pub fn repeated_signature_kinds(&self) -> usize {
        self.groups.len()
    }

    /// Largest occurrence count for any repeated signature group.
    #[must_use]
    pub fn max_repeat_count(&self) -> usize {
        self.groups
            .iter()
            .map(|group| group.occurrences.len())
            .max()
            .unwrap_or_default()
    }

    /// Number of occurrence-pair matches for one candidate period.
    #[must_use]
    pub fn period_matches(&self, period: usize) -> usize {
        self.period_signals
            .iter()
            .find(|signal| signal.period == period)
            .map_or(0, |signal| signal.matches)
    }

    /// Strongest nonzero period signal, ordered by matches then signatures.
    #[must_use]
    pub fn best_period(&self) -> Option<PeriodSignal> {
        self.period_signals
            .iter()
            .copied()
            .max_by_key(|signal| (signal.matches, signal.signature_kinds))
    }

    /// Strongest repeated signatures contributing to one expected period.
    #[must_use]
    pub fn strongest_signatures(&self, expected_period: usize) -> Vec<SignatureSummary> {
        let mut groups = self
            .groups
            .iter()
            .map(|group| {
                (
                    signature_period_matches(group, expected_period),
                    group.occurrences.len(),
                    group,
                )
            })
            .filter(|(matches, _occurrences, _group)| *matches > 0)
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
        groups
            .into_iter()
            .take(3)
            .map(
                |(expected_period_matches, _occurrences, group)| SignatureSummary {
                    signature: group.signature.render(),
                    occurrences: group.occurrences.clone(),
                    expected_period_matches,
                },
            )
            .collect()
    }
}

/// Detects repeated informative first-occurrence signatures in a sequence.
///
/// Windows whose signatures contain no repeated symbol are deliberately
/// ignored. In a large alphabet, all-distinct windows all share the same
/// uninformative signature, so counting them would manufacture spurious
/// repeats.
///
/// # Errors
/// Returns [`IsomorphError`] when `window` is zero, when `window` exceeds the
/// sequence length, or when `min_period..=max_period` is empty.
pub fn detect_isomorphs<T: Eq + Copy>(
    seq: &[T],
    window: usize,
    min_period: usize,
    max_period: usize,
) -> Result<IsomorphDetection, IsomorphError> {
    if window == 0 || window > seq.len() {
        return Err(IsomorphError::InvalidWindow {
            window,
            sequence_len: seq.len(),
        });
    }
    if min_period > max_period {
        return Err(IsomorphError::InvalidPeriodSearch {
            min_period,
            max_period,
        });
    }

    let mut signature_positions: BTreeMap<PatternSignature, Vec<usize>> = BTreeMap::new();
    let mut informative_windows = 0usize;
    for (position, window_symbols) in seq.windows(window).enumerate() {
        let signature = PatternSignature::from_window(window_symbols);
        if signature.has_repeated_symbol() {
            informative_windows += 1;
            signature_positions
                .entry(signature)
                .or_default()
                .push(position);
        }
    }

    let groups = signature_positions
        .into_iter()
        .filter(|(_signature, occurrences)| occurrences.len() > 1)
        .map(|(signature, occurrences)| SignatureGroup {
            signature,
            occurrences,
        })
        .collect::<Vec<_>>();
    let mut period_signals = Vec::new();
    for period in min_period..=max_period {
        let mut matches = 0usize;
        let mut signature_kinds = 0usize;
        for group in &groups {
            let group_matches = signature_period_matches(group, period);
            if group_matches > 0 {
                matches += group_matches;
                signature_kinds += 1;
            }
        }
        if matches > 0 {
            period_signals.push(PeriodSignal {
                period,
                matches,
                signature_kinds,
            });
        }
    }

    Ok(IsomorphDetection {
        informative_windows,
        groups,
        period_signals,
    })
}

/// Counts occurrence pairs whose start-distance is a positive multiple of
/// `period`.
#[must_use]
pub fn signature_period_matches(group: &SignatureGroup, period: usize) -> usize {
    if period == 0 {
        return 0;
    }

    let mut matches = 0usize;
    for (left_index, left) in group.occurrences.iter().enumerate() {
        for right in group.occurrences.iter().skip(left_index + 1) {
            let distance = right.saturating_sub(*left);
            if distance >= period && distance % period == 0 {
                matches += 1;
            }
        }
    }
    matches
}
