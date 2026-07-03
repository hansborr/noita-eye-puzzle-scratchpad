//! Candidate-family enumeration for structured pairclass colorings.

use std::collections::BTreeSet;

use crate::attack::pairclass::PairclassError;

use super::families::{BaseColoring, LabelMode, base_colorings};

/// Structured-coloring family to enumerate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredFamilyProfile {
    /// Curated Avenue-A family covering rank, ASCII, historical, simple, and
    /// keyword-derived conventions.
    Core,
    /// Tiny deterministic family used by tests and self-test.
    Toy,
}

/// One token stream variant to score against structured colorings.
#[derive(Clone, Copy, Debug)]
pub struct StructuredStream<'a> {
    /// Human-readable stream label (`phase0`, `phase1-reversed`, `plant0`, ...).
    pub label: &'a str,
    /// Pairclass tokens for this variant.
    pub tokens: &'a [u8],
    /// Number of token classes in use.
    pub n_classes: u8,
    /// Optional tie table for the stream.
    pub tie_to: Option<&'a [Option<usize>]>,
}

/// Structured-mode budget and filtering knobs.
#[derive(Clone, Copy, Debug)]
pub struct StructuredRunCfg {
    /// Family profile to enumerate.
    pub profile: StructuredFamilyProfile,
    /// Maximum fully pinned oracle decodes to run.
    pub max_decodes: usize,
    /// Generous L1 threshold used to collapse class relabelings.
    pub marginal_l1: f64,
    /// Required score margin over random/null baselines.
    pub score_margin: f32,
}

impl Default for StructuredRunCfg {
    fn default() -> Self {
        Self {
            profile: StructuredFamilyProfile::Core,
            max_decodes: 384,
            marginal_l1: 0.16,
            score_margin: 0.0,
        }
    }
}

/// Candidate metadata reported with every structured oracle attempt.
#[derive(Clone, Debug)]
pub struct StructuredCandidateMeta {
    /// One-based rank after relabel collapse, deduplication, and cap selection.
    pub rank: usize,
    /// Stream variant label.
    pub stream_label: String,
    /// Broad family name.
    pub family: String,
    /// Projection or partition convention.
    pub projection: String,
    /// Alphabet order, keyword, direction, and offset summary.
    pub order: String,
    /// Class relabel or bit-transform summary.
    pub transform: String,
    /// Candidate seed coloring.
    pub coloring: [Option<u8>; 26],
    /// Marginal L1 distance; filter provenance only.
    pub marginal_l1: f64,
    /// Marginal chi-square statistic; filter provenance only.
    pub marginal_chi2: f64,
    /// Whether the retained relabel was inside `StructuredRunCfg::marginal_l1`.
    pub marginal_pass: bool,
}

/// Candidate generation report before expensive oracle solves.
#[derive(Clone, Debug)]
pub struct StructuredGenerationReport {
    /// Base colorings before stream/relabel expansion.
    pub base_colorings: usize,
    /// Relabel/stream candidates evaluated by the cheap marginal pass.
    pub expanded_relabels: usize,
    /// Candidates kept for oracle decode.
    pub candidates: Vec<StructuredCandidateMeta>,
    /// Candidates dropped only because `max_decodes` capped the expensive stage.
    pub dropped_by_cap: usize,
    /// L1 value at the cap boundary, when a cap dropped candidates.
    pub l1_at_cut: Option<f64>,
}

#[derive(Clone)]
struct CandidateDraft {
    stream_label: String,
    family: String,
    projection: String,
    order: String,
    transform: String,
    coloring: [Option<u8>; 26],
    marginal_l1: f64,
    marginal_chi2: f64,
    marginal_pass: bool,
}

#[derive(Clone, Copy)]
struct MarginalModel {
    letter: [f64; 26],
}

/// Generates structured candidates for every supplied stream.
///
/// The marginal filter is applied per base coloring only to collapse its class
/// relabelings; every base keeps at least its best relabel. If the final cap
/// drops candidates, the report records that explicitly.
///
/// # Errors
/// Returns [`PairclassError::EmptyLexicon`] when the word entries cannot
/// produce a letter-frequency model.
pub fn generate_structured_candidates(
    streams: &[StructuredStream<'_>],
    word_entries: &[(String, u64)],
    cfg: &StructuredRunCfg,
) -> Result<StructuredGenerationReport, PairclassError> {
    let bases = base_colorings(cfg.profile);
    let model = MarginalModel::from_word_entries(word_entries)?;
    let mut expanded_relabels = 0usize;
    let mut drafts = Vec::new();
    let mut seen = BTreeSet::new();
    for stream in streams {
        let observed = observed_marginals(stream.tokens);
        for base in &bases {
            let relabels = relabel_candidates(base, stream, &observed, &model, cfg.marginal_l1);
            expanded_relabels = expanded_relabels.saturating_add(relabels.len());
            for draft in relabels {
                if seen.insert((draft.stream_label.clone(), draft.coloring)) {
                    drafts.push(draft);
                }
            }
        }
    }
    drafts.sort_by(|a, b| {
        b.marginal_pass
            .cmp(&a.marginal_pass)
            .then_with(|| a.marginal_l1.total_cmp(&b.marginal_l1))
            .then_with(|| a.stream_label.cmp(&b.stream_label))
            .then_with(|| a.family.cmp(&b.family))
            .then_with(|| a.order.cmp(&b.order))
            .then_with(|| a.projection.cmp(&b.projection))
            .then_with(|| a.transform.cmp(&b.transform))
    });
    let l1_at_cut = drafts.get(cfg.max_decodes).map(|draft| draft.marginal_l1);
    let dropped_by_cap = drafts.len().saturating_sub(cfg.max_decodes);
    drafts.truncate(cfg.max_decodes);
    let candidates = drafts
        .into_iter()
        .enumerate()
        .map(|(index, draft)| StructuredCandidateMeta {
            rank: index + 1,
            stream_label: draft.stream_label,
            family: draft.family,
            projection: draft.projection,
            order: draft.order,
            transform: draft.transform,
            coloring: draft.coloring,
            marginal_l1: draft.marginal_l1,
            marginal_chi2: draft.marginal_chi2,
            marginal_pass: draft.marginal_pass,
        })
        .collect();
    Ok(StructuredGenerationReport {
        base_colorings: bases.len(),
        expanded_relabels,
        candidates,
        dropped_by_cap,
        l1_at_cut,
    })
}

impl MarginalModel {
    fn from_word_entries(entries: &[(String, u64)]) -> Result<Self, PairclassError> {
        let mut counts = [0u64; 26];
        let mut total = 0u64;
        for (word, count) in entries {
            let weight = (*count).max(1);
            for byte in word.bytes().filter(u8::is_ascii_lowercase) {
                let index = usize::from(byte - b'a');
                if let Some(slot) = counts.get_mut(index) {
                    *slot = slot.saturating_add(weight);
                    total = total.saturating_add(weight);
                }
            }
        }
        if total == 0 {
            return Err(PairclassError::EmptyLexicon);
        }
        let mut letter = [0.0; 26];
        for (index, slot) in letter.iter_mut().enumerate() {
            let count = counts.get(index).copied().unwrap_or(0);
            *slot = count as f64 / total as f64;
        }
        Ok(Self { letter })
    }
}

fn relabel_candidates(
    base: &BaseColoring,
    stream: &StructuredStream<'_>,
    observed: &[usize; 4],
    model: &MarginalModel,
    threshold: f64,
) -> Vec<CandidateDraft> {
    let transforms = match base.label_mode {
        LabelMode::FixedBits => bit_transforms(),
        LabelMode::Relabel => relabel_transforms(),
    };
    let mut passed = Vec::new();
    let mut best: Option<CandidateDraft> = None;
    for (name, map) in transforms {
        let coloring = apply_class_map(&base.coloring, map);
        let fit = marginal_fit(&coloring, observed, model, stream.tokens.len());
        let draft = CandidateDraft {
            stream_label: stream.label.to_owned(),
            family: base.family.clone(),
            projection: base.projection.clone(),
            order: base.order.clone(),
            transform: name,
            coloring: coloring.map(Some),
            marginal_l1: fit.0,
            marginal_chi2: fit.1,
            marginal_pass: fit.0 <= threshold,
        };
        if draft.marginal_pass {
            passed.push(draft.clone());
        }
        if best
            .as_ref()
            .is_none_or(|existing| draft.marginal_l1 < existing.marginal_l1)
        {
            best = Some(draft);
        }
    }
    if passed.is_empty() {
        best.into_iter().collect()
    } else {
        passed
    }
}

fn observed_marginals(tokens: &[u8]) -> [usize; 4] {
    let mut counts = [0usize; 4];
    for &token in tokens {
        if let Some(slot) = counts.get_mut(usize::from(token)) {
            *slot += 1;
        }
    }
    counts
}

fn marginal_fit(
    coloring: &[u8; 26],
    observed: &[usize; 4],
    model: &MarginalModel,
    len: usize,
) -> (f64, f64) {
    let mut expected = [0.0; 4];
    for (letter, &class) in coloring.iter().enumerate() {
        let Some(slot) = expected.get_mut(usize::from(class)) else {
            continue;
        };
        *slot += model.letter.get(letter).copied().unwrap_or(0.0);
    }
    let n = len.max(1) as f64;
    let mut l1 = 0.0;
    let mut chi2 = 0.0;
    for class in 0..4 {
        let obs = observed.get(class).copied().unwrap_or(0) as f64 / n;
        let exp = expected.get(class).copied().unwrap_or(0.0);
        l1 += (obs - exp).abs();
        let exp_count = (exp * n).max(1.0e-9);
        let delta = observed.get(class).copied().unwrap_or(0) as f64 - exp_count;
        chi2 += delta * delta / exp_count;
    }
    (l1, chi2)
}

fn bit_transforms() -> Vec<(String, [u8; 4])> {
    let mut out = Vec::with_capacity(8);
    for swap in [false, true] {
        for xor in 0..4u8 {
            let map = std::array::from_fn(|class| bit_transform(class as u8, swap, xor));
            out.push((
                format!("bits:{} xor{}", if swap { "swap" } else { "keep" }, xor),
                map,
            ));
        }
    }
    out
}

fn bit_transform(class: u8, swap: bool, xor: u8) -> u8 {
    let high = (class >> 1) & 1;
    let low = class & 1;
    let base = if swap { (low << 1) | high } else { class };
    base ^ xor
}

fn relabel_transforms() -> Vec<(String, [u8; 4])> {
    let mut out = Vec::with_capacity(24);
    for a in 0..4u8 {
        for b in 0..4u8 {
            for c in 0..4u8 {
                for d in 0..4u8 {
                    let map = [a, b, c, d];
                    if is_permutation(map) {
                        out.push((format!("relabel:{a}{b}{c}{d}"), map));
                    }
                }
            }
        }
    }
    out
}

fn is_permutation(map: [u8; 4]) -> bool {
    let mut seen = [false; 4];
    for value in map {
        let Some(slot) = seen.get_mut(usize::from(value)) else {
            return false;
        };
        if *slot {
            return false;
        }
        *slot = true;
    }
    true
}

fn apply_class_map(coloring: &[u8; 26], map: [u8; 4]) -> [u8; 26] {
    std::array::from_fn(|index| {
        let class = coloring.get(index).copied().unwrap_or(0);
        map.get(usize::from(class)).copied().unwrap_or(0)
    })
}
