//! Candidate-family enumeration for structured pairclass colorings.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::attack::pairclass::PairclassError;

use super::families::{BaseColoring, LabelMode, base_colorings};

/// Default beam for ranking every structured coloring before confirmation.
pub const DEFAULT_STRUCTURED_RANK_BEAM: usize = 400;
// Calibrated on the definitive 348-token structured positives: this keeps the
// three previously dropped truth relabels while bounding the per-stream set.
const GUARANTEED_PASS_RELABELS_PER_BASE: usize = 4;
const RELABEL_EDGE_L1_UNITS: f64 = 13.0;
const RELABEL_NEAR_BEST_CHI2_DELTA: f64 = 9.0;

/// Structured-coloring family to enumerate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructuredFamilyProfile {
    /// Broad Avenue-A family covering expanded rank, ASCII, historical,
    /// simple, and keyword-derived conventions.
    Core,
    /// Pre-broadening curated core family with lower multiple-testing pressure.
    CoreCurated,
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
    /// Extra fully pinned relabel decodes beyond the guaranteed relabel band.
    pub max_decodes: usize,
    /// Beam used for the rank surface: every structured coloring is decoded at
    /// this width for controls, nulls, real ranking, and verdict statistics.
    pub rank_beam: usize,
    /// Generous L1 threshold used to collapse class relabelings.
    pub marginal_l1: f64,
    /// Deprecated compatibility knob; verdicts are matched-null calibrated.
    pub score_margin: f32,
}

impl Default for StructuredRunCfg {
    fn default() -> Self {
        Self {
            profile: StructuredFamilyProfile::Core,
            max_decodes: 384,
            rank_beam: DEFAULT_STRUCTURED_RANK_BEAM,
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
    /// Unique guaranteed near-best relabel candidates retained before extras.
    pub guaranteed_candidates: usize,
    /// Unique additional marginal-passing relabel candidates retained.
    pub extra_candidates: usize,
    /// Relabels dropped by the marginal filter after each base kept its best.
    pub dropped_by_filter: usize,
    /// Lowest L1 among relabels dropped by the marginal filter.
    pub l1_at_filter_cut: Option<f64>,
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

struct RelabelSelection {
    guaranteed: Vec<CandidateDraft>,
    extras: Vec<CandidateDraft>,
    evaluated: usize,
    dropped_by_filter: usize,
    l1_at_filter_cut: Option<f64>,
}

#[derive(Clone, Copy)]
struct MarginalModel {
    letter: [f64; 26],
}

/// Generates structured candidates for every supplied stream.
///
/// The marginal filter is applied per base coloring only to collapse its class
/// relabelings; every base keeps at least its best relabel before any cap is
/// applied. The top marginal-passing relabels and just-over-threshold relabels
/// that remain close to the best chi-square fit are retained to cover
/// finite-sample relabel instability; `StructuredRunCfg::max_decodes` budgets
/// only additional marginal-passing relabels. If the filter or cap drops
/// relabels, the report records that explicitly.
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
    let mut guaranteed = Vec::new();
    let mut extras = Vec::new();
    let mut dropped_by_filter = 0usize;
    let mut l1_at_filter_cut: Option<f64> = None;
    for stream in streams {
        let observed = observed_marginals(stream.tokens);
        for base in &bases {
            let selection = relabel_candidates(base, stream, &observed, &model, cfg.marginal_l1);
            expanded_relabels = expanded_relabels.saturating_add(selection.evaluated);
            dropped_by_filter = dropped_by_filter.saturating_add(selection.dropped_by_filter);
            l1_at_filter_cut = min_option(l1_at_filter_cut, selection.l1_at_filter_cut);
            guaranteed.extend(selection.guaranteed);
            extras.extend(selection.extras);
        }
    }
    sort_drafts(&mut guaranteed);
    sort_drafts(&mut extras);

    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for draft in guaranteed {
        if seen.insert((draft.stream_label.clone(), draft.coloring)) {
            selected.push(draft);
        }
    }
    let guaranteed_candidates = selected.len();

    let mut unique_extras = Vec::new();
    for draft in extras {
        if seen.insert((draft.stream_label.clone(), draft.coloring)) {
            unique_extras.push(draft);
        }
    }
    let l1_at_cut = unique_extras
        .get(cfg.max_decodes)
        .map(|draft| draft.marginal_l1);
    let dropped_by_cap = unique_extras.len().saturating_sub(cfg.max_decodes);
    selected.extend(unique_extras.into_iter().take(cfg.max_decodes));
    let extra_candidates = selected.len().saturating_sub(guaranteed_candidates);
    sort_drafts(&mut selected);

    let candidates = selected
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
        guaranteed_candidates,
        extra_candidates,
        dropped_by_filter,
        l1_at_filter_cut,
        dropped_by_cap,
        l1_at_cut,
    })
}

pub(super) fn expanded_family_colorings(profile: StructuredFamilyProfile) -> BTreeSet<[u8; 26]> {
    let mut out = BTreeSet::new();
    for base in base_colorings(profile) {
        let transforms = match base.label_mode {
            LabelMode::FixedBits => bit_transforms(),
            LabelMode::Relabel => relabel_transforms(),
        };
        for (_name, map) in transforms {
            let _inserted = out.insert(apply_class_map(&base.coloring, map));
        }
    }
    out
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
) -> RelabelSelection {
    let transforms = match base.label_mode {
        LabelMode::FixedBits => bit_transforms(),
        LabelMode::Relabel => relabel_transforms(),
    };
    let mut drafts = Vec::with_capacity(transforms.len());
    for (name, map) in transforms {
        let coloring = apply_class_map(&base.coloring, map);
        let fit = marginal_fit(&coloring, observed, model, stream.tokens.len());
        drafts.push(CandidateDraft {
            stream_label: stream.label.to_owned(),
            family: base.family.clone(),
            projection: base.projection.clone(),
            order: base.order.clone(),
            transform: name,
            coloring: coloring.map(Some),
            marginal_l1: fit.0,
            marginal_chi2: fit.1,
            marginal_pass: fit.0 <= threshold,
        });
    }
    sort_drafts(&mut drafts);
    let evaluated = drafts.len();
    let fallback = drafts
        .first()
        .cloned()
        .unwrap_or_else(|| empty_draft(base, stream));
    let near_best_chi2 = drafts
        .iter()
        .map(|draft| draft.marginal_chi2)
        .min_by(f64::total_cmp)
        .unwrap_or(fallback.marginal_chi2)
        + RELABEL_NEAR_BEST_CHI2_DELTA;
    let mut guaranteed = Vec::new();
    let mut extras = Vec::new();
    let mut dropped_by_filter = 0usize;
    let mut l1_at_filter_cut = None;
    let edge_l1 = threshold + relabel_edge_l1_epsilon(stream.tokens.len());
    let filter_disabled = threshold >= 2.0;
    let mut guaranteed_pass_relabels = 0usize;
    for (index, draft) in drafts.into_iter().enumerate() {
        let keep_pass = !filter_disabled
            && draft.marginal_pass
            && guaranteed_pass_relabels < GUARANTEED_PASS_RELABELS_PER_BASE;
        let keep_edge = !filter_disabled
            && !draft.marginal_pass
            && draft.marginal_l1 <= edge_l1
            && draft.marginal_chi2 <= near_best_chi2;
        if index == 0 || keep_pass || keep_edge {
            if draft.marginal_pass {
                guaranteed_pass_relabels = guaranteed_pass_relabels.saturating_add(1);
            }
            guaranteed.push(draft);
        } else if draft.marginal_pass {
            extras.push(draft);
        } else {
            dropped_by_filter = dropped_by_filter.saturating_add(1);
            l1_at_filter_cut = min_option(l1_at_filter_cut, Some(draft.marginal_l1));
        }
    }
    if guaranteed.is_empty() {
        guaranteed.push(fallback);
    }
    RelabelSelection {
        guaranteed,
        extras,
        evaluated,
        dropped_by_filter,
        l1_at_filter_cut,
    }
}

fn relabel_edge_l1_epsilon(token_len: usize) -> f64 {
    RELABEL_EDGE_L1_UNITS / token_len.max(1) as f64
}

fn sort_drafts(drafts: &mut [CandidateDraft]) {
    drafts.sort_by(compare_drafts);
}

fn compare_drafts(a: &CandidateDraft, b: &CandidateDraft) -> Ordering {
    b.marginal_pass
        .cmp(&a.marginal_pass)
        .then_with(|| a.marginal_l1.total_cmp(&b.marginal_l1))
        .then_with(|| a.stream_label.cmp(&b.stream_label))
        .then_with(|| a.family.cmp(&b.family))
        .then_with(|| a.order.cmp(&b.order))
        .then_with(|| a.projection.cmp(&b.projection))
        .then_with(|| a.transform.cmp(&b.transform))
}

fn empty_draft(base: &BaseColoring, stream: &StructuredStream<'_>) -> CandidateDraft {
    CandidateDraft {
        stream_label: stream.label.to_owned(),
        family: base.family.clone(),
        projection: base.projection.clone(),
        order: base.order.clone(),
        transform: "identity".to_owned(),
        coloring: base.coloring.map(Some),
        marginal_l1: f64::INFINITY,
        marginal_chi2: f64::INFINITY,
        marginal_pass: false,
    }
}

fn min_option(left: Option<f64>, right: Option<f64>) -> Option<f64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
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
