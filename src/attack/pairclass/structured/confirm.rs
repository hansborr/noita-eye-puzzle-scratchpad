//! Full-beam rendering for ranked structured real-stream candidates.

use crate::attack::pairclass::solve::{Solution, SolveCfg, SolveInput, solve};
use crate::attack::pairclass::structured::enumerate::StructuredStream;
use crate::attack::pairclass::structured::pipeline::StructuredRunReport;
use crate::attack::pairclass::{Lexicon, PairclassError};

/// Display-only full-beam render for a ranked real candidate.
#[derive(Clone, Debug)]
pub struct StructuredConfirmRender {
    /// Beam used for this confirmation render.
    pub beam: usize,
    /// Best full-beam solution under the same structured coloring.
    pub solution: Option<Solution>,
    /// Candidates offered during the confirmation solve.
    pub expanded: u64,
    /// Feasible final states during the confirmation solve.
    pub feasible_final: usize,
}

/// Re-decodes the ranked real-stream top candidates at the caller's full beam.
///
/// This only fills the confirmation render on ranked solutions. It must not be
/// used for controls or matched nulls, and it deliberately leaves rank-beam
/// scores unchanged.
///
/// # Errors
/// Propagates solver errors from the full-beam confirmation solves.
pub fn confirm_structured_top_candidates(
    report: &mut StructuredRunReport,
    streams: &[StructuredStream<'_>],
    lexicon: &Lexicon,
    solve_cfg: &SolveCfg,
) -> Result<(), PairclassError> {
    for candidate in &mut report.solutions {
        let Some(stream) = streams
            .iter()
            .find(|stream| stream.label == candidate.meta.stream_label)
        else {
            continue;
        };
        let solved = solve(
            &SolveInput {
                tokens: stream.tokens,
                n_classes: stream.n_classes,
                tie_to: stream.tie_to,
                lexicon,
                truth: None,
                seed_coloring: Some(&candidate.meta.coloring),
                accept_partial_final: false,
            },
            solve_cfg,
        )?;
        candidate.confirm = Some(StructuredConfirmRender {
            beam: solve_cfg.beam,
            solution: solved.solutions.first().cloned(),
            expanded: solved.expanded,
            feasible_final: solved.feasible_final,
        });
    }
    Ok(())
}
