//! Trace-only residual instrumentation for swap recovery.

use super::SwapRecoveryStats;
use super::residual::ResidualDomains;

pub(super) fn trace_stats(label: &str, stats: &SwapRecoveryStats) {
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_none() {
        return;
    }
    eprintln!(
        "cegar: {label} stats candidates={} pruned={} deductions={} nodes={} sat_decisions={} sat_conflicts={} target_rejections={} target_clauses={} target_replay_checks={} target_replay_literals={} target_floor_full_assignment_fallbacks={} candidate_clauses={} truth_checks={}",
        stats.enumerated_candidates,
        stats.domains_pruned,
        stats.deductions,
        stats.nodes,
        stats.sat_decisions,
        stats.sat_conflicts,
        stats.target_rejections,
        stats.target_clauses_learned,
        stats.target_replay_checks,
        stats.target_replay_literals,
        stats.target_floor_full_assignment_fallbacks,
        stats.candidate_clauses_learned,
        stats.truth_preservation_checks
    );
}

pub(super) fn trace_residual(
    label: &str,
    max_swaps: usize,
    residual: &ResidualDomains,
    stats: &SwapRecoveryStats,
) -> bool {
    if std::env::var_os("NOITA_SWAP_TRACE_ONLY").is_none() {
        return false;
    }
    if let Ok(phase) = std::env::var("NOITA_SWAP_TRACE_PHASE")
        && phase != label
    {
        return false;
    }
    let total = residual
        .by_letter
        .values()
        .map(std::vec::Vec::len)
        .sum::<usize>();
    let max = residual
        .by_letter
        .values()
        .map(std::vec::Vec::len)
        .max()
        .unwrap_or(0);
    eprintln!(
        "trace {label} max_swaps={max_swaps} candidates={} total_domain_entries={total} max_domain={max} pruned={} deductions={}",
        residual.candidates.len(),
        stats.domains_pruned,
        stats.deductions
    );
    for (&letter, domain) in &residual.by_letter {
        eprintln!("trace {label} letter {letter}: {}", domain.len());
    }
    true
}
