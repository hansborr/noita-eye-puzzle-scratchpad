//! Two-tier ns=3 target CEGAR driver.

use std::collections::{BTreeMap, BTreeSet};

use super::domain_build::build_residual_domains;
use super::instrumentation::{trace_residual, trace_stats};
use super::learning::{TruthTracker, add_outer_stats};
use super::propagation::{PropagationOptions, propagate_partial_states};
use super::residual::{ResidualDomains, recover_with_residual_domains, restrict_to_targets};
use super::target_conflict::{
    broad_residual_rejects_target_choices, extract_deterministic_target_conflict,
    measure_truth_target_residual,
};
use super::target_solver::TargetAssignmentSolver;
use super::{
    AlignedMessage, RecoveryReport, SwapRecoveryConfig, SwapRecoveryError, SwapRecoveryStats,
};
use crate::attack::gak_attack::lymm_deck::LymmDeckSpec;

const PROJECTION_LETTERS: [char; 5] = ['E', 'H', 'S', 'T', 'Y'];

pub(super) fn recover_ns3_with_target_cegar(
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    config: &SwapRecoveryConfig,
) -> Result<RecoveryReport, SwapRecoveryError> {
    let truth = config.planted_truth().cloned().map(TruthTracker::new);
    let mut residual = build_residual_domains(spec, messages, config)?;
    let mut stats = SwapRecoveryStats {
        enumerated_candidates: residual.candidates.len(),
        ..SwapRecoveryStats::default()
    };
    let propagation = propagate_partial_states(
        spec,
        messages,
        &mut residual,
        &mut stats,
        PropagationOptions::ns3_broad(),
    )?;
    if trace_residual("target", config.max_swaps, &residual, &stats) {
        return Err(SwapRecoveryError::SearchCapExceeded { nodes: 0 });
    }
    if let Some(truth) = truth.as_ref() {
        measure_truth_target_residual(spec, messages, &residual, truth, &mut stats)?;
    }
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: building target solver");
    }
    let mut target_solver =
        TargetAssignmentSolver::new(spec, messages, &propagation.state_domains, &residual);
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: target solver built");
    }
    let mut projection_tracker = TargetProjectionTracker::new(&target_solver);
    let mut target_nodes = 0usize;
    loop {
        if let Some(max_nodes) = config.max_nodes
            && target_nodes >= max_nodes
        {
            trace_stats("target cap", &stats);
            return Err(SwapRecoveryError::SearchCapExceeded {
                nodes: target_nodes,
            });
        }
        let Some(targets) = target_solver.next_assignment()? else {
            return Err(SwapRecoveryError::NoResidualCandidate);
        };
        target_nodes = target_nodes.saturating_add(1);
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
            eprintln!("cegar: target assignment {target_nodes}: {targets:?}");
        }
        let mut targeted = residual.clone();
        restrict_to_targets(&mut targeted, &targets)?;
        let targeted_projection = trace_targeted_entries(&targeted);
        match recover_with_residual_domains(
            spec,
            messages,
            (*config).clone(),
            targeted,
            ns3_targeted_propagation_options(),
            Some(&targets),
            truth.as_ref(),
        ) {
            Ok(mut report) => {
                trace_stats("target success outer", &stats);
                add_outer_stats(&mut report.stats, &stats);
                report.stats.nodes = report.stats.nodes.saturating_add(target_nodes);
                return Ok(report);
            }
            Err(SwapRecoveryError::TargetUnsatCore { choices }) => {
                if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
                    eprintln!("cegar: learned target core size={}", choices.len());
                }
                learn_sat_unsat_core_target_clause(
                    &mut target_solver,
                    SatTargetCoreClause {
                        spec,
                        messages,
                        residual: &residual,
                        targets: &targets,
                        choices: &choices,
                        truth: truth.as_ref(),
                    },
                    &mut stats,
                )?;
                stats.target_rejections = stats.target_rejections.saturating_add(1);
            }
            Err(SwapRecoveryError::NoResidualCandidate) => {
                learn_no_residual_target_clause(
                    &mut target_solver,
                    spec,
                    messages,
                    &residual,
                    &targets,
                    truth.as_ref(),
                    &mut stats,
                )?;
                stats.target_rejections = stats.target_rejections.saturating_add(1);
                projection_tracker.record_rejection(target_nodes, &targets, targeted_projection);
            }
            Err(error) => {
                trace_stats("target abort", &stats);
                return Err(error);
            }
        }
    }
}

const fn ns3_targeted_propagation_options() -> PropagationOptions {
    PropagationOptions {
        max_passes: 2,
        exhaustive_arc: false,
    }
}

#[derive(Clone, Copy)]
pub(super) struct SatTargetCoreClause<'a> {
    pub(super) spec: &'a LymmDeckSpec,
    pub(super) messages: &'a [AlignedMessage],
    pub(super) residual: &'a ResidualDomains,
    pub(super) targets: &'a BTreeMap<char, usize>,
    pub(super) choices: &'a [(char, usize)],
    pub(super) truth: Option<&'a TruthTracker>,
}

pub(super) fn learn_sat_unsat_core_target_clause(
    target_solver: &mut TargetAssignmentSolver,
    core: SatTargetCoreClause<'_>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    if !core.choices.is_empty()
        && broad_residual_rejects_target_choices(
            core.spec,
            core.messages,
            core.residual,
            core.choices,
        )?
    {
        return target_solver.learn_core_clause(core.choices, core.truth, stats);
    }

    let assignment_choices = core
        .targets
        .iter()
        .map(|(&letter, &target)| (letter, target))
        .collect::<Vec<_>>();
    if !broad_residual_rejects_target_choices(
        core.spec,
        core.messages,
        core.residual,
        &assignment_choices,
    )? {
        return Err(SwapRecoveryError::SatSolver(
            "target UNSAT core failed broad-baseline replay".to_owned(),
        ));
    }
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() && !core.choices.is_empty() {
        eprintln!(
            "cegar: target core failed broad replay; learned full assignment size={}",
            assignment_choices.len()
        );
    }
    target_solver.learn_core_clause(&assignment_choices, core.truth, stats)
}

fn trace_targeted_entries(residual: &ResidualDomains) -> TargetedProjection {
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
    if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
        eprintln!("cegar: targeted entries={total} max_domain={max}");
    }
    TargetedProjection {
        entries: total,
        max_domain: max,
    }
}

#[derive(Clone, Copy, Debug)]
struct TargetedProjection {
    entries: usize,
    max_domain: usize,
}

#[derive(Debug)]
struct TargetProjectionTracker {
    domains: BTreeMap<char, Vec<usize>>,
    seen: BTreeSet<[usize; PROJECTION_LETTERS.len()]>,
    seen_by_t: BTreeMap<usize, usize>,
    totals_by_t: BTreeMap<usize, usize>,
    last_t: Option<usize>,
}

impl TargetProjectionTracker {
    fn new(target_solver: &TargetAssignmentSolver) -> Self {
        let domains = PROJECTION_LETTERS
            .into_iter()
            .map(|letter| (letter, target_solver.letter_target_values(letter)))
            .collect();
        Self {
            domains,
            seen: BTreeSet::new(),
            seen_by_t: BTreeMap::new(),
            totals_by_t: BTreeMap::new(),
            last_t: None,
        }
    }

    fn record_rejection(
        &mut self,
        node: usize,
        targets: &BTreeMap<char, usize>,
        targeted: TargetedProjection,
    ) {
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_none() {
            return;
        }
        let Some(tuple) = projected_tuple(targets) else {
            return;
        };
        let target_t = tuple[3];
        let is_new = self.seen.insert(tuple);
        if is_new {
            let entry = self.seen_by_t.entry(target_t).or_insert(0);
            *entry = entry.saturating_add(1);
        }
        let unique_for_t = self.seen_by_t.get(&target_t).copied().unwrap_or(0);
        let total_for_t = self.total_for_t(target_t);
        let remaining_for_t = total_for_t.saturating_sub(unique_for_t);
        let t_change = match self.last_t.replace(target_t) {
            None => "initial".to_owned(),
            Some(previous) if previous == target_t => "same".to_owned(),
            Some(previous) => format!("{previous}->{target_t}"),
        };
        eprintln!(
            "cegar: projected target rejection node={node} E={} H={} S={} T={} Y={} new={} unique_projected={} unique_for_t={} projected_total_for_t={} projected_remaining_for_t={} targeted_entries={} targeted_max_domain={} t_change={}",
            tuple[0],
            tuple[1],
            tuple[2],
            tuple[3],
            tuple[4],
            is_new,
            self.seen.len(),
            unique_for_t,
            total_for_t,
            remaining_for_t,
            targeted.entries,
            targeted.max_domain,
            t_change
        );
    }

    fn total_for_t(&mut self, target_t: usize) -> usize {
        if let Some(&total) = self.totals_by_t.get(&target_t) {
            return total;
        }
        let total = count_projected_total_for_t(&self.domains, target_t);
        let _old = self.totals_by_t.insert(target_t, total);
        total
    }
}

fn projected_tuple(targets: &BTreeMap<char, usize>) -> Option<[usize; PROJECTION_LETTERS.len()]> {
    let mut tuple = [0usize; PROJECTION_LETTERS.len()];
    for (index, letter) in PROJECTION_LETTERS.iter().enumerate() {
        let slot = tuple.get_mut(index)?;
        *slot = *targets.get(letter)?;
    }
    Some(tuple)
}

fn count_projected_total_for_t(domains: &BTreeMap<char, Vec<usize>>, target_t: usize) -> usize {
    if target_t == 0
        || domains
            .get(&'T')
            .is_none_or(|targets| targets.binary_search(&target_t).is_err())
    {
        return 0;
    }
    let Some(e_values) = domains.get(&'E') else {
        return 0;
    };
    let Some(h_values) = domains.get(&'H') else {
        return 0;
    };
    let Some(s_values) = domains.get(&'S') else {
        return 0;
    };
    let Some(y_values) = domains.get(&'Y') else {
        return 0;
    };
    let mut total = 0usize;
    for &e in e_values {
        if e == 0 || e == target_t {
            continue;
        }
        for &h in h_values {
            if h == 0 || h == target_t || h == e {
                continue;
            }
            for &s in s_values {
                if s == 0 || s == target_t || s == e || s == h {
                    continue;
                }
                for &y in y_values {
                    if y == 0 || y == target_t || y == e || y == h || y == s {
                        continue;
                    }
                    total = total.saturating_add(1);
                }
            }
        }
    }
    total
}

fn learn_no_residual_target_clause(
    target_solver: &mut TargetAssignmentSolver,
    spec: &LymmDeckSpec,
    messages: &[AlignedMessage],
    residual: &ResidualDomains,
    targets: &BTreeMap<char, usize>,
    truth: Option<&TruthTracker>,
    stats: &mut SwapRecoveryStats,
) -> Result<(), SwapRecoveryError> {
    let conflict = extract_deterministic_target_conflict(spec, messages, residual, targets, stats)?;
    if let Some(core) = conflict {
        if std::env::var_os("NOITA_SWAP_CEGAR_TRACE").is_some() {
            eprintln!(
                "cegar: learned deterministic target core size={}",
                core.len()
            );
        }
        target_solver.learn_core_clause(&core, truth, stats)?;
    } else {
        let assignment_choices = targets
            .iter()
            .map(|(&letter, &target)| (letter, target))
            .collect::<Vec<_>>();
        if !broad_residual_rejects_target_choices(spec, messages, residual, &assignment_choices)? {
            return Err(SwapRecoveryError::SatSolver(
                "deterministic target rejection failed broad-baseline replay".to_owned(),
            ));
        }
        target_solver.learn_assignment_clause(targets, truth, stats)?;
    }
    Ok(())
}
