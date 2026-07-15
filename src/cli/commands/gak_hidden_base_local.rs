//! Handler for the hidden-base `s = 2..3` local recovery report.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    HiddenBaseFixtureConfig, HiddenBaseKind, HiddenBaseLocalControlReport,
    HiddenBaseLocalJointMoveOrder, HiddenBaseLocalRecoveryReport, HiddenBaseLocalRecoveryState,
    HiddenBaseLocalSelfTestReport, HiddenBaseLocalSolverConfig, LymmDeckSpec,
    hidden_base_local_self_test, plant_hidden_base_fixture,
    recover_hidden_base_local_known_plaintext_with_audit,
};
use noita_eye_puzzle::nulls::null::mix_seed;

use crate::cli::args_gak_hidden_base::{
    GakHiddenBaseJointMoveOrder, GakHiddenBaseKind, GakHiddenBaseLocalRecoverArgs,
};

macro_rules! appendln {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).expect("write to String")
    };
}

/// Dispatches the `gak-hidden-base-local-recover` subcommand.
pub(crate) fn run_gak_hidden_base_local_recover(args: &GakHiddenBaseLocalRecoverArgs) -> ExitCode {
    let controls = if args.skip_controls {
        None
    } else {
        match hidden_base_local_self_test(args.seed) {
            Ok(report) if report.passed() => Some(report),
            Ok(report) => {
                print!("{}", render_local_controls(Some(&report), false));
                eprintln!("gak-hidden-base-local-recover error: solver controls failed");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("gak-hidden-base-local-recover control error: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    if args.trials == 0 {
        eprintln!("gak-hidden-base-local-recover error: trials must be at least one");
        return ExitCode::FAILURE;
    }
    if !(2..=3).contains(&args.num_swaps) {
        eprintln!("gak-hidden-base-local-recover error: --num-swaps must be 2 or 3");
        return ExitCode::FAILURE;
    }

    let mut trials = Vec::with_capacity(args.trials);
    for trial_index in 0..args.trials {
        let seed = mix_seed(
            args.seed,
            0x6c73_7265_636f_7600 ^ u64::try_from(trial_index).unwrap_or(0),
        );
        let fixture_config = HiddenBaseFixtureConfig {
            n: args.n,
            pt_alphabet: args
                .pt_alphabet
                .clone()
                .unwrap_or_else(|| default_pt_alphabet(args.n)),
            swap_budget: args.num_swaps,
            message_count: args.messages,
            message_len: args.message_len,
            seed,
            base_kind: cli_base_kind(args.base_kind, args.n),
        };
        let fixture = match plant_hidden_base_fixture(&fixture_config) {
            Ok(fixture) => fixture,
            Err(error) => {
                eprintln!("gak-hidden-base-local-recover fixture error: {error}");
                return ExitCode::FAILURE;
            }
        };
        let solver_config = solver_config_from_spec(
            &fixture.spec,
            args.num_swaps,
            mix_seed(seed, 0x6c73_736f_6c76_6572),
            args,
        );
        let report = match recover_hidden_base_local_known_plaintext_with_audit(
            &solver_config,
            &fixture.pairs,
            Some(&fixture.spec.base),
        ) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("gak-hidden-base-local-recover solver error: {error}");
                return ExitCode::FAILURE;
            }
        };
        trials.push(LocalTrialReport {
            trial_index,
            seed,
            report,
        });
    }

    print!(
        "{}",
        render_local_recovery_report(args, &trials, controls.as_ref())
    );
    ExitCode::SUCCESS
}

fn default_pt_alphabet(n: usize) -> String {
    let count = n.saturating_sub(1).min(26);
    (0..count)
        .filter_map(|index| {
            u8::try_from(index)
                .ok()
                .and_then(|offset| b'A'.checked_add(offset))
                .map(char::from)
        })
        .collect()
}

fn cli_base_kind(kind: GakHiddenBaseKind, n: usize) -> HiddenBaseKind {
    match kind {
        GakHiddenBaseKind::Random => HiddenBaseKind::Random,
        GakHiddenBaseKind::Affine => HiddenBaseKind::Affine {
            shift: n / 3 + 1,
            decimation: 3,
        },
    }
}

fn solver_config_from_spec(
    spec: &LymmDeckSpec,
    swap_budget: usize,
    seed: u64,
    args: &GakHiddenBaseLocalRecoverArgs,
) -> HiddenBaseLocalSolverConfig {
    HiddenBaseLocalSolverConfig::top_card_swaps(
        spec.n,
        spec.pt_alphabet.iter().collect::<String>(),
        swap_budget,
    )
    .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
    .with_seed(seed)
    .with_attempts(args.attempts)
    .with_max_rounds(args.max_rounds)
    .with_top_source_beam_width(args.top_source_beam)
    .with_third_symbol_top_source_ranking(!args.disable_third_symbol_rank)
    .with_joint_move_order(cli_joint_move_order(args.joint_move_order))
    .with_joint_move_evaluation_cap(args.joint_move_cap)
    .with_joint_move_total_evaluation_cap(args.joint_total_cap)
}

#[derive(Clone, Debug)]
struct LocalTrialReport {
    trial_index: usize,
    seed: u64,
    report: HiddenBaseLocalRecoveryReport,
}

fn render_local_recovery_report(
    args: &GakHiddenBaseLocalRecoverArgs,
    trials: &[LocalTrialReport],
    controls: Option<&HiddenBaseLocalSelfTestReport>,
) -> String {
    let mut out = String::new();
    let alphabet = args
        .pt_alphabet
        .clone()
        .unwrap_or_else(|| default_pt_alphabet(args.n));
    appendln!(
        &mut out,
        "gak-hidden-base-local-recover: trials={} n={} s={} messages={}x{} base={} attempts={} max-rounds={} top-source-beam={} third-symbol-rank={} joint-move-order={} joint-move-cap={} joint-total-cap={}",
        trials.len(),
        args.n,
        args.num_swaps,
        args.messages,
        args.message_len,
        cli_base_kind(args.base_kind, args.n).label(),
        args.attempts,
        args.max_rounds,
        args.top_source_beam,
        !args.disable_third_symbol_rank,
        joint_move_order_label(args.joint_move_order),
        args.joint_move_cap,
        args.joint_total_cap
    );
    appendln!(
        &mut out,
        "cipher convention: state=compose(perm(L), state); compose(p1,p2)[i]=p2[p1[i]]; emit state[0]; perm(L)=B o sigma_L; sigma_L is generated by <=s top swaps; identity restart per message"
    );
    appendln!(
        &mut out,
        "solver: bounded top-source CSP/beam from first-symbol injectivity, second-symbol constraints, and optional third-symbol shared-sigma arc consistency, followed by constraint-filtered coordinate descent and objective-bounded two-letter s=3 moves with selectable pair ordering under per-restart and fair total-run caps; acceptance is exact compressed re-encryption only"
    );
    appendln!(
        &mut out,
        "scope note: a search-cap miss is not a proof that no key exists"
    );
    appendln!(
        &mut out,
        "plaintext alphabet: {} ({} letters)",
        alphabet,
        alphabet.chars().count()
    );
    out.push('\n');
    out.push_str(&render_local_controls(controls, args.skip_controls));
    append_search_surface(&mut out, trials);
    if let Some(first_trial) = trials.first() {
        append_trial0(&mut out, first_trial);
    }
    out
}

fn append_search_surface(out: &mut String, trials: &[LocalTrialReport]) {
    let first = trials.first().map(|trial| &trial.report);
    appendln!(
        out,
        "states: planted={} equivalent-key={} ambiguous={} no-candidate={} search-cap={}",
        local_state_count(trials, HiddenBaseLocalRecoveryState::RecoveredPlantedBase),
        local_state_count(trials, HiddenBaseLocalRecoveryState::RecoveredEquivalentKey),
        local_state_count(
            trials,
            HiddenBaseLocalRecoveryState::AmbiguousEquivalentClass
        ),
        local_state_count(trials, HiddenBaseLocalRecoveryState::NoCandidate),
        local_state_count(trials, HiddenBaseLocalRecoveryState::SearchCapExceeded)
    );
    append_local_work_surface(out, trials);
    appendln!(
        out,
        "top-source stage: retained min/max={} expanded min/max={} pruned min/max={} dropped min/max={} constraint-evaluations min/max={} third-symbol-evaluations min/max={} elapsed-total={}",
        format_range(local_range(trials, |report| report.top_source_hypotheses_retained)),
        format_range(local_range(trials, |report| report.top_source_states_expanded)),
        format_range(local_range(trials, |report| report.top_source_states_pruned)),
        format_range(local_range(trials, |report| report.top_source_states_dropped)),
        format_range(local_range(trials, |report| report.top_source_constraint_evaluations)),
        format_range(local_range(trials, |report| {
            report.top_source_third_symbol_evaluations
        })),
        format_duration(top_source_elapsed(trials))
    );
    appendln!(
        out,
        "top-source planted audit: retained={} dropped={} rank min/max={}",
        trials
            .iter()
            .filter(|trial| trial.report.planted_top_source_hypothesis_retained == Some(true))
            .count(),
        trials
            .iter()
            .filter(|trial| trial.report.planted_top_source_hypothesis_retained == Some(false))
            .count(),
        format_range(optional_local_range(trials, |report| {
            report.planted_top_source_hypothesis_rank
        }))
    );
    appendln!(
        out,
        "best mismatches per trial: {}",
        format_range(local_range(trials, |report| report.best_mismatches))
    );
    appendln!(
        out,
        "elapsed: total={} trial-0={}",
        format_duration(total_elapsed(trials)),
        first.map_or_else(
            || "n/a".to_owned(),
            |report| format_duration(report.elapsed)
        )
    );
    appendln!(
        out,
        "trial outcomes: {}",
        trials
            .iter()
            .map(|trial| format!(
                "{}:{}/rank-{}/evals-{}/joint-{}",
                trial.trial_index,
                trial.report.state.label(),
                trial
                    .report
                    .planted_top_source_hypothesis_rank
                    .map_or_else(|| "n/a".to_owned(), |rank| rank.to_string()),
                trial.report.candidate_evaluations,
                trial.report.joint_move_candidate_evaluations
            ))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn append_local_work_surface(out: &mut String, trials: &[LocalTrialReport]) {
    let first = trials.first().map(|trial| &trial.report);
    appendln!(
        out,
        "search surface: sigma-domain={} brute-force n!={} candidate-evaluations min/max={} replay-events min/max={} joint-evaluations min/max={} joint-replay-events min/max={} joint-moves min/max={} joint-pairs-evaluated min/max={} eligible min/max={} pair-evaluation-minimum min/max={} maximum min/max={} total-budget-exhausted={} exact-candidates min/max={}",
        first.map_or(0, |report| report.sigma_domain_size),
        first
            .and_then(|report| report.brute_force_base_count)
            .map_or_else(|| "overflow".to_owned(), |value| value.to_string()),
        format_range(local_range(trials, |report| report.candidate_evaluations)),
        format_range(local_range(trials, |report| report.replay_event_evaluations)),
        format_range(local_range(trials, |report| report.joint_move_candidate_evaluations)),
        format_range(local_range(trials, |report| {
            report.joint_move_replay_event_evaluations
        })),
        format_range(local_range(trials, |report| report.joint_moves_accepted)),
        format_range(local_range(trials, |report| {
            report.joint_move_letter_pairs_evaluated
        })),
        format_range(local_range(trials, |report| {
            report.joint_move_letter_pairs_eligible
        })),
        format_range(local_range(trials, |report| {
            report.joint_move_pair_evaluations_min
        })),
        format_range(local_range(trials, |report| {
            report.joint_move_pair_evaluations_max
        })),
        trials
            .iter()
            .filter(|trial| trial.report.joint_move_total_budget_exhausted)
            .count(),
        format_range(local_range(trials, |report| report.exact_candidate_count))
    );
}

const fn cli_joint_move_order(order: GakHiddenBaseJointMoveOrder) -> HiddenBaseLocalJointMoveOrder {
    match order {
        GakHiddenBaseJointMoveOrder::PairMajor => HiddenBaseLocalJointMoveOrder::PairMajor,
        GakHiddenBaseJointMoveOrder::PairRoundRobin => {
            HiddenBaseLocalJointMoveOrder::PairRoundRobin
        }
        GakHiddenBaseJointMoveOrder::Hybrid => HiddenBaseLocalJointMoveOrder::Hybrid,
    }
}

const fn joint_move_order_label(order: GakHiddenBaseJointMoveOrder) -> &'static str {
    match order {
        GakHiddenBaseJointMoveOrder::PairMajor => "pair-major",
        GakHiddenBaseJointMoveOrder::PairRoundRobin => "pair-round-robin",
        GakHiddenBaseJointMoveOrder::Hybrid => "hybrid",
    }
}

fn render_local_controls(
    controls: Option<&HiddenBaseLocalSelfTestReport>,
    controls_skipped: bool,
) -> String {
    let mut out = String::new();
    if controls_skipped {
        appendln!(
            &mut out,
            "hidden-base local controls: SKIPPED by --skip-controls"
        );
        out.push('\n');
        return out;
    }
    let Some(controls) = controls else {
        appendln!(&mut out, "hidden-base local controls: not run");
        out.push('\n');
        return out;
    };
    appendln!(
        &mut out,
        "hidden-base local controls: {}",
        if controls.passed() { "PASS" } else { "FAIL" }
    );
    append_control(&mut out, &controls.s2_positive);
    append_control(&mut out, &controls.s3_positive);
    append_control(&mut out, &controls.label_shuffle);
    append_control(&mut out, &controls.over_budget);
    out.push('\n');
    out
}

fn append_control(out: &mut String, control: &HiddenBaseLocalControlReport) {
    appendln!(
        out,
        "  {}: {} expected={} observed={} exact={} best-mismatches={} attempts={}",
        control.name,
        if control.passed() { "PASS" } else { "FAIL" },
        control.expectation.label(),
        control.observed.label(),
        control.exact,
        control.best_mismatches,
        control.attempts_run
    );
}

fn append_trial0(out: &mut String, trial: &LocalTrialReport) {
    let report = &trial.report;
    appendln!(
        out,
        "trial-0 recovery: index={} seed={} state={} attempts={} evals={} exact-candidates={} best-round-trip={}/{} best-mismatches={} planted-base-recovered={}",
        trial.trial_index,
        trial.seed,
        report.state.label(),
        report.attempts_run,
        report.candidate_evaluations,
        report.exact_candidate_count,
        report.best_round_trip.matched,
        report.best_round_trip.total,
        report.best_mismatches,
        report
            .planted_base_recovered
            .map_or_else(|| "n/a".to_owned(), |value| value.to_string())
    );
    appendln!(
        out,
        "trial-0 signal: observed={} anchored={} planted-top-source-rank={} retained={}",
        report.observed_letters.iter().collect::<String>(),
        report.anchored_letters.iter().collect::<String>(),
        report
            .planted_top_source_hypothesis_rank
            .map_or_else(|| "n/a".to_owned(), |rank| rank.to_string()),
        report
            .planted_top_source_hypothesis_retained
            .map_or_else(|| "n/a".to_owned(), |retained| retained.to_string())
    );
    if let Some(audit) = &report.representative_audit {
        appendln!(
            out,
            "trial-0 audit: compatible-bases={} sigma-domain={} round-trip={}/{} exact={} status={}",
            audit.base_candidate_count,
            audit.sigma_domain_size,
            audit.round_trip.matched,
            audit.round_trip.total,
            audit.round_trip.exact,
            audit.status.label()
        );
    }
}

fn local_state_count(trials: &[LocalTrialReport], state: HiddenBaseLocalRecoveryState) -> usize {
    trials
        .iter()
        .filter(|trial| trial.report.state == state)
        .count()
}

fn local_range(
    trials: &[LocalTrialReport],
    value: impl Fn(&HiddenBaseLocalRecoveryReport) -> usize,
) -> Option<(usize, usize)> {
    let mut iter = trials.iter().map(|trial| value(&trial.report));
    let first = iter.next()?;
    let mut min_value = first;
    let mut max_value = first;
    for current in iter {
        min_value = min_value.min(current);
        max_value = max_value.max(current);
    }
    Some((min_value, max_value))
}

fn optional_local_range(
    trials: &[LocalTrialReport],
    value: impl Fn(&HiddenBaseLocalRecoveryReport) -> Option<usize>,
) -> Option<(usize, usize)> {
    let mut iter = trials.iter().filter_map(|trial| value(&trial.report));
    let first = iter.next()?;
    let mut min_value = first;
    let mut max_value = first;
    for current in iter {
        min_value = min_value.min(current);
        max_value = max_value.max(current);
    }
    Some((min_value, max_value))
}

fn format_range(range: Option<(usize, usize)>) -> String {
    range.map_or_else(|| "n/a".to_owned(), |(min, max)| format!("{min}/{max}"))
}

fn total_elapsed(trials: &[LocalTrialReport]) -> Duration {
    trials
        .iter()
        .map(|trial| trial.report.elapsed)
        .fold(Duration::ZERO, Duration::saturating_add)
}

fn top_source_elapsed(trials: &[LocalTrialReport]) -> Duration {
    trials
        .iter()
        .map(|trial| trial.report.top_source_elapsed)
        .fold(Duration::ZERO, Duration::saturating_add)
}

fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros >= 1_000 {
        format!("{}.{:03} ms", micros / 1_000, micros % 1_000)
    } else {
        format!("{micros} us")
    }
}
