//! Handler for the hidden-base `s = 2..3` local recovery report.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    HiddenBaseFixtureConfig, HiddenBaseKind, HiddenBaseLocalControlReport,
    HiddenBaseLocalRecoveryReport, HiddenBaseLocalRecoveryState, HiddenBaseLocalSelfTestReport,
    HiddenBaseLocalSolverConfig, LymmDeckSpec, hidden_base_local_self_test,
    plant_hidden_base_fixture, recover_hidden_base_local_known_plaintext_with_audit,
};
use noita_eye_puzzle::nulls::null::mix_seed;

use crate::cli::args_gak_hidden_base::{GakHiddenBaseKind, GakHiddenBaseLocalRecoverArgs};

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
            args.attempts,
            args.max_rounds,
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
    attempts: usize,
    max_rounds: usize,
) -> HiddenBaseLocalSolverConfig {
    HiddenBaseLocalSolverConfig::top_card_swaps(
        spec.n,
        spec.pt_alphabet.iter().collect::<String>(),
        swap_budget,
    )
    .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
    .with_seed(seed)
    .with_attempts(attempts)
    .with_max_rounds(max_rounds)
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
    let first = trials.first().map(|trial| &trial.report);
    appendln!(
        &mut out,
        "gak-hidden-base-local-recover: trials={} n={} s={} messages={}x{} base={} attempts={} max-rounds={}",
        trials.len(),
        args.n,
        args.num_swaps,
        args.messages,
        args.message_len,
        cli_base_kind(args.base_kind, args.n).label(),
        args.attempts,
        args.max_rounds
    );
    appendln!(
        &mut out,
        "cipher convention: state=compose(perm(L), state); compose(p1,p2)[i]=p2[p1[i]]; emit state[0]; perm(L)=B o sigma_L; sigma_L is generated by <=s top swaps; identity restart per message"
    );
    appendln!(
        &mut out,
        "solver: bounded base-marginalized coordinate descent over sigma_L assignments; B is inferred from first-symbol anchors; acceptance is exact compressed re-encryption only"
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
    appendln!(
        &mut out,
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
    appendln!(
        &mut out,
        "search surface: sigma-domain={} brute-force n!={} candidate-evaluations min/max={} exact-candidates min/max={}",
        first.map_or(0, |report| report.sigma_domain_size),
        first
            .and_then(|report| report.brute_force_base_count)
            .map_or_else(|| "overflow".to_owned(), |value| value.to_string()),
        format_range(local_range(trials, |report| report.candidate_evaluations)),
        format_range(local_range(trials, |report| report.exact_candidate_count))
    );
    appendln!(
        &mut out,
        "best mismatches per trial: {}",
        format_range(local_range(trials, |report| report.best_mismatches))
    );
    appendln!(
        &mut out,
        "elapsed: total={} trial-0={}",
        format_duration(total_elapsed(trials)),
        first.map_or_else(
            || "n/a".to_owned(),
            |report| format_duration(report.elapsed)
        )
    );
    if let Some(first_trial) = trials.first() {
        append_trial0(&mut out, first_trial);
    }
    out
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
        "trial-0 signal: observed={} anchored={}",
        report.observed_letters.iter().collect::<String>(),
        report.anchored_letters.iter().collect::<String>()
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

fn format_range(range: Option<(usize, usize)>) -> String {
    range.map_or_else(|| "n/a".to_owned(), |(min, max)| format!("{min}/{max}"))
}

fn total_elapsed(trials: &[LocalTrialReport]) -> Duration {
    trials
        .iter()
        .map(|trial| trial.report.elapsed)
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
