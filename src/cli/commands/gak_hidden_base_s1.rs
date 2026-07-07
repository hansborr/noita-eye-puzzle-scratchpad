//! Handler for the hidden-base `s = 1` known-plaintext recovery report.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use noita_eye_puzzle::attack::gak_attack::lymm_deck::{
    HiddenBaseFixture, HiddenBaseFixtureConfig, HiddenBaseKind, HiddenBaseS1RecoveryReport,
    HiddenBaseS1RecoveryState, HiddenBaseS1SolverConfig, LymmDeckError, LymmDeckSpec,
    plant_hidden_base_fixture, recover_hidden_base_s1_known_plaintext_with_audit,
};
use noita_eye_puzzle::nulls::null::mix_seed;

use crate::cli::args_gak_hidden_base::{GakHiddenBaseKind, GakHiddenBaseS1RecoverArgs};

macro_rules! appendln {
    ($out:expr, $($arg:tt)*) => {
        writeln!($out, $($arg)*).expect("write to String")
    };
}

/// Dispatches the `gak-hidden-base-s1-recover` subcommand.
pub(crate) fn run_gak_hidden_base_s1_recover(args: &GakHiddenBaseS1RecoverArgs) -> ExitCode {
    let controls = if args.skip_controls {
        None
    } else {
        match run_s1_solver_controls(args.seed) {
            Ok(controls) if controls.iter().all(S1ControlReport::passed) => Some(controls),
            Ok(controls) => {
                print!("{}", render_s1_controls(Some(&controls), false));
                eprintln!("gak-hidden-base-s1-recover error: solver controls failed");
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("gak-hidden-base-s1-recover control error: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    if args.trials == 0 {
        eprintln!("gak-hidden-base-s1-recover error: trials must be at least one");
        return ExitCode::FAILURE;
    }

    let mut trials = Vec::with_capacity(args.trials);
    for trial_index in 0..args.trials {
        let seed = mix_seed(
            args.seed,
            0x7331_7265_636f_7600 ^ u64::try_from(trial_index).unwrap_or(0),
        );
        let fixture_config = HiddenBaseFixtureConfig {
            n: args.n,
            pt_alphabet: args
                .pt_alphabet
                .clone()
                .unwrap_or_else(|| default_pt_alphabet(args.n)),
            swap_budget: 1,
            message_count: args.messages,
            message_len: args.message_len,
            seed,
            base_kind: cli_base_kind(args.base_kind, args.n),
        };
        let fixture = match plant_hidden_base_fixture(&fixture_config) {
            Ok(fixture) => fixture,
            Err(error) => {
                eprintln!("gak-hidden-base-s1-recover fixture error: {error}");
                return ExitCode::FAILURE;
            }
        };
        let solver_config = solver_config_from_spec(&fixture.spec, args.max_base_candidates);
        let report = match recover_hidden_base_s1_known_plaintext_with_audit(
            &solver_config,
            &fixture.pairs,
            Some(&fixture.spec.base),
        ) {
            Ok(report) => report,
            Err(error) => {
                eprintln!("gak-hidden-base-s1-recover solver error: {error}");
                return ExitCode::FAILURE;
            }
        };
        trials.push(S1TrialReport {
            trial_index,
            seed,
            report,
        });
    }

    print!(
        "{}",
        render_s1_recovery_report(args, &trials, controls.as_deref())
    );
    if trials.iter().all(|trial| trial.report.has_exact_recovery()) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
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
    max_base_candidates: Option<usize>,
) -> HiddenBaseS1SolverConfig {
    HiddenBaseS1SolverConfig::top_card_swaps(spec.n, spec.pt_alphabet.iter().collect::<String>())
        .with_ct_alphabet(spec.ct_alphabet.iter().collect::<String>())
        .with_max_base_candidates(max_base_candidates)
}

#[derive(Clone, Debug)]
struct S1TrialReport {
    trial_index: usize,
    seed: u64,
    report: HiddenBaseS1RecoveryReport,
}

#[derive(Clone, Debug)]
struct S1ControlReport {
    name: &'static str,
    expected: HiddenBaseS1RecoveryState,
    observed: HiddenBaseS1RecoveryState,
    exact_candidate_count: usize,
    base_candidates_tested: usize,
}

impl S1ControlReport {
    fn passed(&self) -> bool {
        self.expected == self.observed
    }
}

fn run_s1_solver_controls(seed: u64) -> Result<Vec<S1ControlReport>, LymmDeckError> {
    let positive_config = HiddenBaseFixtureConfig {
        n: 7,
        pt_alphabet: "ABCDEF".to_owned(),
        swap_budget: 1,
        message_count: 8,
        message_len: 48,
        seed,
        base_kind: HiddenBaseKind::Random,
    };
    let positive_fixture = plant_hidden_base_fixture(&positive_config)?;
    let positive = run_s1_control(
        "planted-positive",
        HiddenBaseS1RecoveryState::RecoveredPlantedBase,
        &positive_fixture,
    )?;

    let mut shuffled_fixture = positive_fixture.clone();
    for pair in &mut shuffled_fixture.pairs {
        pair.ciphertext = pair
            .ciphertext
            .chars()
            .map(|ch| match ch {
                '!' => '"',
                '"' => '!',
                other => other,
            })
            .collect();
    }
    let label_shuffle = run_s1_control(
        "ciphertext-label-shuffle-null",
        HiddenBaseS1RecoveryState::NoCandidate,
        &shuffled_fixture,
    )?;
    let over_budget = over_budget_s1_control(seed)?;

    Ok(vec![positive, label_shuffle, over_budget])
}

fn over_budget_s1_control(seed: u64) -> Result<S1ControlReport, LymmDeckError> {
    for attempt in 0..64usize {
        let config = HiddenBaseFixtureConfig {
            n: 7,
            pt_alphabet: "ABCDEF".to_owned(),
            swap_budget: 2,
            message_count: 8,
            message_len: 48,
            seed: mix_seed(
                seed,
                0x7331_6f76_6572_0000 ^ u64::try_from(attempt).unwrap_or(0),
            ),
            base_kind: HiddenBaseKind::Random,
        };
        let fixture = plant_hidden_base_fixture(&config)?;
        let report = run_s1_control(
            "over-budget-key-null",
            HiddenBaseS1RecoveryState::NoCandidate,
            &fixture,
        )?;
        if report.passed() {
            return Ok(report);
        }
    }
    Err(LymmDeckError::HiddenBaseConfig {
        reason: "over-budget s1 null did not produce a rejecting fixture",
    })
}

fn run_s1_control(
    name: &'static str,
    expected: HiddenBaseS1RecoveryState,
    fixture: &HiddenBaseFixture,
) -> Result<S1ControlReport, LymmDeckError> {
    let solver_config = solver_config_from_spec(&fixture.spec, None);
    let report = recover_hidden_base_s1_known_plaintext_with_audit(
        &solver_config,
        &fixture.pairs,
        Some(&fixture.spec.base),
    )?;
    Ok(S1ControlReport {
        name,
        expected,
        observed: report.state,
        exact_candidate_count: report.exact_candidate_count,
        base_candidates_tested: report.base_candidates_tested,
    })
}

fn render_s1_recovery_report(
    args: &GakHiddenBaseS1RecoverArgs,
    trials: &[S1TrialReport],
    controls: Option<&[S1ControlReport]>,
) -> String {
    let mut out = String::new();
    let alphabet = args
        .pt_alphabet
        .clone()
        .unwrap_or_else(|| default_pt_alphabet(args.n));
    let first = trials.first().map(|trial| &trial.report);
    appendln!(
        &mut out,
        "gak-hidden-base-s1-recover: trials={} n={} s=1 messages={}x{} base={} max-base-candidates={}",
        trials.len(),
        args.n,
        args.messages,
        args.message_len,
        cli_base_kind(args.base_kind, args.n).label(),
        args.max_base_candidates
            .map_or_else(|| "none".to_owned(), |value| value.to_string())
    );
    appendln!(
        &mut out,
        "cipher convention: state=compose(perm(L), state); compose(p1,p2)[i]=p2[p1[i]]; emit state[0]; perm(L)=B o (0,k); identity restart per message"
    );
    appendln!(
        &mut out,
        "solver: exhaustive hidden-base enumeration; per-letter domain size n; acceptance is exact compressed re-encryption only"
    );
    appendln!(
        &mut out,
        "plaintext alphabet: {} ({} letters)",
        alphabet,
        alphabet.chars().count()
    );
    out.push('\n');
    out.push_str(&render_s1_controls(controls, args.skip_controls));
    appendln!(
        &mut out,
        "states: planted={} equivalent-key={} ambiguous={} no-candidate={} search-cap={}",
        s1_state_count(trials, HiddenBaseS1RecoveryState::RecoveredPlantedBase),
        s1_state_count(trials, HiddenBaseS1RecoveryState::RecoveredEquivalentKey),
        s1_state_count(trials, HiddenBaseS1RecoveryState::AmbiguousEquivalentClass),
        s1_state_count(trials, HiddenBaseS1RecoveryState::NoCandidate),
        s1_state_count(trials, HiddenBaseS1RecoveryState::SearchCapExceeded)
    );
    let tested_range = s1_range(trials, |report| report.base_candidates_tested).unwrap_or((0, 0));
    let exact_range = s1_range(trials, |report| report.exact_candidate_count).unwrap_or((0, 0));
    appendln!(
        &mut out,
        "base candidates tested per trial: min={} max={} (brute-force n!={})",
        tested_range.0,
        tested_range.1,
        first
            .and_then(|report| report.brute_force_base_count)
            .map_or_else(|| "overflow".to_owned(), |value| value.to_string())
    );
    appendln!(
        &mut out,
        "exact candidates per trial: min={} max={}",
        exact_range.0,
        exact_range.1
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

fn render_s1_controls(controls: Option<&[S1ControlReport]>, controls_skipped: bool) -> String {
    let mut out = String::new();
    if controls_skipped {
        appendln!(
            &mut out,
            "hidden-base s1 controls: SKIPPED by --skip-controls"
        );
        out.push('\n');
        return out;
    }
    let Some(controls) = controls else {
        appendln!(&mut out, "hidden-base s1 controls: not run");
        out.push('\n');
        return out;
    };
    appendln!(
        &mut out,
        "hidden-base s1 controls: {}",
        if controls.iter().all(S1ControlReport::passed) {
            "PASS"
        } else {
            "FAIL"
        }
    );
    for control in controls {
        appendln!(
            &mut out,
            "  {}: {} expected={} observed={} exact-candidates={} tested={}",
            control.name,
            if control.passed() { "PASS" } else { "FAIL" },
            control.expected.label(),
            control.observed.label(),
            control.exact_candidate_count,
            control.base_candidates_tested
        );
    }
    out.push('\n');
    out
}

fn append_trial0(out: &mut String, trial: &S1TrialReport) {
    let report = &trial.report;
    appendln!(
        out,
        "trial-0 recovery: index={} seed={} state={} tested={} exact-candidates={} elapsed={} planted-base-recovered={}",
        trial.trial_index,
        trial.seed,
        report.state.label(),
        report.base_candidates_tested,
        report.exact_candidate_count,
        format_duration(report.elapsed),
        report
            .planted_base_recovered
            .map_or_else(|| "n/a".to_owned(), |value| value.to_string())
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

fn s1_state_count(trials: &[S1TrialReport], state: HiddenBaseS1RecoveryState) -> usize {
    trials
        .iter()
        .filter(|trial| trial.report.state == state)
        .count()
}

fn s1_range(
    trials: &[S1TrialReport],
    value: impl Fn(&HiddenBaseS1RecoveryReport) -> usize,
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

fn total_elapsed(trials: &[S1TrialReport]) -> Duration {
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
