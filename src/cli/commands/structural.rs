//! Bespoke handlers for the structural-battery subcommands.
//!
//! Each analysis keeps its verified eye-corpus default (run with no input flags)
//! and gains a file-driven path: an arbitrary positional / `--input-file` /
//! `--stdin` stream under `--alphabet`, run through the same library computation
//! the eye path uses. A stream is treated as a single message under a neutral
//! raw-rows label — no eye honeycomb traversal is claimed for arbitrary input.

use std::process::ExitCode;

use noita_eye_puzzle::analysis::chaining::{self, ChainingConfig};
use noita_eye_puzzle::analysis::chaining_graph::{self, ChainingGraphConfig};
use noita_eye_puzzle::analysis::isomorph_imperfection::{self, IsomorphImperfectionConfig};
use noita_eye_puzzle::analysis::leak_ceiling::{self, LeakCeilingConfig};
use noita_eye_puzzle::analysis::perfect_isomorphism::{self, PerfectIsomorphismConfig};
use noita_eye_puzzle::core::glyph::Glyph;
use noita_eye_puzzle::core::trigram::TrigramValue;
use noita_eye_puzzle::nulls::isomorph_null::{self, IsomorphNullConfig};
use noita_eye_puzzle::report::Report;

use crate::cli::args_analysis::{
    ChainingArgs, ChainingGraphArgs, IsomorphImperfectionArgs, IsomorphNullArgs, LeakCeilingArgs,
    PerfectIsomorphismArgs,
};
use crate::cli::shared::{
    parse_cli_sequence, resolve_input_text, split_blank_line_messages, stream_message_keys,
};

/// Resolves a file-driven structural-battery stream to its [`TrigramValue`]s plus
/// the declared alphabet size, or an error exit code (after printing the reason).
///
/// A stream input requires `--alphabet`: there is no off-corpus reading-layer
/// default, so the alphabet's char count is the only honest alphabet size. The
/// whole stream is one message; the per-message `5` row delimiter and grid
/// reconstruction are corpus-only.
fn resolve_stream(
    sequence: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
    alphabet: Option<&str>,
) -> Result<(Vec<TrigramValue>, usize), ExitCode> {
    let Some(alphabet_spec) = alphabet else {
        eprintln!("a stream input requires --alphabet (its char count is the alphabet size)");
        return Err(ExitCode::FAILURE);
    };
    let text = match resolve_input_text(sequence, input_file, stdin) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let parsed = match parse_cli_sequence(&text, Some(alphabet_spec), false) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let mut values = Vec::with_capacity(parsed.glyphs.len());
    for glyph in parsed.glyphs {
        let Ok(raw) = u8::try_from(glyph.0) else {
            eprintln!("alphabet symbol value {} exceeds 255", glyph.0);
            return Err(ExitCode::FAILURE);
        };
        match TrigramValue::new(raw) {
            Ok(value) => values.push(value),
            Err(raw) => {
                eprintln!("symbol value {raw} exceeds 124");
                return Err(ExitCode::FAILURE);
            }
        }
    }
    Ok((values, alphabet_spec.chars().count()))
}

/// Converts one message's parsed cipher-alphabet glyphs to bounded
/// [`TrigramValue`]s, printing a labelled error and returning the failure exit
/// code on an out-of-range symbol. Shares the per-symbol bound checks with
/// [`resolve_stream`]; factored out for the per-message multi-stream path.
fn glyphs_to_trigram_values(glyphs: Vec<Glyph>) -> Result<Vec<TrigramValue>, ExitCode> {
    let mut values = Vec::with_capacity(glyphs.len());
    for glyph in glyphs {
        let Ok(raw) = u8::try_from(glyph.0) else {
            eprintln!("alphabet symbol value {} exceeds 255", glyph.0);
            return Err(ExitCode::FAILURE);
        };
        match TrigramValue::new(raw) {
            Ok(value) => values.push(value),
            Err(raw) => {
                eprintln!("symbol value {raw} exceeds 124");
                return Err(ExitCode::FAILURE);
            }
        }
    }
    Ok(values)
}

/// A resolved file-driven multi-message stream: the per-message [`TrigramValue`]s,
/// one display key per message, and the declared alphabet size (its char count).
type ResolvedStreamMulti = (Vec<Vec<TrigramValue>>, Vec<&'static str>, usize);

/// Resolves a file-driven *multi-message* structural-battery stream: like
/// [`resolve_stream`] but split into one or more messages on blank-line
/// boundaries (see [`split_blank_line_messages`]), each tagged with a display key
/// from [`stream_message_keys`]. Used by the cross-message detectors
/// (`perfectiso`, `isomorphimperf`), whose internal-violation test only carries
/// signal across >= 2 distinct messages. Within a message, symbols are parsed
/// exactly as the single-message path parses them, and an input with no
/// blank-line separator yields exactly one message, so this is fully backward
/// compatible. The keys are display-only; the detectors key on message position.
/// The declared alphabet size (the alphabet's char count) is returned alongside, as
/// some instruments (e.g. `leakceiling`) thread it into their supply/demand/bounds.
fn resolve_stream_multi(
    sequence: Option<&str>,
    input_file: Option<&std::path::PathBuf>,
    stdin: bool,
    alphabet: Option<&str>,
) -> Result<ResolvedStreamMulti, ExitCode> {
    let Some(alphabet_spec) = alphabet else {
        eprintln!("a stream input requires --alphabet (its char count is the alphabet size)");
        return Err(ExitCode::FAILURE);
    };
    let text = match resolve_input_text(sequence, input_file, stdin) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return Err(ExitCode::FAILURE);
        }
    };
    let blocks = split_blank_line_messages(&text);
    if blocks.is_empty() {
        eprintln!("input contained no symbols");
        return Err(ExitCode::FAILURE);
    }
    let mut messages = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let parsed = match parse_cli_sequence(block, Some(alphabet_spec), false) {
            Ok(parsed) => parsed,
            Err(error) => {
                eprintln!("{error}");
                return Err(ExitCode::FAILURE);
            }
        };
        messages.push(glyphs_to_trigram_values(parsed.glyphs)?);
    }
    let keys = stream_message_keys(messages.len());
    Ok((messages, keys, alphabet_spec.chars().count()))
}

/// Renders a structural-battery report to stdout, or prints a labelled error to
/// stderr, returning the matching exit code. `print!` (not `println!`) because
/// [`Report::render`] is already newline-terminated.
fn emit_report<R: Report, E: std::fmt::Display>(label: &str, result: Result<R, E>) -> ExitCode {
    match result {
        Ok(report) => {
            print!("{}", report.render());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{label}: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `chaining`: Experiment 7B alphabet-chaining structural control.
///
/// With no input flags, runs the verified eye corpus unchanged (the tuning flags
/// `--seed`/`--trials`/`--min-period`/`--max-period` still apply). With a stream
/// input, runs the same calibrated chaining signature over the arbitrary stream,
/// regenerating the Vigenere positive control and the independent-substitution
/// null to the stream's length and `--alphabet`.
pub(crate) fn run_chaining(args: &ChainingArgs) -> ExitCode {
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        let config = ChainingConfig {
            seed: args.seed,
            trials: args.trials,
            min_period: args.min_period,
            max_period: args.max_period,
            alphabet_size: chaining::DEFAULT_ALPHABET_SIZE,
        };
        return emit_report("chaining error", chaining::run_chaining(config));
    }
    let (values, alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let config = ChainingConfig {
        seed: args.seed,
        trials: args.trials,
        min_period: args.min_period,
        max_period: args.max_period,
        alphabet_size,
    };
    emit_report(
        "chaining error",
        chaining::chaining_for_stream(config, &[values]),
    )
}

/// `isomorphnull`: Experiment 7A real isomorphs vs within-message shuffle null.
///
/// With no input flags, runs the verified eye corpus unchanged. With a stream
/// input, runs the same real-vs-shuffle comparison over the arbitrary stream;
/// the within-message shuffle null is matched to the stream's own length and
/// multiset. The statistic is equality-based, so `--alphabet` only declares the
/// symbol identity (its size is not threaded into the config).
pub(crate) fn run_isomorphnull(args: &IsomorphNullArgs) -> ExitCode {
    let config = IsomorphNullConfig {
        seed: args.seed,
        trials: args.trials,
        min_window: isomorph_null::DEFAULT_MIN_WINDOW,
        max_window: isomorph_null::DEFAULT_MAX_WINDOW,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "isomorph null error",
            isomorph_null::run_isomorph_null(config),
        );
    }
    let (values, _alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    emit_report(
        "isomorph null error",
        isomorph_null::isomorph_null_for_stream(config, &values),
    )
}

/// `chaining-graph`: Thread 5 graph-chaining conflict and coverage audit.
///
/// With no input flags, runs the verified eye corpus unchanged. With a stream
/// input, runs the same audit over the arbitrary stream; `--alphabet`'s char count
/// is the coverage denominator. The synthetic non-commutative positive control is
/// stream-independent, so it self-validates the instrument on any input.
pub(crate) fn run_chaining_graph(args: &ChainingGraphArgs) -> ExitCode {
    let config = ChainingGraphConfig {
        seed: args.seed,
        trials: args.trials,
        ..ChainingGraphConfig::default()
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "chaining-graph error",
            chaining_graph::run_chaining_graph(config),
        );
    }
    let (values, alphabet_size) = match resolve_stream(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    emit_report(
        "chaining-graph error",
        chaining_graph::chaining_graph_for_stream(config, &[values], alphabet_size),
    )
}

/// `perfectiso`: Thread 3 perfect-isomorphism / allomorph-consistency scan.
///
/// With no input flags, runs the verified eye corpus unchanged (the tuning flags
/// `--seed`/`--trials`/`--min-window`/`--max-window` still apply). With a stream
/// input, runs the same mapping-independent compute over the supplied message(s)
/// under a neutral raw-rows label: blank lines separate messages (see
/// [`resolve_stream_multi`]), so the cross-message detector compares aligned
/// repeats across them. The scan is equality- and gap-based, so `--alphabet` only
/// declares symbol identity (its size is not threaded into the config). The eye
/// wiki-regression checks are replaced off-corpus by the stream-independent
/// synthetic short-island positive control, which self-validates the detector on
/// any input.
///
/// Honest limitation: perfect isomorphism compares aligned repeats *across* >= 2
/// messages, so a single-message stream has an empty cross-message catalog by
/// construction and the internal-violation test does not apply to it (the report
/// says so plainly). A genuine cross-message repeat across the user's >= 2
/// messages surfaces as a mapping-independent structural **candidate** to recheck,
/// never a recovery or decode.
pub(crate) fn run_perfectiso(args: &PerfectIsomorphismArgs) -> ExitCode {
    let config = PerfectIsomorphismConfig {
        seed: args.seed,
        trials: args.trials,
        min_window: args.min_window,
        max_window: args.max_window,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "perfect-isomorphism error",
            perfect_isomorphism::run_perfect_isomorphism(config),
        );
    }
    let (messages, keys, _alphabet_size) = match resolve_stream_multi(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(parts) => parts,
        Err(code) => return code,
    };
    emit_report(
        "perfect-isomorphism error",
        perfect_isomorphism::perfect_isomorphism_for_stream(config, &keys, &messages),
    )
}

/// `isomorphimperf`: Thread G2 forward isomorph-imperfection disproof scan.
///
/// With no input flags, runs the verified eye corpus unchanged (the tuning flags
/// `--seed`/`--null-trials`/`--family-trials` still apply). With a stream input,
/// runs the same mapping-independent break-localization + synthetic
/// imperfect-family self-validation over the supplied message(s) under a neutral
/// raw-rows label: blank lines separate messages (see [`resolve_stream_multi`]),
/// so the cross-message break detector compares aligned repeats across them. The
/// scan is equality- and gap-based, so `--alphabet` only declares symbol identity
/// (its size is not threaded into the config). The eye benign-region attribution
/// is keyed to eye message names and so is inert off-corpus; the stream-independent
/// synthetic imperfect-family positive control self-validates the detector on any
/// input.
///
/// Honest limitation: isomorph imperfection is a *cross-message* test (a robust
/// internal violation is a same-gap-pattern repeat that diverges between two
/// messages; the detector skips same-message pairs and a strong record must span
/// two or more distinct messages). A single-message stream therefore has an empty
/// cross-message break catalog by construction and the internal-violation test does
/// not apply to it (the report says so plainly). A robust break localized across
/// the user's >= 2 messages surfaces as a mapping-independent structural
/// **candidate** to recheck against a structure-preserving null, never a recovery.
pub(crate) fn run_isomorphimperf(args: &IsomorphImperfectionArgs) -> ExitCode {
    let config = IsomorphImperfectionConfig {
        seed: args.seed,
        null_trials: args.null_trials,
        family_trials: args.family_trials,
        stutter_sensitivity: args.stutter_sensitivity,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report(
            "isomorph-imperfection error",
            isomorph_imperfection::run_isomorph_imperfection(config),
        );
    }
    let (messages, keys, _alphabet_size) = match resolve_stream_multi(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(parts) => parts,
        Err(code) => return code,
    };
    emit_report(
        "isomorph-imperfection error",
        isomorph_imperfection::isomorph_imperfection_for_stream(config, &keys, &messages),
    )
}

/// `leakceiling`: narrowed leak supply / demand / bounds instrument.
///
/// With no input flags, runs the verified eye corpus unchanged (the full G3 report,
/// including the fitted coverage model, its single-point fit, and the scaling
/// sweep). With a stream input, runs only the transparent, control-free pieces over
/// the supplied message(s) under a neutral raw-rows label: measured supply (Part A),
/// analytic coupon-collector demand (Part B), and information-theoretic / counting
/// bounds (Part C). Blank lines separate messages (see [`resolve_stream_multi`]).
///
/// Unlike the equality/gap-based scans, `--alphabet`'s char count IS threaded here:
/// it is the chaining-graph coverage denominator, the coupon-collector `N`, and the
/// `log2(N!)` key budget. The stream path deliberately omits the fitted coverage /
/// undecidable-fraction prediction (its only free constant has no non-circular
/// control), so it makes no recoverability prediction and needs no positive control:
/// Parts A/B/C are direct measurements and textbook bounds, control-free by
/// construction. The eye path keeps the full report and its calibration intact.
pub(crate) fn run_leakceiling(args: &LeakCeilingArgs) -> ExitCode {
    let config = LeakCeilingConfig {
        chaining_window_len: args.chaining_window_len,
        chaining_core_len: args.chaining_core_len,
        isomorph_window_len: args.isomorph_window_len,
    };
    if args.sequence.is_none() && args.input_file.is_none() && !args.stdin {
        return emit_report("leak-ceiling error", leak_ceiling::run_leak_ceiling(config));
    }
    let (messages, keys, alphabet_size) = match resolve_stream_multi(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
        args.alphabet.as_deref(),
    ) {
        Ok(parts) => parts,
        Err(code) => return code,
    };
    emit_report(
        "leak-ceiling error",
        leak_ceiling::leak_ceiling_for_stream(config, &keys, &messages, alphabet_size),
    )
}
