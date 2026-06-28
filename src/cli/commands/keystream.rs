//! The `keystream` subcommand (polyalphabetic Vigenere/Beaufort/autokey crack)
//! and the `profile` subcommand (ciphertext structural profile).

use std::process::ExitCode;

use noita_eye_puzzle::attack::{keystream, profile, quadgram};

use crate::cli::args_attack::{KeystreamArgs, ProfileArgs};
use crate::cli::shared::{display_prefix, resolve_input_text};

pub(crate) fn run_profile(args: &ProfileArgs) -> ExitCode {
    let report = if let Some(puzzle) = args.puzzle {
        profile::profile_puzzle(puzzle.into()).render_report()
    } else {
        // No built-in puzzle selected: read raw text from the file or stdin.
        let text =
            match resolve_input_text(None, args.input_file.as_ref(), args.input_file.is_none()) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("failed to read input: {error}");
                    return ExitCode::FAILURE;
                }
            };
        profile::profile_text(&text).render_report()
    };
    print!("{report}");
    ExitCode::SUCCESS
}

pub(crate) fn run_keystream(args: &KeystreamArgs) -> ExitCode {
    let ciphertext = match keystream_ciphertext(args) {
        Ok(ciphertext) => ciphertext,
        Err(code) => return code,
    };
    if ciphertext.is_empty() {
        eprintln!("no cipher letters in input");
        return ExitCode::FAILURE;
    }
    let model = match quadgram::QuadgramModel::english() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("quadgram model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let families: Vec<keystream::KeystreamFamily> = if args.family.is_empty() {
        keystream::KeystreamFamily::all().to_vec()
    } else {
        args.family.iter().map(|family| (*family).into()).collect()
    };
    let key_lengths: Vec<usize> = if let Some(fixed) = args.key_len {
        vec![fixed.max(1)]
    } else {
        let lo = args.min_key_len.max(1);
        let hi = args.max_key_len.max(lo);
        (lo..=hi).collect()
    };
    let cfg = keystream::KeystreamSearchConfig {
        alphabet_size: args.alphabet_size.max(1),
        restarts: args.restarts,
        iterations: args.iterations,
        anneal_temp: args.anneal_temp,
        seed: args.seed,
        null_trials: args.null_trials,
        matched_null_trials: args.matched_null_trials,
    };

    let mut candidates = Vec::new();
    for &family in &families {
        for &key_len in &key_lengths {
            candidates.push(keystream::crack_with_model(
                &ciphertext,
                family,
                key_len,
                &cfg,
                &model,
            ));
        }
    }

    print_keystream_table(&candidates);
    print_keystream_best(&candidates);

    let label = args
        .label
        .clone()
        .or_else(|| args.puzzle.map(|puzzle| puzzle.label().to_owned()))
        .unwrap_or_else(|| "input".to_owned());
    emit_keystream_verdict(&candidates, &args.candidates_dir, &label, args.seed)
}

fn keystream_ciphertext(args: &KeystreamArgs) -> Result<Vec<u8>, ExitCode> {
    if let Some(puzzle) = args.puzzle {
        return Ok(keystream::normalize_puzzle(
            keystream::practice_puzzle_text(puzzle.into()),
        ));
    }
    match resolve_input_text(None, args.input_file.as_ref(), args.stdin) {
        Ok(text) => Ok(keystream::normalize_puzzle(&text)),
        Err(error) => {
            eprintln!("failed to read input: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn print_keystream_table(candidates: &[keystream::KeystreamCandidate]) {
    println!("Keystream candidates: hypothesis, not decode");
    println!(
        "survives requires both nulls: matched_z (search-overfitting gate) and null_z (ct-autokey key-independence-leak gate)"
    );
    println!(
        "{:11} {:>3} {:>10} {:>12} {:>10} {:>8} {:>10} {:>8}",
        "family", "L", "best", "matched_mean", "matched_z", "null_z", "round_trip", "survives"
    );
    for candidate in candidates {
        println!(
            "{:11} {:>3} {:>10.4} {:>12.4} {:>10.2} {:>8.2} {:>10} {:>8}",
            candidate.family.name(),
            candidate.key_len,
            candidate.best_score,
            candidate.matched_mean,
            candidate.matched_z,
            candidate.z,
            candidate.round_trip_ok,
            candidate.survives,
        );
    }
}

fn print_keystream_best(candidates: &[keystream::KeystreamCandidate]) {
    // Rank by matched_z (the survival statistic), survivors first.
    let best = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .max_by(|left, right| left.matched_z.total_cmp(&right.matched_z))
        .or_else(|| {
            candidates
                .iter()
                .max_by(|left, right| left.matched_z.total_cmp(&right.matched_z))
        });
    let Some(best) = best else {
        return;
    };
    println!(
        "best (highest matched_z{}):",
        if best.survives {
            ", surviving"
        } else {
            ", non-surviving"
        }
    );
    println!(
        "  family: {}  key-len: {}",
        best.family.name(),
        best.key_len
    );
    println!("  key: {:?}", best.key);
    println!(
        "  matched_z: {:.4}  matched_margin: {:.4}  matched_mean: {:.4}",
        best.matched_z,
        best.best_score - best.matched_mean,
        best.matched_mean,
    );
    println!(
        "  random-key null_z (ct-autokey-leak gate): {:.4}  null_mean: {:.4}",
        best.z, best.null_mean,
    );
    println!(
        "  decrypt: {}",
        display_prefix(&best.render_plaintext(), 120)
    );
}

fn emit_keystream_verdict(
    candidates: &[keystream::KeystreamCandidate],
    candidates_dir: &std::path::Path,
    label: &str,
    seed: u64,
) -> ExitCode {
    let survivors: Vec<&keystream::KeystreamCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.survives)
        .collect();
    if survivors.is_empty() {
        println!(
            "honest-negative: no (family, key length) candidate cleared the round-trip + matched-null + random-key-null (each z>={:.0} and margin>={:.0} nat) + held-out gates. A clean honest negative is a success, not an error.",
            keystream::Z_THRESHOLD,
            keystream::MIN_NAT_MARGIN,
        );
        return ExitCode::SUCCESS;
    }
    for candidate in survivors {
        println!(
            "hypothesis (not a confirmed decode; cleared both null gates): family={} key-len={} matched_z={:.2} null_z={:.2}",
            candidate.family.name(),
            candidate.key_len,
            candidate.matched_z,
            candidate.z,
        );
        println!("  full decrypt: {}", candidate.render_plaintext());
        match keystream::write_keystream_record(candidates_dir, label, seed, candidate) {
            Ok(path) => println!("  record: {}", path.display()),
            Err(error) => {
                eprintln!("failed to write candidate record: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}
