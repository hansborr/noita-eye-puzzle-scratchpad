//! The `solve` subcommand: hypothesis search + scoring, the clock-free
//! provenance command, and the candidate-record auto-log.

use std::process::ExitCode;

use noita_eye_puzzle::{
    attack::{codec, language, solve},
    ciphers,
    core::ingest,
};

use crate::cli::args_attack::{SolveArgs, SolveCodecArg, SolveFamilyArg};
use crate::cli::shared::{display_prefix, parse_cli_sequence, resolve_input_text};

const DEFAULT_SOLVE_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub(crate) fn run_solve(args: &SolveArgs) -> ExitCode {
    let text = match resolve_input_text(
        args.ciphertext.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    ) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("failed to read input: {error}");
            return ExitCode::FAILURE;
        }
    };
    let alphabet_spec = args
        .alphabet
        .as_deref()
        .or((!args.honeycomb).then_some(DEFAULT_SOLVE_ALPHABET));
    let parsed = match parse_cli_sequence(&text, alphabet_spec, args.honeycomb) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let english = match language::english_model() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("English model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let finnish = match language::finnish_model() {
        Ok(model) => model,
        Err(error) => {
            eprintln!("Finnish model error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let cipher_alphabet_size = solve_alphabet_size(args, alphabet_spec, &parsed);
    let mappings = solve_mapping_strategy(args, cipher_alphabet_size, english.alphabet().len());
    let request = solve::SolveRequest {
        ciphertext: &parsed.glyphs,
        // Transparent (pass-through) symbols recorded at ingest — e.g. puzzle
        // `six`'s preserved spaces — reinserted into each candidate's rendered
        // text at codec-aware spots; empty (a strict no-op) for inputs without
        // any (the eyes, the default letter path).
        transparent: &parsed.transparent,
        space: solve::HypothesisSpace {
            families: solve_families(cipher_alphabet_size, &args.family),
            // Codec stage: Identity by default (the eyes' 83-symbol alphabet already
            // spans the 29-letter language); --codec selects a Fixed codec and
            // --codec-search flips to the bounded codec enumeration that widens a
            // small cipher alphabet (5/6/12 symbols) enough to host the language.
            codec: solve_codec_strategy(args),
            mappings,
            language: solve::LanguageChoice::Both,
            cipher_alphabet_size,
            seed: args.seed,
            null_trials: args.null_trials,
        },
        english: &english,
        finnish: &finnish,
    };

    let candidates = match solve::solve(&request) {
        Ok(candidates) => candidates,
        Err(error) => {
            eprintln!("solve error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_solve_report(&candidates);

    // Auto-log: persist the verbatim claim ceiling, all three gates, and both
    // language scores as a labelled HYPOTHESIS (the eyes honest-negative record
    // included). This is load-bearing claim discipline, not just stdout.
    //
    // The provenance string is the exact, clock-free command that reproduces this
    // record: every run-affecting flag is printed explicitly so the
    // command is default-drift-proof.
    let provenance = solve_provenance_command(args);
    match solve::log_solve_run(
        &args.candidates_dir,
        solve::SolveRunIdentity {
            label: &args.label,
            seed: args.seed,
            cipher_alphabet_size,
            // The ciphertext (cipher-symbol) count, so the record header reports the
            // real length even on the zero-candidate honest negative.
            total_symbols: parsed.glyphs.len(),
        },
        &provenance,
        &candidates,
        &english,
        &finnish,
    ) {
        Ok(path) => {
            println!("record: {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to write candidate record: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Builds the canonical, clock-free command embedded in the solve record's
/// Provenance section: the copy-pasteable invocation that reproduces
/// the record byte-for-byte. Every run-affecting flag is printed EXPLICITLY (no
/// reliance on compiled-in defaults) so the command stays reproducible even if a
/// default later drifts. Only the codec/mapping mode actually in effect is
/// emitted (`--codec-search` OR `--mapping-search` OR a non-identity `--codec`);
/// the eyes/default path emits none of them.
fn solve_provenance_command(args: &SolveArgs) -> String {
    let mut parts: Vec<String> = vec!["solve".to_owned()];
    if let Some(path) = args.input_file.as_ref() {
        parts.push(format!("--input-file {}", path.display()));
    } else if args.stdin {
        parts.push("--stdin".to_owned());
    } else if let Some(ciphertext) = args.ciphertext.as_ref() {
        // Positional ciphertext (rare for these file-backed puzzles); emit it
        // verbatim right after the subcommand.
        parts.push(ciphertext.clone());
    }
    if args.honeycomb {
        parts.push("--honeycomb".to_owned());
    }
    if let Some(alphabet) = args.alphabet.as_ref() {
        parts.push(format!("--alphabet {alphabet}"));
    }
    if args.codec_search {
        parts.push("--codec-search".to_owned());
    } else if args.mapping_search {
        parts.push("--mapping-search".to_owned());
    } else if matches!(args.codec, SolveCodecArg::Honeycomb) {
        parts.push("--codec honeycomb".to_owned());
    }
    parts.push(format!("--restarts {}", args.restarts));
    parts.push(format!("--iterations {}", args.iterations));
    parts.push(format!("--null-trials {}", args.null_trials));
    parts.push(format!("--seed 0x{:016x}", args.seed));
    parts.push(format!("--label {}", args.label));
    parts.push(format!(
        "--candidates-dir {}",
        args.candidates_dir.display()
    ));
    format!("make run ARGS='{}'", parts.join(" "))
}

/// Resolves the codec stage from the CLI flags. `--codec-search` takes precedence
/// and flips the stage to the bounded library enumeration ([`codec::default_codec_search`]);
/// otherwise a single declared [`codec::AnyCodec`] is scored (`--codec`). The
/// no-flag default is `Fixed([Identity])`, byte-for-byte the pre-flag behavior.
fn solve_codec_strategy(args: &SolveArgs) -> codec::CodecStrategy {
    if args.codec_search {
        return codec::CodecStrategy::Search(codec::default_codec_search(args.seed));
    }
    let codec = match args.codec {
        SolveCodecArg::Identity => codec::AnyCodec::Identity,
        SolveCodecArg::Honeycomb => codec::honeycomb_codec(),
    };
    codec::CodecStrategy::Fixed(vec![codec])
}

fn solve_mapping_strategy(
    args: &SolveArgs,
    cipher_alphabet_size: usize,
    language_alphabet_size: usize,
) -> solve::MappingStrategy {
    // `--codec-search` enables a WIDENING codec search: a grouping codec lifts the
    // bare cipher alphabet to base^group_len, which the default `Fixed` mapping
    // (sized to the bare alphabet) cannot host. A codec search therefore REQUIRES a
    // mapping search over the widened alphabet, so auto-enable it (with a one-line
    // note) when the user asked for `--codec-search` but not `--mapping-search`.
    // The no-flag default is unchanged: neither set => `Fixed`.
    if args.codec_search && !args.mapping_search {
        eprintln!(
            "note: --codec-search implies a mapping search over the widened alphabet; enabling --mapping-search"
        );
    }
    if args.mapping_search || args.codec_search {
        solve::MappingStrategy::Search(solve::MappingSearch {
            restarts: args.restarts,
            iterations: args.iterations,
            anneal: (args.anneal_temp > 0.0).then_some(solve::AnnealSchedule {
                start_temperature: args.anneal_temp,
                end_temperature: 0.0,
            }),
            seed: args.seed,
        })
    } else {
        solve::MappingStrategy::Fixed(solve_mappings(cipher_alphabet_size, language_alphabet_size))
    }
}

fn solve_alphabet_size(
    args: &SolveArgs,
    alphabet_spec: Option<&str>,
    parsed: &ingest::ParsedSequence,
) -> usize {
    if args.honeycomb {
        return ciphers::EYE_READING_ALPHABET_SIZE;
    }
    if let Some(spec) = alphabet_spec {
        return spec.chars().count();
    }
    parsed
        .glyphs
        .iter()
        .map(|glyph| usize::from(glyph.0) + 1)
        .max()
        .unwrap_or(0)
}

fn solve_families(
    cipher_alphabet_size: usize,
    requested: &[SolveFamilyArg],
) -> Vec<solve::CipherFamilySpec> {
    let selected = if requested.is_empty() {
        vec![SolveFamilyArg::Identity, SolveFamilyArg::Caesar]
    } else {
        requested.to_vec()
    };
    let mut families = Vec::new();
    for family in selected {
        match family {
            SolveFamilyArg::Identity => families.push(solve::CipherFamilySpec {
                label: "identity".to_owned(),
                ciphers: vec![ciphers::AnyCipher::Identity],
            }),
            SolveFamilyArg::Caesar => families.push(solve::CipherFamilySpec {
                label: "Caesar".to_owned(),
                ciphers: caesar_family(cipher_alphabet_size),
            }),
            SolveFamilyArg::Transposition => families.push(solve::CipherFamilySpec {
                label: "transposition".to_owned(),
                ciphers: transposition_family(cipher_alphabet_size),
            }),
        }
    }
    families
}

fn caesar_family(cipher_alphabet_size: usize) -> Vec<ciphers::AnyCipher> {
    (0..cipher_alphabet_size)
        .filter_map(
            |shift| match ciphers::CaesarKey::new(cipher_alphabet_size, shift) {
                Ok(key) => Some(ciphers::AnyCipher::Caesar(key)),
                Err(_error) => None,
            },
        )
        .collect()
}

fn transposition_family(cipher_alphabet_size: usize) -> Vec<ciphers::AnyCipher> {
    let max_period = cipher_alphabet_size.clamp(2, 6);
    (2..=max_period)
        .filter_map(|period| {
            let permutation = (0..period).rev().collect::<Vec<_>>();
            match ciphers::TranspositionKey::new(period, permutation) {
                Ok(key) => Some(ciphers::AnyCipher::Transposition(key)),
                Err(_error) => None,
            }
        })
        .collect()
}

fn solve_mappings(
    cipher_alphabet_size: usize,
    language_alphabet_size: usize,
) -> Vec<solve::Mapping> {
    if cipher_alphabet_size <= language_alphabet_size {
        vec![solve::Mapping::identity(cipher_alphabet_size)]
    } else {
        vec![solve::Mapping::from_table(
            (0..cipher_alphabet_size)
                .map(|symbol| symbol % language_alphabet_size)
                .collect(),
        )]
    }
}

fn print_solve_report(candidates: &[solve::Candidate]) {
    println!("Solve candidates: HYPOTHESIS, not decode");
    println!("candidates: {}", candidates.len());
    let Some(top) = candidates.first() else {
        println!("no candidate survived the cipher-layer round-trip gate");
        return;
    };
    println!("top:");
    println!("  cipher: {}", top.cipher.name());
    println!("  language: {:?}", top.language);
    println!("  crypto_round_trip_ok: {}", top.crypto_round_trip_ok);
    println!("  score: {:.6}", top.score);
    println!("  heldout_mapping_score: {:.6}", top.heldout_mapping_score);
    println!("  null_mean: {:.6}", top.null_mean);
    println!("  beats_null: {}", top.beats_null);
    println!(
        "  rendered_text: {}",
        display_prefix(&top.rendered_text, 120)
    );
}
