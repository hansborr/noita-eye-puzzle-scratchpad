//! Handler for `shadowfinish`: crib-free finish over shadow q classes.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::process::ExitCode;

use noita_eye_puzzle::analysis::shadow_finish::{
    self, FinishCandidate, ShadowFinishReport, ShadowFinishSelfTest, ShadowFinishTable,
    ShadowFinishVerdict,
};

use crate::cli::args_shadowfinish::ShadowfinishArgs;
use crate::cli::shared::{parse_cli_sequence, resolve_input_text};

/// Dispatches the `shadowfinish` subcommand.
pub(crate) fn run_shadowfinish(args: &ShadowfinishArgs) -> ExitCode {
    if args.self_test {
        return run_self_test(args.seed);
    }
    run_real(args)
}

fn run_self_test(seed: u64) -> ExitCode {
    match shadow_finish::shadow_finish_self_test(seed) {
        Ok(report) => {
            print_self_test(seed, &report);
            if report.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("shadowfinish self-test error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_real(args: &ShadowfinishArgs) -> ExitCode {
    let controls = match shadow_finish::shadow_finish_self_test(args.seed) {
        Ok(report) if report.passed => report,
        Ok(report) => {
            print_self_test(args.seed, &report);
            eprintln!("shadowfinish refused real-file output because self-test failed");
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("shadowfinish self-test error: {error}");
            return ExitCode::FAILURE;
        }
    };

    let Some(artifact_path) = args.artifact.as_ref() else {
        eprintln!("shadowfinish needs --artifact <shadowsearch-output.json>");
        return ExitCode::FAILURE;
    };
    let artifact_text = match std::fs::read_to_string(artifact_path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!(
                "failed to read artifact {}: {error}",
                artifact_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let ciphertext = match read_ciphertext(args) {
        Ok(values) => values,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let wordlist = match load_wordlist(args) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let extra_tables = match load_tables(&args.table_files) {
        Ok(tables) => tables,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    print_self_test(args.seed, &controls);
    let config = args.into();
    let report = match shadow_finish::run_shadow_finish(
        &artifact_text,
        &ciphertext,
        &wordlist,
        &extra_tables,
        &config,
    ) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("shadowfinish error: {error}");
            return ExitCode::FAILURE;
        }
    };
    print_report(&report, artifact_path);
    if let Some(path) = args.output.as_ref()
        && let Err(error) = std::fs::write(path, report_json(&report))
    {
        eprintln!(
            "failed to write shadowfinish JSON {}: {error}",
            path.display()
        );
        return ExitCode::FAILURE;
    }
    if let Some(path) = maybe_write_candidate(args, &report) {
        match path {
            Ok(path) => println!("  candidate hypothesis: {}", path.display()),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
}

fn read_ciphertext(args: &ShadowfinishArgs) -> Result<Vec<u16>, String> {
    let text = resolve_input_text(
        args.sequence.as_deref(),
        args.input_file.as_ref(),
        args.stdin,
    )
    .map_err(|error| format!("failed to read ciphertext input: {error}"))?;
    let parsed = parse_cli_sequence(&text, args.alphabet.as_deref(), false)
        .map_err(|error| error.to_string())?;
    Ok(parsed.glyphs.iter().map(|glyph| glyph.0).collect())
}

fn load_wordlist(args: &ShadowfinishArgs) -> Result<String, String> {
    if let Some(path) = args.wordlist.as_ref() {
        return std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read wordlist {}: {error}", path.display()));
    }
    if let Some(path) = args.word_corpus_file.as_ref() {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read corpus {}: {error}", path.display()))?;
        return Ok(derive_wordlist(&text));
    }
    Err("shadowfinish needs --wordlist or --word-corpus-file".to_owned())
}

fn derive_wordlist(text: &str) -> String {
    let mut counts = BTreeMap::<String, u64>::new();
    let mut word = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphabetic() {
            word.push(ch.to_ascii_lowercase());
        } else if !word.is_empty() {
            *counts.entry(std::mem::take(&mut word)).or_insert(0) += 1;
        }
    }
    if !word.is_empty() {
        *counts.entry(word).or_insert(0) += 1;
    }
    let mut rows = counts.into_iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    rows.into_iter()
        .map(|(word, count)| format!("{word} {count}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn load_tables(paths: &[std::path::PathBuf]) -> Result<Vec<ShadowFinishTable>, String> {
    let mut tables = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read table file {}: {error}", path.display()))?;
        let parsed = shadow_finish::parse_table_file(&text).map_err(|error| error.to_string())?;
        tables.extend(parsed);
    }
    Ok(tables)
}

fn print_self_test(seed: u64, report: &ShadowFinishSelfTest) {
    println!("shadowfinish self-test (seed=0x{seed:016x}):");
    println!(
        "  planted positive: {} (candidate verdict: {}, roundtrip invariant: {}, truth rank {:?}, margin vs junk max {:.4})",
        pass_fail(
            report.positive_candidate_verdict
                && report.positive_roundtrip
                && report.positive_truth_top_k
        ),
        pass_fail(report.positive_candidate_verdict),
        pass_fail(report.positive_roundtrip),
        report.positive_truth_rank,
        report.positive_margin_vs_junk_max
    );
    println!(
        "  vacuity control: {} (alternate roundtrip: {}, distinct plaintext: {})",
        pass_fail(report.vacuity_both_roundtrip && report.vacuity_distinct_plaintexts),
        report.vacuity_both_roundtrip,
        report.vacuity_distinct_plaintexts
    );
    println!(
        "  wrong-plaintext sanity: {} (inside junk: {})",
        pass_fail(report.wrong_plaintext_no_roundtrip),
        report.wrong_plaintext_inside_junk
    );
    println!("  SELF-TEST: {}", pass_fail(report.passed));
}

fn print_report(report: &ShadowFinishReport, artifact_path: &std::path::Path) {
    println!("shadowfinish: {}", artifact_path.display());
    println!(
        "  surface: {} class(es) x {} perms x {} orders x {} table(s) x {} phase(s) = {} interpretations",
        report.surface.classes,
        report.surface.permutations_per_class,
        report.surface.digit_orders,
        report.surface.tables,
        report.surface.phases,
        report.surface.total_interpretations
    );
    println!(
        "  dropped q-symbols: phase0 {}{}",
        report.surface.phase0_dropped_q_symbols,
        report
            .surface
            .phase1_dropped_q_symbols
            .map_or(String::new(), |drop| format!(", phase1 {drop}"))
    );
    println!("  tables: {}", report.table_names.join(", "));
    println!(
        "  table note: table count is object count; ascii32 and ascii96 share byte decoding for 6-bit values 0..63"
    );
    println!(
        "  tier A: visited {}, retained {}, top-K dropped {}, loose rejects {}, strict passes {}",
        report.tier_a.visited,
        report.tier_a.retained_for_tier_b,
        report.tier_a.top_k_dropped,
        report.tier_a.loose_rejects,
        report.tier_a.strict_passes
    );
    println!(
        "  matched null: trials {}, observed {:.4}, null_ge {}, p_emp {:.4}, margin vs null max {:.4}",
        report.calibration.trials,
        report.calibration.observed_best,
        report.calibration.null_ge,
        report.calibration.p_emp,
        report.calibration.margin_vs_null_max
    );
    println!("  null scope: {}", report.calibration.null_scope);
    if let Some(best) = report.top_candidates.first() {
        println!(
            "  best: class {} table {} {} {} score {:.4} word {:.4} anchor {:.4} roundtrip invariant {}",
            best.class_index,
            best.table,
            best.phase.label(),
            best.order.label(),
            best.combined_score,
            best.word_score,
            best.anchor_score,
            best.roundtrip
        );
        println!(
            "  roundtrip note: {}",
            shadow_finish::ROUNDTRIP_INVARIANT_NOTE
        );
    }
    println!("  VERDICT: {}", report.verdict.label());
}

fn maybe_write_candidate(
    args: &ShadowfinishArgs,
    report: &ShadowFinishReport,
) -> Option<Result<std::path::PathBuf, String>> {
    if report.verdict != ShadowFinishVerdict::Candidate {
        return None;
    }
    let candidate = report.top_candidates.first()?.clone();
    Some(write_candidate_record(args, report, &candidate))
}

fn write_candidate_record(
    args: &ShadowfinishArgs,
    report: &ShadowFinishReport,
    candidate: &FinishCandidate,
) -> Result<std::path::PathBuf, String> {
    std::fs::create_dir_all(&args.candidates_dir).map_err(|error| {
        format!(
            "failed to create candidates dir {}: {error}",
            args.candidates_dir.display()
        )
    })?;
    let path = args.candidates_dir.join(format!(
        "shadowfinish-{}-seed-{:016x}.md",
        args.label, args.seed
    ));
    std::fs::write(&path, candidate_record(args, report, candidate)).map_err(|error| {
        format!(
            "failed to write candidate record {}: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

fn candidate_record(
    args: &ShadowfinishArgs,
    report: &ShadowFinishReport,
    candidate: &FinishCandidate,
) -> String {
    format!(
        "# Shadowfinish candidate: {}\n\n\
         Stable label: label={} seed=0x{:016x}\n\n\
         ## Verdict\n\n\
         **{} — logged as a HYPOTHESIS, not a verified decode.**\n\n\
         Round-trip invariant satisfied: {}. {}\n\
         Matched-null p_emp: {:.6} (null_ge {}/{})\n\
         Matched-null scope: {}\n\
         Surface: {} interpretations; Tier-A retained {}; top-K dropped {}\n\n\
         ## Candidate Metadata\n\n\
         - class: {}\n\
         - table: {}\n\
         - phase: {}\n\
         - digit order: {}\n\
         - permutation: {:?}\n\
         - combined score: {:.6}\n\
         - quadgram score: {:.6}\n\
         - word score: {:.6}\n\
         - anchor score: {:.6}\n\n\
         ## Candidate cleartext (verbatim; hypothesis)\n\n\
         ```text\n{}\n```\n",
        args.label,
        args.label,
        args.seed,
        report.verdict.label(),
        candidate.roundtrip,
        shadow_finish::ROUNDTRIP_INVARIANT_NOTE,
        report.calibration.p_emp,
        report.calibration.null_ge,
        report.calibration.trials,
        report.calibration.null_scope,
        report.surface.total_interpretations,
        report.tier_a.retained_for_tier_b,
        report.tier_a.top_k_dropped,
        candidate.class_index,
        candidate.table,
        candidate.phase.label(),
        candidate.order.label(),
        candidate.permutation,
        candidate.combined_score,
        candidate.quadgram_score,
        candidate.word_score,
        candidate.anchor_score,
        String::from_utf8_lossy(&candidate.plaintext)
    )
}

fn report_json(report: &ShadowFinishReport) -> String {
    let mut out = String::new();
    writeln!(&mut out, "{{").expect("write to String");
    writeln!(&mut out, "  \"tool\": \"shadowfinish\",").expect("write to String");
    writeln!(&mut out, "  \"verdict\": \"{}\",", report.verdict.label()).expect("write to String");
    writeln!(
        &mut out,
        "  \"roundtrip_semantics\": \"{}\",",
        json_escape(shadow_finish::ROUNDTRIP_INVARIANT_NOTE)
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"surface\": {{\"classes\":{},\"permutations_per_class\":{},\"digit_orders\":{},\"tables\":{},\"phases\":{},\"total_interpretations\":{},\"phase0_dropped_q_symbols\":{},\"phase1_dropped_q_symbols\":{}}},",
        report.surface.classes,
        report.surface.permutations_per_class,
        report.surface.digit_orders,
        report.surface.tables,
        report.surface.phases,
        report.surface.total_interpretations,
        report.surface.phase0_dropped_q_symbols,
        report.surface.phase1_dropped_q_symbols.map_or_else(|| "null".to_owned(), |value| value.to_string())
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"tier_a\": {{\"visited\":{},\"retained_for_tier_b\":{},\"top_k_dropped\":{},\"loose_rejects\":{},\"strict_passes\":{}}},",
        report.tier_a.visited,
        report.tier_a.retained_for_tier_b,
        report.tier_a.top_k_dropped,
        report.tier_a.loose_rejects,
        report.tier_a.strict_passes
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"calibration\": {{\"null_scope\":\"{}\",\"trials\":{},\"observed_best\":{:.8},\"null_ge\":{},\"p_emp\":{:.8},\"null_max\":{:.8},\"margin_vs_null_max\":{:.8}}},",
        json_escape(&report.calibration.null_scope),
        report.calibration.trials,
        report.calibration.observed_best,
        report.calibration.null_ge,
        report.calibration.p_emp,
        report.calibration.null_max,
        report.calibration.margin_vs_null_max
    )
    .expect("write to String");
    writeln!(
        &mut out,
        "  \"top_candidates\": {}",
        candidates_json(&report.top_candidates)
    )
    .expect("write to String");
    writeln!(&mut out, "}}").expect("write to String");
    out
}

fn candidates_json(candidates: &[FinishCandidate]) -> String {
    let rows = candidates
        .iter()
        .map(|candidate| {
            format!(
                "{{\"class_index\":{},\"table\":\"{}\",\"phase\":\"{}\",\"order\":\"{}\",\"permutation\":{},\"combined_score\":{:.8},\"quadgram_score\":{:.8},\"word_score\":{:.8},\"anchor_score\":{:.8},\"strict_valid\":{},\"roundtrip_invariant\":{}}}",
                candidate.class_index,
                json_escape(&candidate.table),
                candidate.phase.label(),
                candidate.order.label(),
                u8_json(&candidate.permutation),
                candidate.combined_score,
                candidate.quadgram_score,
                candidate.word_score,
                candidate.anchor_score,
                candidate.strict_valid,
                candidate.roundtrip
            )
        })
        .collect::<Vec<_>>();
    format!("[{}]", rows.join(","))
}

fn u8_json(values: &[u8]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn json_escape(raw: &str) -> String {
    let mut escaped = String::new();
    for ch in raw.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn pass_fail(passed: bool) -> &'static str {
    if passed { "PASS" } else { "FAIL" }
}
