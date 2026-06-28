use super::*;

// ---------------------------------------------------------------------------
// Step 9 — candidate auto-logging (mirrors gak_attack::eyes' private writer).
// ---------------------------------------------------------------------------

/// The verbatim claim ceiling reproduced in every solve candidate record. It is
/// the same ceiling the eye records carry: no record may make a stronger claim.
pub const SOLVE_CLAIM_CEILING: &str = "deterministic, engine-generated, strikingly structured data of unknown meaning; unsolved; no primary developer source confirms recoverable plaintext.";

/// The top candidate's record fields, scored under BOTH language models.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "record DTO: codec/cipher round-trip, beats-null, and survived are four independent gate verdicts surfaced verbatim, not a packed state machine"
)]
pub struct SolveRecordCandidate<'a> {
    /// Stable, display-only cipher family name.
    pub cipher_name: &'a str,
    /// Stable, display-only codec family name ([`Codec::name`]): the transduction
    /// stage between the decrypted cipher symbols and the symbol->letter mapping.
    pub codec_name: &'a str,
    /// Codec round-trip gate (the fourth structural check, alongside the cipher
    /// round-trip): re-expanding the transduced stream reproduces the decrypted
    /// symbols. Like the cipher round-trip it proves only codec/cipher consistency,
    /// never a decode.
    pub codec_round_trip_ok: bool,
    /// Cipher-layer round-trip gate (necessary, not sufficient).
    pub crypto_round_trip_ok: bool,
    /// In-sample bigram mean log-likelihood under the candidate's language.
    pub score: f64,
    /// Held-out fold mapping score (the mapping-confidence gate).
    pub heldout_mapping_score: f64,
    /// Matched-null full-stream mean (the overfit bar).
    pub null_mean: f64,
    /// Matched-null HELD-OUT fold mean (the generalization bar).
    pub null_heldout_mean: f64,
    /// Matched-null overfit-guard verdict.
    pub beats_null: bool,
    /// The rendered text scored under the English model.
    pub english_bigram: f64,
    /// The rendered text scored under the Finnish model.
    pub finnish_bigram: f64,
    /// Rendered candidate text (logged verbatim for human review).
    pub rendered_text: &'a str,
    /// Whether the candidate clears all three gates ([`candidate_survives`]).
    pub survived: bool,
}

/// Inputs for one solve candidate record (keeps the writer signature small).
#[derive(Clone, Copy, Debug)]
pub struct SolveRecordInputs<'a> {
    /// Stable run/puzzle label (used in the seed-derived filename).
    pub label: &'a str,
    /// Deterministic run seed (the only filename entropy — no wall clock).
    pub seed: u64,
    /// Declared cipher alphabet size.
    pub cipher_alphabet_size: usize,
    /// Number of cipher symbols in the ciphertext.
    pub total_symbols: usize,
    /// The exact, copy-pasteable command that reproduces this record; clock-free;
    /// the D2 reproducibility guarantee.
    pub provenance: &'a str,
    /// Number of round-trip-consistent candidates the run produced.
    pub candidates_evaluated: usize,
    /// Number of candidates that cleared all three gates.
    pub survivors: usize,
    /// The top candidate, if any survived the cipher-layer round-trip.
    pub top: Option<SolveRecordCandidate<'a>>,
}

/// The stable identity and shape of one solve run, reproduced verbatim in the
/// record header. The seed is the only entropy (no wall clock), so these four
/// cohesive fields fully determine the record's filename and header line.
#[derive(Clone, Copy, Debug)]
pub struct SolveRunIdentity<'a> {
    /// Stable run/puzzle label (used in the seed-derived filename).
    pub label: &'a str,
    /// Deterministic run seed (the only filename entropy — no wall clock).
    pub seed: u64,
    /// Declared cipher alphabet size.
    pub cipher_alphabet_size: usize,
    /// Number of cipher symbols in the ciphertext (the D2 length, reported even on
    /// the zero-candidate honest negative).
    pub total_symbols: usize,
}

/// Builds the stable, clock-free record filename from the run label and seed.
fn solve_record_filename(label: &str, seed: u64) -> String {
    let slug: String = label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    format!("solve-{slug}-seed-{seed:016x}.md")
}

/// Writes the mandatory solve candidate record (filename is a STABLE label/seed,
/// no clock; re-running the same config overwrites the prior record).
///
/// Returns the path written. The record carries the verbatim claim ceiling, the
/// HYPOTHESIS-not-decode label, all three gate verdicts, both language scores,
/// and any candidate cleartext verbatim for human review.
///
/// # Errors
/// Returns [`SolveError::CandidateRecordWrite`] if the directory cannot be
/// created or the file cannot be written.
pub fn write_solve_candidate_record(
    dir: &Path,
    inputs: &SolveRecordInputs<'_>,
) -> Result<PathBuf, SolveError> {
    let path = dir.join(solve_record_filename(inputs.label, inputs.seed));
    let body = render_solve_candidate_record(inputs).map_err(|_error| {
        SolveError::CandidateRecordWrite {
            path: path.clone(),
            source: io::Error::other("record formatting failed"),
        }
    })?;
    std::fs::create_dir_all(dir).map_err(|source| SolveError::CandidateRecordWrite {
        path: path.clone(),
        source,
    })?;
    std::fs::write(&path, body).map_err(|source| SolveError::CandidateRecordWrite {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

/// Renders the candidate-record markdown body (pure; unit-testable without the
/// filesystem).
///
/// # Errors
/// Returns [`std::fmt::Error`] only if a write to the in-memory string buffer
/// fails (in practice never).
pub fn render_solve_candidate_record(inputs: &SolveRecordInputs<'_>) -> Result<String, fmt::Error> {
    let mut out = String::new();
    let verdict = match inputs.top {
        Some(top) if top.survived => {
            "CANDIDATE SURVIVED ALL THREE GATES — logged as a HYPOTHESIS, NOT a decode"
        }
        _ => "NO surviving candidate — decode remains blocked",
    };
    writeln!(out, "# Solve candidate record: {}", inputs.label)?;
    writeln!(out)?;
    writeln!(
        out,
        "Stable label (NO wall-clock): label={} seed=0x{:016x} cipher-alphabet={} symbols={}",
        inputs.label, inputs.seed, inputs.cipher_alphabet_size, inputs.total_symbols
    )?;
    writeln!(out)?;
    writeln!(out, "## Provenance (reproducible)")?;
    writeln!(out)?;
    writeln!(out, "{}", inputs.provenance)?;
    writeln!(out)?;
    writeln!(out, "## Verdict")?;
    writeln!(out)?;
    writeln!(out, "**{verdict}.**")?;
    writeln!(out)?;
    writeln!(
        out,
        "This record is a HYPOTHESIS, NOT a decode. solve SEARCHES and SCORES; a high"
    )?;
    writeln!(
        out,
        "score is not a decode. Round-trip-consistent candidates: {}; survivors of all three gates: {}.",
        inputs.candidates_evaluated, inputs.survivors
    )?;
    writeln!(out)?;
    writeln!(out, "## Claim ceiling (absolute)")?;
    writeln!(out)?;
    writeln!(out, "{SOLVE_CLAIM_CEILING}")?;
    writeln!(
        out,
        "Nothing in this record is stronger. A clean honest negative is a SUCCESS."
    )?;
    writeln!(out)?;
    render_solve_gates(&mut out, inputs)?;
    Ok(out)
}

fn render_solve_gates(out: &mut String, inputs: &SolveRecordInputs<'_>) -> fmt::Result {
    writeln!(out, "## Three independent gates (never collapsed)")?;
    writeln!(out)?;
    let Some(top) = inputs.top else {
        writeln!(
            out,
            "No candidate survived the cipher-layer round-trip; nothing to score."
        )?;
        return Ok(());
    };
    writeln!(out, "Top candidate cipher: {}", top.cipher_name)?;
    writeln!(
        out,
        "Top candidate codec: {} (the transduction stage; codec round-trip below)",
        top.codec_name
    )?;
    writeln!(
        out,
        "- Gate 1 cipher round-trip (necessary, NOT sufficient): {}",
        top.crypto_round_trip_ok
    )?;
    writeln!(
        out,
        "- Gate 1b codec round-trip (codec/cipher consistency, NOT a decode): {}",
        top.codec_round_trip_ok
    )?;
    writeln!(
        out,
        "- Gate 2 held-out mapping score: {:.6} (matched-null held-out mean {:.6}); generalizes: {}",
        top.heldout_mapping_score,
        top.null_heldout_mean,
        top.heldout_mapping_score > top.null_heldout_mean
    )?;
    writeln!(
        out,
        "- Gate 3 matched-null in-sample: score {:.6} vs null {:.6}; beats_null: {}",
        top.score, top.null_mean, top.beats_null
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "## Language scores (Finnish weighted at least as highly)"
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "- Finnish bigram mean log-likelihood: {:.6}",
        top.finnish_bigram
    )?;
    writeln!(
        out,
        "- English bigram mean log-likelihood: {:.6}",
        top.english_bigram
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "## Candidate cleartext (verbatim; a HYPOTHESIS, not a decode)"
    )?;
    writeln!(out)?;
    writeln!(out, "{}", top.rendered_text)?;
    Ok(())
}

/// Builds a [`SolveRecordInputs`] from a solve run and writes its record.
///
/// Scores the top candidate's rendered text under BOTH language models (Finnish
/// first), derives the survivor counts via [`candidate_survives`], and delegates
/// to [`write_solve_candidate_record`]. This is the auto-logging entry the CLI
/// and validation tests call.
///
/// `total_symbols` is the ciphertext length (cipher-symbol count), passed by the
/// caller so the record header reports it even on the zero-candidate honest
/// negative — it must not be derived from `candidates.first()`, which is empty
/// then. Every cipher family is length-preserving, so on the has-candidate path
/// this equals the top candidate's `decrypted_symbols.len()`.
///
/// `provenance` is the exact, clock-free command that reproduces this record (the
/// D2 reproducibility guarantee); it is threaded verbatim into the record's
/// Provenance section.
///
/// # Errors
/// Returns [`SolveError`] if a language score fails or the record cannot be
/// written.
// The run identity/shape (label + seed + cipher-alphabet + defect-3 total_symbols)
// is bundled into [`SolveRunIdentity`]; defect-D2's `provenance`, the candidates,
// and both language models are the remaining heterogeneous inputs.
pub fn log_solve_run(
    dir: &Path,
    identity: SolveRunIdentity<'_>,
    provenance: &str,
    candidates: &[Candidate],
    english: &LanguageModel,
    finnish: &LanguageModel,
) -> Result<PathBuf, SolveError> {
    let SolveRunIdentity {
        label,
        seed,
        cipher_alphabet_size,
        total_symbols,
    } = identity;
    let survivors = candidates.iter().filter(|c| candidate_survives(c)).count();
    let top = match candidates.first() {
        Some(candidate) => Some(SolveRecordCandidate {
            cipher_name: candidate.cipher.name(),
            codec_name: candidate.codec.name(),
            codec_round_trip_ok: candidate.codec_round_trip_ok,
            crypto_round_trip_ok: candidate.crypto_round_trip_ok,
            score: candidate.score,
            heldout_mapping_score: candidate.heldout_mapping_score,
            null_mean: candidate.null_mean,
            null_heldout_mean: candidate.null_heldout_mean,
            beats_null: candidate.beats_null,
            english_bigram: english
                .score_text(&candidate.rendered_text)?
                .bigram_mean_log_likelihood,
            finnish_bigram: finnish
                .score_text(&candidate.rendered_text)?
                .bigram_mean_log_likelihood,
            rendered_text: &candidate.rendered_text,
            survived: candidate_survives(candidate),
        }),
        None => None,
    };
    let inputs = SolveRecordInputs {
        label,
        seed,
        cipher_alphabet_size,
        total_symbols,
        provenance,
        candidates_evaluated: candidates.len(),
        survivors,
        top,
    };
    write_solve_candidate_record(dir, &inputs)
}
