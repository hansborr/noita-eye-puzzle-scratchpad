//! Report rendering for the Experiment 11 positive controls.
//!
//! Holds the `Report` implementations and the shared isomorph-fixture
//! `append_*` helper, split out of the controls battery body.

use super::{IsomorphControlReport, IsomorphFixtureReport, MonoalphabeticControlReport};
use crate::report::{self, Report};

impl Report for MonoalphabeticControlReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(&mut out, "Experiment 11 monoalphabetic positive control");
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "alphabet: {} symbols ({})",
            self.alphabet_size,
            self.alphabet
        );
        report::appendln!(&mut out, "generated key: {}", self.key_mapping);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "long fixture: {} letters from {}",
            self.long_fixture.length,
            self.long_fixture.label
        );
        report::appendln!(
            &mut out,
            "plaintext:  {}",
            report::preview_text(&self.long_fixture.normalized_plaintext, 96)
        );
        report::appendln!(
            &mut out,
            "ciphertext: {}",
            report::preview_text(&self.long_fixture.ciphertext, 96)
        );
        report::appendln!(
            &mut out,
            "recovered:  {}",
            report::preview_text(&self.long_fixture.recovered_plaintext, 96)
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "IoC plaintext/ciphertext: {:.6} / {:.6} (exactly preserved)",
            self.long_fixture.plaintext_ioc,
            self.long_fixture.ciphertext_ioc
        );
        report::appendln!(
            &mut out,
            "IoC balanced uniform: {:.6}; uniform floor 1/k: {:.6}",
            self.flattened_ioc,
            self.uniform_floor
        );
        report::appendln!(
            &mut out,
            "entropy plaintext/ciphertext/balanced uniform: {:.4} / {:.4} / {:.4} bits/symbol",
            self.long_fixture.plaintext_entropy,
            self.long_fixture.ciphertext_entropy,
            self.flattened_entropy
        );
        report::appendln!(
            &mut out,
            "frequency multiset preserved: {}",
            report::yes_no(self.long_fixture.frequency_multiset_preserved)
        );
        report::appendln!(
            &mut out,
            "bigram count multiset preserved: {}",
            report::yes_no(self.long_fixture.bigram_multiset_preserved)
        );
        report::appendln!(
            &mut out,
            "known-key recovery: {}",
            report::yes_no(self.long_fixture.known_key_recovered)
        );
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "documented Common Glyphs plaintext vectors (known-key exactness only):"
        );
        for fixture in &self.documented_vectors {
            report::appendln!(
                &mut out,
                "  {}: {:?} -> {} -> {}",
                fixture.label,
                fixture.source_plaintext,
                fixture.ciphertext,
                fixture.recovered_plaintext
            );
        }
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Interpretation: this proves the frequency/substitution tooling is not systematically blind to a known monoalphabetic substitution fixture. It does not claim frequency-only recovery of the short Common Glyphs phrases, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
        );
        out
    }
}

impl Report for IsomorphControlReport {
    fn render(&self) -> String {
        let mut out = String::new();
        report::appendln!(
            &mut out,
            "Experiment 11 isomorph/polyalphabetic positive control"
        );
        report::appendln!(&mut out, "seed: {}", self.config.seed);
        report::appendln!(
            &mut out,
            "alphabet: {} symbols ({})",
            self.alphabet_size,
            self.alphabet
        );
        report::appendln!(
            &mut out,
            "detector: first-occurrence signatures over {}-glyph windows; periods {}..={}",
            self.window,
            self.min_period,
            self.max_period
        );
        report::appendln!(
            &mut out,
            "ground truth: plaintext has period-aligned planted repeats; Vigenere key period is {}; autokey and running-key have no short repeating key",
            self.expected_period
        );
        report::appendln!(
            &mut out,
            "invariant: Vigenere period matches >= {}; each absent fixture max period matches <= {}",
            self.required_present_matches,
            self.allowed_absent_matches
        );
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.vigenere);
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.autokey);
        report::appendln!(&mut out);
        append_isomorph_fixture(&mut out, &self.running_key);
        report::appendln!(&mut out);
        report::appendln!(
            &mut out,
            "Interpretation: this control shows the isomorph/period tooling recovers the repeating-key Vigenere period when English prose contains period-aligned planted repeats. The autokey and running-key fixtures use the same planted repeats but do not show a short period, so the contrast isolates key structure rather than plaintext content. It does not claim arbitrary natural text would produce this signal, and it says nothing about whether the unsolved eye glyphs encode a message. If this control fails, the methodology is suspect."
        );
        out
    }
}

fn append_isomorph_fixture(out: &mut String, fixture: &IsomorphFixtureReport) {
    report::appendln!(out, "{} ({})", fixture.label, fixture.cipher);
    report::appendln!(out, "key: {}", fixture.key_summary);
    report::appendln!(out, "length: {} glyphs", fixture.length);
    report::appendln!(
        out,
        "plaintext:  {}",
        report::preview_text(&fixture.plaintext, 84)
    );
    report::appendln!(
        out,
        "ciphertext: {}",
        report::preview_text(&fixture.ciphertext, 84)
    );
    report::appendln!(
        out,
        "cipher entropy/IoC/distinct: {:.4} bits / {:.6} / {}",
        fixture.ciphertext_entropy,
        fixture.ciphertext_ioc,
        fixture.distinct_cipher_symbols
    );
    report::appendln!(out, "plaintext IoC: {:.6}", fixture.plaintext_ioc);
    report::appendln!(
        out,
        "informative windows: {}; repeated signature kinds: {}; exact repeated windows: {}",
        fixture.informative_windows,
        fixture.repeated_signature_kinds,
        fixture.exact_repeated_windows
    );
    report::appendln!(
        out,
        "period-{} signature matches: {}",
        fixture.expected_period,
        fixture.expected_period_matches
    );
    match fixture.best_period {
        Some(signal) => report::appendln!(
            out,
            "best period: {} ({} matches across {} signatures)",
            signal.period,
            signal.matches,
            signal.signature_kinds
        ),
        None => report::appendln!(out, "best period: none"),
    }
    if !fixture.strongest_signatures.is_empty() {
        report::appendln!(out, "top period-{} signatures:", fixture.expected_period);
        for signature in &fixture.strongest_signatures {
            report::appendln!(
                out,
                "  [{}] at {} ({} period matches)",
                signature.signature,
                report::format_positions(&signature.occurrences),
                signature.expected_period_matches
            );
        }
    }
}
