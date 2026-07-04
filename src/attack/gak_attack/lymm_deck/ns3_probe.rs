//! Ignored production-path probe for the measured ns=3 frontier.

use std::time::{Duration, Instant};

use super::{
    LymmDeckSpec, SwapRecoveryConfig, SwapRecoveryError, parse_known_plaintext_pairs,
    recover_known_plaintext_swaps,
};

#[test]
#[ignore = "bounded production-path probe for the measured ns=3 frontier"]
fn ns3_real_file_production_path_frontier_probe() {
    let spec = LymmDeckSpec::lymm_default().expect("spec");
    let pairs = parse_known_plaintext_pairs(
        &spec,
        include_str!("../../../../research/data/practice-puzzles/deck-swap/plaintexts.txt"),
        include_str!("../../../../research/data/practice-puzzles/deck-swap/3_swap_ct.txt"),
    )
    .expect("known plaintext pairs");
    let mut config = SwapRecoveryConfig::with_max_swaps(3);
    config.max_nodes = Some(env_usize("NOITA_SWAP_NS3_PROBE_MAX_NODES").unwrap_or(200));
    if let Some(seconds) = env_usize("NOITA_SWAP_NS3_PROBE_SECONDS") {
        config.time_budget = Some(Duration::from_secs(seconds as u64));
    }

    let started = Instant::now();
    match recover_known_plaintext_swaps(&spec, &pairs, config) {
        Ok(report) => {
            eprintln!(
                "ns=3 real probe recovered: exact={} round_trip={}/{} elapsed={:?} stats={:?}",
                report.round_trip.exact(),
                report.round_trip.matched,
                report.round_trip.total,
                started.elapsed(),
                report.stats
            );
            assert!(report.round_trip.exact());
            assert_eq!(report.round_trip.matched, 2439);
            assert_eq!(report.round_trip.total, 2439);
        }
        Err(error) => {
            eprintln!(
                "ns=3 real probe stopped: error={error:?} elapsed={:?}",
                started.elapsed()
            );
            assert!(
                matches!(
                    error,
                    SwapRecoveryError::NoResidualCandidate
                        | SwapRecoveryError::SearchCapExceeded { .. }
                        | SwapRecoveryError::SearchTimeExceeded { .. }
                        | SwapRecoveryError::SatSolver(_)
                ),
                "unexpected ns=3 probe error: {error:?}"
            );
        }
    }
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}
