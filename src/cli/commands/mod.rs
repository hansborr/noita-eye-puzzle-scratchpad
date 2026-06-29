//! Per-command `run_*` handlers for the irregular subcommands (multi-report,
//! nested subcommand, positional parse, and the solve/keystream/ragbaby
//! pipelines). The uniform experiments are dispatched generically in
//! [`super::dispatch`].

mod gak;
mod keystream;
mod misc;
mod ragbaby;
mod solve;

pub(crate) use gak::run_gak;
pub(crate) use keystream::{run_keystream, run_profile};
pub(crate) use misc::{
    run_controls, run_demo, run_grouping, run_orders, run_pipelinenull, run_stats,
};
pub(crate) use ragbaby::run_ragbaby;
pub(crate) use solve::run_solve;
