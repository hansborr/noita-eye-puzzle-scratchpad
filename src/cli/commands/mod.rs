//! Per-command `run_*` handlers for the irregular subcommands (multi-report,
//! nested subcommand, positional parse, and the solve/keystream/ragbaby
//! pipelines). The uniform experiments are dispatched generically in
//! [`super::dispatch`].

mod bigramcodec;
mod codecpower;
mod crcscan;
mod cribfit;
mod ctakscan;
mod gak;
mod gak_swap;
mod gak_swap_report;
mod groupscan;
mod isoscan;
mod keydiff;
mod keystream;
mod maskdecode;
mod mdlcodec;
mod misc;
mod pairclass;
mod predscan;
mod ragbaby;
mod rankcodec;
mod rlcodec;
mod solve;
mod structural;

pub(crate) use bigramcodec::run_bigramcodec;
pub(crate) use codecpower::run_codecpower;
pub(crate) use crcscan::run_crcscan;
pub(crate) use cribfit::run_cribfit;
pub(crate) use ctakscan::run_ctakscan;
pub(crate) use gak::run_gak;
pub(crate) use gak_swap::run_gak_swap_recover;
pub(crate) use groupscan::run_groupscan;
pub(crate) use isoscan::run_isoscan;
pub(crate) use keydiff::run_keydiff;
pub(crate) use keystream::{run_keystream, run_profile};
pub(crate) use maskdecode::run_maskdecode;
pub(crate) use mdlcodec::run_mdlcodec;
pub(crate) use misc::{
    run_controls, run_demo, run_grouping, run_orders, run_pipelinenull, run_stats,
};
pub(crate) use pairclass::run_pairclass;
pub(crate) use predscan::run_predscan;
pub(crate) use ragbaby::run_ragbaby;
pub(crate) use rankcodec::run_rankcodec;
pub(crate) use rlcodec::run_rlcodec;
pub(crate) use solve::run_solve;
pub(crate) use structural::{
    run_chaining, run_chaining_graph, run_isomorphimperf, run_isomorphnull, run_leakceiling,
    run_perfectiso,
};
