//! Bin-private CLI module tree for the `noita-eye` binary.
//!
//! `clap` owns argument parsing and usage text; the [`args`] module holds the
//! parser definitions, [`dispatch`] holds the run loop and the uniform-experiment
//! registry, [`commands`] holds the irregular per-command handlers, and
//! [`shared`] holds helpers used across more than one command. None of this is
//! part of the library's public API.

mod args;
mod args_analysis;
mod args_attack;
mod args_cribfit;
mod args_ctak;
mod args_predicates;
mod args_rlcodec;
mod commands;
mod dispatch;
mod shared;

pub(crate) use dispatch::run;
