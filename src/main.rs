//! Command-line entry point for the Noita eye-puzzle toolkit.
//!
//! This is intentionally a thin wrapper over the library so that all logic
//! stays testable in [`noita_eye_puzzle`]. `clap` owns argument parsing and
//! usage text; domain analysis and report rendering live in the library. The
//! parser, dispatch loop, and per-command handlers live in the bin-private
//! [`cli`] module tree.

mod cli;

fn main() -> std::process::ExitCode {
    cli::run()
}
