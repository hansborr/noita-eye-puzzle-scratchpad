//! Verified message data and the engine storage-layer decoder.
//!
//! - [`corpus`]: the verified transcribed message data.
//! - [`generator`]: the engine storage-layer base-7 decoder and vendored input
//!   blocks used for corpus cross-checks.

pub mod corpus;
pub mod generator;
