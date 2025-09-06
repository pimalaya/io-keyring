//! Collection of I/O-free, resumable and composable keyring state
//! machines.
//!
//! Coroutines emit [I/O] requests that need to be processed by
//! [runtimes] in order to continue their progression.
//!
//! [I/O]: crate::io::KeyringIo
//! [runtimes]: crate::runtimes

pub mod delete;
pub mod read;
pub mod write;
