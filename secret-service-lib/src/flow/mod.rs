//! # Flows
//!
//! Module dedicated to I/O-free, iterable state machine flows.

#[path = "read-entry.rs"]
mod read_entry;
#[path = "write-entry.rs"]
mod write_entry;

#[doc(inline)]
pub use self::{read_entry::*, write_entry::*};
