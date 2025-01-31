//! # Flows
//!
//! Module dedicated to I/O-free, iterable state machine flows.

#[path = "delete-entry.rs"]
mod delete_entry;
#[path = "read-entry.rs"]
mod read_entry;
#[path = "write-entry.rs"]
mod write_entry;

#[doc(inline)]
pub use self::{delete_entry::*, read_entry::*, write_entry::*};
