//! # Sans I/O
//!
//! This module contains the state machine [`Flow`] and [`Io`]
//! definitions, as well as commonly-used flows definition like
//! [`ReadEntryFlow`], [`WriteEntryFlow`] and [`DeleteEntryFlow`].

mod flow;
#[path = "flow-entry-delete.rs"]
mod flow_entry_delete;
#[path = "flow-entry-read.rs"]
mod flow_entry_read;
#[path = "flow-entry-write.rs"]
mod flow_entry_write;
mod io;

#[doc(inline)]
pub use self::{flow::*, flow_entry_delete::*, flow_entry_read::*, flow_entry_write::*, io::*};
