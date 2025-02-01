//! # Flows
//!
//! Module dedicated to I/O-free, iterable state machine flows.

mod decrypt;
mod encrypt;

#[doc(inline)]
pub use self::{decrypt::*, encrypt::*};
