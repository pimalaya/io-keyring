#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

mod constants;
pub mod crypto;
#[cfg(feature = "encryption")]
mod flow;
#[cfg(any(feature = "blocking", feature = "nonblock"))]
pub mod generated;
#[cfg(feature = "encryption")]
mod io;
mod session;
#[cfg(feature = "encryption")]
mod state;

#[doc(inline)]
pub use self::{constants::*, session::Session};
#[cfg(feature = "encryption")]
#[doc(inline)]
pub use self::{flow::*, io::Io, state::State};
