#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

pub mod coroutines;
pub mod entry;
pub mod io;
pub mod runtimes;
#[cfg(feature = "serde")]
pub mod serde;
