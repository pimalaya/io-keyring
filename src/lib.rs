#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "apple-keychain")]
pub mod apple;
pub mod flow;
pub mod io;
#[cfg(feature = "secret-service")]
pub mod secret_service;
pub mod std;
#[cfg(feature = "windows-credentials")]
pub mod windows;

pub use self::{flow::*, io::*};
