#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

mod connector;
mod credential;
mod error;

#[doc(inline)]
pub use self::{
    connector::Connector,
    error::{Error, Result},
};
