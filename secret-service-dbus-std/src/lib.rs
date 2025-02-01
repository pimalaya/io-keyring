#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

mod collection;
mod connector;
mod error;
mod item;
mod service;
mod session;

#[doc(inline)]
pub use self::{
    connector::Connector,
    error::{Error, Result},
    session::Session,
};
