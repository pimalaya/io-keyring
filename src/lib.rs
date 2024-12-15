#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(target_vendor = "apple")]
#[cfg(feature = "apple-native")]
pub mod apple;
pub mod event;
mod io;
#[cfg(target_os = "linux")]
#[cfg(feature = "ss-dbus-std")]
pub mod secret_service;
pub mod state;
#[cfg(target_os = "windows")]
#[cfg(feature = "windows-native")]
pub mod windows;

pub use io::Io;
