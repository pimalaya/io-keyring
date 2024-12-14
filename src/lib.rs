#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

pub mod event;
pub mod io;
pub mod state;

#[cfg(target_vendor = "apple")]
#[cfg(feature = "apple-native")]
pub mod apple;
#[cfg(target_os = "linux")]
#[cfg(feature = "ss-dbus-std")]
pub mod secret_service;
#[cfg(target_os = "windows")]
#[cfg(feature = "windows-native")]
pub mod windows;
