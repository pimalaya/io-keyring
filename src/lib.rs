#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

pub mod event;
pub mod state;

#[cfg(target_os = "linux")]
#[cfg(feature = "secret-service-blocking")]
pub mod secret_service_blocking;
// #[cfg(feature = "secret-service-nonblock")]
// #[cfg(any(target_os = "linux", debug_assertions))]
// pub mod secret_service_nonblock;
#[cfg(target_vendor = "apple")]
#[cfg(feature = "apple-native")]
pub mod apple;
#[cfg(target_os = "windows")]
#[cfg(feature = "windows-native")]
pub mod windows;
