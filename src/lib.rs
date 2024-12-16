#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

mod io;

#[cfg(target_vendor = "apple")]
#[cfg(feature = "apple-native-std")]
pub mod apple;
#[cfg(target_os = "linux")]
#[cfg(feature = "secret-service-dbus-std")]
pub mod secret_service;
#[cfg(any(debug_assertions, target_os = "windows"))]
#[cfg(feature = "windows-native-std")]
pub mod windows;

pub use io::Io;
