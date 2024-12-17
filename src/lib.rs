#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

pub mod io;

#[cfg(target_vendor = "apple")]
#[cfg(any(feature = "apple-native-std"))]
pub mod apple;
#[cfg(target_os = "linux")]
#[cfg(any(
    feature = "secret-service-dbus-std",
    feature = "secret-service-dbus-tokio",
    feature = "secret-service-zbus-std",
    feature = "secret-service-zbus-async-std",
    feature = "secret-service-zbus-tokio",
))]
pub mod secret_service;
#[cfg(target_os = "windows")]
#[cfg(any(feature = "windows-native-std"))]
pub mod windows;

pub use io::Io;
