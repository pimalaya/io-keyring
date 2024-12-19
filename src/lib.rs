#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![doc = include_str!("../README.md")]

#[cfg(feature = "apple-keychain")]
#[path = "apple-keychain/mod.rs"]
pub mod apple_keychain;
#[path = "sans-io.rs"]
pub mod sans_io;
#[cfg(feature = "secret-service")]
#[path = "secret-service/mod.rs"]
pub mod secret_service;
pub mod std;
#[cfg(feature = "windows-credentials")]
#[path = "windows-credentials/mod.rs"]
pub mod windows_credentials;
