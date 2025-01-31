#![cfg(target_vendor = "apple")]

use std::io::stderr;

use keyring_apple_keychain_std::Connector;
use keyring_lib::{DeleteEntry, ReadEntry, WriteEntry};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(stderr))
        .with(EnvFilter::from_default_env())
        .init();

    let conn = Connector::new("tests");

    let mut flow = WriteEntry::new("key", "secret1");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    let mut flow = ReadEntry::new("key");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    let mut flow = DeleteEntry::new("key");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }
}
