use std::io::stderr;

use keyring_lib::{DeleteEntry, ReadEntry, WriteEntry};
use keyring_windows_credentials_std::Connector;
use secrecy::ExposeSecret;
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

    let secret = flow.take_secret().unwrap();
    let secret = secret.expose_secret();
    println!("secret: {secret}");

    let mut flow = DeleteEntry::new("key");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    let mut flow = ReadEntry::new("key");

    while let Some(io) = flow.next() {
        let err = conn.execute(&mut flow, io).unwrap_err();
        println!("err: {err:?}");
    }
}
