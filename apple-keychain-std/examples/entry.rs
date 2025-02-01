use std::io::stderr;

use keyring_apple_keychain_std::Connector;
use keyring_lib::{DeleteEntry, ReadEntry, WriteEntry};
use secrecy::ExposeSecret;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const SERVICE: &'static str = "example";
const KEY: &'static str = "key";

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(stderr))
        .with(EnvFilter::from_default_env())
        .init();

    println!("create a new I/O connector for service {SERVICE:?}");
    let conn = Connector::new(SERVICE);

    println!();
    println!("read undefined secret at entry {KEY:?}");

    let mut flow = ReadEntry::new(KEY);

    while let Some(io) = flow.next() {
        let res = conn.execute(&mut flow, io);
        println!("read result: {res:?}");
        assert!(res.is_err());
        break;
    }

    println!();
    println!("write secret at entry {KEY:?}");

    let mut flow = WriteEntry::new(KEY, "secret1");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    println!();
    println!("read secret at entry {KEY:?}");

    let mut flow = ReadEntry::new(KEY);

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    let secret = flow.take_secret().unwrap();
    let secret = secret.expose_secret();
    println!("read secret: {secret}");
    assert_eq!("secret1", secret);

    println!();
    println!("write another secret at entry {KEY:?}");

    let mut flow = WriteEntry::new(KEY, "secret2");

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    println!();
    println!("read secret at entry {KEY:?}");

    let mut flow = ReadEntry::new(KEY);

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    let secret = flow.take_secret().unwrap();
    let secret = secret.expose_secret();
    println!("read secret: {secret}");
    assert_eq!("secret2", secret);

    println!();
    println!("delete secret at entry {KEY:?}");

    let mut flow = DeleteEntry::new(KEY);

    while let Some(io) = flow.next() {
        conn.execute(&mut flow, io).unwrap();
    }

    assert!(flow.is_deleted());

    println!();
    println!("read deleted secret at entry {KEY:?}");

    let mut flow = ReadEntry::new(KEY);

    while let Some(io) = flow.next() {
        let res = conn.execute(&mut flow, io);
        println!("read result: {res:?}");
        assert!(res.is_err());
        break;
    }
}
