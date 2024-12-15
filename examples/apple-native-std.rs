#![cfg(target_vendor = "apple")]
#![cfg(feature = "apple-native-std")]

use keyring::{
    apple::{
        flow::{ReadEntryFlow, WriteEntryFlow},
        std::IoConnector,
        Flow,
    },
    Io,
};
use secrecy::ExposeSecret;

fn main() {
    const SERVICE: &str = "service";
    const ACCOUNT: &str = "account";
    const SECRET: &str = "test";

    println!("write secret {SECRET:?} to entry {ACCOUNT}@{SERVICE}");
    let mut flow = WriteEntryFlow::new(SERVICE, ACCOUNT, SECRET.as_bytes().to_vec());
    while let Some(io) = flow.next() {
        match io {
            Io::Write => {
                IoConnector::write(&mut flow).unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new(SERVICE, ACCOUNT);
    while let Some(io) = flow.next() {
        match io {
            Io::Read => {
                IoConnector::read(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let secret = flow.take_secret().unwrap();
    let secret = secret.expose_secret();
    let secret = String::from_utf8_lossy(&secret);
    println!("read secret from entry {ACCOUNT}@{SERVICE}: {secret:?}");
}
