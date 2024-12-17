#![cfg(target_os = "windows")]
#![cfg(feature = "windows-native-std")]

use std::env;

use keyring::{
    windows::{
        flow::{ReadEntryFlow, WriteEntryFlow},
        std::IoConnector as Credentials,
        Flow,
    },
    Io,
};
use secrecy::ExposeSecret;

fn main() {
    const SECRET: &str = "windows-native-std";

    let service = env::var("SERVICE").unwrap_or(String::from("test-service"));
    println!("using service name: {service:?}");

    let account = env::var("ACCOUNT").unwrap_or(String::from("test-account"));
    println!("using account name: {service:?}");

    let credentials = Credentials::new();

    println!("write secret {SECRET:?} to entry {service}:{account}");
    let mut flow = WriteEntryFlow::new(&service, &account, SECRET.as_bytes().to_vec());
    while let Some(io) = flow.next() {
        match io {
            Io::Write => {
                credentials.write(&mut flow).unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new(&service, &account);
    while let Some(io) = flow.next() {
        match io {
            Io::Read => {
                credentials.read(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let secret = flow.take_secret().unwrap();
    let secret = secret.expose_secret();
    let secret = String::from_utf8_lossy(&secret);
    println!("read secret {secret:?} from entry {service}:{account}");
}
