#![cfg(target_os = "windows")]
#![cfg(feature = "windows-native-std")]

use std::env;

use keyring::{
    windows::std::IoConnector as Credentials, DeleteEntryFlow, Io, ReadEntryFlow, TakeSecret,
    WriteEntryFlow,
};
use secrecy::ExposeSecret;

fn main() {
    const SECRET: &str = "windows-native-std";

    let service = env::var("SERVICE").unwrap_or(String::from("test-service"));
    println!("using service name: {service:?}");

    let key = env::var("KEY").unwrap_or(String::from("test-key"));
    println!("using entry key: {key:?}");

    let credentials = Credentials::new(&service);

    println!("write secret {SECRET:?} to entry {service}:{key}");
    let mut flow = WriteEntryFlow::new(&key, SECRET.as_bytes().to_vec());
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

    let mut flow = ReadEntryFlow::new(&key);
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
    println!("read secret {secret:?} from entry {service}:{key}");

    let mut flow = DeleteEntryFlow::new(&key);
    while let Some(io) = flow.next() {
        match io {
            Io::Delete => {
                credentials.delete(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }
    println!("delete secret from entry {service}:{key}");
}
