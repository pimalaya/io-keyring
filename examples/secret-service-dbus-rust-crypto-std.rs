#![cfg(target_os = "linux")]
#![cfg(feature = "secret-service-dbus-std")]
#![cfg(feature = "secret-service-rust-crypto-std")]

use std::env;

use keyring::{
    secret_service::{
        self,
        crypto::{self, algorithm::Algorithm, rust_crypto::std::IoConnector as CryptoIoConnector},
        dbus::blocking::std::IoConnector as DbusIoConnector,
        flow::{ReadEntryFlow, WriteEntryFlow},
    },
    Io,
};
use secrecy::ExposeSecret;

fn main() {
    const SECRET: &str = "secret-service-dbus-rust-crypto-std";

    let service = env::var("SERVICE").unwrap_or(String::from("test-service"));
    println!("using service name: {service:?}");

    let account = env::var("ACCOUNT").unwrap_or(String::from("test-account"));
    println!("using account name: {service:?}");

    let encryption = match env::var("ENCRYPTION") {
        Ok(alg) if alg.trim().eq_ignore_ascii_case("dh") => Algorithm::Dh,
        _ => Algorithm::Plain,
    };
    println!("using encryption algorithm: {encryption:?}");

    let mut dbus = DbusIoConnector::new(&service, &account, encryption.clone()).unwrap();
    let mut crypto = CryptoIoConnector::new(dbus.session()).unwrap();

    println!("write secret {SECRET:?} to entry {service}:{account}");
    let mut flow = WriteEntryFlow::new(SECRET.as_bytes().to_vec(), encryption.clone());
    while let Some(io) = flow.next() {
        match io {
            secret_service::Io::Crypto(crypto::Io::Encrypt) => {
                crypto.encrypt(&mut flow).unwrap();
            }
            secret_service::Io::Entry(Io::Write) => {
                dbus.write(&mut flow).unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new(encryption);
    while let Some(io) = flow.next() {
        match io {
            secret_service::Io::Entry(Io::Read) => {
                dbus.read(&mut flow).unwrap();
            }
            secret_service::Io::Crypto(crypto::Io::Decrypt) => {
                crypto.decrypt(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let secret = flow.secret.take().unwrap();
    let secret = secret.expose_secret();
    let secret = String::from_utf8_lossy(&secret);
    println!("read secret {secret:?} from entry {service}:{account}");
}
