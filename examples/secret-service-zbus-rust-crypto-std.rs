#![cfg(target_os = "linux")]
#![cfg(feature = "secret-service-zbus-std")]
#![cfg(feature = "secret-service-rust-crypto-std")]

use std::env;

use keyring::{
    secret_service::{
        self,
        crypto::{self, algorithm::Algorithm, rust_crypto::std::IoConnector as CryptoIoConnector},
        flow::{DeleteEntryFlow, ReadEntryFlow, WriteEntryFlow},
        zbus::std::IoConnector as ZbusIoConnector,
    },
    Io, TakeSecret,
};
use secrecy::ExposeSecret;

#[async_std::main]
async fn main() {
    const SECRET: &str = "secret-service-zbus-rust-crypto-std";

    let service = env::var("SERVICE").unwrap_or(String::from("test-service"));
    println!("using service name: {service:?}");

    let key = env::var("KEY").unwrap_or(String::from("test-key"));
    println!("using entry key: {key:?}");

    let encryption = match env::var("ENCRYPTION") {
        Ok(alg) if alg.trim().eq_ignore_ascii_case("dh") => Algorithm::Dh,
        _ => Algorithm::Plain,
    };
    println!("using encryption algorithm: {encryption:?}");

    let mut zbus = ZbusIoConnector::new(&service, encryption.clone()).unwrap();
    let mut crypto = CryptoIoConnector::new(zbus.session()).unwrap();

    println!("write secret {SECRET:?} to entry {service}:{key}");
    let mut flow = WriteEntryFlow::new(&key, SECRET.as_bytes().to_vec(), encryption.clone());
    while let Some(io) = flow.next() {
        match io {
            secret_service::Io::Crypto(crypto::Io::Encrypt) => {
                crypto.encrypt(&mut flow).unwrap();
            }
            secret_service::Io::Entry(Io::Write) => {
                zbus.write(&mut flow).unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new(&key, encryption);
    while let Some(io) = flow.next() {
        match io {
            secret_service::Io::Entry(Io::Read) => {
                zbus.read(&mut flow).unwrap();
            }
            secret_service::Io::Crypto(crypto::Io::Decrypt) => {
                crypto.decrypt(&mut flow).unwrap();
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
            secret_service::Io::Entry(Io::Delete) => {
                zbus.delete(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }
    println!("delete secret from entry {service}:{key}");
}
