#![cfg(target_os = "linux")]
#![cfg(feature = "secret-service-dbus-tokio")]
#![cfg(feature = "secret-service-dbus-openssl-std")]

use std::env;

use keyring::{
    secret_service::{
        self,
        crypto::{self, openssl::std::IoConnector as CryptoIoConnector, Algorithm},
        dbus::nonblock::tokio::IoConnector as DbusIoConnector,
        flow::{ReadEntryFlow, WriteEntryFlow},
    },
    Io,
};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() {
    let service = env::var("SERVICE").unwrap_or(String::from("test-service"));
    println!("using service name: {service:?}");

    let account = env::var("ACCOUNT").unwrap_or(String::from("test-account"));
    println!("using account name: {service:?}");

    let encryption = match env::var("ENCRYPTION") {
        Ok(alg) if alg.trim().eq_ignore_ascii_case("dh") => Algorithm::Dh,
        _ => Algorithm::Plain,
    };
    println!("using encryption algorithm: {encryption:?}");

    let mut dbus = DbusIoConnector::new(&service, &account, encryption.clone())
        .await
        .unwrap();
    let mut crypto = CryptoIoConnector::new(dbus.session()).unwrap();

    println!("write secret {:?} to entry {service}:{account}", "test");
    let mut flow = WriteEntryFlow::new(b"test".to_vec(), encryption.clone());
    while let Some(io) = flow.next() {
        match io {
            secret_service::Io::Crypto(crypto::Io::Encrypt) => {
                crypto.encrypt(&mut flow).unwrap();
            }
            secret_service::Io::Entry(Io::Write) => {
                dbus.write(&mut flow).await.unwrap();
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
                dbus.read(&mut flow).await.unwrap();
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
