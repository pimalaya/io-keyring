#![cfg(target_os = "linux")]
#![cfg(feature = "secret-service-dbus-tokio")]
#![cfg(feature = "secret-service-dbus-rust-crypto-std")]

use keyring::{
    secret_service::dbus::{
        self,
        crypto::{self, rust_crypto::std::IoConnector as CryptoIoConnector, Algorithm},
        flow::{ReadEntryFlow, WriteEntryFlow},
        nonblock::tokio::IoConnector as DbusIoConnector,
    },
    Io,
};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() {
    const SERVICE: &str = "service";
    const ACCOUNT: &str = "account";
    const SECRET: &str = "test";

    let mut dbus = DbusIoConnector::new(SERVICE, ACCOUNT, Algorithm::Dh)
        .await
        .unwrap();
    let mut crypto = CryptoIoConnector::new(dbus.session()).unwrap();

    println!("write secret {SECRET:?} to entry {SERVICE}:{ACCOUNT}");
    let mut flow = WriteEntryFlow::new(SECRET.as_bytes().to_vec());
    while let Some(io) = flow.next() {
        match io {
            dbus::Io::Crypto(crypto::Io::Encrypt) => {
                crypto.encrypt(&mut flow).unwrap();
            }
            dbus::Io::Entry(Io::Write) => {
                dbus.write(&mut flow).await.unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new();
    while let Some(io) = flow.next() {
        match io {
            dbus::Io::Entry(Io::Read) => {
                dbus.read(&mut flow).await.unwrap();
            }
            dbus::Io::Crypto(crypto::Io::Decrypt) => {
                crypto.decrypt(&mut flow).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let secret = flow.secret.take().unwrap();
    let secret = secret.expose_secret();
    let secret = String::from_utf8_lossy(&secret);
    println!("read secret {secret:?} from entry {SERVICE}:{ACCOUNT}");
}
