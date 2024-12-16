#![cfg(target_os = "linux")]
#![cfg(feature = "secret-service-dbus-std")]
#![cfg(feature = "secret-service-dbus-openssl-std")]

use keyring::{
    secret_service::dbus_blocking::{
        self,
        crypto::{self, algorithm::Algorithm},
        flow::{ReadEntryFlow, WriteEntryFlow},
    },
    Io,
};
use secrecy::ExposeSecret;

fn main() {
    const SERVICE: &str = "service";
    const ACCOUNT: &str = "account";
    const SECRET: &str = "test";

    let mut entry = dbus_blocking::std::IoConnector::new(SERVICE, ACCOUNT).unwrap();
    let mut crypto =
        dbus_blocking::crypto::openssl::std::IoConnector::new(entry.connection(), Algorithm::Dh)
            .unwrap();

    println!("write secret {SECRET:?} to entry {SERVICE}:{ACCOUNT}");
    let mut flow = WriteEntryFlow::new(crypto.session_path.clone(), SECRET.as_bytes().to_vec());
    while let Some(io) = flow.next() {
        match io {
            dbus_blocking::Io::Crypto(crypto::Io::Encrypt) => {
                crypto.encrypt(&mut flow).unwrap();
            }
            dbus_blocking::Io::Entry(Io::Write) => {
                entry.write(&mut flow).unwrap();
            }
            _ => {
                unreachable!();
            }
        }
    }

    let mut flow = ReadEntryFlow::new(crypto.session_path.clone());
    while let Some(io) = flow.next() {
        match io {
            dbus_blocking::Io::Entry(Io::Read) => {
                entry.read(&mut flow).unwrap();
            }
            dbus_blocking::Io::Crypto(crypto::Io::Decrypt) => {
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
