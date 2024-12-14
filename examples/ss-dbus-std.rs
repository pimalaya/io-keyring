#![cfg(target_os = "linux")]
#![cfg(feature = "ss-dbus-std")]

use keyring::secret_service::dbus_blocking::{
    crypto::{algorithm::Algorithm, openssl::std::SecretServiceOpensslStdProcessor},
    flow::{ReadEntryFlow, WriteEntryFlow},
    io::SecretServiceIo,
    std::SecretServiceDbusStdProcessor,
};
use secrecy::ExposeSecret;

fn main() {
    const SERVICE: &str = "service";
    const ACCOUNT: &str = "account";
    const SECRET: &str = "test";

    let mut entry_std = SecretServiceDbusStdProcessor::try_new(SERVICE, ACCOUNT).unwrap();
    let mut crypto_std = SecretServiceOpensslStdProcessor::try_new(
        entry_std.connection(),
        Algorithm::DhIetf1024Sha256Aes128CbcPkcs7,
    )
    .unwrap();

    println!("write secret {SECRET:?} to entry {SERVICE}:{ACCOUNT}");
    let mut flow = WriteEntryFlow::new(SECRET);
    while let Some(io) = flow.next() {
        match io {
            SecretServiceIo::Encrypt => {
                crypto_std.secret_to_encrypt = flow.secret.take();
                let secret = crypto_std.encrypt().unwrap();
                entry_std.secret.replace(secret);
            }
            SecretServiceIo::Write => {
                entry_std.save(crypto_std.session_path.clone()).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let mut flow = ReadEntryFlow::new();
    while let Some(io) = flow.next() {
        match io {
            SecretServiceIo::Read => {
                let (secret, salt) = entry_std.read(crypto_std.session_path.clone()).unwrap();
                crypto_std.secret_to_decrypt.replace((secret, salt));
            }
            SecretServiceIo::Decrypt => {
                flow.secret.replace(crypto_std.decrypt().unwrap());
            }
            _ => unreachable!(),
        }
    }
    let secret = flow.secret.take().unwrap();
    let secret = secret.expose_secret();
    println!("read secret {secret:?} from entry {SERVICE}:{ACCOUNT}");
}
