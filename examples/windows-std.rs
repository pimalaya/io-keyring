#![cfg(target_os = "windows")]
#![cfg(feature = "windows-native")]
#![cfg(feature = "std")]

use keyring::{event::KeyringEvent, state::EntryState, windows::std::progress};
use secrecy::ExposeSecret;

fn main() {
    println!("create new keyring entry");
    let mut entry = KeyringEntry::new("service", "account");

    println!("update secret");
    entry.update_secret("test");
    progress(&mut entry).expect("should update secret");

    println!("read secret");
    entry.read_secret();
    match progress(&mut entry) {
        Ok(Some(KeyringEvent::SecretRead(secret))) => {
            println!("secret: {secret:?}");
            println!("exposed secret: {:?}", secret.expose_secret());
        }
        otherwise => panic!("should read secret: {otherwise:?}"),
    }

    println!("delete entry");
    entry.delete_secret();
    match progress(&mut entry) {
        Ok(Some(KeyringEvent::SecretDeleted)) => (),
        otherwise => panic!("should delete secret: {otherwise:?}"),
    }

    println!("read secret again");
    entry.read_secret();
    match progress(&mut entry) {
        Err(_) => (),
        otherwise => panic!("should not read secret: {otherwise:?}"),
    }
}
