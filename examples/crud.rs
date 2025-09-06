#![cfg(feature = "std")]

use std::{
    env,
    io::{stdin, stdout, Write},
};

use io_keyring::{
    coroutines::{
        delete::{DeleteSecret, DeleteSecretResult},
        read::{ReadSecret, ReadSecretResult},
        write::{WriteSecret, WriteSecretResult},
    },
    entry::KeyringEntry,
    runtimes::std::handle,
};
use secrecy::ExposeSecret;

fn main() {
    env_logger::init();

    let service = match env::var("SERVICE") {
        Ok(service) => service,
        Err(_) => read_line("Keyring service?"),
    };

    let name = match env::var("NAME") {
        Ok(name) => name,
        Err(_) => read_line("Keyring entry name?"),
    };

    let password = match env::var("PASSWORD") {
        Ok(password) => password,
        Err(_) => read_line("Keyring entry password?"),
    };

    let entry = KeyringEntry::new(name).with_service(service);

    let mut arg = None;
    let mut read = ReadSecret::new(entry.clone());

    let secret = loop {
        match read.resume(arg.take()) {
            ReadSecretResult::Ok(secret) => break Ok(secret),
            ReadSecretResult::Io(io) => match handle(io) {
                Ok(io) => arg = Some(io),
                Err(err) => break Err(err),
            },
            ReadSecretResult::Err(err) => panic!("{err}"),
        }
    };

    println!("first read: {secret:?}");

    println!("store new password");

    let mut arg = None;
    let mut write = WriteSecret::new(entry.clone(), password);

    loop {
        match write.resume(arg.take()) {
            WriteSecretResult::Ok(()) => break,
            WriteSecretResult::Io(io) => arg = Some(handle(io).unwrap()),
            WriteSecretResult::Err(err) => panic!("{err}"),
        }
    }

    let mut arg = None;
    let mut read = ReadSecret::new(entry.clone());

    let secret = loop {
        match read.resume(arg.take()) {
            ReadSecretResult::Ok(secret) => break secret,
            ReadSecretResult::Io(io) => arg = Some(handle(io).unwrap()),
            ReadSecretResult::Err(err) => panic!("{err}"),
        }
    };

    println!("second read: {:?}", secret.expose_secret());

    println!("delete entry");

    let mut arg = None;
    let mut delete = DeleteSecret::new(entry.clone());

    while let DeleteSecretResult::Io(io) = delete.resume(arg) {
        arg = Some(handle(io).unwrap());
    }

    let mut arg = None;
    let mut read = ReadSecret::new(entry);

    let secret = loop {
        match read.resume(arg.take()) {
            ReadSecretResult::Ok(secret) => break Ok(secret),
            ReadSecretResult::Io(io) => match handle(io) {
                Ok(io) => arg = Some(io),
                Err(err) => break Err(err),
            },
            ReadSecretResult::Err(err) => panic!("{err}"),
        }
    };

    println!("no third read possible: {secret:?}");
}

fn read_line(prompt: &str) -> String {
    print!("{prompt} ");
    stdout().flush().unwrap();

    let mut line = String::new();
    stdin().read_line(&mut line).unwrap();

    line.trim().to_owned()
}
