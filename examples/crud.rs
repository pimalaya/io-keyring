#![cfg(feature = "std")]

use std::{
    env,
    io::{stdin, stdout, Write as _},
};

use io_keyring::{
    coroutines::{Delete, Read, Write},
    runtimes::std::handle,
    Entry,
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

    let entry = Entry::new(name).service(service);

    let mut arg = None;
    let mut read = Read::new(entry.clone());

    let secret = loop {
        match read.resume(arg.take()) {
            Ok(secret) => break Ok(secret),
            Err(io) => match handle(io) {
                Ok(io) => arg = Some(io),
                Err(err) => break Err(err),
            },
        }
    };

    println!("first read: {secret:?}");

    println!("store new password");

    let mut arg = None;
    let mut write = Write::new(entry.clone(), password);

    while let Err(io) = write.resume(arg) {
        arg = Some(handle(io).unwrap());
    }

    let mut arg = None;
    let mut read = Read::new(entry.clone());

    let secret = loop {
        match read.resume(arg) {
            Ok(secret) => break secret,
            Err(io) => arg = Some(handle(io).unwrap()),
        }
    };

    println!("second read: {:?}", secret.expose_secret());

    println!("delete entry");

    let mut arg = None;
    let mut delete = Delete::new(entry.clone());

    while let Err(io) = delete.resume(arg) {
        arg = Some(handle(io).unwrap());
    }

    let mut arg = None;
    let mut read = Read::new(entry);

    let secret = loop {
        match read.resume(arg.take()) {
            Ok(secret) => break Ok(secret),
            Err(io) => match handle(io) {
                Ok(io) => arg = Some(io),
                Err(err) => break Err(err),
            },
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
