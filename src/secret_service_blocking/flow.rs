#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Io {
    Read,
    Write,
    Delete,
    Crypto(CryptoIo),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoIo {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadEntryFlow {
    read: Option<Io>,
    decrypt: Option<CryptoIo>,
}

impl Default for ReadEntryFlow {
    fn default() -> Self {
        Self {
            read: Some(Io::Read),
            decrypt: Some(CryptoIo::Decrypt),
        }
    }
}

impl Iterator for ReadEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.read.take() {
            Some(io) => Some(io),
            None => Some(Io::Crypto(self.decrypt.take()?)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteEntryFlow {
    encrypt: Option<CryptoIo>,
    write: Option<Io>,
}

impl Default for WriteEntryFlow {
    fn default() -> Self {
        Self {
            encrypt: Some(CryptoIo::Encrypt),
            write: Some(Io::Write),
        }
    }
}

impl Iterator for WriteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        match self.encrypt.take() {
            Some(io) => Some(Io::Crypto(io)),
            None => self.write.take(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteEntryFlow {
    delete: Option<Io>,
}

impl Default for DeleteEntryFlow {
    fn default() -> Self {
        Self {
            delete: Some(Io::Delete),
        }
    }
}

impl Iterator for DeleteEntryFlow {
    type Item = Io;

    fn next(&mut self) -> Option<Self::Item> {
        self.delete.take()
    }
}
