use crate::{PutSecret, TakeSecret};

pub trait TakeSalt: TakeSecret {
    fn take_salt(&mut self) -> Option<Vec<u8>>;
}

pub trait PutSalt: PutSecret {
    fn put_salt(&mut self, salt: Vec<u8>);
}
