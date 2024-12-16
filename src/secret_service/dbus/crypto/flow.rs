use secrecy::SecretSlice;

pub trait Flow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>>;
    fn take_salt(&mut self) -> Option<Vec<u8>>;

    fn give_secret(&mut self, secret: SecretSlice<u8>);
    fn give_salt(&mut self, salt: Vec<u8>);
}
