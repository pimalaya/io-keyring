use secrecy::SecretSlice;

/// Trait used for building keyring-related sans I/O state machine
/// flows.
///
/// A flow is defined as an iterable state machine, where every
/// `.next()` call produces a potential [`Io`] that needs to be
/// performed outside of the flow, and makes the state go forward. No
/// [`Io`] produced means that the flow is terminated and does not
/// require any longer [`Io`] to be performed.
pub trait Flow: Iterator {}

/// Trait dedicated to flows that operate on specific keyring entries.
///
/// This trait make sure that the given flow knows how to retrieve the
/// key of the targeted keyring entry.
pub trait GetKey: Flow {
    fn get_key(&self) -> &str;
}

/// Trait dedicated to flows that needs to take secrets.
///
/// This trait make sure that the given flow knows how to take a
/// secret from its inner state.
pub trait TakeSecret: Flow {
    fn take_secret(&mut self) -> Option<SecretSlice<u8>>;
}

/// Trait dedicated to flows that needs to put secrets.
///
/// This trait make sure that the given flow knows how to put a secret
/// into its inner state.
pub trait PutSecret: Flow {
    fn put_secret(&mut self, secret: SecretSlice<u8>);
}
