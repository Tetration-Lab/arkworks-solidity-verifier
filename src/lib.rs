pub(crate) mod pairings;
pub(crate) mod utils;

pub mod schemes;

pub trait PairingLibrary {
    fn template() -> &'static str;
}

pub trait SolidityVerifier<E: PairingLibrary> {
    type Proof;
    type VerifyingKey;

    fn export(vk: &Self::VerifyingKey) -> String;
}
