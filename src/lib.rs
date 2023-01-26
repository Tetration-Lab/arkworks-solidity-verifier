use ark_ec::PairingEngine;

pub(crate) mod constants;
pub(crate) mod pairings;
pub(crate) mod utils;

pub mod schemes;

pub trait PairingLibrary: PairingEngine {
    fn template(g2_addition: bool) -> String;

    fn g1_to_string(g1: &Self::G1Affine) -> String;

    fn g2_to_string(g2: &Self::G2Affine) -> String;
}

pub trait SolidityVerifier<E: PairingLibrary> {
    type Proof;
    type VerifyingKey;

    fn export(vk: &Self::VerifyingKey) -> String;
}
