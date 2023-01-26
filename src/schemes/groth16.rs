use ark_ec::PairingEngine;
use ark_groth16::{Groth16, Proof, VerifyingKey};

use crate::{PairingLibrary, SolidityVerifier};

impl<E: PairingEngine + PairingLibrary> SolidityVerifier<E> for Groth16<E> {
    type Proof = Proof<E>;

    type VerifyingKey = VerifyingKey<E>;

    fn export(_vk: &Self::VerifyingKey) -> String {
        todo!()
    }
}
