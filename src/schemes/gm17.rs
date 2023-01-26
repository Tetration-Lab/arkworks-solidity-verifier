use ark_ec::PairingEngine;
use ark_gm17::{Proof, VerifyingKey, GM17};

use crate::{PairingLibrary, SolidityVerifier};

impl<E: PairingEngine + PairingLibrary> SolidityVerifier<E> for GM17<E> {
    type Proof = Proof<E>;

    type VerifyingKey = VerifyingKey<E>;

    fn export(_vk: &Self::VerifyingKey) -> String {
        todo!()
    }
}
