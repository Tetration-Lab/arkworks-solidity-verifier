use ark_ec::PairingEngine;
use ark_marlin::{IndexVerifierKey, Marlin, Proof};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::PolynomialCommitment;
use digest::Digest;

use crate::{PairingLibrary, SolidityVerifier};

impl<
        E: PairingEngine + PairingLibrary,
        PC: PolynomialCommitment<E::Fr, DensePolynomial<E::Fr>>,
        D: Digest,
    > SolidityVerifier<E> for Marlin<E::Fr, PC, D>
{
    type Proof = Proof<E::Fr, PC>;

    type VerifyingKey = IndexVerifierKey<E::Fr, PC>;

    fn export(_vk: &Self::VerifyingKey) -> String {
        todo!()
    }
}
