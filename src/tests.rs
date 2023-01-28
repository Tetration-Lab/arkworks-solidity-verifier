use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr};
use ark_ec::PairingEngine;
use ark_gm17::GM17;
use ark_groth16::Groth16;
use ark_marlin::Marlin;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::marlin_pc::MarlinKZG10;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{error::Error, test_rng};
use blake2::Blake2s;

use crate::SolidityVerifier;

/// Simple circuit that enforces self.0 * self.1 == self.2 when self.0 and self.1 is private witness
struct ExpCircuits<E: PairingEngine>(Option<u64>, Option<u64>, Option<u64>, PhantomData<E>);

impl<E: PairingEngine> ConstraintSynthesizer<E::Fr> for ExpCircuits<E> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<E::Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        let base = FpVar::new_witness(cs.clone(), || {
            self.0
                .map(E::Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mult = FpVar::new_witness(cs.clone(), || {
            self.1
                .map(E::Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let result = FpVar::new_input(cs.clone(), || {
            self.2
                .map(E::Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        (&base * &mult).enforce_equal(&result)?;

        Ok(())
    }
}

#[test]
fn circuit_works() -> Result<(), Box<dyn Error>> {
    let mut rng = test_rng();
    let (pk, vk) = Groth16::<Bn254>::setup(
        ExpCircuits::<Bn254>(None, None, None, PhantomData),
        &mut rng,
    )?;
    let base = 5;
    let mult = 10;
    let result = base * mult;
    let proof = Groth16::prove(
        &pk,
        ExpCircuits::<Bn254>(Some(base), Some(mult), Some(result), PhantomData),
        &mut rng,
    )?;

    assert!(Groth16::verify(&vk, &[Fr::from(result)], &proof)?);
    assert!(!Groth16::verify(&vk, &[Fr::from(result + 1)], &proof)?);

    Ok(())
}

#[test]
fn export_works() -> Result<(), Box<dyn Error>> {
    type MarlinInst = Marlin<Fr, MarlinKZG10<Bn254, DensePolynomial<Fr>>, Blake2s>;

    let rng = &mut test_rng();

    let (_, vk) =
        Groth16::<Bn254>::setup(ExpCircuits::<Bn254>(None, None, None, PhantomData), rng)?;
    let _sol_verifier = Groth16::export(&vk);

    let (_, vk) = GM17::<Bn254>::setup(ExpCircuits::<Bn254>(None, None, None, PhantomData), rng)?;
    let _sol_verifier = GM17::export(&vk);

    let srs = MarlinInst::universal_setup(5, 3, 3, rng).unwrap();
    let (_, vk) =
        MarlinInst::index(&srs, ExpCircuits::<Bn254>(None, None, None, PhantomData)).unwrap();
    let _sol_verifier = MarlinInst::export(&vk);

    Ok(())
}
