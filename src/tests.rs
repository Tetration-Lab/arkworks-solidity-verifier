use std::marker::PhantomData;

use ark_bn254::{Bn254, Fr};
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::error::Error;
use rand::thread_rng;

use crate::SolidityVerifier;

/// Simple circuit that enforces self.0 * self.1 == self.2 when self.0 and self.1 is private witness
struct ExpCircuits<E: Pairing>(Option<u64>, Option<u64>, Option<u64>, PhantomData<E>);

impl<E: Pairing> ConstraintSynthesizer<E::ScalarField> for ExpCircuits<E> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<E::ScalarField>,
    ) -> ark_relations::r1cs::Result<()> {
        let base = FpVar::new_witness(cs.clone(), || {
            self.0
                .map(E::ScalarField::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mult = FpVar::new_witness(cs.clone(), || {
            self.1
                .map(E::ScalarField::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        let result = FpVar::new_input(cs.clone(), || {
            self.2
                .map(E::ScalarField::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        (&base * &mult).enforce_equal(&result)?;

        Ok(())
    }
}

#[test]
fn circuit_works() -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();
    let (pk, vk) = Groth16::<Bn254>::setup(
        ExpCircuits::<Bn254>(None, None, None, PhantomData),
        &mut rng,
    )?;
    let base = 5;
    let mult = 10;
    let result = base * mult;
    let proof = Groth16::<Bn254>::prove(
        &pk,
        ExpCircuits::<Bn254>(Some(base), Some(mult), Some(result), PhantomData),
        &mut rng,
    )?;

    assert!(Groth16::<Bn254>::verify(&vk, &[Fr::from(result)], &proof)?);
    assert!(!Groth16::<Bn254>::verify(
        &vk,
        &[Fr::from(result + 1)],
        &proof
    )?);

    Ok(())
}

#[test]
fn export_works() -> Result<(), Box<dyn Error>> {
    let rng = &mut thread_rng();

    let (_, vk) =
        Groth16::<Bn254>::setup(ExpCircuits::<Bn254>(None, None, None, PhantomData), rng)?;
    let _sol_verifier = Groth16::export(&vk);

    println!("{}", _sol_verifier);

    Ok(())
}
