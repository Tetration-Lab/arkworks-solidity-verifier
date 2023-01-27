# Arkworks Solidity Verifier

Solidity SNARK verifier generator for Arkwork's proof systems. Extensible with future Ethereum's compatible curve or custom precompiled curve using trait implementation.

## Supported Algorithms

### Curves

- BN254 [[BCTV14](https://eprint.iacr.org/2013/879.pdf)] using [ark_bn254](https://github.com/arkworks-rs/curves/tree/master/bn254)

### Proof Systems

- Groth16 using ark_groth16
- GM17 using ark_gm17
- Marlin with Marlin polynomial commitment using ark_marlin and ark_poly_commit::marlin_pc

## Acknowledgement

The Solidity verifier template was modified from [ZoKrates](https://github.com/Zokrates/ZoKrates) implementation.

- https://github.com/Zokrates/ZoKrates/tree/develop/zokrates_proof_systems
