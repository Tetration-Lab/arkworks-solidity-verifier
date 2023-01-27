# Arkworks Solidity Verifier

Solidity SNARK verifier generator for Arkwork's proof systems. Extensible with future Ethereum's compatible curve or custom precompiled curve using trait implementation.

## Supported Algorithms

### Curves

- BN254 [[BCTV14]](https://eprint.iacr.org/2013/879.pdf) using [ark_bn254](https://github.com/arkworks-rs/curves/tree/master/bn254)

### Proof Systems

- Groth16 [[Gro16]](https://eprint.iacr.org/2016/260) using [ark_groth16](https://github.com/arkworks-rs/groth16)
- GM17 [[GM17]](https://eprint.iacr.org/2017/540) using [ark_gm17](https://github.com/arkworks-rs/gm17)
- Marlin with Marlin polynomial commitment [[CHMMVW20]](https://ia.cr/2019/1047) using [ark_marlin](https://github.com/arkworks-rs/marlin) and [ark_poly_commit::marlin_pc](https://github.com/arkworks-rs/poly-commit/tree/master/src/marlin)

## Acknowledgement

The Solidity verifier template was modified from [ZoKrates](https://github.com/Zokrates/ZoKrates) implementation.

- <https://github.com/Zokrates/ZoKrates/tree/develop/zokrates_proof_systems>
