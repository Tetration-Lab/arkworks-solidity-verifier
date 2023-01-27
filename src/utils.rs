use ark_ff::{BigInteger, FpParameters, PrimeField};

pub fn format_bigint<V: BigInteger>(v: V) -> String {
    format!("0x{v}")
}

pub fn format_modulus<F: PrimeField>() -> String {
    format_bigint(<<F as PrimeField>::Params as FpParameters>::MODULUS)
}

pub fn format_inv<F: PrimeField>() -> String {
    <<F as PrimeField>::Params as FpParameters>::INV.to_string()
}
