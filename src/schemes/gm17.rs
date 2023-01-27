use ark_ec::PairingEngine;
use ark_gm17::{Proof, VerifyingKey, GM17};
use regex::Regex;

use crate::{
    constants::TEMPLATE_PREFIX_TEXT, utils::format_modulus, PairingLibrary, SolidityVerifier,
};

impl<E: PairingEngine + PairingLibrary> SolidityVerifier<E> for GM17<E> {
    type Proof = Proof<E>;

    type VerifyingKey = VerifyingKey<E>;

    fn export(vk: &Self::VerifyingKey) -> String {
        let mut template_text = String::from(CONTRACT_TEMPLATE);

        // replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_query_len_regex = Regex::new(r#"(<%vk_query_length%>)"#).unwrap();
        let vk_query_repeat_regex = Regex::new(r#"(<%vk_query_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        let input_loop = Regex::new(r#"(<%input_loop%>)"#).unwrap();
        let input_argument = Regex::new(r#"(<%input_argument%>)"#).unwrap();

        template_text = vk_regex
            .replace(template_text.as_str(), E::g2_to_string(&vk.h_g2))
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), E::g1_to_string(&vk.g_alpha_g1))
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), E::g2_to_string(&vk.h_beta_g2))
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), E::g1_to_string(&vk.g_gamma_g1))
            .into_owned();

        template_text = vk_regex
            .replace(template_text.as_str(), E::g2_to_string(&vk.h_gamma_g2))
            .into_owned();

        let query_count: usize = vk.query.len();
        template_text = vk_query_len_regex
            .replace(template_text.as_str(), format!("{query_count}").as_str())
            .into_owned();

        template_text = vk_input_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", query_count - 1).as_str(),
            )
            .into_owned();

        // feed input values only if there are any
        template_text = if query_count > 1 {
            input_loop.replace(
                template_text.as_str(),
                r#"
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }"#,
            )
        } else {
            input_loop.replace(template_text.as_str(), "")
        }
        .to_string();

        // take input values as argument only if there are any
        template_text = if query_count > 1 {
            input_argument.replace(
                template_text.as_str(),
                format!(", uint[{}] memory input", query_count - 1).as_str(),
            )
        } else {
            input_argument.replace(template_text.as_str(), "")
        }
        .to_string();

        let mut query_repeat_text = String::new();
        for (i, g1) in vk.query.iter().enumerate() {
            query_repeat_text.push_str(
                format!(
                    "vk.query[{}] = Pairing.G1Point({});",
                    i,
                    E::g1_to_string(g1)
                )
                .as_str(),
            );
            if i < query_count - 1 {
                query_repeat_text.push_str("\n        ");
            }
        }

        template_text = vk_query_repeat_regex
            .replace(template_text.as_str(), query_repeat_text.as_str())
            .into_owned();

        let scalar_field = Regex::new(r"<%scalar_field%>").unwrap();
        template_text = scalar_field
            .replace(&template_text, format_modulus::<E::Fr>())
            .to_string();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();

        format!(
            "{}\n{}\n{}",
            TEMPLATE_PREFIX_TEXT,
            E::template(true),
            template_text
        )
    }
}

const CONTRACT_TEMPLATE: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G2Point h;
        Pairing.G1Point g_alpha;
        Pairing.G2Point h_beta;
        Pairing.G1Point g_gamma;
        Pairing.G2Point h_gamma;
        Pairing.G1Point[] query;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.h= Pairing.G2Point(<%vk_h%>);
        vk.g_alpha = Pairing.G1Point(<%vk_g_alpha%>);
        vk.h_beta = Pairing.G2Point(<%vk_h_beta%>);
        vk.g_gamma = Pairing.G1Point(<%vk_g_gamma%>);
        vk.h_gamma = Pairing.G2Point(<%vk_h_gamma%>);
        vk.query = new Pairing.G1Point[](<%vk_query_length%>);
        <%vk_query_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = <%scalar_field%>;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.query.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.query[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.query[0]);
        /**
         * e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
         *                              * e(C, H)
         * where psi = \sum_{i=0}^l input_i pvk.query[i]
         */
        if (!Pairing.pairingProd4(vk.g_alpha, vk.h_beta, vk_x, vk.h_gamma, proof.c, vk.h, Pairing.negate(Pairing.addition(proof.a, vk.g_alpha)), Pairing.addition(proof.b, vk.h_beta))) return 1;
        /**
         * e(A, H^{gamma}) = e(G^{gamma}, B)
         */
        if (!Pairing.pairingProd2(proof.a, vk.h_gamma, Pairing.negate(vk.g_gamma), proof.b)) return 2;
        return 0;
    }
    function verifyTx(
            Proof memory proof<%input_argument%>
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](<%vk_input_length%>);
        <%input_loop%>
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
"#;
