use poseidon::poseidon2::Poseidon2;

global DEPTH: u32 = 20;

pub fn smt_process_proof(
    key: Field,
    value: Field,
    siblings: [Field; DEPTH],
    depth_eff: u32
) -> Field {
    let mut h = Poseidon2::hash([key, value, Field::from(1)], 3);
    let bits: [u1; 254] = key.to_le_bits();

    for j in 0..DEPTH { // for each level of the SMT
        let i = (DEPTH - 1 - j) as u32; // i = DEPTH - 1 - j

        if i < depth_eff { // if the current level is within the depth of the proof
            let sib = siblings[i]; // sib = siblings[i]
            let bit = bits[i]; // bit = bits[i]

            if bit == 1 {
                h = Poseidon2::hash([sib, h], 2); // h = hash(sibling, h)
            } else {
                h = Poseidon2::hash([h, sib], 2); // h = hash(h, sibling)
            }
        }
    }

    h // return the root of the SMT
}