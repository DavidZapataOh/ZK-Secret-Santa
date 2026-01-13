use poseidon::poseidon2::Poseidon2;

global DEPTH: u32 = 20;

pub fn smt_process_proof(
    key: Field, // key = hash(value)
    value: Field, // value = participant address or H
    siblings: [Field; DEPTH], // siblings of the proof
    depth_eff: u32 // depth of the proof
) -> Field {
    let mut h = Poseidon2::hash([Poseidon2::hash([value], 1), value, Field::from(1)], 3); // h = hash(key, value, 1)
    let bits: [u1; 254] = (Poseidon2::hash([value], 1)).to_le_bits(); // bits = hash(value).to_le_bits()

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