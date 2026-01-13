use dep::ecrecover;
use poseidon::poseidon2::Poseidon2;
mod sparse_merkle_tree;

global DEPTH: u32 = 20;

fn main(
    // PRIVATE INPUTS
    sig: [u8; 64], // r||s ECDSA signature
    pub_key_x: [u8; 32], // x coordinate of public key
    pub_key_y: [u8; 32], // y coordinate of public key
    address: [u8; 20], // address of the sender
    proof_p_siblings: [Field; DEPTH], // siblings of the proof for participants
    proof_p_depth_eff: u32, // depth of the proof for participants
    proof_c_siblings: [Field; DEPTH], // siblings of the proof for commitments
    proof_c_depth_eff: u32, // depth of the proof for commitments

    // PUBLIC INPUTS
    r: pub Field, // randomness
    event_id: pub [u8; 32], // event id
    root_p: pub Field, // root of the participants SMT
    root_c: pub Field, // root of the commitments SMT
    null_s: pub Field, // nullifier sender

) {
    // 1. Compute the message
    let mut msg: [u8; 52] = [0; 52]; // 20 bytes for address + 32 bytes for event id
    for i in 0..20 { // copy address to msg
        msg[i] = address[i];
    }
    for i in 0..32 { // copy event id to msg
        msg[i + 20] = event_id[i];
    }
    let hashed_msg: [u8; 32] = keccak256::keccak256(msg, 32); // hash the message
    
    // 2. Recover the address
    let recovered: Field = ecrecover::ecrecover(pub_key_x, pub_key_y, sig, hashed_msg);  // recover the address
    assert(recovered != Field::from(0)); // check that the address is not the zero address

    // 3. Convert the address to Field
    let mut padded: [u8; 32] = [0; 32]; // pad the address with 12 bytes of zeros
    for i in 0..20 {
        padded[12 + i] = address[i];
    }
    let address_field = Field::from_be_bytes(padded); // convert the address to Field
    assert(recovered == address_field); // check that the recovered address matches the input address
    
    // 4. Compute the nullifier
    let mut s_bytes: [u8; 32] = [0; 32]; // extract s from the signature
    for i in 0..32 {
        s_bytes[i] = sig[i + 32]; // copy s to s_bytes
    }
    let s_field = Field::from_be_bytes(s_bytes); // convert s_bytes to Field
    let computed_nulls = Poseidon2::hash([s_field], 1); // compute the nullifier
    assert(computed_nulls == null_s); // check that the computed nullifier matches the input nullifier

    // 5. H = hash(sig)
    let mut r_bytes: [u8; 32] = [0; 32]; // extract r from the signature
    for i in 0..32 {
        r_bytes[i] = sig[i]; // copy r to r_bytes
    }
    let r_field = Field::from_be_bytes(r_bytes); // convert r_bytes to Field
    let H = Poseidon2::hash([r_field, s_field], 2); // compute H

    // 6. Merkle verify participants
    let root_p_calc = sparse_merkle_tree::smt_process_proof(
        Poseidon2::hash([address_field], 1),
        address_field,
        proof_p_siblings,
        proof_p_depth_eff,
    ); // compute the root of the participants SMT
    assert(root_p_calc == root_p); // check that the computed root matches the input root
    
    // 7. Merkle verify commitments
    let root_c_calc = sparse_merkle_tree::smt_process_proof(
        Poseidon2::hash([H], 1),
        H,
        proof_c_siblings,
        proof_c_depth_eff,
    ); // compute the root of the commitments SMT
    assert(root_c_calc == root_c); // check that the computed root matches the input root
}

