use poseidon::poseidon2::Poseidon2;
use dep::ecrecover;
mod u128BE;

fn main(
    // PRIVATE INPUTS
    sig: [u8; 64], // r||s ECDSA signature
    pub_key_x: [u8; 32], // x coordinate of public key
    pub_key_y: [u8; 32], // y coordinate of public key

    // PUBLIC INPUTS
    address: pub Field, // address of the receiver
    event_hi: pub Field,  // top 128 bits of eventId
    event_lo: pub Field, // bottom 128 bits of eventId
    null_s: pub Field, // nullifier sender

) {
    // 1. Convert the event id to bytes
    let hi16 = u128BE::field_to_u128_bytes16_be(event_hi);
    let lo16 = u128BE::field_to_u128_bytes16_be(event_lo);

    let mut event_id_bytes: [u8; 32] = [0; 32];
    for i in 0..16 { event_id_bytes[i] = hi16[i]; }
    for i in 0..16 { event_id_bytes[16 + i] = lo16[i]; }

    // 2. Convert the address to bytes
    let b32: [u8; 32] = address.to_be_bytes(); // convert address to bytes
    for i in 0..12 {
        assert(b32[i] == 0);
    }
    let mut addr: [u8; 20] = [0; 20]; // pad the address with 12 bytes of zeros
    for i in 0..20 {
        addr[i] = b32[12 + i];
    }

    // 3. Compute the message
    let mut msg: [u8; 52] = [0; 52]; // initialize message with 52 bytes of zeros 
    for i in 0..20 {
        msg[i] = addr[i]; // copy address to message
    }
    for i in 0..32 {
        msg[i + 20] = event_id_bytes[i]; // copy event id to message
    }
    let hashed_msg: [u8; 32] = keccak256::keccak256(msg, 52); // hash the message
    
    // 4. Recover the address
    let recovered: Field = ecrecover::ecrecover(pub_key_x, pub_key_y, sig, hashed_msg); // recover the address
    assert(recovered != Field::from(0)); // check that the recovered address is not the zero address
    assert(recovered == address); // check that the recovered address matches the input address

    // 5. Compute the nullifier
    let mut s_bytes: [u8; 32] = [0; 32]; // extract s from the signature
    for i in 0..32 {
        s_bytes[i] = sig[i + 32]; // copy s to s_bytes
    }
    let s_field = Field::from_be_bytes(s_bytes); // convert s_bytes to Field
    let null_r = Poseidon2::hash([s_field], 1); // compute the nullifier receiver
    assert(null_r != null_s); // check that the nullifier receiver is not equal to the nullifier sender
}

