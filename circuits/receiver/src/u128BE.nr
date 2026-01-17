pub fn field_to_u128_bytes16_be(x: Field) -> [u8; 16] {
    let b: [u8; 32] = x.to_be_bytes();
    // x must fit in 128 bits => top 16 bytes are 0
    for i in 0..16 {
        assert(b[i] == 0);
    }
    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = b[16 + i];
    }
    out
}
