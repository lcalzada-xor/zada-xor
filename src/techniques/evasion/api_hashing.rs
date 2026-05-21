const XOR_KEY: u32 = 0x7F3A9C12;
const ROR_SHIFT: u32 = 7;
const FNV_PRIME: u32 = 16777619;

#[inline]
pub fn unique_hash(name: &str) -> u32 {
    let bytes = name.as_bytes();
    let mut hash: u32 = 0x811C9DC5;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash = (hash >> ROR_SHIFT) | (hash << (32 - ROR_SHIFT));
        i += 1;
    }
    hash ^ XOR_KEY
}
