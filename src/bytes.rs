use std::convert::TryInto;

pub trait Bytes {
    fn u8_be(&self, i: usize) -> u8;
    fn u16_be(&self, i: usize) -> u16;
    fn u32_be(&self, i: usize) -> u32;
    fn u64_be(&self, i: usize) -> u64;
    fn u128_be(&self, i: usize) -> u128;

    fn u8_le(&self, i: usize) -> u8;
    fn u16_le(&self, i: usize) -> u16;
    fn u32_le(&self, i: usize) -> u32;
    fn u64_le(&self, i: usize) -> u64;
    fn u128_le(&self, i: usize) -> u128;

    fn u8_ne(&self, i: usize) -> u8;
    fn u16_ne(&self, i: usize) -> u16;
    fn u32_ne(&self, i: usize) -> u32;
    fn u64_ne(&self, i: usize) -> u64;
    fn u128_ne(&self, i: usize) -> u128;
}

impl Bytes for [u8] {
    fn u8_be(&self, i: usize) -> u8 {
        u8::from_be_bytes(self[i .. i + 1].try_into().unwrap())
    }
    fn u16_be(&self, i: usize) -> u16 {
        u16::from_be_bytes(self[i .. i + 2].try_into().unwrap())
    }
    fn u32_be(&self, i: usize) -> u32 {
        u32::from_be_bytes(self[i .. i + 4].try_into().unwrap())
    }
    fn u64_be(&self, i: usize) -> u64 {
        u64::from_be_bytes(self[i .. i + 8].try_into().unwrap())
    }
    fn u128_be(&self, i: usize) -> u128 {
        u128::from_be_bytes(self[i .. i + 16].try_into().unwrap())
    }

    fn u8_le(&self, i: usize) -> u8 {
        u8::from_le_bytes(self[i .. i + 1].try_into().unwrap())
    }
    fn u16_le(&self, i: usize) -> u16 {
        u16::from_le_bytes(self[i .. i + 2].try_into().unwrap())
    }
    fn u32_le(&self, i: usize) -> u32 {
        u32::from_le_bytes(self[i .. i + 4].try_into().unwrap())
    }
    fn u64_le(&self, i: usize) -> u64 {
        u64::from_le_bytes(self[i .. i + 8].try_into().unwrap())
    }
    fn u128_le(&self, i: usize) -> u128 {
        u128::from_le_bytes(self[i .. i + 16].try_into().unwrap())
    }

    fn u8_ne(&self, i: usize) -> u8 {
        u8::from_ne_bytes(self[i .. i + 1].try_into().unwrap())
    }
    fn u16_ne(&self, i: usize) -> u16 {
        u16::from_ne_bytes(self[i .. i + 2].try_into().unwrap())
    }
    fn u32_ne(&self, i: usize) -> u32 {
        u32::from_ne_bytes(self[i .. i + 4].try_into().unwrap())
    }
    fn u64_ne(&self, i: usize) -> u64 {
        u64::from_ne_bytes(self[i .. i + 8].try_into().unwrap())
    }
    fn u128_ne(&self, i: usize) -> u128 {
        u128::from_ne_bytes(self[i .. i + 16].try_into().unwrap())
    }
}

