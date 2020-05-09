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

    fn put_u8_be(&mut self, i: usize, x: u8);
    fn put_u16_be(&mut self, i: usize, x: u16);
    fn put_u32_be(&mut self, i: usize, x: u32);
    fn put_u64_be(&mut self, i: usize, x: u64);
    fn put_u128_be(&mut self, i: usize, x: u128);

    fn put_u8_le(&mut self, i: usize, x: u8);
    fn put_u16_le(&mut self, i: usize, x: u16);
    fn put_u32_le(&mut self, i: usize, x: u32);
    fn put_u64_le(&mut self, i: usize, x: u64);
    fn put_u128_le(&mut self, i: usize, x: u128);

    fn put_u8_ne(&mut self, i: usize, x: u8);
    fn put_u16_ne(&mut self, i: usize, x: u16);
    fn put_u32_ne(&mut self, i: usize, x: u32);
    fn put_u64_ne(&mut self, i: usize, x: u64);
    fn put_u128_ne(&mut self, i: usize, x: u128);
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

    fn put_u8_be(&mut self, i: usize, x: u8) {
        self[i .. i + 1].copy_from_slice(&x.to_be_bytes())
    }
    fn put_u16_be(&mut self, i: usize, x: u16) {
        self[i .. i + 2].copy_from_slice(&x.to_be_bytes())
    }
    fn put_u32_be(&mut self, i: usize, x: u32) {
        self[i .. i + 4].copy_from_slice(&x.to_be_bytes())
    }
    fn put_u64_be(&mut self, i: usize, x: u64) {
        self[i .. i + 8].copy_from_slice(&x.to_be_bytes())
    }
    fn put_u128_be(&mut self, i: usize, x: u128) {
        self[i .. i + 16].copy_from_slice(&x.to_be_bytes())
    }

    fn put_u8_le(&mut self, i: usize, x: u8) {
        self[i .. i + 1].copy_from_slice(&x.to_le_bytes())
    }
    fn put_u16_le(&mut self, i: usize, x: u16) {
        self[i .. i + 2].copy_from_slice(&x.to_le_bytes())
    }
    fn put_u32_le(&mut self, i: usize, x: u32) {
        self[i .. i + 4].copy_from_slice(&x.to_le_bytes())
    }
    fn put_u64_le(&mut self, i: usize, x: u64) {
        self[i .. i + 8].copy_from_slice(&x.to_le_bytes())
    }
    fn put_u128_le(&mut self, i: usize, x: u128) {
        self[i .. i + 16].copy_from_slice(&x.to_le_bytes())
    }

    fn put_u8_ne(&mut self, i: usize, x: u8) {
        self[i .. i + 1].copy_from_slice(&x.to_ne_bytes())
    }
    fn put_u16_ne(&mut self, i: usize, x: u16) {
        self[i .. i + 2].copy_from_slice(&x.to_ne_bytes())
    }
    fn put_u32_ne(&mut self, i: usize, x: u32) {
        self[i .. i + 4].copy_from_slice(&x.to_ne_bytes())
    }
    fn put_u64_ne(&mut self, i: usize, x: u64) {
        self[i .. i + 8].copy_from_slice(&x.to_ne_bytes())
    }
    fn put_u128_ne(&mut self, i: usize, x: u128) {
        self[i .. i + 16].copy_from_slice(&x.to_ne_bytes())
    }
}

