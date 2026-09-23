const CRC32C_POLYNOMIAL: u32 = 0x82f6_3b78;

pub(crate) fn crc32c_with_zeroed_range(bytes: &[u8], zero_start: usize, zero_end: usize) -> u32 {
    let mut checksum = u32::MAX;
    for (index, &byte) in bytes.iter().enumerate() {
        let byte = if (zero_start..zero_end).contains(&index) {
            0
        } else {
            byte
        };
        checksum ^= u32::from(byte);
        for _ in 0..8 {
            checksum = if checksum & 1 == 1 {
                (checksum >> 1) ^ CRC32C_POLYNOMIAL
            } else {
                checksum >> 1
            };
        }
    }
    !checksum
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_the_crc32c_reference_vector() {
        assert_eq!(
            super::crc32c_with_zeroed_range(b"123456789", 0, 0),
            0xe306_9283
        );
    }

    #[test]
    fn zeroed_range_is_equivalent_to_zero_bytes() {
        let bytes = [1_u8, 2, 3, 4, 5];
        assert_eq!(
            super::crc32c_with_zeroed_range(&bytes, 1, 4),
            super::crc32c_with_zeroed_range(&[1, 0, 0, 0, 5], 0, 0)
        );
    }
}
