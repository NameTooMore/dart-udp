use crate::error::ProtocolError;

/// QUIC 风格变长整数支持的最大值（62 位上限：2^62 - 1）
pub(crate) const MAX_VALUE: u64 = (1_u64 << 62) - 1;

/// 计算数值按变长整数编码所需的字节数（1、2、4 或 8 字节）
pub(crate) fn encoded_len(value: u64) -> Result<usize, ProtocolError> {
    if value <= 0x3f {
        Ok(1)
    } else if value <= 0x3fff {
        Ok(2)
    } else if value <= 0x3fff_ffff {
        Ok(4)
    } else if value <= MAX_VALUE {
        Ok(8)
    } else {
        Err(ProtocolError::VarIntOverflow)
    }
}

/// 将 62 位整数按大端变长格式编码追加至输出缓冲区中
///
/// 最高 2 bit 用于标识编码长度：
/// - 00: 1 字节
/// - 01: 2 字节（带掩码 0x4000）
/// - 10: 4 字节（带掩码 0x8000_0000）
/// - 11: 8 字节（带掩码 0xc000_0000_0000_0000）
pub(crate) fn encode(value: u64, output: &mut Vec<u8>) -> Result<(), ProtocolError> {
    let length = encoded_len(value)?;
    match length {
        1 => output.push(value as u8),
        2 => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        4 => output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        8 => output.extend_from_slice(&((value | 0xc000_0000_0000_0000).to_be_bytes())),
        _ => return Err(ProtocolError::InvalidVarIntLength { length }),
    }
    Ok(())
}

/// 从输入字节流当前偏移 `offset` 解析变长整数，并向前推进 `offset`
pub(crate) fn decode(input: &[u8], offset: &mut usize) -> Result<u64, ProtocolError> {
    let first = *input
        .get(*offset)
        .ok_or(ProtocolError::Truncated { context: "varint" })?;
    // 首字节高 2 位决定总长度：1 << (first >> 6)，可能为 1, 2, 4, 8 字节
    let length = 1_usize << usize::from(first >> 6);
    let end = offset
        .checked_add(length)
        .ok_or(ProtocolError::VarIntOverflow)?;
    let bytes = input
        .get(*offset..end)
        .ok_or(ProtocolError::Truncated { context: "varint" })?;
    // 读取对应字节并滤去高 2 位的长度标识位
    let value = match length {
        1 => u64::from(bytes[0] & 0x3f),
        2 => u64::from(u16::from_be_bytes([bytes[0], bytes[1]]) & 0x3fff),
        4 => u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) & 0x3fff_ffff),
        8 => u64::from_be_bytes([
            bytes[0] & 0x3f,
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
        ]),
        _ => return Err(ProtocolError::InvalidVarIntLength { length }),
    };
    *offset = end;
    Ok(value)
}


#[cfg(test)]
mod tests {
    use super::{MAX_VALUE, decode, encode};

    #[test]
    fn round_trips_all_wire_lengths() {
        for value in [
            0_u64,
            63,
            64,
            255,
            256,
            16_383,
            16_384,
            u64::from(u32::MAX),
            MAX_VALUE,
        ] {
            let mut encoded = Vec::new();
            encode(value, &mut encoded).expect("value should encode");
            let mut offset = 0;
            assert_eq!(
                decode(&encoded, &mut offset).expect("value should decode"),
                value
            );
            assert_eq!(offset, encoded.len());
        }
    }

    #[test]
    fn rejects_values_above_the_62_bit_limit() {
        let mut encoded = Vec::new();
        assert!(encode(MAX_VALUE + 1, &mut encoded).is_err());
    }
}
