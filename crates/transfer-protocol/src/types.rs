use core::{fmt, str::FromStr};

use crate::error::RandomnessError;

pub const ID_LEN: usize = 16;
pub const CHECK_TOKEN_LEN: usize = 32;
pub const PAIRING_CODE_MIN_LEN: usize = 8;
pub const PAIRING_CODE_MAX_LEN: usize = 10;

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; ID_LEN]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
                &self.0
            }

            pub fn random() -> Result<Self, RandomnessError> {
                let mut bytes = [0_u8; ID_LEN];
                getrandom::fill(&mut bytes).map_err(|_| RandomnessError)?;
                Ok(Self(bytes))
            }

            pub fn generate() -> Result<Self, RandomnessError> {
                Self::random()
            }
        }

        impl From<[u8; ID_LEN]> for $name {
            fn from(bytes: [u8; ID_LEN]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&HexBytes(&self.0))
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in &self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    };
}

define_id!(PairingId);
define_id!(TransferId);
define_id!(FileId);
define_id!(ClientInstanceId);
define_id!(CandidateId);
define_id!(PathId);
define_id!(RelayId);
define_id!(TransactionId);

#[derive(Clone, PartialEq, Eq)]
pub struct SessionTicket(Vec<u8>);

impl SessionTicket {
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SessionTicket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionTicket")
            .field("length", &self.0.len())
            .finish()
    }
}

impl From<Vec<u8>> for SessionTicket {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckToken([u8; CHECK_TOKEN_LEN]);

impl CheckToken {
    pub const fn from_bytes(bytes: [u8; CHECK_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; CHECK_TOKEN_LEN] {
        &self.0
    }

    pub fn random() -> Result<Self, RandomnessError> {
        let mut bytes = [0_u8; CHECK_TOKEN_LEN];
        getrandom::fill(&mut bytes).map_err(|_| RandomnessError)?;
        Ok(Self(bytes))
    }
}

impl From<[u8; CHECK_TOKEN_LEN]> for CheckToken {
    fn from(bytes: [u8; CHECK_TOKEN_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for CheckToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CheckToken")
            .field(&HexBytes(&self.0))
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest {
    pub algorithm: HashAlgorithm,
    pub bytes: [u8; 32],
}

impl Digest {
    pub const fn new(algorithm: HashAlgorithm, bytes: [u8; 32]) -> Self {
        Self { algorithm, bytes }
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Digest")
            .field("algorithm", &self.algorithm)
            .field("bytes", &HexBytes(&self.bytes))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HashAlgorithm {
    Blake3 = 1,
    Sha256 = 2,
}

impl TryFrom<u8> for HashAlgorithm {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Blake3),
            2 => Ok(Self::Sha256),
            _ => Err(()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PairingCode(String);

impl PairingCode {
    pub fn generate() -> Result<Self, crate::ProtocolError> {
        Self::generate_with_len(PAIRING_CODE_MIN_LEN)
    }

    pub fn generate_with_len(length: usize) -> Result<Self, crate::ProtocolError> {
        if !(PAIRING_CODE_MIN_LEN..=PAIRING_CODE_MAX_LEN).contains(&length) {
            return Err(crate::ProtocolError::InvalidValue {
                field: "pairing code length",
            });
        }

        let byte_len = (length * 5).div_ceil(8);
        let mut random = [0_u8; 7];
        getrandom::fill(&mut random[..byte_len])
            .map_err(|_| crate::ProtocolError::RandomnessUnavailable)?;
        let mut output = String::with_capacity(length);
        for index in 0..length {
            let bit_offset = index * 5;
            let byte_index = bit_offset / 8;
            let intra_byte_offset = bit_offset % 8;
            let mut value = u16::from(random[byte_index]) << 8;
            if byte_index + 1 < byte_len {
                value |= u16::from(random[byte_index + 1]);
            }
            let symbol = ((value >> (11 - intra_byte_offset)) & 0x1f) as usize;
            output.push(char::from(CROCKFORD_ALPHABET[symbol]));
        }
        Ok(Self(output))
    }

    pub fn parse(value: &str) -> Result<Self, crate::ProtocolError> {
        if !(PAIRING_CODE_MIN_LEN..=PAIRING_CODE_MAX_LEN).contains(&value.len())
            || !value.bytes().all(|byte| {
                let upper = byte.to_ascii_uppercase();
                CROCKFORD_ALPHABET.contains(&upper)
            })
        {
            return Err(crate::ProtocolError::InvalidPairingCode);
        }
        Ok(Self(
            value
                .bytes()
                .map(|byte| byte.to_ascii_uppercase() as char)
                .collect(),
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for PairingCode {
    type Err = crate::ProtocolError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for PairingCode {
    type Error = crate::ProtocolError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PairingCode").field(&self.0).finish()
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Debug for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("0x")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
