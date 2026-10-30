//! Random bearer credentials and their one-way persistent representation.

pub(crate) use crate::model::SecretToken;
use crate::policy::{GrantError, Result};
use sha2::{Digest, Sha256};

impl SecretToken {
    pub(crate) fn generate() -> Result<Self> {
        Ok(Self(random_identifier(32, "dst_")?))
    }
    pub(crate) fn hash(&self) -> String {
        hash(self.expose())
    }
}

fn hexadecimal(bytes: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn random_identifier(bytes: usize, prefix: &str) -> Result<String> {
    let mut random = vec![0; bytes];
    getrandom::fill(&mut random).map_err(|_| GrantError("Secure randomness unavailable"))?;
    Ok(format!("{prefix}{}", hexadecimal(&random)))
}

fn hash(token: &str) -> String {
    hexadecimal(&Sha256::digest(token.as_bytes()))
}

pub(crate) fn lookup_hash(token: &str) -> Result<String> {
    if token.len() != 68
        || !token.starts_with("dst_")
        || !token.as_bytes()[4..]
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(GrantError("Invalid or inactive delegation token"));
    }
    Ok(hash(token))
}
