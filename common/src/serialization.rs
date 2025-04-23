use anyhow::{anyhow, Result};
use num_bigint::BigUint;

/// Converts a BigUint to a hexadecimal string.
pub fn biguint_to_hex(n: &BigUint) -> String {
    n.to_bytes_be()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Converts a hexadecimal string to a BigUint.
pub fn hex_to_biguint(hex: &str) -> Result<BigUint> {
    let decoded = hex::decode(hex).map_err(|e| anyhow!("Failed to decode hex string: {}", e))?;
    Ok(BigUint::from_bytes_be(&decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn test_hex_biguint_conversion() -> Result<()> {
        let num = BigUint::parse_bytes(b"1234567890abcdef", 16).unwrap();
        let hex = biguint_to_hex(&num);
        assert_eq!(hex, "1234567890abcdef");
        let converted_num = hex_to_biguint(&hex)?;
        assert_eq!(num, converted_num);
        Ok(())
    }

    #[test]
    fn test_hex_biguint_zero() -> Result<()> {
        let num = BigUint::from(0u32);
        let hex = biguint_to_hex(&num);
        // Note: BigUint(0) serializes to the byte [0], resulting in hex "00"
        assert_eq!(hex, "00");
        // Test deserialization of "00"
        let converted_zero = hex_to_biguint(&hex)?;
        assert_eq!(num, converted_zero);

        // Test a non-zero small value
        let num_one = BigUint::one();
        let hex_one = biguint_to_hex(&num_one);
        assert_eq!(hex_one, "01");
        let converted_one = hex_to_biguint(&hex_one)?;
        assert_eq!(num_one, converted_one);
        Ok(())
    }

    #[test]
    fn test_invalid_hex() {
        let invalid_hex = "invalid-hex";
        let result = hex_to_biguint(invalid_hex);
        assert!(result.is_err());
    }
}
