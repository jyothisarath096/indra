//! Exact CLI amount parsing helpers.

use crate::{CliError, CliResult};

/// Number of Spark in one INDRA.
pub const SPARK_PER_INDRA: u64 = 100_000_000;

/// Parse a human-entered INDRA decimal amount into Spark exactly.
///
/// The parser accepts unsigned decimal strings with at most eight fractional
/// digits, matching the Spark denomination. It intentionally avoids `f64`
/// because binary floating point can round values like `0.00000003` below the
/// exact Spark integer.
pub fn parse_indra_amount_to_spark(raw: &str, field_name: &str) -> CliResult<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::Parse(format!(
            "{field_name} must be a non-negative INDRA decimal amount"
        )));
    }
    if trimmed.starts_with('-') || trimmed.starts_with('+') {
        return Err(CliError::Parse(format!(
            "{field_name} must be a non-negative INDRA decimal amount"
        )));
    }

    let mut parts = trimmed.split('.');
    let whole = parts.next().unwrap_or_default();
    let fractional = parts.next();
    if parts.next().is_some() {
        return Err(CliError::Parse(format!(
            "{field_name} has too many decimal points"
        )));
    }

    if whole.is_empty() && fractional.is_none() {
        return Err(CliError::Parse(format!(
            "{field_name} must be a non-negative INDRA decimal amount"
        )));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) {
        return Err(CliError::Parse(format!(
            "{field_name} must contain only decimal digits"
        )));
    }

    let whole_spark = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u64>()
            .map_err(|_| CliError::Parse(format!("{field_name} is too large")))?
            .checked_mul(SPARK_PER_INDRA)
            .ok_or_else(|| CliError::Parse(format!("{field_name} is too large")))?
    };

    let fractional_spark = match fractional {
        Some(frac) => {
            if frac.is_empty() {
                return Err(CliError::Parse(format!(
                    "{field_name} must include digits after the decimal point"
                )));
            }
            if frac.len() > 8 {
                return Err(CliError::Parse(format!(
                    "{field_name} has more than 8 decimal places; smallest unit is 1 Spark"
                )));
            }
            if !frac.chars().all(|c| c.is_ascii_digit()) {
                return Err(CliError::Parse(format!(
                    "{field_name} must contain only decimal digits"
                )));
            }
            let mut padded = frac.to_string();
            while padded.len() < 8 {
                padded.push('0');
            }
            padded
                .parse::<u64>()
                .map_err(|_| CliError::Parse(format!("{field_name} is invalid")))?
        }
        None => 0,
    };

    whole_spark
        .checked_add(fractional_spark)
        .ok_or_else(|| CliError::Parse(format!("{field_name} is too large")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_indra_amounts_exactly_to_spark() {
        for (raw, expected) in [
            ("0", 0),
            ("1", 100_000_000),
            ("10.5", 1_050_000_000),
            ("0.00000001", 1),
            ("0.00000003", 3),
            ("123456789.12345678", 12_345_678_912_345_678),
            (" 2.00000000 ", 200_000_000),
        ] {
            assert_eq!(
                parse_indra_amount_to_spark(raw, "--amount").unwrap(),
                expected
            );
        }
    }

    #[test]
    fn rejects_invalid_indra_amounts_clearly() {
        for raw in [
            "",
            "-1",
            "+1",
            "1.000000001",
            "1.",
            ".",
            "abc",
            "1_000",
            "1.2.3",
            "184467440737.09551616",
        ] {
            let err = parse_indra_amount_to_spark(raw, "--amount").unwrap_err();
            assert!(
                err.to_string().contains("--amount"),
                "error for {raw:?} did not include field name: {err}"
            );
        }
    }
}
