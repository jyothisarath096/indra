#![no_std]
//! Verification-only fixed-limb shadow of INDRA's Q768 sortition arithmetic.
//!
//! This crate is standalone evidence. It is not imported by any production
//! crate and deliberately exposes no integration surface for consensus code.

use core::cmp::Ordering;

pub const Q_BITS: usize = 768;
pub const VALUE_LIMBS: usize = 16;
pub const WIDE_LIMBS: usize = 32;
pub const MAX_F: u64 = 1 << 63;
pub const PRODUCTION_MAX_INTERVAL_WIDTH: u64 = 1 << 24;
pub const PROVED_MAX_INTERVAL_WIDTH: u64 = 1537;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArithmeticError {
    InvalidF,
    InvalidStake,
    DivisionByZero,
    Overflow,
    Underflow,
    QuotientOverflow,
    InvertedInterval,
    WidthGuardExceeded,
    ThresholdOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Uint(pub [u64; VALUE_LIMBS]);

impl Uint {
    pub const ZERO: Self = Self([0; VALUE_LIMBS]);

    pub const fn from_u64(value: u64) -> Self {
        let mut words = [0; VALUE_LIMBS];
        words[0] = value;
        Self(words)
    }

    pub const fn power_of_two(bit: usize) -> Self {
        let mut words = [0; VALUE_LIMBS];
        words[bit / 64] = 1u64 << (bit % 64);
        Self(words)
    }

    pub fn is_zero(&self) -> bool {
        let mut i = 0;
        while i < VALUE_LIMBS {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    pub fn bit_len(&self) -> usize {
        let mut i = VALUE_LIMBS;
        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    fn set_bit(&mut self, bit: usize) {
        self.0[bit / 64] |= 1u64 << (bit % 64);
    }

    pub fn checked_add(&self, rhs: &Self) -> Result<Self, ArithmeticError> {
        let mut out = [0; VALUE_LIMBS];
        let mut carry = false;
        let mut i = 0;
        while i < VALUE_LIMBS {
            let (first, carry_first) = self.0[i].overflowing_add(rhs.0[i]);
            let (second, carry_second) = first.overflowing_add(carry as u64);
            out[i] = second;
            carry = carry_first || carry_second;
            i += 1;
        }
        if carry {
            Err(ArithmeticError::Overflow)
        } else {
            Ok(Self(out))
        }
    }

    pub fn checked_add_u64(&self, rhs: u64) -> Result<Self, ArithmeticError> {
        self.checked_add(&Self::from_u64(rhs))
    }

    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, ArithmeticError> {
        if self < rhs {
            return Err(ArithmeticError::Underflow);
        }
        Ok(self.wrapping_sub(rhs))
    }

    fn wrapping_sub(&self, rhs: &Self) -> Self {
        let mut out = [0; VALUE_LIMBS];
        let mut borrow = false;
        let mut i = 0;
        while i < VALUE_LIMBS {
            let (first, borrow_first) = self.0[i].overflowing_sub(rhs.0[i]);
            let (second, borrow_second) = first.overflowing_sub(borrow as u64);
            out[i] = second;
            borrow = borrow_first || borrow_second;
            i += 1;
        }
        Self(out)
    }

    pub fn checked_shl(&self, shift: usize) -> Result<Self, ArithmeticError> {
        if shift >= VALUE_LIMBS * 64 {
            return if self.is_zero() {
                Ok(Self::ZERO)
            } else {
                Err(ArithmeticError::Overflow)
            };
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0; VALUE_LIMBS];
        let mut i = 0;
        while i < VALUE_LIMBS {
            let word = self.0[i];
            if word != 0 {
                let target = i + word_shift;
                if target >= VALUE_LIMBS {
                    return Err(ArithmeticError::Overflow);
                }
                out[target] |= word << bit_shift;
                if bit_shift != 0 {
                    let high = word >> (64 - bit_shift);
                    if high != 0 {
                        if target + 1 >= VALUE_LIMBS {
                            return Err(ArithmeticError::Overflow);
                        }
                        out[target + 1] |= high;
                    }
                }
            }
            i += 1;
        }
        Ok(Self(out))
    }

    pub fn shr(&self, shift: usize) -> Self {
        if shift >= VALUE_LIMBS * 64 {
            return Self::ZERO;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0; VALUE_LIMBS];
        let mut target = 0;
        while target + word_shift < VALUE_LIMBS {
            let source = target + word_shift;
            out[target] |= self.0[source] >> bit_shift;
            if bit_shift != 0 && source + 1 < VALUE_LIMBS {
                out[target] |= self.0[source + 1] << (64 - bit_shift);
            }
            target += 1;
        }
        Self(out)
    }

    pub fn mul(&self, rhs: &Self) -> Wide {
        let mut out = [0; WIDE_LIMBS];
        let mut i = 0;
        while i < VALUE_LIMBS {
            let mut carry = 0u128;
            let mut j = 0;
            while j < VALUE_LIMBS {
                let index = i + j;
                let product = (self.0[i] as u128) * (rhs.0[j] as u128);
                let total = product + (out[index] as u128) + carry;
                out[index] = total as u64;
                carry = total >> 64;
                j += 1;
            }
            out[i + VALUE_LIMBS] = carry as u64;
            i += 1;
        }
        Wide(out)
    }

    pub fn mul_u64(&self, rhs: u64) -> Wide {
        let mut out = [0; WIDE_LIMBS];
        let mut carry = 0u128;
        let mut i = 0;
        while i < VALUE_LIMBS {
            let total = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = total as u64;
            carry = total >> 64;
            i += 1;
        }
        out[VALUE_LIMBS] = carry as u64;
        Wide(out)
    }

    pub fn div_rem_u64(&self, divisor: u64) -> Result<(Self, u64), ArithmeticError> {
        if divisor == 0 {
            return Err(ArithmeticError::DivisionByZero);
        }
        let mut out = [0; VALUE_LIMBS];
        let mut remainder = 0u128;
        let mut i = VALUE_LIMBS;
        while i > 0 {
            i -= 1;
            let numerator = (remainder << 64) | self.0[i] as u128;
            out[i] = (numerator / divisor as u128) as u64;
            remainder = numerator % divisor as u128;
        }
        Ok((Self(out), remainder as u64))
    }

    pub fn floor_div_u64(&self, divisor: u64) -> Result<Self, ArithmeticError> {
        Ok(self.div_rem_u64(divisor)?.0)
    }

    pub fn ceil_div_u64(&self, divisor: u64) -> Result<Self, ArithmeticError> {
        let (quotient, remainder) = self.div_rem_u64(divisor)?;
        if remainder == 0 {
            Ok(quotient)
        } else {
            quotient.checked_add_u64(1)
        }
    }

    fn as_u128(&self) -> Result<u128, ArithmeticError> {
        let mut i = 2;
        while i < VALUE_LIMBS {
            if self.0[i] != 0 {
                return Err(ArithmeticError::Overflow);
            }
            i += 1;
        }
        Ok(self.0[0] as u128 | ((self.0[1] as u128) << 64))
    }

    fn div_rem_small_u128(&self, divisor: u128) -> Result<(Self, u128), ArithmeticError> {
        if divisor == 0 {
            return Err(ArithmeticError::DivisionByZero);
        }
        // Processing base-2^32 digits keeps (remainder << 32) within u128 for
        // the 65-bit cancelled denominator used by the y substitution.
        if divisor >> 96 != 0 {
            return Err(ArithmeticError::Overflow);
        }
        let mut quotient = [0; VALUE_LIMBS];
        let mut remainder = 0u128;
        let mut digit = VALUE_LIMBS * 2;
        while digit > 0 {
            digit -= 1;
            let limb = digit / 2;
            let shift = (digit % 2) * 32;
            let input_digit = (self.0[limb] >> shift) & 0xffff_ffff;
            let numerator = (remainder << 32) | input_digit as u128;
            let quotient_digit = numerator / divisor;
            if quotient_digit > u32::MAX as u128 {
                return Err(ArithmeticError::QuotientOverflow);
            }
            quotient[limb] |= (quotient_digit as u64) << shift;
            remainder = numerator % divisor;
        }
        Ok((Self(quotient), remainder))
    }

    fn floor_div_small_u128(&self, divisor: u128) -> Result<Self, ArithmeticError> {
        Ok(self.div_rem_small_u128(divisor)?.0)
    }

    fn ceil_div_small_u128(&self, divisor: u128) -> Result<Self, ArithmeticError> {
        let (quotient, remainder) = self.div_rem_small_u128(divisor)?;
        if remainder == 0 {
            Ok(quotient)
        } else {
            quotient.checked_add_u64(1)
        }
    }

    fn shl1_with_bit(&mut self, bit: bool) -> bool {
        let mut carry = bit as u64;
        let mut i = 0;
        while i < VALUE_LIMBS {
            let next = self.0[i] >> 63;
            self.0[i] = (self.0[i] << 1) | carry;
            carry = next;
            i += 1;
        }
        carry != 0
    }

    pub fn min(self, rhs: Self) -> Self {
        if self <= rhs {
            self
        } else {
            rhs
        }
    }
}

impl Ord for Uint {
    fn cmp(&self, rhs: &Self) -> Ordering {
        let mut i = VALUE_LIMBS;
        while i > 0 {
            i -= 1;
            match self.0[i].cmp(&rhs.0[i]) {
                Ordering::Equal => {}
                different => return different,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Uint {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Wide(pub [u64; WIDE_LIMBS]);

impl Wide {
    pub const ZERO: Self = Self([0; WIDE_LIMBS]);

    fn bit(&self, bit: usize) -> bool {
        ((self.0[bit / 64] >> (bit % 64)) & 1) != 0
    }

    pub fn bit_len(&self) -> usize {
        let mut i = WIDE_LIMBS;
        while i > 0 {
            i -= 1;
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub fn narrow(&self) -> Result<Uint, ArithmeticError> {
        let mut i = VALUE_LIMBS;
        while i < WIDE_LIMBS {
            if self.0[i] != 0 {
                return Err(ArithmeticError::Overflow);
            }
            i += 1;
        }
        let mut out = [0; VALUE_LIMBS];
        out.copy_from_slice(&self.0[..VALUE_LIMBS]);
        Ok(Uint(out))
    }

    fn shr_to_uint(&self, shift: usize) -> Result<Uint, ArithmeticError> {
        if shift >= WIDE_LIMBS * 64 {
            return Ok(Uint::ZERO);
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut out = [0; VALUE_LIMBS];
        let mut target = 0;
        while target < VALUE_LIMBS && target + word_shift < WIDE_LIMBS {
            let source = target + word_shift;
            out[target] |= self.0[source] >> bit_shift;
            if bit_shift != 0 && source + 1 < WIDE_LIMBS {
                out[target] |= self.0[source + 1] << (64 - bit_shift);
            }
            target += 1;
        }
        let first_unrepresented = word_shift + VALUE_LIMBS;
        let mut high = first_unrepresented;
        while high < WIDE_LIMBS {
            if self.0[high] != 0 {
                return Err(ArithmeticError::QuotientOverflow);
            }
            high += 1;
        }
        Ok(Uint(out))
    }

    pub fn checked_mul_u64(&self, rhs: u64) -> Result<Self, ArithmeticError> {
        let mut out = [0; WIDE_LIMBS];
        let mut carry = 0u128;
        let mut i = 0;
        while i < WIDE_LIMBS {
            let total = (self.0[i] as u128) * (rhs as u128) + carry;
            out[i] = total as u64;
            carry = total >> 64;
            i += 1;
        }
        if carry != 0 {
            Err(ArithmeticError::Overflow)
        } else {
            Ok(Self(out))
        }
    }

    pub fn div_rem_u64(&self, divisor: u64) -> Result<(Self, u64), ArithmeticError> {
        if divisor == 0 {
            return Err(ArithmeticError::DivisionByZero);
        }
        let mut out = [0; WIDE_LIMBS];
        let mut remainder = 0u128;
        let mut i = WIDE_LIMBS;
        while i > 0 {
            i -= 1;
            let numerator = (remainder << 64) | self.0[i] as u128;
            out[i] = (numerator / divisor as u128) as u64;
            remainder = numerator % divisor as u128;
        }
        Ok((Self(out), remainder as u64))
    }

    pub fn floor_div_u64_to_uint(&self, divisor: u64) -> Result<Uint, ArithmeticError> {
        self.div_rem_u64(divisor)?.0.narrow()
    }

    pub fn ceil_div_u64_to_uint(&self, divisor: u64) -> Result<Uint, ArithmeticError> {
        let (mut quotient, remainder) = self.div_rem_u64(divisor)?;
        if remainder != 0 {
            quotient.add_one()?;
        }
        quotient.narrow()
    }

    fn add_one(&mut self) -> Result<(), ArithmeticError> {
        let mut i = 0;
        while i < WIDE_LIMBS {
            let (word, carry) = self.0[i].overflowing_add(1);
            self.0[i] = word;
            if !carry {
                return Ok(());
            }
            i += 1;
        }
        Err(ArithmeticError::Overflow)
    }

    pub fn floor_div_scale(&self) -> Result<Uint, ArithmeticError> {
        const SCALE_WORDS: usize = Q_BITS / 64;
        let mut out = [0; VALUE_LIMBS];
        let mut i = 0;
        while i < VALUE_LIMBS {
            out[i] = self.0[i + SCALE_WORDS];
            i += 1;
        }
        let mut high = SCALE_WORDS + VALUE_LIMBS;
        while high < WIDE_LIMBS {
            if self.0[high] != 0 {
                return Err(ArithmeticError::QuotientOverflow);
            }
            high += 1;
        }
        Ok(Uint(out))
    }

    pub fn ceil_div_scale(&self) -> Result<Uint, ArithmeticError> {
        const SCALE_WORDS: usize = Q_BITS / 64;
        let mut quotient = self.floor_div_scale()?;
        let mut remainder_nonzero = false;
        let mut i = 0;
        while i < SCALE_WORDS {
            remainder_nonzero |= self.0[i] != 0;
            i += 1;
        }
        if remainder_nonzero {
            quotient = quotient.checked_add_u64(1)?;
        }
        Ok(quotient)
    }

    pub fn div_rem_uint(&self, divisor: &Uint) -> Result<(Uint, Uint), ArithmeticError> {
        if divisor.is_zero() {
            return Err(ArithmeticError::DivisionByZero);
        }
        let mut quotient = Uint::ZERO;
        let mut remainder = Uint::ZERO;
        let mut bit = WIDE_LIMBS * 64;
        while bit > 0 {
            bit -= 1;
            let overflow = remainder.shl1_with_bit(self.bit(bit));
            if overflow || remainder >= *divisor {
                remainder = remainder.wrapping_sub(divisor);
                if bit >= VALUE_LIMBS * 64 {
                    return Err(ArithmeticError::QuotientOverflow);
                }
                quotient.set_bit(bit);
            }
        }
        Ok((quotient, remainder))
    }

    pub fn floor_div_uint(&self, divisor: &Uint) -> Result<Uint, ArithmeticError> {
        Ok(self.div_rem_uint(divisor)?.0)
    }

    pub fn ceil_div_uint(&self, divisor: &Uint) -> Result<Uint, ArithmeticError> {
        let (quotient, remainder) = self.div_rem_uint(divisor)?;
        if remainder.is_zero() {
            Ok(quotient)
        } else {
            quotient.checked_add_u64(1)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Interval {
    lo: Uint,
    hi: Uint,
}

fn scale() -> Uint {
    Uint::power_of_two(Q_BITS)
}

fn mul_interval(a: &Interval, b: &Interval) -> Result<Interval, ArithmeticError> {
    Ok(Interval {
        lo: a.lo.mul(&b.lo).floor_div_scale()?,
        hi: a.hi.mul(&b.hi).ceil_div_scale()?,
    })
}

fn div_interval_u64(a: &Interval, divisor: u64) -> Result<Interval, ArithmeticError> {
    Ok(Interval {
        lo: a.lo.floor_div_u64(divisor)?,
        hi: a.hi.ceil_div_u64(divisor)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Signed {
    negative: bool,
    magnitude: Uint,
}

impl Signed {
    const ZERO: Self = Self {
        negative: false,
        magnitude: Uint::ZERO,
    };

    fn normalize(&mut self) {
        if self.magnitude.is_zero() {
            self.negative = false;
        }
    }

    fn add_positive(&mut self, value: &Uint) -> Result<(), ArithmeticError> {
        if self.negative {
            match self.magnitude.cmp(value) {
                Ordering::Greater => self.magnitude = self.magnitude.checked_sub(value)?,
                Ordering::Equal => self.magnitude = Uint::ZERO,
                Ordering::Less => {
                    self.magnitude = value.checked_sub(&self.magnitude)?;
                    self.negative = false;
                }
            }
        } else {
            self.magnitude = self.magnitude.checked_add(value)?;
        }
        self.normalize();
        Ok(())
    }

    fn sub_positive(&mut self, value: &Uint) -> Result<(), ArithmeticError> {
        if self.negative {
            self.magnitude = self.magnitude.checked_add(value)?;
        } else {
            match self.magnitude.cmp(value) {
                Ordering::Greater => self.magnitude = self.magnitude.checked_sub(value)?,
                Ordering::Equal => self.magnitude = Uint::ZERO,
                Ordering::Less => {
                    self.magnitude = value.checked_sub(&self.magnitude)?;
                    self.negative = true;
                }
            }
        }
        self.normalize();
        Ok(())
    }

    fn nonnegative_or_zero(self) -> Uint {
        if self.negative {
            Uint::ZERO
        } else {
            self.magnitude
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertifiedLogInterval {
    pub lo: Uint,
    pub hi: Uint,
}

pub fn certified_log(f: u64) -> Result<CertifiedLogInterval, ArithmeticError> {
    if f == 0 || f > MAX_F {
        return Err(ArithmeticError::InvalidF);
    }
    let scale = scale();
    let fq = Uint::from_u64(f).checked_shl(Q_BITS - 64)?;
    let denominator = scale.checked_shl(1)?.checked_sub(&fq)?;
    let numerator = fq.mul(&scale);
    // Both operands contain exactly the common factor 2^(Q_BITS-64). The
    // cancellation is integer-exact and therefore preserves both floor and
    // ceil quotients while reducing the divisor to 2^65-f.
    let cancelled_numerator = numerator.shr_to_uint(Q_BITS - 64)?;
    let cancelled_denominator = denominator.shr(Q_BITS - 64).as_u128()?;
    let y = Interval {
        lo: cancelled_numerator.floor_div_small_u128(cancelled_denominator)?,
        hi: cancelled_numerator.ceil_div_small_u128(cancelled_denominator)?,
    };
    let y2 = mul_interval(&y, &y)?;
    let mut power = y;
    let mut lo = Uint::ZERO;
    let mut hi = Uint::ZERO;
    let mut n = 0u64;
    while n < 256 {
        let term = div_interval_u64(&power, 2 * n + 1)?;
        lo = lo.checked_add(&term.lo)?;
        hi = hi.checked_add(&term.hi)?;
        if n != 255 {
            power = mul_interval(&power, &y2)?;
        }
        n += 1;
    }
    let y513 = mul_interval(&power, &y2)?;
    let tail_numerator = y513.hi.mul(&scale).checked_mul_u64(2)?;
    let tail_denominator = scale.checked_sub(&y2.hi)?.mul_u64(513).narrow()?;
    let tail = tail_numerator.ceil_div_uint(&tail_denominator)?;
    Ok(CertifiedLogInterval {
        lo: lo.checked_shl(1)?,
        hi: hi.checked_shl(1)?.checked_add(&tail)?,
    })
}

fn phi(z: Uint, terms: u64, lower: bool) -> Result<Uint, ArithmeticError> {
    let point = Interval { lo: z, hi: z };
    let mut term = point;
    let mut sum = Signed::ZERO;
    let mut k = 1u64;
    while k <= terms {
        if k > 1 {
            term = div_interval_u64(&mul_interval(&term, &point)?, k)?;
        }
        let value = if k % 2 == 1 {
            if lower {
                term.lo
            } else {
                term.hi
            }
        } else if lower {
            term.hi
        } else {
            term.lo
        };
        if k % 2 == 1 {
            sum.add_positive(&value)?;
        } else {
            sum.sub_positive(&value)?;
        }
        k += 1;
    }
    Ok(sum.nonnegative_or_zero())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Threshold512(pub [u64; 8]);

impl Threshold512 {
    fn from_q768_lower(value: &Uint) -> Result<Self, ArithmeticError> {
        let shifted = value.shr(Q_BITS - 512);
        let mut i = 8;
        while i < VALUE_LIMBS {
            if shifted.0[i] != 0 {
                return Err(ArithmeticError::ThresholdOverflow);
            }
            i += 1;
        }
        let mut limbs = [0; 8];
        limbs.copy_from_slice(&shifted.0[..8]);
        Ok(Self(limbs))
    }

    pub fn from_be_bytes(bytes: &[u8; 64]) -> Self {
        let mut limbs = [0; 8];
        let mut limb = 0;
        while limb < 8 {
            let source = 7 - limb;
            let mut word = 0u64;
            let mut byte = 0;
            while byte < 8 {
                word = (word << 8) | bytes[source * 8 + byte] as u64;
                byte += 1;
            }
            limbs[limb] = word;
            limb += 1;
        }
        Self(limbs)
    }

    fn output_is_below(bytes: &[u8; 64], threshold: &Self) -> bool {
        let mut index = 0;
        while index < 64 {
            let limb = 7 - index / 8;
            let shift = 8 * (7 - index % 8);
            let threshold_byte = ((threshold.0[limb] >> shift) & 0xff) as u8;
            if bytes[index] < threshold_byte {
                return true;
            }
            if bytes[index] > threshold_byte {
                return false;
            }
            index += 1;
        }
        false
    }
}

impl Ord for Threshold512 {
    fn cmp(&self, rhs: &Self) -> Ordering {
        let mut i = 8;
        while i > 0 {
            i -= 1;
            match self.0[i].cmp(&rhs.0[i]) {
                Ordering::Equal => {}
                different => return different,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for Threshold512 {
    fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SortitionResult {
    pub eligible: bool,
    pub threshold: Threshold512,
    pub interval_width: Uint,
}

pub fn evaluate(
    log: &CertifiedLogInterval,
    validator_stake: u64,
    total_stake: u64,
    output: &[u8; 64],
) -> Result<SortitionResult, ArithmeticError> {
    if validator_stake == 0 || total_stake == 0 || validator_stake > total_stake {
        return Err(ArithmeticError::InvalidStake);
    }
    let lower_numerator = log.lo.mul_u64(validator_stake);
    let upper_numerator = log.hi.mul_u64(validator_stake);
    let zlo = lower_numerator.floor_div_u64_to_uint(total_stake)?;
    let zhi = upper_numerator.ceil_div_u64_to_uint(total_stake)?;
    let scale = scale();
    let lower_probability = phi(zlo, 128, true)?.min(scale);
    let upper_probability = phi(zhi, 129, false)?.min(scale);
    if upper_probability < lower_probability {
        return Err(ArithmeticError::InvertedInterval);
    }
    let interval_width = upper_probability.checked_sub(&lower_probability)?;
    if interval_width > Uint::from_u64(PRODUCTION_MAX_INTERVAL_WIDTH) {
        return Err(ArithmeticError::WidthGuardExceeded);
    }
    let threshold = Threshold512::from_q768_lower(&lower_probability)?;
    let eligible = Threshold512::output_is_below(output, &threshold);
    Ok(SortitionResult {
        eligible,
        threshold,
        interval_width,
    })
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn admissible_inputs() -> (u64, u64, u64, [u8; 64]) {
        let f: u64 = kani::any();
        let validator_stake: u64 = kani::any();
        let total_stake: u64 = kani::any();
        let output: [u8; 64] = kani::any();
        kani::assume(f > 0);
        kani::assume(f <= MAX_F);
        kani::assume(total_stake > 0);
        kani::assume(validator_stake > 0);
        kani::assume(validator_stake <= total_stake);
        (f, validator_stake, total_stake, output)
    }

    #[kani::proof]
    fn certificate_width_is_at_most_1537() {
        let (f, validator_stake, total_stake, output) = admissible_inputs();
        let log = certified_log(f).expect("admissible F must produce a log interval");
        let result = evaluate(&log, validator_stake, total_stake, &output)
            .expect("admissible stake must evaluate without arithmetic error");
        assert!(result.interval_width <= Uint::from_u64(PROVED_MAX_INTERVAL_WIDTH));
    }

    #[kani::proof]
    fn admissible_domain_has_no_panic_overflow_or_arithmetic_error() {
        let (f, validator_stake, total_stake, output) = admissible_inputs();
        let log = certified_log(f);
        assert!(log.is_ok());
        let result = evaluate(&log.unwrap(), validator_stake, total_stake, &output);
        assert!(result.is_ok());
    }

    #[kani::proof]
    fn certified_log_and_probability_intervals_are_ordered() {
        let (f, validator_stake, total_stake, output) = admissible_inputs();
        let log = certified_log(f).expect("admissible F must produce a log interval");
        assert!(log.lo <= log.hi);
        let result = evaluate(&log, validator_stake, total_stake, &output)
            .expect("admissible stake must evaluate");
        assert!(result.interval_width <= Uint::from_u64(PRODUCTION_MAX_INTERVAL_WIDTH));
    }

    #[kani::proof]
    fn stake_to_threshold_conversion_is_monotone() {
        let f: u64 = kani::any();
        let lower_stake: u64 = kani::any();
        let higher_stake: u64 = kani::any();
        let total_stake: u64 = kani::any();
        kani::assume(f > 0);
        kani::assume(f <= MAX_F);
        kani::assume(total_stake > 0);
        kani::assume(lower_stake > 0);
        kani::assume(lower_stake <= higher_stake);
        kani::assume(higher_stake <= total_stake);
        let log = certified_log(f).expect("admissible F must produce a log interval");
        let lower =
            evaluate(&log, lower_stake, total_stake, &[0; 64]).expect("lower stake must evaluate");
        let higher = evaluate(&log, higher_stake, total_stake, &[0; 64])
            .expect("higher stake must evaluate");
        assert!(lower.threshold <= higher.threshold);
    }

    #[kani::proof]
    fn vrf_big_endian_conversion_matches_eligibility_comparison() {
        let (f, validator_stake, total_stake, output) = admissible_inputs();
        let log = certified_log(f).expect("admissible F must produce a log interval");
        let result = evaluate(&log, validator_stake, total_stake, &output)
            .expect("admissible stake must evaluate");
        let independently_converted = Threshold512::from_be_bytes(&output);
        assert_eq!(result.eligible, independently_converted < result.threshold);
    }

    #[kani::proof]
    fn fixed_limb_vrf_comparison_core_is_correct() {
        let output: [u8; 64] = kani::any();
        let threshold_limbs: [u64; 8] = kani::any();
        let threshold = Threshold512(threshold_limbs);
        let independently_converted = Threshold512::from_be_bytes(&output);
        assert_eq!(
            Threshold512::output_is_below(&output, &threshold),
            independently_converted < threshold
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_limb_shapes_match_the_design() {
        assert_eq!(core::mem::size_of::<Uint>(), 128);
        assert_eq!(core::mem::size_of::<Wide>(), 256);
        assert_eq!(scale().bit_len(), 769);
    }

    #[test]
    fn multiplication_and_power_of_two_rescaling_are_outward() {
        let third_floor = scale().floor_div_u64(3).unwrap();
        let third_ceil = scale().ceil_div_u64(3).unwrap();
        let interval = Interval {
            lo: third_floor,
            hi: third_ceil,
        };
        let square = mul_interval(&interval, &interval).unwrap();
        assert!(square.lo <= square.hi);
        assert_eq!(
            square.hi.checked_sub(&square.lo).unwrap(),
            Uint::from_u64(2)
        );
    }

    #[test]
    fn general_wide_division_rounds_in_both_directions() {
        let numerator = Uint::from_u64(10).mul(&Uint::from_u64(10));
        let divisor = Uint::from_u64(6);
        assert_eq!(
            numerator.floor_div_uint(&divisor).unwrap(),
            Uint::from_u64(16)
        );
        assert_eq!(
            numerator.ceil_div_uint(&divisor).unwrap(),
            Uint::from_u64(17)
        );
    }

    #[test]
    fn cancelled_y_division_matches_the_uncancelled_ratio() {
        for f in [1, MAX_F] {
            let scale = scale();
            let fq = Uint::from_u64(f).checked_shl(Q_BITS - 64).unwrap();
            let denominator = scale.checked_shl(1).unwrap().checked_sub(&fq).unwrap();
            let numerator = fq.mul(&scale);
            let cancelled_numerator = numerator.shr_to_uint(Q_BITS - 64).unwrap();
            let cancelled_denominator = denominator.shr(Q_BITS - 64).as_u128().unwrap();
            assert_eq!(
                numerator.floor_div_uint(&denominator).unwrap(),
                cancelled_numerator
                    .floor_div_small_u128(cancelled_denominator)
                    .unwrap()
            );
            assert_eq!(
                numerator.ceil_div_uint(&denominator).unwrap(),
                cancelled_numerator
                    .ceil_div_small_u128(cancelled_denominator)
                    .unwrap()
            );
        }
    }

    #[test]
    fn endpoint_inputs_complete_and_are_ordered() {
        for f in [1, MAX_F] {
            let log = certified_log(f).unwrap();
            assert!(log.lo > Uint::ZERO);
            assert!(log.lo <= log.hi);
            let result = evaluate(&log, 1, 1, &[0; 64]).unwrap();
            assert!(result.interval_width <= Uint::from_u64(PROVED_MAX_INTERVAL_WIDTH));
        }
    }

    #[test]
    fn zero_output_is_below_a_positive_threshold() {
        let log = certified_log(MAX_F).unwrap();
        let result = evaluate(&log, 1, 1, &[0; 64]).unwrap();
        assert!(result.eligible);
        assert!(Threshold512::from_be_bytes(&[0; 64]) < result.threshold);
    }
}
