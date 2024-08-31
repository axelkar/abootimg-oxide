use std::fmt;

use binrw::{BinRead, BinWrite};

/// OS version and patch level
///
/// # Bitwise format
///
/// * 7 bits indicate first part of version
/// * 7 bits indicate second part of version
/// * 7 bits indicate third part of version
/// * 12 bits indicate patch year
/// * 4 bits indicate patch month
#[derive(BinRead, BinWrite, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[br(little)]
pub struct OsVersionPatch(u32);

impl OsVersionPatch {
    /// Creates a new `OsVersionPatch`.
    pub fn new(version: OsVersion, patch: OsPatch) -> Self {
        Self((version.0 << 11) + patch.0 as u32)
    }
    /// Returns the version part.
    pub fn version(self) -> OsVersion {
        OsVersion(self.0 >> 11)
    }
    /// Returns the patch part.
    pub fn patch(self) -> OsPatch {
        OsPatch((self.0 & 0x7ff) as u16)
    }
}

impl fmt::Debug for OsVersionPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OsVersionPatch({}, {})", self.version(), self.patch())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsPatch(u16);
impl OsPatch {
    /// Creates a new `OsPatch`.
    pub fn new(year: u16, month: u8) -> Self {
        Self(((year - 2000) << 4) + month as u16)
    }
    /// Returns the year.
    pub fn year(self) -> u16 {
        // Highest 12 bits indicate year
        (self.0 >> 4) + 2000
    }
    /// Returns the month.
    pub fn month(self) -> u8 {
        // Lowest 4 bits indicate month
        (self.0 & 0xf) as u8
    }
}

impl fmt::Display for OsPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{:02}", self.year(), self.month())
    }
}
impl fmt::Debug for OsPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsVersion(u32);
impl OsVersion {
    /// Creates a new `OsVersion`.
    pub fn new(a: u8, b: u8, c: u8) -> Self {
        Self(((a as u32) << 14) | ((b as u32) << 7) | c as u32)
    }
    /// Returns the version parts.
    pub fn version_parts(self) -> (u8, u8, u8) {
        let x = self.0;
        let a = x >> 14; // Top 7 bits
        let b = (x >> 7) & 0x7f; // Middle 7 bits
        let c = x & 0x7f; // Low 7 bits
        (a as u8, b as u8, c as u8)
    }
}

impl fmt::Display for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (a, b, c) = self.version_parts();
        write!(f, "{a}.{b}.{c}")
    }
}
impl fmt::Debug for OsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
#[test]
fn test() {
    let vp = OsVersionPatch(402653574);
    assert_eq!(format!("{vp:?}"), "OsVersionPatch(12.0.0, 2024-06)");
    assert_eq!(vp.version().to_string(), "12.0.0");
    assert_eq!(vp.patch().to_string(), "2024-06");
    assert_eq!(vp, OsVersionPatch::new(vp.version(), vp.patch()));
    assert_eq!(vp.version(), OsVersion::new(12, 0, 0));
    assert_eq!(vp.patch(), OsPatch::new(2024, 6));
}
