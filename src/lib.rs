//! A parser for Android boot image headers (e.g. `boot.img` or `vendor_boot.img`).
//!
//! This can be used to extract or patch e.g. the kernel or ramdisk.
//!
//! Byte array fields (`[u8; N]`) can be used as null-terminated strings.

#![warn(missing_docs)]

use binrw::{binrw, io::NoSeek, BinRead, BinWrite};

mod vendor;
mod version;
pub use vendor::{VendorHeader, VendorHeaderV4};
pub use version::{OsPatch, OsVersion, OsVersionPatch};

/// Android boot image header versions 0, 1 and 2
///
/// ## Section layout
///
/// ```text
/// ┌─────────────────────────┐
/// │boot image header        │
/// │+ padding to page size   │
/// ├─────────────────────────┤
/// │kernel                   │
/// │+ padding to page size   │
/// ├─────────────────────────┤
/// │ramdisk                  │
/// │+ padding to page size   │
/// ├─────────────────────────┤
/// │second stage bootloader  │
/// │+ padding to page size   │
/// ├─────────────────────────┤
/// │recovery dtbo/acpio (v1+)│
/// │+ padding to page size   │
/// ├─────────────────────────┤
/// │dtb (v2)                 │
/// │+ padding to page size   │
/// └─────────────────────────┘
/// ```
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[brw(little, magic = b"ANDROID!")]
pub struct HeaderV0 {
    /// Kernel size
    pub kernel_size: u32,
    /// Kernel physical load address
    pub kernel_addr: u32,
    /// Ramdisk size
    pub ramdisk_size: u32,
    /// Ramdisk physical load address
    pub ramdisk_addr: u32,
    /// Second bootloader size
    pub second_bootloader_size: u32,
    /// Second bootloader physical load address
    pub second_bootloader_addr: u32,
    /// Kernel tags physical load address
    pub tags_addr: u32,
    /// Page size in bytes
    pub page_size: u32,
    /// Header version
    #[br(temp)]
    #[bw(calc = self.header_version())]
    header_version: u32,
    /// OS version and patch level
    pub osversionpatch: OsVersionPatch,
    /// Board or product name
    pub board_name: [u8; 16],
    /// Kernel command line, part 1
    pub cmdline_part_1: Box<[u8; 512]>,
    /// Hash digest
    pub hash_digest: [u8; 32],
    /// Kernel command line, part 2
    pub cmdline_part_2: Box<[u8; 1024]>,
    /// Version-specific part of the boot image header.
    #[br(args(header_version))]
    pub versioned: HeaderV0Versioned,
}
// TODO: store cmdline as one contiguous [u8; 1536]
impl HeaderV0 {
    fn get_padding(&self, size: usize) -> usize {
        // self.page_size must be a power of two
        let page_size = self.page_size as usize;
        (page_size - (size & (page_size - 1))) & (page_size - 1)
    }
    /// Returns the boot image header's version number.
    pub fn header_version(&self) -> u32 {
        match self.versioned {
            HeaderV0Versioned::V0 => 0,
            HeaderV0Versioned::V1 { .. } => 1,
            HeaderV0Versioned::V2 { .. } => 2,
        }
    }
    /// Returns the kernel's position in the boot image.
    pub fn kernel_position(&self) -> usize {
        1660 + self.get_padding(1660)
    }
    /// Returns the ramdisk's position in the boot image.
    pub fn ramdisk_position(&self) -> usize {
        self.kernel_position()
            + self.kernel_size as usize
            + self.get_padding(self.kernel_size as usize)
    }
    /// Returns the second stage bootloader's position in the boot image.
    pub fn second_bootloader_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + self.get_padding(self.ramdisk_size as usize)
    }
    /// Returns the recovery DTBO's position in the boot image.
    pub fn recovery_dtbo_position(&self) -> usize {
        self.second_bootloader_position()
            + self.second_bootloader_size as usize
            + self.get_padding(self.second_bootloader_size as usize)
    }
    /// Returns the DTB's position in the boot image.
    ///
    /// This returns `None` at version 0.
    pub fn dtb_position(&self) -> Option<usize> {
        match self.versioned {
            HeaderV0Versioned::V0 => None,
            HeaderV0Versioned::V1 {
                recovery_dtbo_size, ..
            }
            | HeaderV0Versioned::V2 {
                recovery_dtbo_size, ..
            } => Some(
                self.second_bootloader_position()
                    + recovery_dtbo_size as usize
                    + self.get_padding(recovery_dtbo_size as usize),
            ),
        }
    }
}

/// Version-specific part of boot image headers v0-v2
#[binrw]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[br(import(header_version: u32))]
pub enum HeaderV0Versioned {
    /// V0-specific fields
    #[br(pre_assert(header_version == 0))]
    V0,
    /// V1-specific fields
    #[br(pre_assert(header_version == 1))]
    V1 {
        /// Recovery DTBO/ACPIO size
        recovery_dtbo_size: u32,
        /// Recovery DTBO/ACPIO physical load address
        recovery_dtbo_addr: u64,
        #[br(temp, assert(header_size == 1648))]
        #[bw(calc = 1648)]
        header_size: u32,
    },
    /// V2-specific fields
    #[br(pre_assert(header_version == 2))]
    V2 {
        /// Recovery DTBO/ACPIO size
        recovery_dtbo_size: u32,
        /// Recovery DTBO/ACPIO physical load address
        recovery_dtbo_addr: u64,
        #[br(temp, assert(header_size == 1660))]
        #[bw(calc = 1660)]
        header_size: u32,
        /// DTB size
        dtb_size: u32,
        /// DTB physical load address
        dtb_addr: u64,
    },
}

/// Android boot image header versions 3 and 4
///
/// The page size is always 4096 bytes.
///
/// ## Section layout
///
/// ```text
/// ┌───────────────────────┐
/// │boot image header      │
/// │+ padding to page size │
/// ├───────────────────────┤
/// │kernel                 │
/// │+ padding to page size │
/// ├───────────────────────┤
/// │ramdisk                │
/// │+ padding to page size │
/// ├───────────────────────┤
/// │boot signature (v4)    │
/// │+ padding to page size │
/// └───────────────────────┘
/// ```
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[brw(little, magic = b"ANDROID!")]
#[br(assert(header_size == self.header_size()))]
pub struct HeaderV3 {
    /// Kernel size
    pub kernel_size: u32,
    /// Ramdisk size
    pub ramdisk_size: u32,
    /// OS version and patch level
    pub osversionpatch: OsVersionPatch,
    #[br(temp)]
    #[bw(calc = self.header_size())]
    header_size: u32,
    #[brw(pad_before = 16)]
    #[br(temp)]
    #[bw(calc = self.header_version())]
    header_version: u32,
    /// Kernel command line
    pub cmdline: Box<[u8; 1024 + 512]>,
    /// Boot signature size.
    ///
    /// This is only present in version 4 and the version will be inferred from this field.
    #[br(if(header_version == 4))]
    pub v4_signature_size: Option<u32>,
}
impl HeaderV3 {
    const PAGE_SIZE: usize = 4096;

    /// Returns the boot image header's version number.
    pub fn header_version(&self) -> u32 {
        if self.v4_signature_size.is_some() {
            4
        } else {
            3
        }
    }
    fn header_size(&self) -> u32 {
        if self.v4_signature_size.is_some() {
            1584
        } else {
            1580
        }
    }
    fn get_padding(size: usize) -> usize {
        (Self::PAGE_SIZE - (size & (Self::PAGE_SIZE - 1))) & (Self::PAGE_SIZE - 1)
    }
    /// Returns the kernel's position in the boot image.
    ///
    /// Hardcoded to the page size, which is 4096.
    pub const fn kernel_position() -> usize {
        Self::PAGE_SIZE
    }
    /// Returns the ramdisk's position in the boot image.
    pub fn ramdisk_position(&self) -> usize {
        Self::kernel_position()
            + self.kernel_size as usize
            + Self::get_padding(self.kernel_size as usize)
    }
    /// Returns the boot signature's position in the boot image.
    pub fn bootsig_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + Self::get_padding(self.ramdisk_size as usize)
    }
}

/// Android boot image header for versions 0 through 4
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Header {
    /// Header for versions 0-2
    V0(HeaderV0),
    /// Header for versions 3-4
    V3(HeaderV3),
}
impl Header {
    /// Parses an Android boot image header from a reader.
    pub fn parse<R: std::io::Read + std::io::Seek>(reader: &mut R) -> Result<Self, binrw::Error> {
        reader.seek(std::io::SeekFrom::Start(0x28))?;
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        reader.seek(std::io::SeekFrom::Start(0))?;

        Ok(match u32::from_le_bytes(version_buf) {
            0..=2 => Self::V0(HeaderV0::read(reader)?),
            3 | 4 => Self::V3(HeaderV3::read(reader)?),
            version => {
                return Err(binrw::Error::AssertFail {
                    pos: 0x28,
                    message: format!("Unknown header version: {}", version),
                })
            }
        })
    }
    /// Serializes an Android boot image header to a writer.
    ///
    /// Note that you must write the kernel, ramdisk, etc. yourself.
    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> Result<(), binrw::Error> {
        let writer = &mut NoSeek::new(writer);
        match self {
            Self::V0(hdr) => hdr.write(writer),
            Self::V3(hdr) => hdr.write(writer),
        }
    }
    /// Returns the boot image header's version number.
    pub fn header_version(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.header_version(),
            Self::V3(hdr) => hdr.header_version(),
        }
    }
    /// Returns the boot image header's OS version and patch level.
    pub fn osversionpatch(&self) -> OsVersionPatch {
        match self {
            Self::V0(hdr) => hdr.osversionpatch,
            Self::V3(hdr) => hdr.osversionpatch,
        }
    }
    /// Returns the kernel's position in the boot image.
    pub fn kernel_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.kernel_position(),
            Self::V3(_) => HeaderV3::kernel_position(),
        }
    }
    /// Returns the kernel's size.
    pub fn kernel_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.kernel_size,
            Self::V3(hdr) => hdr.kernel_size,
        }
    }
    /// Returns the ramdisk's position in the boot image.
    pub fn ramdisk_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.ramdisk_position(),
            Self::V3(hdr) => hdr.ramdisk_position(),
        }
    }
    /// Returns the ramdisk's size.
    pub fn ramdisk_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.ramdisk_size,
            Self::V3(hdr) => hdr.ramdisk_size,
        }
    }
    /// Returns the page size in bytes.
    pub fn page_size(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.page_size as usize,
            Self::V3(_) => HeaderV3::PAGE_SIZE,
        }
    }
}

// TODO: unit tests
