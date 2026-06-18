use alloc::{boxed::Box, format};
use binrw::{
    binrw,
    io::{NoSeek, Read, Seek, SeekFrom, Write},
    BinRead, BinWrite,
};

use crate::version::OsVersionPatch;

// TODO: extent/part/section type!!!

/// Standard Android boot image header versions 0, 1 and 2
///
/// # Section layout in the image
///
/// Sections after the header are marked by fields of the form `*_size`, and are stored
/// consecutively, padded to page size.
///
/// Sections in [`HeaderV0`] are also marked with the physical address where a bootloader should
/// load them to.
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
///
/// # Additional Documentation
///
/// - <https://source.android.com/docs/core/architecture/bootloader/boot-image-header>
/// - <https://docs.u-boot.org/en/latest/android/boot-image.html>
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
    #[br(temp)]
    #[bw(calc = *self.cmdline.first_chunk().unwrap())]
    cmdline_part_1: [u8; 512],
    /// Hash digest
    ///
    /// Usually either a SHA1 (20 bytes of digest, 12 null-bytes) or a SHA256 (32 bytes of digest) digest of the following: kernel, ramdisk, second bootloader, recovery DTBO and DTB.
    ///
    /// - If the size is nonzero, hash the contents.
    /// - Update the hash with the little-endian representation of the 32-bit unsigned size ([`u32::to_le_bytes`]), which may be zero.
    pub hash_digest: [u8; 32],
    #[br(temp)]
    #[bw(calc = *self.cmdline.last_chunk().unwrap())]
    cmdline_part_2: [u8; 1024],
    /// Kernel command line
    #[br(calc = [cmdline_part_1.as_slice(), cmdline_part_2.as_slice()].concat().try_into().unwrap())]
    #[bw(ignore)]
    pub cmdline: Box<[u8; 512 + 1024]>,
    /// Version-specific part of the boot image header.
    #[br(args(header_version))]
    pub versioned: HeaderV0Versioned,
}

impl HeaderV0 {
    pub(crate) const fn get_padding(&self, size: usize) -> usize {
        let page_size = self.page_size as usize;
        (page_size - (size % page_size)) % page_size
    }
    /// Returns the boot image header's version number.
    #[must_use]
    pub const fn header_version(&self) -> u32 {
        match self.versioned {
            HeaderV0Versioned::V0 => 0,
            HeaderV0Versioned::V1 { .. } => 1,
            HeaderV0Versioned::V2 { .. } => 2,
        }
    }
    /// Returns the kernel's position in the boot image.
    #[must_use]
    pub const fn kernel_position(&self) -> usize {
        1660 + self.get_padding(1660)
    }
    /// Returns the ramdisk's position in the boot image.
    #[must_use]
    pub const fn ramdisk_position(&self) -> usize {
        self.kernel_position()
            + self.kernel_size as usize
            + self.get_padding(self.kernel_size as usize)
    }
    /// Returns the second stage bootloader's position in the boot image.
    #[must_use]
    pub const fn second_bootloader_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + self.get_padding(self.ramdisk_size as usize)
    }
    /// Returns the recovery DTBO's position in the boot image.
    #[must_use]
    pub const fn recovery_dtbo_position(&self) -> usize {
        self.second_bootloader_position()
            + self.second_bootloader_size as usize
            + self.get_padding(self.second_bootloader_size as usize)
    }
    /// Returns the DTB's position in the boot image.
    ///
    /// This returns `None` in version 0.
    ///
    /// Note that this section is undefined in version 1.
    #[must_use]
    pub const fn dtb_position(&self) -> Option<usize> {
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
    /// Returns the size of the boot image.
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "dtb_position always returns Some on V1 and V2"
    )]
    pub const fn boot_image_size(&self) -> usize {
        match self.versioned {
            HeaderV0Versioned::V0 => self.recovery_dtbo_position(),
            HeaderV0Versioned::V1 { .. } => self.dtb_position().unwrap(),
            HeaderV0Versioned::V2 { dtb_size, .. } => {
                self.dtb_position().unwrap()
                    + dtb_size as usize
                    + self.get_padding(dtb_size as usize)
            }
        }
    }

    /// Finalizes the passed in `hasher` to create a [`Self::hash_digest`].
    ///
    /// # Errors
    ///
    /// Passes through errors that occur in the readers and errors when more than [`u32::MAX`]
    /// bytes were read from a single file.
    #[cfg(feature = "hash")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hash")))]
    pub fn compute_hash_digest<R: Read, D: digest::Digest>(
        kernel: Option<&mut R>,
        ramdisk: Option<&mut R>,
        second_bootloader: Option<&mut R>,
        recovery_dtbo: Option<&mut R>,
        dtb: Option<&mut R>,
    ) -> binrw::io::Result<[u8; 32]> {
        let mut hasher = D::new();

        for r in [kernel, ramdisk, second_bootloader, recovery_dtbo, dtb] {
            if let Some(r) = r {
                let mut buf = alloc::vec::Vec::new();
                r.read_to_end(&mut buf)?;
                hasher.update(&buf);
                hasher.update(
                    u32::try_from(buf.len())
                        .map_err(|_| binrw::io::ErrorKind::InvalidInput)?
                        .to_le_bytes(),
                );
            } else {
                hasher.update(0u32.to_le_bytes());
            }
        }

        let digest = hasher.finalize();
        let mut buf = [0; _];
        buf[..digest.len()].copy_from_slice(&digest);
        Ok(buf)
    }

    /// Writes the full Android boot image, including the different parts after the header.
    ///
    /// - Requires the Rust standard library for [`std::io::copy`].
    /// - Assumes that the readers will output exact amounts. That is, `kernel` will only ever output exactly [`Self::kernel_size`] bytes.
    /// - Assumes that the writer supports seeking up to [`Self::boot_image_size()`]. Note that
    ///   POSIX-compatible filesystems automatically extend the file so you shouldn't need to
    ///   worry about calling [`std::fs::File::set_len()`]).
    ///
    /// # Errors
    ///
    /// Passes through errors that occur in the readers or the writer or during serialization
    /// of the header.
    #[cfg(feature = "std")]
    #[cfg_attr(docsrs, doc(cfg(feature = "std")))]
    pub fn full_write<W: Write + Seek, R: Read>(
        &self,
        writer: &mut W,
        kernel: Option<&mut R>,
        ramdisk: Option<&mut R>,
        second_bootloader: Option<&mut R>,
        recovery_dtbo: Option<&mut R>,
        dtb: Option<&mut R>,
    ) -> binrw::BinResult<()> {
        let w = writer;

        self.write(w)?;

        if let Some(r) = kernel {
            w.seek(SeekFrom::Start(self.kernel_position() as u64))?;
            std::io::copy(r, w)?;
        }

        if let Some(r) = ramdisk {
            w.seek(SeekFrom::Start(self.ramdisk_position() as u64))?;
            std::io::copy(r, w)?;
        }

        if let Some(r) = second_bootloader {
            w.seek(SeekFrom::Start(self.second_bootloader_position() as u64))?;
            std::io::copy(r, w)?;
        }

        if let Some(r) = recovery_dtbo {
            w.seek(SeekFrom::Start(self.recovery_dtbo_position() as u64))?;
            std::io::copy(r, w)?;
        }

        if let Some(dtb_position) = self.dtb_position() {
            if let Some(r) = dtb {
                w.seek(SeekFrom::Start(dtb_position as u64))?;
                std::io::copy(r, w)?;
            }
        }

        // Final padding to page size
        w.seek(SeekFrom::Start(self.boot_image_size() as u64))?;

        Ok(())
    }
}

/// Version-specific part of boot image headers v0-v2
#[binrw]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[br(import(header_version: u32))]
#[br(pre_assert([0,1,2].contains(&header_version), "invalid header version: {header_version}"))]
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

/// Standard Android boot image header versions 3 and 4
///
/// The page size is always 4096 bytes.
///
/// # Section layout in the image
///
/// Sections after the header are marked by fields of the form `*_size`, and are stored
/// consecutively, padded to page size.
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
#[br(assert(header_size == self.header_size(), "invalid header size: {header_size}"))]
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
    #[br(assert(header_version == 3 || header_version == 4, "invalid header version: {header_version}"))]
    #[bw(calc = self.header_version())]
    header_version: u32,
    /// Kernel command line
    pub cmdline: Box<[u8; 512 + 1024]>,
    /// Boot signature size.
    ///
    /// This is only present in version 4 and the version will be inferred from this field.
    #[br(if(header_version == 4))]
    pub v4_signature_size: Option<u32>,
}

impl HeaderV3 {
    pub(crate) const PAGE_SIZE: usize = 4096;

    /// Returns the boot image header's version number.
    #[must_use]
    pub const fn header_version(&self) -> u32 {
        if self.v4_signature_size.is_some() {
            4
        } else {
            3
        }
    }
    pub(crate) const fn header_size(&self) -> u32 {
        if self.v4_signature_size.is_some() {
            1584
        } else {
            1580
        }
    }
    pub(crate) const fn get_padding(size: usize) -> usize {
        // Equivalent to `size.div_ceil(PAGE_SIZE) * PAGE_SIZE - size`
        // or `PAGE_SIZE - (size % PAGE_SIZE)) % PAGE_SIZE`, but more efficient.
        (Self::PAGE_SIZE - (size % Self::PAGE_SIZE)) % Self::PAGE_SIZE
    }
    /// Returns the kernel's position in the boot image.
    ///
    /// Hardcoded to the page size, which is 4096.
    #[must_use]
    pub const fn kernel_position() -> usize {
        Self::PAGE_SIZE
    }
    /// Returns the ramdisk's position in the boot image.
    #[must_use]
    pub const fn ramdisk_position(&self) -> usize {
        Self::kernel_position()
            + self.kernel_size as usize
            + Self::get_padding(self.kernel_size as usize)
    }
    /// Returns the boot signature's position in the boot image.
    ///
    /// Note that this section is undefined in version 3.
    #[must_use]
    pub const fn bootsig_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + Self::get_padding(self.ramdisk_size as usize)
    }
}

/// Standard Android boot image header for versions 0 through 4
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Header {
    /// Header for versions 0-2
    V0(HeaderV0),
    /// Header for versions 3-4
    V3(HeaderV3),
}

impl Header {
    /// Parses a standard Android boot image header from a reader.
    ///
    /// # Errors
    ///
    /// This returns an error if reading fails or if the header is invalid.
    pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<Self, binrw::Error> {
        reader.seek(binrw::io::SeekFrom::Start(0x28))?;
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        reader.seek(binrw::io::SeekFrom::Start(0))?;

        // TODO: on next breaking change bump binrw
        // TODO: on next breaking change, make `Header` implement/use binrw's traits!
        Ok(match u32::from_le_bytes(version_buf) {
            0..=2 => Self::V0(HeaderV0::read(reader)?),
            3 | 4 => Self::V3(HeaderV3::read(reader)?),
            version => {
                return Err(binrw::Error::AssertFail {
                    pos: 0x28,
                    message: format!("Unknown header version: {version}"),
                })
            }
        })
    }
    /// Serializes a standard Android boot image header to a writer.
    ///
    /// Note that you must write the kernel, ramdisk, etc. yourself.
    ///
    /// # Errors
    ///
    /// This forwards errors from `writer`.
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), binrw::Error> {
        let writer = &mut NoSeek::new(writer);
        match self {
            Self::V0(hdr) => hdr.write(writer),
            Self::V3(hdr) => hdr.write(writer),
        }
    }
    /// Returns the boot image header's version number.
    #[must_use]
    pub const fn header_version(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.header_version(),
            Self::V3(hdr) => hdr.header_version(),
        }
    }
    /// Returns the boot image header's OS version and patch level.
    #[must_use]
    pub const fn osversionpatch(&self) -> OsVersionPatch {
        match self {
            Self::V0(hdr) => hdr.osversionpatch,
            Self::V3(hdr) => hdr.osversionpatch,
        }
    }
    /// Returns the kernel's position in the boot image.
    #[must_use]
    pub const fn kernel_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.kernel_position(),
            Self::V3(_) => HeaderV3::kernel_position(),
        }
    }
    /// Returns the kernel's size.
    #[must_use]
    pub const fn kernel_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.kernel_size,
            Self::V3(hdr) => hdr.kernel_size,
        }
    }
    /// Returns the ramdisk's position in the boot image.
    #[must_use]
    pub const fn ramdisk_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.ramdisk_position(),
            Self::V3(hdr) => hdr.ramdisk_position(),
        }
    }
    /// Returns the ramdisk's size.
    #[must_use]
    pub const fn ramdisk_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.ramdisk_size,
            Self::V3(hdr) => hdr.ramdisk_size,
        }
    }
    /// Returns the page size in bytes.
    #[must_use]
    pub const fn page_size(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.page_size as usize,
            Self::V3(_) => HeaderV3::PAGE_SIZE,
        }
    }
    /// Returns the kernel command line.
    #[must_use]
    pub const fn cmdline(&self) -> &[u8; 512 + 1024] {
        match self {
            Self::V0(hdr) => &hdr.cmdline,
            Self::V3(hdr) => &hdr.cmdline,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use binrw::io::Cursor;
    use expect_test_bytes::expect_file;

    use super::*;

    #[test]
    fn simple_write_read() {
        fn pad_slice_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
            let mut arr = [0u8; N];
            let len = slice.len().min(N);
            arr[..len].copy_from_slice(&slice[..len]);
            arr
        }
        let expected_header = Header::V3(HeaderV3 {
            kernel_size: 0x7357_0001,
            ramdisk_size: 0x7357_0002,
            osversionpatch: OsVersionPatch(0x7357_0003),
            cmdline: Box::new(pad_slice_to_array(b"example")),
            v4_signature_size: None,
        });

        let mut actual_bytes = Vec::new();
        expected_header
            .write(&mut Cursor::new(&mut actual_bytes))
            .unwrap();

        expect_file!["test_data/standard/simple_write_read"].assert_eq(&actual_bytes);

        let actual_header = Header::parse(&mut Cursor::new(&actual_bytes)).unwrap();

        assert_eq!(expected_header, actual_header);

        let either_header = crate::EitherHeader::read(&mut Cursor::new(&actual_bytes)).unwrap();

        assert_eq!(
            crate::EitherHeader::Standard(expected_header),
            either_header
        );
    }
}
