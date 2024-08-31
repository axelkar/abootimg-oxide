use binrw::{binrw, io::NoSeek, BinRead, BinWrite};
use version::OsVersionPatch;

mod version;

/// Android boot image header versions 0, 1 and 2
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[brw(little, magic = b"ANDROID!")]
pub struct HeaderV0 {
    /// Kernel size
    pub kernel_size: u32,
    /// Kernel physical load addr
    pub kernel_addr: u32,
    /// Ramdisk size
    pub ramdisk_size: u32,
    /// Ramdisk physical load addr
    pub ramdisk_addr: u32,
    /// Second bootloader size
    pub second_bootloader_size: u32,
    /// Second bootloader physical load addr
    pub second_bootloader_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    /// Header version
    #[br(temp)]
    #[bw(calc = self.header_version())]
    header_version: u32,
    // OS version and patch level
    pub osversionpatch: OsVersionPatch,
    pub board_name: [u8; 16],
    /// Kernel command line, part 1
    pub cmdline_part_1: Box<[u8; 512]>,
    pub hash_digest: [u8; 32],
    /// Kernel command line, part 2
    pub cmdline_part_2: Box<[u8; 1024]>,
    #[br(args(header_version))]
    pub versioned: HeaderV0Versioned,
}
impl HeaderV0 {
    fn get_padding(&self, size: usize) -> usize {
        // self.page_size must be a power of two
        let page_size = self.page_size as usize;
        (page_size - (size & (page_size - 1))) & (page_size - 1)
    }
    pub fn kernel_position(&self) -> usize {
        1660 + self.get_padding(1660)
    }
    pub fn ramdisk_position(&self) -> usize {
        self.kernel_position()
            + self.kernel_size as usize
            + self.get_padding(self.kernel_size as usize)
    }
    pub fn second_bootloader_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + self.get_padding(self.ramdisk_size as usize)
    }
    pub fn recovery_dtbo_position(&self) -> usize {
        self.second_bootloader_position()
            + self.second_bootloader_size as usize
            + self.get_padding(self.second_bootloader_size as usize)
    }
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
                    + self.get_padding(recovery_dtbo_size as usize)
            )
        }
    }
    pub fn header_version(&self) -> u32 {
        match self.versioned {
            HeaderV0Versioned::V0 => 0,
            HeaderV0Versioned::V1 { .. } => 1,
            HeaderV0Versioned::V2 { .. } => 2,
        }
    }
}

#[binrw]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[br(import(header_version: u32))]
pub enum HeaderV0Versioned {
    #[br(pre_assert(header_version == 0))]
    V0,
    #[br(pre_assert(header_version == 1))]
    V1 {
        recovery_dtbo_size: u32,
        recovery_dtbo_addr: u64,
        #[br(temp, assert(header_size == 1648))]
        #[bw(calc = 1648)]
        header_size: u32,
    },
    #[br(pre_assert(header_version == 2))]
    V2 {
        recovery_dtbo_size: u32,
        recovery_dtbo_addr: u64,
        #[br(temp, assert(header_size == 1660))]
        #[bw(calc = 1660)]
        header_size: u32,
        dtb_size: u32,
        dtb_addr: u64,
    },
}

/// Android boot image header versions 3 and 4
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[brw(little, magic = b"ANDROID!")]
#[br(assert(header_size == self.header_size()))]
pub struct HeaderV3 {
    /// Kernel size
    pub kernel_size: u32,
    /// Ramdisk size
    pub ramdisk_size: u32,
    // OS version and patch level
    pub osversionpatch: OsVersionPatch,
    /// Header size
    #[br(temp)]
    #[bw(calc = self.header_size())]
    header_size: u32,
    #[brw(pad_before = 16)]
    #[br(temp)]
    #[bw(calc = self.header_version())]
    header_version: u32,
    /// Kernel command line
    pub cmdline: Box<[u8; 1024 + 512]>,
    #[br(if(header_version == 4))]
    pub v4_signature_size: Option<u32>,
}
impl HeaderV3 {
    // TODO: make this configurable by the developer
    const PAGE_SIZE: usize = 4096;
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
    pub const fn kernel_position() -> usize {
        Self::PAGE_SIZE
    }
    pub fn ramdisk_position(&self) -> usize {
        Self::kernel_position()
            + self.kernel_size as usize
            + Self::get_padding(self.kernel_size as usize)
    }
    pub fn bootsig_position(&self) -> usize {
        self.ramdisk_position()
            + self.ramdisk_size as usize
            + Self::get_padding(self.ramdisk_size as usize)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Header {
    V0(HeaderV0),
    V3(HeaderV3),
}
impl Header {
    pub fn parse<R: std::io::Read + std::io::Seek>(reader: &mut R) -> Result<Self, binrw::Error> {
        reader.seek(std::io::SeekFrom::Start(0x28))?;
        let mut version_buf = [0u8; 4];
        reader.read_exact(&mut version_buf)?;
        reader.seek(std::io::SeekFrom::Start(0))?;

        Ok(match u32::from_le_bytes(version_buf) {
            0..=2 => Self::V0(HeaderV0::read(reader)?),
            3 | 4 => Self::V3(HeaderV3::read(reader)?),
            _ => todo!(),
        })
    }
    pub fn write<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
    ) -> Result<(), binrw::Error> {
        let writer = &mut NoSeek::new(writer);
        match self {
            Self::V0(hdr) => hdr.write(writer),
            Self::V3(hdr) => hdr.write(writer),
        }
    }
    pub fn header_version(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.header_version(),
            Self::V3(hdr) => hdr.header_version(),
        }
    }
    pub fn osversionpatch(&self) -> OsVersionPatch {
        match self {
            Self::V0(hdr) => hdr.osversionpatch,
            Self::V3(hdr) => hdr.osversionpatch,
        }
    }
    pub fn kernel_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.kernel_position(),
            Self::V3(_) => HeaderV3::kernel_position(),
        }
    }
    pub fn page_size(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.page_size as usize,
            Self::V3(_) => HeaderV3::PAGE_SIZE,
        }
    }
    pub fn kernel_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.kernel_size,
            Self::V3(hdr) => hdr.kernel_size,
        }
    }
    pub fn ramdisk_position(&self) -> usize {
        match self {
            Self::V0(hdr) => hdr.ramdisk_position(),
            Self::V3(hdr) => hdr.ramdisk_position(),
        }
    }
    pub fn ramdisk_size(&self) -> u32 {
        match self {
            Self::V0(hdr) => hdr.ramdisk_size,
            Self::V3(hdr) => hdr.ramdisk_size,
        }
    }
}


// TODO: vendor boot img header

/// Android vendor boot image header version 3 and 4
#[derive(BinRead, BinWrite)]
#[brw(magic = b"VNDRBOOT")]
pub struct VendorHeader {}
