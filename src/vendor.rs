use binrw::{binrw, BinRead, BinWrite};

/// Android vendor boot image header version 3 and 4
#[binrw]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[brw(magic = b"VNDRBOOT")]
#[br(assert(header_size == self.header_size()))]
pub struct VendorHeader {
    #[br(temp)]
    #[bw(calc = self.header_version())]
    header_version: u32,
    /// Page size in bytes
    pub page_size: u32,
    /// Kernel physical load address
    pub kernel_addr: u32,
    /// Ramdisk physical load address
    pub ramdisk_addr: u32,
    /// Vendor ramdisk size
    pub vendor_ramdisk_size: u32,
    /// Kernel command line
    pub cmdline: Box<[u8; 2048]>,
    /// Kernel tags physical load address
    pub tags_addr: u32,
    /// Board or product name
    pub board_name: [u8; 16],
    #[br(temp)]
    #[bw(calc = self.header_size())]
    header_size: u32,
    /// DTB size
    pub dtb_size: u32,
    /// DTB physical load address
    pub dtb_addr: u64,
    /// V4-specific fields.
    ///
    /// This is only present in version 4 and the version will be inferred from this field.
    #[br(if(header_version == 4))]
    pub v4: Option<VendorHeaderV4>,
}
impl VendorHeader {
    /// Returns the vendor boot image header's version number.
    pub fn header_version(&self) -> u32 {
        if self.v4.is_some() {
            4
        } else {
            3
        }
    }
    fn header_size(&self) -> u32 {
        if self.v4.is_some() {
            2128
        } else {
            2112
        }
    }

    // TODO: functions to return positions according to the `data` table in
    // https://github.com/cfig/Android_boot_image_editor/blob/master/doc/layout.md
}

/// V4-specific fields of the Android vendor boot image header
#[derive(BinRead, BinWrite, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VendorHeaderV4 {
    pub vendor_ramdisk_table_size: u32,
    pub vendor_ramdisk_table_entry_num: u32,
    pub vendor_ramdisk_table_entry_size: u32,
    pub bootconfig_size: u32,
}
