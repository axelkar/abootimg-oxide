use std::{
    fs::{create_dir_all, File},
    io::{self, stdout, BufReader, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use abootimg_oxide::{Header, HeaderV0, HeaderV0Versioned};
use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the boot, recovery or vendor_boot image
    #[arg(long = "boot_img", value_name = "FILE")]
    boot_img: PathBuf,

    /// Output directory of the unpacked images
    #[arg(long, default_value = "out")]
    out: PathBuf,

    /// Whether to skip writing to `out` (added in abootimg-oxide)
    #[arg(long)]
    no_write: bool,

    /// Whether to also extract any "extra" data after defined sections (added in abootimg-oxide).
    ///
    /// The "extra" data may contain, for example, an AVB VBMeta image with the magic string "AVBf"
    /// and an AVB footer with the magic string "AVB0".
    #[arg(long)]
    extract_extra: bool,

    /// Text output format
    #[arg(value_enum, long, default_value_t = TextOutputFormat::Info)]
    format: TextOutputFormat,

    /// Output null-terminated argument strings
    #[arg(short = '0', long)]
    null: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum TextOutputFormat {
    /// Pretty-printed info-rich text format suitable for human inspection. Identical output to AOSP `unpack_bootimg`
    Info,
    /// Like the above but contains extra information like the hash digest (added in abootimg-oxide)
    InfoExtended,
    /// Output shell-escaped (quoted) argument strings that can be used to
    /// reconstruct the boot image using `mkbootimg`
    Mkbootimg,
}

struct OutPaths {
    kernel: PathBuf,
    ramdisk: PathBuf,
    second: PathBuf,
    recovery_dtbo: PathBuf,
    dtb: PathBuf,
}

fn main() {
    let args = Args::parse();
    let mut r = BufReader::new(File::open(&args.boot_img).unwrap());
    let hdr = Header::parse(&mut r).unwrap();

    let out_paths = OutPaths {
        kernel: args.out.join("kernel"),
        ramdisk: args.out.join("ramdisk"),
        second: args.out.join("second"),
        recovery_dtbo: args.out.join("recovery_dtbo"),
        dtb: args.out.join("dtb"),
    };

    // Get the inner File, so copy_file_range can be used
    let r = r.get_mut();

    if !args.no_write {
        create_dir_all(&args.out).unwrap();
    }

    let mut max_end_pos = 0;
    let mut extract_part = |pos: usize, size: u32, path: &Path| {
        let end_pos = pos + size as usize;
        if end_pos > max_end_pos {
            max_end_pos = end_pos;
        }

        if args.no_write {
            return;
        }
        r.seek(SeekFrom::Start(pos as u64)).unwrap();
        io::copy(
            &mut r.take(u64::from(size)),
            &mut File::create(path).unwrap(),
        )
        .unwrap();
    };

    extract_part(hdr.kernel_position(), hdr.kernel_size(), &out_paths.kernel);
    extract_part(
        hdr.ramdisk_position(),
        hdr.ramdisk_size(),
        &out_paths.ramdisk,
    );

    match &hdr {
        Header::V0(v0) => {
            if v0.second_bootloader_size != 0 {
                extract_part(
                    v0.second_bootloader_position(),
                    v0.second_bootloader_size,
                    &out_paths.second,
                );
            }
            if let HeaderV0Versioned::V1 {
                recovery_dtbo_size, ..
            }
            | HeaderV0Versioned::V2 {
                recovery_dtbo_size, ..
            } = v0.versioned
            {
                if recovery_dtbo_size != 0 {
                    extract_part(
                        v0.recovery_dtbo_position(),
                        recovery_dtbo_size,
                        &out_paths.recovery_dtbo,
                    );
                }
            }
            if let HeaderV0Versioned::V2 { dtb_size, .. } = v0.versioned {
                if dtb_size != 0 {
                    extract_part(v0.dtb_position().unwrap(), dtb_size, &out_paths.dtb);
                }
            }
        }
        Header::V3(v3) => {
            if let Some(size) = v3.v4_signature_size.filter(|size| *size != 0) {
                extract_part(
                    v3.bootsig_position(),
                    size,
                    &args.out.join("boot_signature"),
                );
            }
        }
    }

    if args.extract_extra {
        let file_len = r.metadata().unwrap().len();
        let diff = file_len as i64 - max_end_pos as i64;
        println!("max_end_pos={max_end_pos:#x}, file_len={file_len:#x}. diff={diff:#x}");

        if !args.no_write && (max_end_pos as u64) < file_len {
            r.seek(SeekFrom::Start(max_end_pos as u64)).unwrap();
            io::copy(r, &mut File::create(args.out.join("extra")).unwrap()).unwrap();
        }
    }

    match args.format {
        TextOutputFormat::Info | TextOutputFormat::InfoExtended => {
            info_fmt(
                &hdr,
                matches!(args.format, TextOutputFormat::InfoExtended),
                r,
            );
        }
        TextOutputFormat::Mkbootimg => {
            mkbootimg_fmt(&hdr, &args, &out_paths);
        }
    }
}

fn info_fmt(hdr: &Header, extended: bool, r: &mut (impl Read + Seek)) {
    // TODO: vendor boot images
    println!("boot magic: ANDROID!");
    match hdr {
        Header::V0(v0) => {
            println!("kernel_size: {}", v0.kernel_size);
            println!("kernel load address: 0x{:08x}", v0.kernel_addr);
            println!("ramdisk size: {}", v0.ramdisk_size);
            println!("ramdisk load address: 0x{:08x}", v0.ramdisk_addr);
            println!("second bootloader size: {}", v0.second_bootloader_size);
            println!(
                "second bootloader load address: 0x{:08x}",
                v0.second_bootloader_addr
            );
            println!("kernel tags load address: 0x{:08x}", v0.tags_addr);
            println!("page size: {}", v0.page_size);

            if extended {
                println!("hash digest in header: {}", hex_fmt::HexFmt(v0.hash_digest));

                // Naive heuristic
                let is_sha1 = v0.hash_digest[20..] == [0; 32 - 20];

                fn read_part(r: &mut (impl Read + Seek), pos: usize, size: u32) -> Vec<u8> {
                    let mut buf = Vec::new();
                    r.seek(SeekFrom::Start(pos as u64));
                    r.take(size as u64).read_to_end(&mut buf);
                    buf
                }

                let kernel = read_part(r, v0.kernel_position(), v0.kernel_size);
                let ramdisk = read_part(r, v0.ramdisk_position(), v0.ramdisk_size);
                let second_bootloader = read_part(
                    r,
                    v0.second_bootloader_position(),
                    v0.second_bootloader_size,
                );
                let recovery_dtbo = if let HeaderV0Versioned::V1 {
                    recovery_dtbo_size, ..
                }
                | HeaderV0Versioned::V2 {
                    recovery_dtbo_size, ..
                } = v0.versioned
                {
                    Some(read_part(
                        r,
                        v0.recovery_dtbo_position(),
                        recovery_dtbo_size,
                    ))
                } else {
                    None
                };
                let dtb = if let HeaderV0Versioned::V2 { dtb_size, .. } = v0.versioned {
                    Some(read_part(r, v0.dtb_position().unwrap(), dtb_size))
                } else {
                    None
                };

                let hash_digest = if is_sha1 {
                    HeaderV0::compute_hash_digest::<_, sha1::Sha1>(
                        Some(Cursor::new(kernel)).as_mut(),
                        Some(Cursor::new(ramdisk)).as_mut(),
                        Some(Cursor::new(second_bootloader)).as_mut(),
                        recovery_dtbo.map(Cursor::new).as_mut(),
                        dtb.map(Cursor::new).as_mut(),
                    )
                    .unwrap()
                } else {
                    HeaderV0::compute_hash_digest::<_, sha2::Sha256>(
                        Some(Cursor::new(kernel)).as_mut(),
                        Some(Cursor::new(ramdisk)).as_mut(),
                        Some(Cursor::new(second_bootloader)).as_mut(),
                        recovery_dtbo.map(Cursor::new).as_mut(),
                        dtb.map(Cursor::new).as_mut(),
                    )
                    .unwrap()
                };

                println!("computed hash digest: {}", hex_fmt::HexFmt(hash_digest));
            }
        }
        Header::V3(v3) => {
            println!("kernel_size: {}", v3.kernel_size);
            println!("ramdisk size: {}", v3.kernel_size);
        }
    }

    println!("os version: {}", hdr.osversionpatch().version());
    println!("os patch level: {}", hdr.osversionpatch().patch());
    println!("boot image header version: {}", hdr.header_version());
    match hdr {
        Header::V0(v0) => {
            print!("product name: ");
            print_null_bytestring(&v0.board_name);
            print!("\ncommand line args: ");
            print_null_bytestring(&v0.cmdline[..512]);
            print!("\nadditional command line args: ");
            print_null_bytestring(&v0.cmdline[512..]);
            println!();
            match v0.versioned {
                HeaderV0Versioned::V1 {
                    recovery_dtbo_size,
                    recovery_dtbo_addr,
                } => {
                    println!("recovery dtbo size: {recovery_dtbo_size}");
                    println!("recovery dtbo offset: 0x{recovery_dtbo_addr:016x}");
                    println!("boot header size: 1648");
                }
                HeaderV0Versioned::V2 {
                    recovery_dtbo_size,
                    recovery_dtbo_addr,
                    dtb_size,
                    dtb_addr,
                } => {
                    println!("recovery dtbo size: {recovery_dtbo_size}");
                    println!("recovery dtbo offset: 0x{recovery_dtbo_addr:016x}");
                    println!("boot header size: 1660");
                    println!("dtb size: {dtb_size}");
                    println!("dtb address: 0x{dtb_addr:016x}");
                }
                HeaderV0Versioned::V0 => {}
            }
        }
        Header::V3(v3) => {
            print!("command line args: ");
            print_null_bytestring(v3.cmdline.as_slice());
            println!();
            if let Some(signature_size) = v3.v4_signature_size {
                println!("boot.img signature size: {signature_size}");
            }
        }
    }
}

fn mkbootimg_fmt(hdr: &Header, args: &Args, out_paths: &OutPaths) {
    let sep = if args.null { '\0' } else { ' ' };

    print!(
        "--header_version{sep}{}{sep}--os_version{sep}{}{sep}--os_patch_level{sep}{}",
        hdr.header_version(),
        hdr.osversionpatch().version(),
        hdr.osversionpatch().patch()
    );
    {
        // TODO: quote if out has whitespace
        print!("{sep}--kernel{sep}");
        stdout()
            .write_all(out_paths.kernel.as_os_str().as_encoded_bytes())
            .ok();
        print!("{sep}--ramdisk{sep}");
        stdout()
            .write_all(out_paths.ramdisk.as_os_str().as_encoded_bytes())
            .ok();
        if let Header::V0(v0) = &hdr {
            if v0.second_bootloader_size != 0 {
                print!("{sep}--second{sep}");
                stdout()
                    .write_all(out_paths.second.as_os_str().as_encoded_bytes())
                    .ok();
            }
            if let HeaderV0Versioned::V1 {
                recovery_dtbo_size, ..
            }
            | HeaderV0Versioned::V2 {
                recovery_dtbo_size, ..
            } = v0.versioned
            {
                if recovery_dtbo_size != 0 {
                    print!("{sep}--recovery_dtbo{sep}");
                    stdout()
                        .write_all(out_paths.recovery_dtbo.as_os_str().as_encoded_bytes())
                        .ok();
                }
            }
            if let HeaderV0Versioned::V2 { dtb_size, .. } = v0.versioned {
                if dtb_size != 0 {
                    print!("{sep}--dtb{sep}");
                    stdout()
                        .write_all(out_paths.dtb.as_os_str().as_encoded_bytes())
                        .ok();
                }
            }
        }
    }
    if let Header::V0(v0) = &hdr {
        print!("{sep}--pagesize{sep}0x{:08x}", hdr.page_size());
        print!("{sep}--base{sep}0x{:08x}", 0);
        print!("{sep}--kernel_offset{sep}0x{:08x}", v0.kernel_addr);
        print!("{sep}--ramdisk_offset{sep}0x{:08x}", v0.ramdisk_addr);
        print!(
            "{sep}--second_offset{sep}0x{:08x}",
            v0.second_bootloader_addr
        );
        print!("{sep}--tags_offset{sep}0x{:08x}", v0.tags_addr);
        if let HeaderV0Versioned::V2 { dtb_addr, .. } = v0.versioned {
            print!(" --dtb_offset 0x{dtb_addr:016x}");
        }
        print!("{sep}--board{sep}");
        if args.null {
            print_null_bytestring(&v0.board_name);
        } else {
            print_escaped_null_bytestring(&v0.board_name);
        }
        print!("{sep}--cmdline{sep}");
        if args.null {
            print_null_bytestring(v0.cmdline.as_slice());
        } else {
            print_escaped_null_bytestring(v0.cmdline.as_slice());
        }
    }
    if args.null {
        print!("\0");
    } else {
        println!();
    }
}

fn take_until_null(input: &[u8]) -> &[u8] {
    input
        .iter()
        .position(|x| *x == 0)
        .map_or(input, |null_idx| &input[..null_idx])
}
fn print_escaped_null_bytestring(input: &[u8]) {
    let q = shlex::bytes::Quoter::new();
    stdout()
        .write_all(&q.quote(take_until_null(input)).unwrap())
        .ok();
}
fn print_null_bytestring(input: &[u8]) {
    stdout().write_all(take_until_null(input)).ok();
}
