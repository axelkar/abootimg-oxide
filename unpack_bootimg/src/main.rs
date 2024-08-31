use std::{
    fs::{create_dir_all, File},
    io::{self, stdout, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use abootimg_oxide::{Header, HeaderV0Versioned};
use clap::{Parser, ValueEnum};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the boot, recovery or vendor_boot image
    #[arg(long = "boot_img")]
    boot_img: PathBuf,

    /// Output directory of the unpacked images
    #[arg(long, default_value = "out")]
    out: PathBuf,

    /// Text output format
    #[arg(value_enum, long, default_value_t = TextOutputFormat::Info)]
    format: TextOutputFormat,

    /// Output null-terminated argument strings
    #[arg(short = '0', long)]
    null: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum TextOutputFormat {
    /// Pretty-printed info-rich text format suitable for human inspection
    Info,
    /// Output shell-escaped (quoted) argument strings that can be used to
    /// reconstruct the boot image using `mkbootimg`
    Mkbootimg,
}

fn main() {
    let args = Args::parse();
    let mut r = BufReader::new(File::open(args.boot_img).unwrap());
    let hdr = Header::parse(&mut r).unwrap();

    let kernel_out_path = args.out.join("kernel");
    let ramdisk_out_path = args.out.join("ramdisk");
    let second_out_path = args.out.join("second");
    let recovery_dtbo_out_path = args.out.join("recovery_dtbo");
    let dtb_out_path = args.out.join("dtb");

    // Get the inner File, so copy_file_range can be used
    let r = r.get_mut();

    create_dir_all(&args.out).unwrap();

    let mut extract_part = |pos: usize, size: u32, path: &Path| {
        r.seek(SeekFrom::Start(pos as u64)).unwrap();
        io::copy(&mut r.take(size as u64), &mut File::create(path).unwrap()).unwrap();
    };

    extract_part(hdr.kernel_position(), hdr.kernel_size(), &kernel_out_path);
    extract_part(
        hdr.ramdisk_position(),
        hdr.ramdisk_size(),
        &ramdisk_out_path,
    );

    match &hdr {
        Header::V0(v0) => {
            if v0.second_bootloader_size != 0 {
                extract_part(
                    v0.second_bootloader_position(),
                    v0.second_bootloader_size,
                    &second_out_path,
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
                        &recovery_dtbo_out_path,
                    );
                }
            }
            if let HeaderV0Versioned::V2 { dtb_size, .. } = v0.versioned {
                if dtb_size != 0 {
                    extract_part(v0.dtb_position().unwrap(), dtb_size, &dtb_out_path);
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

    match args.format {
        TextOutputFormat::Info => {
            // TODO: vendor boot images
            println!("boot magic: ANDROID!");
            match &hdr {
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
                }
                Header::V3(v3) => {
                    println!("kernel_size: {}", v3.kernel_size);
                    println!("ramdisk size: {}", v3.kernel_size);
                }
            }

            println!("os version: {}", hdr.osversionpatch().version());
            println!("os patch level: {}", hdr.osversionpatch().patch());
            println!("boot image header version: {}", hdr.header_version());
            match &hdr {
                Header::V0(v0) => {
                    print!("product name: ");
                    print_null_bytestring(&v0.board_name);
                    print!("\ncommand line args: ");
                    print_null_bytestring(&*v0.cmdline_part_1);
                    print!("\nadditional command line args: ");
                    print_null_bytestring(&*v0.cmdline_part_2);
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
                        _ => {}
                    }
                }
                Header::V3(v3) => {
                    print!("command line args: ");
                    print_null_bytestring(&*v3.cmdline);
                    println!();
                    if let Some(signature_size) = v3.v4_signature_size {
                        println!("boot.img signature size: {signature_size}");
                    }
                }
            }
        }
        TextOutputFormat::Mkbootimg => {
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
                    .write_all(kernel_out_path.as_os_str().as_encoded_bytes())
                    .ok();
                print!("{sep}--ramdisk{sep}");
                stdout()
                    .write_all(ramdisk_out_path.as_os_str().as_encoded_bytes())
                    .ok();
                if let Header::V0(v0) = &hdr {
                    if v0.second_bootloader_size != 0 {
                        print!("{sep}--second{sep}");
                        stdout()
                            .write_all(second_out_path.as_os_str().as_encoded_bytes())
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
                                .write_all(recovery_dtbo_out_path.as_os_str().as_encoded_bytes())
                                .ok();
                        }
                    }
                    if let HeaderV0Versioned::V2 { dtb_size, .. } = v0.versioned {
                        if dtb_size != 0 {
                            print!("{sep}--dtb{sep}");
                            stdout()
                                .write_all(dtb_out_path.as_os_str().as_encoded_bytes())
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
                let mut cmdline = v0.cmdline_part_1.to_vec();
                cmdline.extend_from_slice(&*v0.cmdline_part_2);
                if args.null {
                    print_null_bytestring(&cmdline);
                } else {
                    print_escaped_null_bytestring(&cmdline);
                }
            }
            if args.null {
                print!("\0");
            } else {
                println!();
            }
        }
    }
}

fn take_until_null(input: &[u8]) -> &[u8] {
    match input.iter().position(|x| *x == 0) {
        Some(null_idx) => &input[..null_idx],
        None => input,
    }
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
