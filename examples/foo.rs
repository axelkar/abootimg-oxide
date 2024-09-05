use std::{
    fs::File,
    io::{self, BufWriter, Read, Seek, SeekFrom},
};

use abootimg_oxide::Header;
use binrw::io::BufReader;

fn main() {
    let mut r = BufReader::new(File::open("/home/axel/nordce-update/boot_a.img").unwrap());
    let hdr = Header::parse(&mut r).unwrap();
    println!("{hdr:#?}");

    println!("kpos {}", hdr.kernel_position());
    let mut w = BufWriter::new(File::create("boot_a_kernel").unwrap());
    let r = r.get_mut();
    r.seek(SeekFrom::Start(hdr.kernel_position() as u64))
        .unwrap();
    io::copy(&mut r.take(hdr.kernel_size() as u64), w.get_mut()).unwrap();
}
