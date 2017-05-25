#[macro_use]
extern crate nix;

use std::io;
use std::fs::OpenOptions;
use std::path::Path;
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;
use std::str::from_utf8;

use nix::sys::ioctl::ioctl as nix_ioctl;

#[derive(Debug)]
pub enum Sg3Error {
    Nix(nix::Error),
    Io(io::Error),
}

pub type Sg3Result<T> = Result<T, Sg3Error>;

impl From<io::Error> for Sg3Error {
    fn from(err: io::Error) -> Sg3Error {
        Sg3Error::Io(err)
    }
}

impl From<nix::Error> for Sg3Error {
    fn from(err: nix::Error) -> Sg3Error {
        Sg3Error::Nix(err)
    }
}


mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn inquiry(path: &Path) -> Sg3Result<StdInquiry> {

    let f = try!(OpenOptions::new().read(true).open(path));

    let mut sgbuf: ffi::sg_io_hdr = Default::default();
    let mut sb = [0u8; 64];
    let mut inquiry = StdInquiry::new();
    let mut cmd = [0u8; 6];

    cmd[0] = 0x12;
    cmd[4] = inquiry.as_buf().len() as u8;

    sgbuf.interface_id = 'S' as i32;
    sgbuf.dxfer_direction = ffi::SG_DXFER_FROM_DEV;
    sgbuf.cmd_len = 6;
    sgbuf.mx_sb_len = sb.len() as u8;
    sgbuf.dxfer_len = inquiry.as_buf().len() as u32;
    sgbuf.dxferp = inquiry.as_buf().as_mut_ptr() as *mut c_void;
    sgbuf.cmdp = cmd.as_mut_ptr();
    sgbuf.sbp = sb.as_mut_ptr();

    if let Err(e) = unsafe {
           convert_ioctl_res!(nix_ioctl(f.as_raw_fd(), ffi::SG_IO as u64, &sgbuf))
       } {
        return Err(Sg3Error::Nix(e));
    }

    Ok(inquiry)
}

pub struct StdInquiry {
    buf: Vec<u8>,
}

impl StdInquiry {
    fn new() -> StdInquiry {
        StdInquiry { buf: vec![0; 96] }
    }

    fn as_buf(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn vendor(&self) -> &str {
        from_utf8(&self.buf[8..16]).unwrap()
    }

    pub fn product_id(&self) -> &str {
        from_utf8(&self.buf[16..32]).unwrap()
    }

    pub fn product_revision(&self) -> &str {
        from_utf8(&self.buf[32..36]).unwrap()
    }

    pub fn peripheral_device_type(&self) -> u8 {
        self.buf[0]
    }

    pub fn version(&self) -> u8 {
        self.buf[2]
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    // #[test]
    // fn test_bd_init() {
    //     let fs_plugin_so = unsafe { ffi::bd_get_plugin_soname(ffi::BD_PLUGIN_FS) };
    //     println!("so = {:?}", fs_plugin_so);
    //     let mut thing = ffi::BDPluginSpec {
    //         name: ffi::BD_PLUGIN_FS,
    //         so_name: fs_plugin_so,
    //     };
    //     let raw = &mut thing as *mut ffi::BDPluginSpec;
    //     super::bd_init();
    // }

    #[test]
    fn test_inquiry() {
        let x = super::inquiry(Path::new("/dev/sda1"));
        panic!(format!("hi {:?}", x));
    }
}
