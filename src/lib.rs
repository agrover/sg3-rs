#[macro_use]
extern crate nix;
extern crate byteorder;

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
    sgbuf.dxferp = inquiry.as_mut_buf().as_mut_ptr() as *mut c_void;
    sgbuf.cmdp = cmd.as_mut_ptr();
    sgbuf.sbp = sb.as_mut_ptr();

    if let Err(e) = unsafe {
           convert_ioctl_res!(nix_ioctl(f.as_raw_fd(), ffi::SG_IO as u64, &sgbuf))
       } {
        return Err(Sg3Error::Nix(e));
    }

    if inquiry.response_data_format() != 2 {
        return Err(Sg3Error::Io(io::Error::new(io::ErrorKind::Other,
                                               "Unknown/unsupported response data format")));
    }

    Ok(inquiry)
}

pub struct StdInquiry {
    buf: Vec<u8>,
}

/// Struct containing the standard inquiry result, with field accessor methods.
impl StdInquiry {
    fn new() -> StdInquiry {
        StdInquiry { buf: vec![0; 96] }
    }

    /// Get the raw return buffer containing the inquiry response.
    pub fn as_buf(&self) -> &[u8] {
        &self.buf
    }

    fn as_mut_buf(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn peripheral_qualifier(&self) -> u8 {
        self.buf[0] >> 5
    }

    pub fn peripheral_device_type(&self) -> u8 {
        self.buf[0] & 0x1f
    }

    pub fn rmb(&self) -> u8 {
        (self.buf[1] & 0x80) >> 7
    }

    pub fn lu_cong(&self) -> u8 {
        (self.buf[1] & 0x40) >> 6
    }

    pub fn version(&self) -> u8 {
        self.buf[2]
    }

    pub fn norm_aca(&self) -> u8 {
        (self.buf[3] & 0x20) >> 5
    }

    pub fn hi_sup(&self) -> u8 {
        (self.buf[3] & 0x10) >> 5
    }

    pub fn response_data_format(&self) -> u8 {
        self.buf[3] & 0x0f
    }

    pub fn sccs(&self) -> u8 {
        (self.buf[5] & 0x80) >> 7
    }

    pub fn acc(&self) -> u8 {
        (self.buf[5] & 0x40) >> 6
    }

    pub fn tpgs(&self) -> u8 {
        (self.buf[5] & 0x30) >> 4
    }

    pub fn third_party_copy(&self) -> u8 {
        (self.buf[5] & 0x08) >> 3
    }

    pub fn protect(&self) -> u8 {
        self.buf[5] & 0x01
    }

    pub fn enc_serv(&self) -> u8 {
        (self.buf[6] & 0x40) >> 6
    }

    pub fn multi_p(&self) -> u8 {
        (self.buf[6] & 0x10) >> 4
    }

    pub fn addr16(&self) -> u8 {
        self.buf[6] & 0x01
    }

    pub fn wbus16(&self) -> u8 {
        (self.buf[7] & 0x20) >> 5
    }

    pub fn sync(&self) -> u8 {
        (self.buf[7] & 0x10) >> 5
    }

    pub fn cmd_que(&self) -> u8 {
        (self.buf[7] & 0x02) >> 1
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
}

pub fn inquiry_vpd_80(path: &Path) -> Sg3Result<InquiryVpd80> {

    let f = try!(OpenOptions::new().read(true).open(path));

    let mut sgbuf: ffi::sg_io_hdr = Default::default();
    let mut sb = [0u8; 64];
    let mut inquiry = InquiryVpd80::new();
    let mut cmd = [0u8; 6];

    cmd[0] = 0x12;
    cmd[1] = 1;
    cmd[2] = 0x80;
    cmd[4] = inquiry.as_buf().len() as u8;

    sgbuf.interface_id = 'S' as i32;
    sgbuf.dxfer_direction = ffi::SG_DXFER_FROM_DEV;
    sgbuf.cmd_len = 6;
    sgbuf.mx_sb_len = sb.len() as u8;
    sgbuf.dxfer_len = inquiry.as_buf().len() as u32;
    sgbuf.dxferp = inquiry.as_mut_buf().as_mut_ptr() as *mut c_void;
    sgbuf.cmdp = cmd.as_mut_ptr();
    sgbuf.sbp = sb.as_mut_ptr();

    if let Err(e) = unsafe {
           convert_ioctl_res!(nix_ioctl(f.as_raw_fd(), ffi::SG_IO as u64, &sgbuf))
       } {
        return Err(Sg3Error::Nix(e));
    }

    Ok(inquiry)
}

pub struct InquiryVpd80 {
    buf: Vec<u8>,
}

/// Struct containing the standard inquiry result, with field accessor methods.
impl InquiryVpd80 {
    fn new() -> InquiryVpd80 {
        InquiryVpd80 { buf: vec![0; 96] }
    }

    /// Get the raw return buffer containing the inquiry response.
    pub fn as_buf(&self) -> &[u8] {
        &self.buf
    }

    fn as_mut_buf(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn serial_number(&self) -> &str {
        let length = self.buf[3] as usize;
        from_utf8(&self.buf[4..length + 3]).unwrap()
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
        super::inquiry(Path::new("/dev/sda1")).unwrap();
    }

    #[test]
    fn test_inquiry_80() {
        super::inquiry_vpd_80(Path::new("/dev/sda1")).unwrap();
    }
}
