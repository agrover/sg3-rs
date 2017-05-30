//! SCSI Commands using the Linux SCSI Generic (sg3) driver
//!
//! # Overview
//!
//! The Linux sg driver interface allows userspace to craft and send
//! SCSI commands to SCSI devices present on the system.
//!
//! More information can be found [here](http://sg.danny.cz/sg/p/sg_v3_ho.html).
//!
//! Currently, this library does not expose the full capabilities of
//! the interface, but just handles a few commands that were
//! immediately of interest to the author -- calling and parsing
//! various types of INQUIRY. If other capabilities are desired, it
//! should be possible to add support beyond this with relative ease.

#[macro_use]
extern crate nix;
extern crate byteorder;
#[macro_use]
extern crate nom;

use std::io;
use std::fs::OpenOptions;
use std::path::Path;
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;
use std::str::from_utf8;

use byteorder::{ByteOrder, BigEndian};
use nix::sys::ioctl::ioctl as nix_ioctl;
use nom::{be_u8, be_u16};

#[derive(Debug)]
pub enum Sg3Error {
    Nix(nix::Error),
    Io(io::Error),
    Nom(nom::ErrorKind),
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

impl From<nom::ErrorKind> for Sg3Error {
    fn from(err: nom::ErrorKind) -> Sg3Error {
        Sg3Error::Nom(err)
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

#[derive(Debug, PartialEq, Eq)]
pub enum PeripheralQualifier {
    Connected,
    NotConnected,
    Reserved,
    NotCapable,
    VS,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeripheralDeviceType {
    DirectAccess,
    SequentialAccess,
    Printer,
    Processor,
    WriteOnce,
    CdDvd,
    Obsolete,
    OpticalMemory,
    MediaChanger,
    StorageArrayController,
    EnclosureServices,
    SimplifiedDirectAccess,
    OpticalCardReader,
    ObjectBasedStorage,
    AutomationDriveInterface,
    Reserved,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolIdentifier {
    Fcp,
    Spi,
    Ssa,
    Sbp,
    Srp,
    IScsi,
    Spl,
    Adt,
    Acs,
    Uas,
    Sop,
    Reserved,
    Unspecified,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Association {
    AddressedLogicalUnit,
    TargetPort,
    ScsiTargetDevice,
    Reserved,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DesignatorType {
    VS,
    T10VendorId,
    Eui64,
    Naa,
    RelativeTargetPortIdentifier,
    TargetPortGroup,
    LogicalUnitGroup,
    Md5LogicalUnitIdentifier,
    ScsiNameString,
    ProtocolSpecificPortIdentifier,
    Reserved,
}

// Send SCSI INQUIRY command to the SCSI device at the given path.
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

    pub fn peripheral_qualifier(&self) -> PeripheralQualifier {
        to_qualifier(self.buf[0] >> 5)
    }

    pub fn peripheral_device_type(&self) -> PeripheralDeviceType {
        to_device_type(self.buf[0] & 0x1f)
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

fn inquiry_vpd(path: &Path, vpd: u8, buf: &mut [u8]) -> Sg3Result<()> {

    let f = try!(OpenOptions::new().read(true).open(path));

    let mut sgbuf: ffi::sg_io_hdr = Default::default();
    let mut sb = [0u8; 64];
    let mut cmd = [0u8; 6];

    cmd[0] = 0x12;
    cmd[1] = 1;
    cmd[2] = vpd;
    BigEndian::write_u16(&mut cmd[3..5], buf.len() as u16);

    sgbuf.interface_id = 'S' as i32;
    sgbuf.dxfer_direction = ffi::SG_DXFER_FROM_DEV;
    sgbuf.cmd_len = 6;
    sgbuf.mx_sb_len = sb.len() as u8;
    sgbuf.dxfer_len = buf.len() as u32;
    sgbuf.dxferp = buf.as_mut_ptr() as *mut c_void;
    sgbuf.cmdp = cmd.as_mut_ptr();
    sgbuf.sbp = sb.as_mut_ptr();

    if let Err(e) = unsafe {
           convert_ioctl_res!(nix_ioctl(f.as_raw_fd(), ffi::SG_IO as u64, &sgbuf))
       } {
        return Err(Sg3Error::Nix(e));
    }

    Ok(())
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

    pub fn peripheral_qualifier(&self) -> PeripheralQualifier {
        to_qualifier(self.buf[0] >> 5)
    }

    pub fn peripheral_device_type(&self) -> PeripheralDeviceType {
        to_device_type(self.buf[0] & 0x1f)
    }

    pub fn serial_number(&self) -> &str {
        let length = BigEndian::read_u16(&self.buf[2..4]);
        from_utf8(&self.buf[4..length as usize + 3]).unwrap()
    }
}

// Send SCSI INQUIRY for VPD 80 (Unit Serial Number) to the SCSI
// device at the given path.
pub fn inquiry_vpd_80(path: &Path) -> Sg3Result<InquiryVpd80> {
    let mut inquiry = InquiryVpd80::new();
    try!(inquiry_vpd(path, 0x80, inquiry.as_mut_buf()));
    Ok(inquiry)
}

fn to_protocol(ident: u8, assoc: Association, piv: u8) -> ProtocolIdentifier {
    if piv == 0 || !(assoc == Association::TargetPort || assoc == Association::ScsiTargetDevice) {
        return ProtocolIdentifier::Reserved;
    }

    match ident {
        0 => ProtocolIdentifier::Fcp,
        1 => ProtocolIdentifier::Spi,
        2 => ProtocolIdentifier::Ssa,
        3 => ProtocolIdentifier::Sbp,
        4 => ProtocolIdentifier::Srp,
        5 => ProtocolIdentifier::IScsi,
        6 => ProtocolIdentifier::Spl,
        7 => ProtocolIdentifier::Adt,
        8 => ProtocolIdentifier::Acs,
        9 => ProtocolIdentifier::Uas,
        0xa => ProtocolIdentifier::Sop,
        0xb...0xe => ProtocolIdentifier::Reserved,
        _ => ProtocolIdentifier::Unspecified,
    }
}

fn to_association(i: u8) -> Association {
    match i {
        0 => Association::AddressedLogicalUnit,
        1 => Association::TargetPort,
        2 => Association::ScsiTargetDevice,
        _ => Association::Reserved,
    }
}

fn to_designator_type(i: u8) -> DesignatorType {
    match i {
        0 => DesignatorType::VS,
        1 => DesignatorType::T10VendorId,
        2 => DesignatorType::Eui64,
        3 => DesignatorType::Naa,
        4 => DesignatorType::RelativeTargetPortIdentifier,
        5 => DesignatorType::TargetPortGroup,
        6 => DesignatorType::LogicalUnitGroup,
        7 => DesignatorType::Md5LogicalUnitIdentifier,
        8 => DesignatorType::ScsiNameString,
        9 => DesignatorType::ProtocolSpecificPortIdentifier,
        _ => DesignatorType::Reserved,
    }
}

// Return up to the first \0, or the entire slice
//
fn slice_to_null(slc: &[u8]) -> &[u8] {
    for (i, c) in slc.iter().enumerate() {
        if *c == b'\0' {
            return &slc[..i];
        };
    }
    slc
}

#[derive(Debug)]
pub enum Designator {
    Binary(Vec<u8>),
    String(String),
}

fn to_designator(code: u8, data: &[u8]) -> Designator {
    match code {
        0...1 => Designator::Binary(Vec::from(data)),
        2...3 => Designator::String(String::from_utf8_lossy(slice_to_null(data)).into_owned()),
        _ => Designator::Binary(Vec::from(data)),
    }
}

#[derive(Debug)]
pub struct DesignationDescriptor {
    pub protocol: ProtocolIdentifier,
    pub association: Association,
    pub designator_type: DesignatorType,
    pub designator: Designator,
}

named!( dd_byte0<(u8, u8)>, bits!( pair!( take_bits!( u8, 4 ), take_bits!(u8, 4) ) ) );
named!( dd_byte1<(u8, u8, u8, u8)>, bits!( tuple!(
    take_bits!(u8, 1),
    take_bits!(u8, 1),
    take_bits!(u8, 2),
    take_bits!(u8, 4)
) ) );

named!(des_desc<DesignationDescriptor>,
       dbg_dmp!(
       do_parse!(
       byte0: dd_byte0 >>
       byte1: dd_byte1 >>
       take!(1) >>
       length: be_u8 >>
       designator: take!(length) >>
       (DesignationDescriptor {
           protocol: to_protocol(byte0.0, to_association(byte1.2), byte1.0),
           association: to_association(byte1.2),
           designator_type: to_designator_type(byte1.3),
           designator: to_designator(byte0.1, designator),
      })
)));

named!(des_descs<Vec<DesignationDescriptor> >, many0!(des_desc));

#[derive(Debug)]
pub struct InquiryVpd83 {
    pub qualifier: PeripheralQualifier,
    pub device_type: PeripheralDeviceType,
    pub descriptors: Vec<DesignationDescriptor>,
}

named!(periph<(u8, u8)>, bits!( pair!( take_bits!( u8, 3 ), take_bits!(u8, 5) ) ) );

fn to_qualifier(i: u8) -> PeripheralQualifier {
    match i {
        0 => PeripheralQualifier::Connected,
        1 => PeripheralQualifier::NotConnected,
        2 => PeripheralQualifier::Reserved,
        3 => PeripheralQualifier::NotCapable,
        4...7 => PeripheralQualifier::VS,
        _ => PeripheralQualifier::Reserved,
    }
}

fn to_device_type(i: u8) -> PeripheralDeviceType {
    match i {
        0 => PeripheralDeviceType::DirectAccess,
        1 => PeripheralDeviceType::SequentialAccess,
        2 => PeripheralDeviceType::Printer,
        3 => PeripheralDeviceType::Processor,
        4 => PeripheralDeviceType::WriteOnce,
        5 => PeripheralDeviceType::CdDvd,
        6 => PeripheralDeviceType::Obsolete,
        7 => PeripheralDeviceType::OpticalMemory,
        8 => PeripheralDeviceType::MediaChanger,
        0x9...0xb => PeripheralDeviceType::Obsolete,
        0xc => PeripheralDeviceType::StorageArrayController,
        0xd => PeripheralDeviceType::EnclosureServices,
        0xe => PeripheralDeviceType::SimplifiedDirectAccess,
        0xf => PeripheralDeviceType::OpticalCardReader,
        0x10 => PeripheralDeviceType::Reserved,
        0x11 => PeripheralDeviceType::ObjectBasedStorage,
        0x12 => PeripheralDeviceType::AutomationDriveInterface,
        _ => PeripheralDeviceType::Reserved,
    }
}

named!(vpd83<InquiryVpd83>, dbg_dmp!(do_parse!(
    per: periph >>
    tag!( &[ 0x83u8 ][..] ) >>
    descs: length_value!(be_u16, des_descs) >>
    (InquiryVpd83 {
        qualifier: to_qualifier(per.0),
        device_type: to_device_type(per.1),
        descriptors: descs,
    })
)));

// Send SCSI INQUIRY for VPD 83 (Device Identification) to the SCSI
// device at the given path.
pub fn inquiry_vpd_83(path: &Path) -> Sg3Result<InquiryVpd83> {
    let mut inquiry = [0u8; 1024];
    try!(inquiry_vpd(path, 0x83, &mut inquiry));
    let res = try!(vpd83(&inquiry).to_result());
    Ok(res)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn test_inquiry() {
        super::inquiry(Path::new("/dev/sda")).unwrap();
    }

    #[test]
    fn test_inquiry_80() {
        super::inquiry_vpd_80(Path::new("/dev/sda")).unwrap();
    }

    #[test]
    fn test_inquiry_83() {
        super::inquiry_vpd_83(Path::new("/dev/sda")).unwrap();
    }
}
