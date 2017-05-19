//! Encoding and decoding of IPv4 headers
//!
//! # Example
//! ```
//! extern crate ipv4;
//! use ipv4::*;
//! use std::net::Ipv4Addr;
//!
//! fn main() {
//!     const PAYLOAD_SIZE: usize = 40; // Dummy payload
//!     let mut packet = [0u8; IPV4_HEADER_MIN_SIZE + PAYLOAD_SIZE];
//!     let mut hdr = Ipv4Header::new(Ipv4Addr::new(192, 168, 1, 2),
//!                                   Ipv4Addr::new(192, 168, 1, 1));
//!     hdr.flags = IPV4_FLAG_DF;
//!     // Write the header to the packet buffer
//!     hdr.encode(&mut packet, None, PAYLOAD_SIZE).unwrap();
//!
//!     // ...Append payload and send the packet...
//!
//!     // Decode header from a received packet
//!     let (hdr, options, payload) = Ipv4Header::decode(&packet).unwrap();
//!     assert_eq!(options.len(), 0);
//!     assert_eq!(payload.len(), PAYLOAD_SIZE);
//!     assert_eq!(hdr.source, Ipv4Addr::new(192, 168, 1, 2));
//! }
//! ```
#[macro_use]
extern crate bitflags;
extern crate byteorder;

use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};

bitflags! {
    pub flags Ipv4Flags: u8 {
        const IPV4_FLAG_RESERVED = 0b100,
        const IPV4_FLAG_DF = 0b010,
        const IPV4_FLAG_MF = 0b001,
    }
}

impl Default for Ipv4Flags {
    fn default() -> Ipv4Flags {
        Ipv4Flags::empty()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// The packet is less than the size of the IPv4 header.
    TooShort,
    /// The header length field is less than 5
    IHLTooShort(u8),
    /// The packet is less than the total size in the IPv4 header.
    PayloadTooShort,
    /// The packet's total size cannot be expressed in the IPv4 header.
    PayloadTooLong,
    /// Version field is not 4. Contains actual value.
    BadVersion(u8),
    /// Checksum mismatch. Contains a tuple of provided, calculated.
    InvalidChecksum((u16, u16)),
    /// Options length not a multiple of 4 bytes or too long
    BadOptionLength,
}

/// Panics if the buffer size is not a multiple of 2
///
/// Returns tuple of checksum provided in the buffer, and the calculated checksum.
pub fn ipv4_checksum(buf: &[u8]) -> (u16, u16) {
    let mut sum = buf.chunks(2)
        .map(|buf| BigEndian::read_u16(buf))
        .fold(0u32, |sum, val| sum.wrapping_add(val as u32));
    // Remove the checksum field from the sum
    let chksum_field = BigEndian::read_u16(&buf[10..12]);
    sum = sum.wrapping_sub(chksum_field as u32);
    // Add carry
    sum = (sum >> 16) + sum & 0xffff;
    sum += sum >> 16;
    (chksum_field, !sum as u16)
}

pub const IPV4_HEADER_MIN_SIZE: usize = 20;

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub dscp: u8,
    pub ecn: u8,
    pub identification: u16,
    pub flags: Ipv4Flags,
    pub frag_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

impl Ipv4Header {
    pub fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Ipv4Header {
            dscp: 0,
            ecn: 0,
            identification: 0,
            flags: Ipv4Flags::empty(),
            frag_offset: 0,
            ttl: 0,
            protocol: 0,
            source: src,
            destination: dst,
        }
    }

    /// Decode the IPv4 header in the given packet
    ///
    /// Returns a tuple of the header, a slice of the options area of the header (may be zero
    /// length), and a slice of the payload in the packet.
    pub fn decode(packet: &[u8]) -> Result<(Ipv4Header, &[u8], &[u8]), Error> {
        if packet.len() < IPV4_HEADER_MIN_SIZE {
            return Err(Error::TooShort);
        }
        if packet[0] >> 4 != 4 {
            return Err(Error::BadVersion(packet[0]));
        }
        let ihl = packet[0] & 0xf;
        if ihl < 5 {
            return Err(Error::IHLTooShort(ihl));
        }
        let hlen = ihl as usize * 4;
        let chk = ipv4_checksum(&packet[0..hlen]);
        if chk.0 != chk.1 {
            return Err(Error::InvalidChecksum(chk));
        }
        let total_len = BigEndian::read_u16(&packet[2..4]);
        if packet.len() < total_len as usize {
            return Err(Error::PayloadTooShort);
        }
        let flags_frag = BigEndian::read_u16(&packet[6..8]);
        Ok((Ipv4Header {
            dscp: packet[1] >> 2,
            ecn: packet[1] & 0x3,
            identification: BigEndian::read_u16(&packet[4..6]),
            flags: Ipv4Flags::from_bits_truncate((flags_frag >> 13) as u8),
            frag_offset: flags_frag & 0x1fff,
            ttl: packet[8],
            protocol: packet[9],
            source: BigEndian::read_u32(&packet[12..16]).into(),
            destination: BigEndian::read_u32(&packet[16..20]).into(),
        },
            &packet[hlen + hlen - 20..hlen],
            &packet[hlen..]))
    }

    /// Write the IPv4 header to the given buffer
    ///
    /// The buffer must be large enough to hold the 20-byte header and the provided options.
    /// Returns the header length.
    pub fn encode<'a>(&self,
                      packet: &'a mut [u8],
                      options: Option<&[u8]>,
                      payload_length: usize)
                      -> Result<(usize), Error> {
        let optlen = if let Some(opts) = options {
            if opts.len() % 4 != 0 {
                return Err(Error::BadOptionLength);
            }
            opts.len()
        } else {
            0
        };
        let ihl_bytes = IPV4_HEADER_MIN_SIZE + optlen;
        let ihl = ihl_bytes / 4;
        if ihl > 0xf {
            return Err(Error::BadOptionLength);
        }
        let total_bytes = ihl_bytes + payload_length;
        if total_bytes > u16::max_value() as usize {
            return Err(Error::PayloadTooLong);
        }
        {
            // Fill in the normal 20-byte header. Hopefully this initial slice will allow
            // optimizing away the subsequent bounds checking.
            let header = &mut packet[..ihl_bytes];
            header[0] = ((4 << 4) | ihl) as u8;
            header[1] = (self.dscp << 2) | (self.ecn & 0x3);
            BigEndian::write_u16(&mut header[2..4], total_bytes as u16);
            BigEndian::write_u16(&mut header[4..6], self.identification);
            BigEndian::write_u16(&mut header[6..8],
                                 (self.frag_offset & 0x1fff) | ((self.flags.bits() as u16) << 13));
            header[8] = self.ttl;
            header[9] = self.protocol;
            header[12..16].copy_from_slice(&self.source.octets());
            header[16..20].copy_from_slice(&self.destination.octets());
            if let Some(opts) = options {
                header[IPV4_HEADER_MIN_SIZE..].copy_from_slice(opts);
            }
            let (_, chk) = ipv4_checksum(header);
            BigEndian::write_u16(&mut header[10..12], chk);
        }
        Ok(ihl_bytes)
    }
}

#[test]
fn test() {
    let packet = [0x45, 0x00, 0x00, 0x31, 0xb2, 0x51, 0x40, 0x00, 0x40, 0x11, 0x35, 0x0c, 0x9d,
                  0xb8, 0x8b, 0xee, 0x9d, 0xb8, 0x8b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    let (hdr, options, payload) = Ipv4Header::decode(&packet).unwrap();
    assert_eq!(options.len(), 0);
    assert_eq!(hdr.dscp, 0);
    assert_eq!(hdr.ecn, 0);
    assert_eq!(hdr.identification, 0xb251);
    assert_eq!(hdr.flags, IPV4_FLAG_DF);
    assert_eq!(hdr.frag_offset, 0);
    assert_eq!(hdr.ttl, 64);
    assert_eq!(hdr.protocol, 17);
    assert_eq!(hdr.source, Ipv4Addr::new(157, 184, 139, 238));
    assert_eq!(hdr.destination, Ipv4Addr::new(157, 184, 139, 255));
    assert_eq!(payload, &[0xffu8; 29]);

    let capacity = IPV4_HEADER_MIN_SIZE + 29;
    let mut outpacket = Vec::with_capacity(capacity);
    outpacket.resize(capacity, 0);
    let len = hdr.encode(&mut outpacket, None, 29).unwrap();
    assert_eq!(len, 20);
    assert_eq!(&packet[..len], &outpacket[..len]);
}
