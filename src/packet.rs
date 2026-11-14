//! Raw IPv4 / TCP / UDP packet parsing and building.
//!
//! The Android VPN interface hands us whole layer-3 packets. We need to:
//!  * read the few header fields we care about (addresses, ports, seq/ack, flags...)
//!  * forge response packets with correct checksums (the phone silently drops
//!    packets with a bad checksum, so this must be exact).

use std::net::{Ipv4Addr, SocketAddrV4};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// MTU configured by the Android client (GnirehtetService.MTU = 0x4000).
pub const MTU: usize = 0x4000;
pub const IPV4_HEADER_LEN: usize = 20;
pub const TCP_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;
pub const MAX_TCP_PAYLOAD: usize = MTU - IPV4_HEADER_LEN - TCP_HEADER_LEN;
pub const MAX_UDP_PAYLOAD: usize = MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

#[inline]
fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
#[inline]
fn be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// How many bytes the packet at the start of `buf` occupies, if its header is
/// already available. Used to split the byte stream coming from the phone into
/// individual packets.
pub enum Framing {
    NeedMore,
    Packet(usize),
    Invalid,
}

pub fn frame(buf: &[u8]) -> Framing {
    if buf.is_empty() {
        return Framing::NeedMore;
    }
    match buf[0] >> 4 {
        4 => {
            if buf.len() < 4 {
                return Framing::NeedMore;
            }
            let len = be16(buf, 2) as usize;
            if len < IPV4_HEADER_LEN {
                Framing::Invalid
            } else {
                Framing::Packet(len)
            }
        }
        6 => {
            // The VPN only routes IPv4, but frame IPv6 correctly anyway so a
            // stray one doesn't desynchronise the stream.
            if buf.len() < 6 {
                return Framing::NeedMore;
            }
            Framing::Packet(40 + be16(buf, 4) as usize)
        }
        _ => Framing::Invalid,
    }
}

/// Parsed view over an IPv4 packet carrying TCP or UDP.
#[derive(Debug)]
pub struct Ipv4<'a> {
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Everything after the IPv4 header (transport header + payload).
    pub transport: &'a [u8],
}

impl<'a> Ipv4<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < IPV4_HEADER_LEN || raw[0] >> 4 != 4 {
            return None;
        }
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        let total = be16(raw, 2) as usize;
        if ihl < IPV4_HEADER_LEN || total < ihl || total > raw.len() {
            return None;
        }
        // Fragmented packets (MF flag or non-zero offset) are not supported.
        if be16(raw, 6) & 0x3fff != 0 {
            return None;
        }
        Some(Self {
            protocol: raw[9],
            src: Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]),
            dst: Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]),
            transport: &raw[ihl..total],
        })
    }
}

#[derive(Debug)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

impl<'a> Tcp<'a> {
    pub fn parse(t: &'a [u8]) -> Option<Self> {
        if t.len() < TCP_HEADER_LEN {
            return None;
        }
        let data_offset = ((t[12] >> 4) as usize) * 4;
        if data_offset < TCP_HEADER_LEN || data_offset > t.len() {
            return None;
        }
        Some(Self {
            src_port: be16(t, 0),
            dst_port: be16(t, 2),
            seq: be32(t, 4),
            ack: be32(t, 8),
            flags: t[13],
            window: be16(t, 14),
            payload: &t[data_offset..],
        })
    }
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[derive(Debug)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn parse(t: &'a [u8]) -> Option<Self> {
        if t.len() < UDP_HEADER_LEN {
            return None;
        }
        let len = be16(t, 4) as usize;
        if len < UDP_HEADER_LEN || len > t.len() {
            return None;
        }
        Some(Self {
            src_port: be16(t, 0),
            dst_port: be16(t, 2),
            payload: &t[UDP_HEADER_LEN..len],
        })
    }
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

/// Accumulate 16-bit big-endian words (RFC 1071). Not yet folded.
fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc += u16::from_be_bytes(*w) as u32;
    }
    if let [last] = rest {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

pub fn ipv4_checksum(header: &[u8]) -> u16 {
    fold(sum16(header, 0))
}

/// TCP/UDP checksum: covers a pseudo-header (src, dst, proto, length) plus
/// the whole transport segment.
pub fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut acc = sum16(&src.octets(), 0);
    acc = sum16(&dst.octets(), acc);
    acc += proto as u32;
    acc += segment.len() as u32;
    fold(sum16(segment, acc))
}

// ---------------------------------------------------------------------------
// Building packets
// ---------------------------------------------------------------------------

/// Write a 20-byte IPv4 header into `h`.
fn write_ipv4_header(h: &mut [u8], total_len: usize, proto: u8, src: Ipv4Addr, dst: Ipv4Addr) {
    h[0] = 0x45; // version 4, IHL 5
    h[1] = 0;
    h[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    h[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    h[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
    h[8] = 64; // TTL
    h[9] = proto;
    h[10..12].copy_from_slice(&[0, 0]);
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    let c = ipv4_checksum(&h[..IPV4_HEADER_LEN]);
    h[10..12].copy_from_slice(&c.to_be_bytes());
}

/// Fields of a TCP segment sent *to the phone*.
#[derive(Clone, Copy, Debug)]
pub struct TcpOut {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
}

/// Fill in IPv4+TCP headers for a packet whose payload is already in
/// `pkt[40..]`. `pkt.len()` must be exactly 40 + payload length.
pub fn finish_tcp(pkt: &mut [u8], o: &TcpOut) {
    let total = pkt.len();
    let (ip, tcp) = pkt.split_at_mut(IPV4_HEADER_LEN);
    write_ipv4_header(ip, total, PROTO_TCP, *o.src.ip(), *o.dst.ip());
    tcp[0..2].copy_from_slice(&o.src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&o.dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&o.seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&o.ack.to_be_bytes());
    tcp[12] = (TCP_HEADER_LEN as u8 / 4) << 4;
    tcp[13] = o.flags;
    tcp[14..16].copy_from_slice(&o.window.to_be_bytes());
    tcp[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
    tcp[18..20].copy_from_slice(&[0, 0]); // urgent pointer
    let c = transport_checksum(*o.src.ip(), *o.dst.ip(), PROTO_TCP, tcp);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
}

/// Build a complete TCP packet (appends to `out`).
pub fn push_tcp(out: &mut Vec<u8>, o: &TcpOut, payload: &[u8]) {
    let start = out.len();
    out.resize(start + IPV4_HEADER_LEN + TCP_HEADER_LEN, 0);
    out.extend_from_slice(payload);
    finish_tcp(&mut out[start..], o);
}

/// Fill in IPv4+UDP headers for a packet whose payload is in `pkt[28..]`.
pub fn finish_udp(pkt: &mut [u8], src: SocketAddrV4, dst: SocketAddrV4) {
    let total = pkt.len();
    let (ip, udp) = pkt.split_at_mut(IPV4_HEADER_LEN);
    write_ipv4_header(ip, total, PROTO_UDP, *src.ip(), *dst.ip());
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    let udp_len = udp.len() as u16;
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&[0, 0]);
    let mut c = transport_checksum(*src.ip(), *dst.ip(), PROTO_UDP, udp);
    if c == 0 {
        c = 0xffff; // 0 means "no checksum" for UDP
    }
    udp[6..8].copy_from_slice(&c.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Mock packet from gnirehtet's TCPHeaderTest: 18.52.86.120 -> 162.162.66.66,
    /// ports 0x1234 -> 0x5678, seq 0x111, ack 0x222, payload 11 22 ee ff [88].
    fn mock_packet(odd: bool) -> Vec<u8> {
        let mut p = hex("45000000 00000000 00060000 12345678 a2a24242 \
                         12345678 00000111 00000222 50000000 00790000 1122eeff");
        if odd {
            p.push(0x88);
        }
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    /// Expected checksums, summed by hand exactly like the Java reference test
    /// (the zero words are kept on purpose to mirror the header layout).
    #[allow(clippy::identity_op)]
    fn reference_sum(odd: bool) -> u16 {
        let seg_len: u32 = if odd { 0x19 } else { 0x18 };
        let mut sum: u32 = 0x1234 + 0x5678 + 0xa2a2 + 0x4242 + 0x0006 + seg_len;
        sum += 0x1234 + 0x5678 + 0x0000 + 0x0111 + 0x0000 + 0x0222 + 0x5000;
        sum += 0x1122 + 0xeeff + if odd { 0x8800 } else { 0 };
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn tcp_checksum_matches_gnirehtet_reference_vectors() {
        for odd in [false, true] {
            let mut p = mock_packet(odd);
            p[36..38].copy_from_slice(&[0, 0]); // zero the fake 0x0079 checksum
            let ip = Ipv4::parse(&p).unwrap();
            let c = transport_checksum(ip.src, ip.dst, PROTO_TCP, ip.transport);
            assert_eq!(c, reference_sum(odd), "odd={odd}");
            // With the checksum stored, the segment must verify to zero.
            p[36..38].copy_from_slice(&c.to_be_bytes());
            let ip = Ipv4::parse(&p).unwrap();
            assert_eq!(
                transport_checksum(ip.src, ip.dst, PROTO_TCP, ip.transport),
                0
            );
            let tcp = Tcp::parse(ip.transport).unwrap();
            assert_eq!(
                (tcp.src_port, tcp.dst_port, tcp.seq, tcp.ack),
                (0x1234, 0x5678, 0x111, 0x222)
            );
            assert_eq!(tcp.payload.len(), if odd { 5 } else { 4 });
        }
    }

    #[test]
    fn ipv4_header_checksum_matches_known_example() {
        // Classic example from Wikipedia "IPv4 header checksum".
        let mut h = hex("450000730000400040110000c0a80001c0a800c7");
        assert_eq!(ipv4_checksum(&h), 0xb861);
        h[10..12].copy_from_slice(&0xb861u16.to_be_bytes());
        // A header including its correct checksum sums to zero.
        assert_eq!(ipv4_checksum(&h), 0);
    }

    #[test]
    fn built_tcp_packet_round_trips_and_validates() {
        let o = TcpOut {
            src: "93.184.216.34:80".parse().unwrap(),
            dst: "10.0.0.2:41234".parse().unwrap(),
            seq: 0xdeadbeef,
            ack: 12345,
            flags: ACK | PSH,
            window: 65535,
        };
        let mut v = Vec::new();
        push_tcp(&mut v, &o, b"hello, odd length");
        assert_eq!(ipv4_checksum(&v[..20]), 0);
        let ip = Ipv4::parse(&v).unwrap();
        assert_eq!(
            transport_checksum(ip.src, ip.dst, PROTO_TCP, ip.transport),
            0
        );
        let t = Tcp::parse(ip.transport).unwrap();
        assert_eq!(
            (t.seq, t.ack, t.flags, t.window),
            (0xdeadbeef, 12345, ACK | PSH, 65535)
        );
        assert_eq!(t.payload, b"hello, odd length");
        assert!(matches!(frame(&v), Framing::Packet(n) if n == v.len()));
    }

    #[test]
    fn built_udp_packet_validates() {
        let src: SocketAddrV4 = "8.8.8.8:53".parse().unwrap();
        let dst: SocketAddrV4 = "10.0.0.2:5555".parse().unwrap();
        let payload = b"dns-ish";
        let mut v = vec![0u8; 28 + payload.len()];
        v[28..].copy_from_slice(payload);
        finish_udp(&mut v, src, dst);
        let ip = Ipv4::parse(&v).unwrap();
        assert_eq!(
            transport_checksum(ip.src, ip.dst, PROTO_UDP, ip.transport),
            0
        );
        let u = Udp::parse(ip.transport).unwrap();
        assert_eq!(
            (u.src_port, u.dst_port, u.payload),
            (53, 5555, &payload[..])
        );
    }

    #[test]
    fn framing_splits_stream() {
        let p = mock_packet(false);
        let mut stream = p.clone();
        stream.extend_from_slice(&p[..10]);
        assert!(matches!(frame(&stream), Framing::Packet(44)));
        assert!(matches!(frame(&stream[44..46]), Framing::NeedMore));
        assert!(matches!(frame(&[0x00, 0, 0, 0]), Framing::Invalid));
    }
}
