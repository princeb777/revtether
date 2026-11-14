//! End-to-end tests: a fake "phone" speaks raw IPv4 packets to the real relay,
//! which talks to local echo servers. Every packet the relay produces must
//! have valid checksums (a real phone would silently drop it otherwise).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use crate::packet::{self, ACK, FIN, Framing, Ipv4, PROTO_TCP, PROTO_UDP, SYN, Tcp, TcpOut, Udp};
use crate::relay::Relay;

const PHONE_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn start_relay() -> u16 {
    let mut relay = Relay::bind(0).unwrap();
    let port = relay.local_port();
    thread::spawn(move || relay.run().unwrap());
    port
}

struct Phone {
    s: TcpStream,
    buf: Vec<u8>,
}

#[derive(Debug)]
struct Seg {
    /// Phone-side port this segment is addressed to.
    port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: Vec<u8>,
}

impl Phone {
    fn connect(port: u16) -> Self {
        Self::handshake(TcpStream::connect(("127.0.0.1", port)).unwrap())
    }

    /// A phone with a tiny socket receive buffer (disables autotuning), so the
    /// relay's writes to it block quickly.
    fn connect_slow_reader(port: u16) -> Self {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        sock.set_recv_buffer_size(16 * 1024).unwrap();
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
        sock.connect(&addr.into()).unwrap();
        Self::handshake(sock.into())
    }

    fn handshake(mut s: TcpStream) -> Self {
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut id = [0u8; 4];
        s.read_exact(&mut id).unwrap();
        Self { s, buf: Vec::new() }
    }

    fn next_packet(&mut self) -> Vec<u8> {
        loop {
            if let Framing::Packet(n) = packet::frame(&self.buf)
                && self.buf.len() >= n
            {
                return self.buf.drain(..n).collect();
            }
            let mut chunk = [0u8; 65536];
            let n = self
                .s
                .read(&mut chunk)
                .expect("timed out waiting for a packet");
            assert!(n > 0, "relay closed the connection");
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read the next TCP segment and check both checksums.
    fn next_tcp(&mut self) -> Seg {
        let raw = self.next_packet();
        assert_eq!(packet::ipv4_checksum(&raw[..20]), 0, "bad IPv4 checksum");
        let ip = Ipv4::parse(&raw).unwrap();
        assert_eq!(ip.protocol, PROTO_TCP);
        assert_eq!(ip.dst, PHONE_IP);
        assert_eq!(
            packet::transport_checksum(ip.src, ip.dst, PROTO_TCP, ip.transport),
            0,
            "bad TCP checksum"
        );
        let t = Tcp::parse(ip.transport).unwrap();
        assert!(raw.len() <= packet::MTU);
        Seg {
            port: t.dst_port,
            seq: t.seq,
            ack: t.ack,
            flags: t.flags,
            window: t.window,
            payload: t.payload.to_vec(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send_tcp(
        &mut self,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) {
        let mut v = Vec::new();
        packet::push_tcp(
            &mut v,
            &TcpOut {
                src,
                dst,
                seq,
                ack,
                flags,
                window,
            },
            payload,
        );
        self.s.write_all(&v).unwrap();
    }
}

#[test]
fn tcp_handshake_data_and_close() {
    // Echo server: echoes until EOF, then closes.
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut c, _) = server.accept().unwrap();
        let mut b = [0u8; 1024];
        loop {
            let n = c.read(&mut b).unwrap();
            if n == 0 {
                break;
            }
            c.write_all(&b[..n]).unwrap();
        }
    });

    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 40000);
    let srv = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport);

    phone.send_tcp(me, srv, 1000, 0, SYN, 65535, &[]);
    let synack = phone.next_tcp();
    assert_eq!(synack.flags, SYN | ACK);
    assert_eq!(synack.ack, 1001);
    let mut their = synack.seq.wrapping_add(1);

    phone.send_tcp(me, srv, 1001, their, ACK, 65535, b"hello world");
    // Expect an ACK for our data and the echoed data (in either order).
    let (mut acked, mut echoed) = (false, Vec::new());
    while !(acked && echoed.len() == 11) {
        let s = phone.next_tcp();
        if s.ack == 1012 {
            acked = true;
        }
        if !s.payload.is_empty() {
            assert_eq!(s.seq, their);
            their = their.wrapping_add(s.payload.len() as u32);
            echoed.extend_from_slice(&s.payload);
        }
    }
    assert_eq!(echoed, b"hello world");

    // We close: FIN. The relay half-closes upstream; the echo server then
    // closes, so the relay must send its own FIN.
    phone.send_tcp(me, srv, 1012, their, FIN | ACK, 65535, &[]);
    let mut got_fin = false;
    while !got_fin {
        let s = phone.next_tcp();
        assert_eq!(s.ack, 1013, "FIN must be acked: {s:?}");
        if s.flags & FIN != 0 {
            assert_eq!(s.seq, their);
            got_fin = true;
        }
    }
    phone.send_tcp(me, srv, 1013, their.wrapping_add(1), ACK, 65535, &[]);
}

#[test]
fn tcp_large_download_respects_window() {
    const SIZE: usize = 1 << 20;
    const WINDOW: u16 = 6000;
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    thread::spawn(move || {
        let (mut c, _) = server.accept().unwrap();
        let data: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        c.write_all(&data).unwrap();
    });

    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 40001);
    let srv = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport);
    phone.send_tcp(me, srv, 5000, 0, SYN, WINDOW, &[]);
    let synack = phone.next_tcp();
    let start = synack.seq.wrapping_add(1);
    phone.send_tcp(me, srv, 5001, start, ACK, WINDOW, &[]);

    let mut received = Vec::with_capacity(SIZE);
    let mut acked = start;
    loop {
        let s = phone.next_tcp();
        if s.flags & FIN != 0 {
            assert_eq!(s.seq, start.wrapping_add(received.len() as u32));
            break;
        }
        assert_eq!(
            s.seq,
            start.wrapping_add(received.len() as u32),
            "out of order / lost data"
        );
        received.extend_from_slice(&s.payload);
        let in_flight = start
            .wrapping_add(received.len() as u32)
            .wrapping_sub(acked);
        assert!(
            in_flight <= WINDOW as u32,
            "relay overran the window: {in_flight}"
        );
        // Ack everything every time the window is full.
        if in_flight == WINDOW as u32 {
            acked = start.wrapping_add(received.len() as u32);
            phone.send_tcp(me, srv, 5001, acked, ACK, WINDOW, &[]);
        }
    }
    assert_eq!(received.len(), SIZE);
    assert!(
        received
            .iter()
            .enumerate()
            .all(|(i, &b)| b == (i % 251) as u8)
    );
}

#[test]
fn tcp_connection_refused_gets_rst() {
    // Find a closed port.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 40002);
    phone.send_tcp(
        me,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
        7,
        0,
        SYN,
        65535,
        &[],
    );
    let s = phone.next_tcp();
    assert!(s.flags & packet::RST != 0, "expected RST, got {s:?}");
    assert_eq!(s.ack, 8);
}

#[test]
fn udp_round_trip() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut b = [0u8; 2048];
        let (n, from) = server.recv_from(&mut b).unwrap();
        b[..n].reverse();
        server.send_to(&b[..n], from).unwrap();
    });

    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 5353);
    let srv = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport);
    let mut v = vec![0u8; 28 + 5];
    v[28..].copy_from_slice(b"abcde");
    packet::finish_udp(&mut v, me, srv);
    phone.s.write_all(&v).unwrap();

    let raw = phone.next_packet();
    let ip = Ipv4::parse(&raw).unwrap();
    assert_eq!(ip.protocol, PROTO_UDP);
    assert_eq!(
        packet::transport_checksum(ip.src, ip.dst, PROTO_UDP, ip.transport),
        0
    );
    let u = Udp::parse(ip.transport).unwrap();
    assert_eq!(
        (u.src_port, u.dst_port, u.payload),
        (sport, 5353, &b"edcba"[..])
    );
    assert_eq!(ip.dst, PHONE_IP);
}

#[test]
fn window_field_reflects_buffer() {
    // Smoke check that the advertised window is non-zero on a fresh connection.
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    thread::spawn(move || {
        let _c = server.accept().unwrap();
        thread::sleep(Duration::from_secs(2));
    });
    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 40003);
    phone.send_tcp(
        me,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport),
        1,
        0,
        SYN,
        65535,
        &[],
    );
    let s = phone.next_tcp();
    assert!(s.window > 0);
}

/// Many parallel downloads while the phone stops reading for a while: the
/// relay's output buffer fills up, connections must pause and later resume,
/// and no byte may be lost or reordered.
#[test]
fn parallel_downloads_survive_output_backpressure() {
    // 100 flows x 64 KB windows = 6.4 MB in flight: more than the relay's
    // socket send buffer (4 MB max) + its 512 KB output buffer, while the
    // phone's receive buffer is 16 KB. The output buffer must fill.
    const FLOWS: u16 = 100;
    const SIZE: usize = 256 << 10;
    const WINDOW: u16 = 65535;
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    thread::spawn(move || {
        for c in server.incoming() {
            let mut c = c.unwrap();
            thread::spawn(move || {
                let data: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
                c.write_all(&data).unwrap();
            });
        }
    });

    let mut phone = Phone::connect_slow_reader(start_relay());
    let srv = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport);
    let me = |i: u16| SocketAddrV4::new(PHONE_IP, 41000 + i);
    for i in 0..FLOWS {
        phone.send_tcp(me(i), srv, 100, 0, SYN, WINDOW, &[]);
    }
    // Per flow: (start seq, bytes received, last acked seq, fin seen)
    let mut st = vec![(0u32, 0usize, 0u32, false); FLOWS as usize];
    let mut synacks = 0;
    while synacks < FLOWS {
        let s = phone.next_tcp();
        assert_eq!(s.flags, SYN | ACK);
        let i = (s.port - 41000) as usize;
        let start = s.seq.wrapping_add(1);
        st[i] = (start, 0, start, false);
        phone.send_tcp(me(i as u16), srv, 101, start, ACK, WINDOW, &[]);
        synacks += 1;
    }

    // Stop reading: upstream keeps sending, so the relay must back off.
    thread::sleep(Duration::from_millis(500));

    let mut done = 0;
    while done < FLOWS {
        let s = phone.next_tcp();
        let i = (s.port - 41000) as usize;
        let (start, ref mut got, ref mut acked, ref mut fin) = st[i];
        let next = start.wrapping_add(*got as u32);
        assert_eq!(s.seq, next, "flow {i}: data lost or reordered");
        if s.flags & FIN != 0 {
            assert_eq!(*got, SIZE, "flow {i}: FIN before all data");
            *fin = true;
            done += 1;
            continue;
        }
        for (k, &b) in s.payload.iter().enumerate() {
            assert_eq!(b, ((*got + k) % 251) as u8, "flow {i}: corrupted data");
        }
        *got += s.payload.len();
        let next = start.wrapping_add(*got as u32);
        let in_flight = next.wrapping_sub(*acked);
        assert!(in_flight <= WINDOW as u32, "flow {i}: window overrun");
        if in_flight >= WINDOW as u32 / 2 {
            *acked = next;
            phone.send_tcp(me(i as u16), srv, 101, next, ACK, WINDOW, &[]);
        }
    }
    let resumed = crate::relay::RESUMED_AFTER_STARVATION.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        resumed > 0,
        "output buffer never filled; backpressure path not exercised"
    );
    eprintln!("parallel: connections resumed after full buffer {resumed} times");
}

/// Upload 24 MB to a reader that starts late: kernel buffers and then the
/// relay's per-connection buffer fill up, the phone must stop at the advertised
/// window, and the relay's ACK + window update after draining must resume it.
/// The fake phone respects the window and retransmits on timeout.
#[test]
fn upload_to_slow_server() {
    const SIZE: usize = 24 << 20;
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let sport = server.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut c, _) = server.accept().unwrap();
        // Don't read at first, so kernel buffers and then the relay's buffer fill up.
        thread::sleep(Duration::from_millis(1500));
        let mut all = Vec::new();
        let mut b = [0u8; 4096];
        loop {
            let n = c.read(&mut b).unwrap();
            if n == 0 {
                break;
            }
            all.extend_from_slice(&b[..n]);
        }
        tx.send(all).unwrap();
    });

    let data: Vec<u8> = (0..SIZE).map(|i| (i % 253) as u8).collect();
    let mut phone = Phone::connect(start_relay());
    let me = SocketAddrV4::new(PHONE_IP, 42000);
    let srv = SocketAddrV4::new(Ipv4Addr::LOCALHOST, sport);
    phone.send_tcp(me, srv, 0, 0, SYN, 65535, &[]);
    let synack = phone.next_tcp();
    let their = synack.seq.wrapping_add(1);
    let mut window = synack.window as usize;
    phone
        .s
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();

    let base = 1u32; // our first data byte's sequence number
    let (mut acked, mut sent) = (0usize, 0usize); // offsets into `data`
    phone.send_tcp(me, srv, base, their, ACK, 65535, &[]);
    let mut min_window = usize::MAX;
    let mut stalls = 0;
    let mut blocked_on_full_buffer = false;
    while acked < SIZE {
        while sent < SIZE && sent - acked < window {
            let n = (SIZE - sent).min(window - (sent - acked)).min(1400);
            phone.send_tcp(
                me,
                srv,
                base + sent as u32,
                their,
                ACK,
                65535,
                &data[sent..sent + n],
            );
            sent += n;
        }
        // Wait for an ACK (or retransmit from `acked` on timeout).
        let mut chunk = [0u8; 65536];
        match phone.s.read(&mut chunk) {
            Ok(n) => {
                assert!(n > 0);
                phone.buf.extend_from_slice(&chunk[..n]);
                while let Framing::Packet(len) = packet::frame(&phone.buf) {
                    if phone.buf.len() < len {
                        break;
                    }
                    let s = phone.next_tcp();
                    let a = s.ack.wrapping_sub(base) as usize;
                    if a > acked && a <= SIZE {
                        acked = a;
                    }
                    window = s.window as usize;
                    min_window = min_window.min(window);
                }
            }
            Err(_) => {
                stalls += 1;
                // Everything the relay advertised is in its buffer, unacked.
                blocked_on_full_buffer |= sent - acked >= window;
                assert!(stalls < 100, "upload stalled at {acked}/{SIZE}");
                sent = acked; // go-back-N retransmit
                if window == 0 {
                    window = 1; // zero-window probe
                }
            }
        }
    }
    phone.send_tcp(me, srv, base + SIZE as u32, their, FIN | ACK, 65535, &[]);
    let got = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("sink never saw EOF");
    assert_eq!(got.len(), SIZE);
    assert!(got == data, "upload corrupted");
    eprintln!("upload: min advertised window {min_window}, {stalls} waits on a full window");
    assert!(
        blocked_on_full_buffer,
        "relay buffer never filled; backpressure path not exercised"
    );
}
