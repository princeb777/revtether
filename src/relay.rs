//! The relay server: a single-threaded mio event loop.
//!
//! ```text
//!  phone apps ──► Android VpnService (tun) ──► gnirehtet app
//!       ──► local socket "gnirehtet" ──adb reverse──► 127.0.0.1:31416 (this)
//!       ──► per-flow OS sockets ──► Internet
//! ```
//!
//! Every phone (a "client") is one TCP connection carrying raw IPv4 packets
//! back to back. For each (protocol, src, dst) flow we open a real socket on
//! the PC and translate between packets and socket data.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{debug, info, trace, warn};
use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};
use slab::Slab;

use crate::packet::{self, Framing, Ipv4, PROTO_TCP, PROTO_UDP, Tcp, Udp};
use crate::tcp::TcpConn;
use crate::udp::UdpConn;

/// Soft cap on bytes queued towards one phone. Connections stop reading from
/// the network when it is full (control packets may still exceed it slightly).
const CLIENT_OUT_CAP: usize = 512 * 1024;

/// 10.0.2.2 on the phone means "the PC's localhost" (same trick as the Android emulator).
const LOCALHOST_ALIAS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

const LISTENER: Token = Token(usize::MAX);

/// Test-only: how many times connections were resumed after the client
/// output buffer was full (proves the backpressure path ran).
#[cfg(test)]
pub static RESUMED_AFTER_STARVATION: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn client_token(i: usize) -> Token {
    Token(i << 1)
}
fn conn_token(i: usize) -> Token {
    Token((i << 1) | 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    /// Phone side (10.0.0.2:port).
    pub src: SocketAddrV4,
    /// Destination as the phone sees it.
    pub dst: SocketAddrV4,
}

impl FlowKey {
    /// Where we actually connect on the PC side.
    pub fn upstream(&self) -> SocketAddr {
        if *self.dst.ip() == LOCALHOST_ALIAS {
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.dst.port()).into()
        } else {
            self.dst.into()
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let p = if self.proto == PROTO_TCP {
            "TCP"
        } else {
            "UDP"
        };
        write!(f, "[{p} {} -> {}]", self.src, self.dst)
    }
}

/// Bytes waiting to be written to the phone. Connections append whole IPv4
/// packets directly into `buf`.
pub struct ClientOut {
    pub buf: Vec<u8>,
    pos: usize,
    /// Set when some connection stopped reading because we were full.
    pub starved: bool,
}

impl ClientOut {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64 * 1024),
            pos: 0,
            starved: false,
        }
    }
    pub fn pending(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn has_room(&self, n: usize) -> bool {
        self.pending() + n <= CLIENT_OUT_CAP
    }
    fn compact(&mut self) {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos > CLIENT_OUT_CAP / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

struct Client {
    id: u32,
    stream: TcpStream,
    inbuf: Vec<u8>,
    out: ClientOut,
    writable: bool,
    router: HashMap<FlowKey, usize>,
}

enum Conn {
    Tcp(TcpConn),
    Udp(UdpConn),
}

impl Conn {
    fn key(&self) -> &FlowKey {
        match self {
            Conn::Tcp(c) => &c.key,
            Conn::Udp(c) => &c.key,
        }
    }
    fn client(&self) -> usize {
        match self {
            Conn::Tcp(c) => c.client,
            Conn::Udp(c) => c.client,
        }
    }
    fn is_closed(&self) -> bool {
        match self {
            Conn::Tcp(c) => c.closed,
            Conn::Udp(c) => c.closed,
        }
    }
    fn pump_read(&mut self, out: &mut ClientOut) {
        match self {
            Conn::Tcp(c) => c.pump_read(out),
            Conn::Udp(c) => c.pump_read(out),
        }
    }
}

pub struct Relay {
    poll: Poll,
    listener: TcpListener,
    clients: Slab<Client>,
    conns: Slab<Conn>,
    next_client_id: u32,
}

impl Relay {
    pub fn bind(port: u16) -> Result<Self> {
        let poll = Poll::new()?;
        // Loopback only: adb reverse connects from localhost, and binding
        // wider would expose an open proxy to the LAN.
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut listener =
            TcpListener::bind(addr).with_context(|| format!("cannot listen on {addr}"))?;
        poll.registry()
            .register(&mut listener, LISTENER, Interest::READABLE)?;
        info!("Relay server listening on {addr}");
        Ok(Self {
            poll,
            listener,
            clients: Slab::new(),
            conns: Slab::new(),
            next_client_id: 0,
        })
    }

    #[cfg(test)]
    pub fn local_port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    pub fn run(&mut self) -> Result<()> {
        let mut events = Events::with_capacity(1024);
        let mut last_cleanup = Instant::now();
        loop {
            match self.poll.poll(&mut events, Some(Duration::from_secs(30))) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
            for ev in events.iter() {
                let t = ev.token();
                if t == LISTENER {
                    self.accept_clients();
                } else if t.0 & 1 == 0 {
                    self.on_client_event(t.0 >> 1, ev);
                } else {
                    self.on_conn_event(t.0 >> 1, ev);
                }
            }
            if last_cleanup.elapsed() >= Duration::from_secs(60) {
                self.remove_expired_udp();
                last_cleanup = Instant::now();
            }
        }
    }

    // ----------------------------------------------------------------------
    // Clients (phones)
    // ----------------------------------------------------------------------

    fn accept_clients(&mut self) {
        loop {
            let (mut stream, addr) = match self.listener.accept() {
                Ok(x) => x,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) => {
                    warn!("accept: {e}");
                    return;
                }
            };
            let entry = self.clients.vacant_entry();
            let token = client_token(entry.key());
            if let Err(e) = self.poll.registry().register(
                &mut stream,
                token,
                Interest::READABLE | Interest::WRITABLE,
            ) {
                warn!("register client: {e}");
                continue;
            }
            let id = self.next_client_id;
            self.next_client_id = self.next_client_id.wrapping_add(1);
            let _ = stream.set_nodelay(true);
            let mut out = ClientOut::new();
            // Handshake: the app waits for a 4-byte big-endian client id
            // before it considers itself connected.
            out.buf.extend_from_slice(&id.to_be_bytes());
            entry.insert(Client {
                id,
                stream,
                inbuf: Vec::new(),
                out,
                writable: false,
                router: HashMap::new(),
            });
            info!("Client #{id} connected ({addr})");
        }
    }

    fn on_client_event(&mut self, ci: usize, ev: &Event) {
        if !self.clients.contains(ci) {
            return;
        }
        if ev.is_writable() {
            self.clients[ci].writable = true;
        }
        if (ev.is_readable() || ev.is_read_closed() || ev.is_error()) && !self.read_from_client(ci)
        {
            return;
        }
        self.service_client(ci);
    }

    /// Returns false if the client was closed.
    fn read_from_client(&mut self, ci: usize) -> bool {
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let c = &mut self.clients[ci];
            match c.stream.read(&mut chunk) {
                Ok(0) => {
                    self.close_client(ci, "disconnected");
                    return false;
                }
                Ok(n) => {
                    c.inbuf.extend_from_slice(&chunk[..n]);
                    if !self.process_inbuf(ci) {
                        return false;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return true,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.close_client(ci, &format!("read error: {e}"));
                    return false;
                }
            }
        }
    }

    /// Split the byte stream into packets and route each one.
    fn process_inbuf(&mut self, ci: usize) -> bool {
        let inbuf = std::mem::take(&mut self.clients[ci].inbuf);
        let mut off = 0;
        loop {
            match packet::frame(&inbuf[off..]) {
                Framing::NeedMore => break,
                Framing::Invalid => {
                    self.close_client(ci, "invalid packet stream");
                    return false;
                }
                Framing::Packet(n) => {
                    if inbuf.len() - off < n {
                        break;
                    }
                    self.route_packet(ci, &inbuf[off..off + n]);
                    off += n;
                }
            }
        }
        let mut inbuf = inbuf;
        inbuf.drain(..off);
        self.clients[ci].inbuf = inbuf;
        true
    }

    /// Write queued packets to the phone; then let connections that were
    /// blocked on a full buffer read more from the network.
    fn service_client(&mut self, ci: usize) {
        loop {
            let c = &mut self.clients[ci];
            while c.writable && c.out.pending() > 0 {
                match c.stream.write(&c.out.buf[c.out.pos..]) {
                    Ok(n) => c.out.pos += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.writable = false,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        self.close_client(ci, &format!("write error: {e}"));
                        return;
                    }
                }
            }
            c.out.compact();
            if !c.out.starved || !c.out.has_room(packet::MTU) {
                return;
            }
            c.out.starved = false;
            #[cfg(test)]
            RESUMED_AFTER_STARVATION.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let before = c.out.pending();
            let keys: Vec<usize> = c.router.values().copied().collect();
            for k in keys {
                let (c, conn) = (&mut self.clients[ci], &mut self.conns[k]);
                conn.pump_read(&mut c.out);
                if conn.is_closed() {
                    self.remove_conn(k);
                }
            }
            if self.clients[ci].out.pending() == before {
                return;
            }
        }
    }

    fn close_client(&mut self, ci: usize, why: &str) {
        let mut c = self.clients.remove(ci);
        info!("Client #{} {why}", c.id);
        let _ = self.poll.registry().deregister(&mut c.stream);
        for (_, k) in c.router.drain() {
            self.drop_conn(k);
        }
    }

    // ----------------------------------------------------------------------
    // Routing phone packets to connections
    // ----------------------------------------------------------------------

    fn route_packet(&mut self, ci: usize, raw: &[u8]) {
        let Some(ip) = Ipv4::parse(raw) else {
            trace!("dropping non-IPv4 / malformed packet");
            return;
        };
        match ip.protocol {
            PROTO_TCP => {
                let Some(tcp) = Tcp::parse(ip.transport) else {
                    return;
                };
                let key = FlowKey {
                    proto: PROTO_TCP,
                    src: SocketAddrV4::new(ip.src, tcp.src_port),
                    dst: SocketAddrV4::new(ip.dst, tcp.dst_port),
                };
                let client = &mut self.clients[ci];
                if let Some(&k) = client.router.get(&key) {
                    if let Conn::Tcp(conn) = &mut self.conns[k] {
                        conn.on_device(&tcp, &mut client.out);
                        if conn.closed {
                            self.remove_conn(k);
                        }
                    }
                } else {
                    let entry = self.conns.vacant_entry();
                    let k = entry.key();
                    if let Some(conn) = TcpConn::open(
                        key,
                        ci,
                        &tcp,
                        self.poll.registry(),
                        conn_token(k),
                        &mut client.out,
                    ) {
                        entry.insert(Conn::Tcp(conn));
                        client.router.insert(key, k);
                    }
                }
            }
            PROTO_UDP => {
                let Some(udp) = Udp::parse(ip.transport) else {
                    return;
                };
                let key = FlowKey {
                    proto: PROTO_UDP,
                    src: SocketAddrV4::new(ip.src, udp.src_port),
                    dst: SocketAddrV4::new(ip.dst, udp.dst_port),
                };
                let client = &mut self.clients[ci];
                let k = match client.router.get(&key) {
                    Some(&k) => k,
                    None => {
                        let entry = self.conns.vacant_entry();
                        let k = entry.key();
                        match UdpConn::open(key, ci, self.poll.registry(), conn_token(k)) {
                            Ok(conn) => {
                                entry.insert(Conn::Udp(conn));
                                client.router.insert(key, k);
                                k
                            }
                            Err(e) => {
                                debug!("{key} cannot open: {e}");
                                return;
                            }
                        }
                    }
                };
                if let Conn::Udp(conn) = &mut self.conns[k] {
                    conn.on_device(udp.payload);
                }
            }
            p => trace!("dropping packet with protocol {p} (only TCP/UDP are relayed)"),
        }
    }

    fn on_conn_event(&mut self, k: usize, ev: &Event) {
        let Some(conn) = self.conns.get_mut(k) else {
            return;
        };
        let ci = conn.client();
        let out = &mut self.clients[ci].out;
        match conn {
            Conn::Tcp(c) => c.on_event(ev, out),
            Conn::Udp(c) => c.on_readable(out),
        }
        if conn.is_closed() {
            self.remove_conn(k);
        }
        self.service_client(ci);
    }

    /// Remove a connection and unlink it from its client's router.
    fn remove_conn(&mut self, k: usize) {
        let key = *self.conns[k].key();
        let ci = self.conns[k].client();
        if let Some(c) = self.clients.get_mut(ci) {
            c.router.remove(&key);
        }
        self.drop_conn(k);
    }

    fn drop_conn(&mut self, k: usize) {
        let reg = self.poll.registry();
        match self.conns.remove(k) {
            Conn::Tcp(mut c) => {
                let _ = reg.deregister(c.stream_mut());
            }
            Conn::Udp(mut c) => {
                debug!("{} close", c.key);
                let _ = reg.deregister(c.socket_mut());
            }
        }
    }

    fn remove_expired_udp(&mut self) {
        let now = Instant::now();
        let expired: Vec<usize> = self
            .conns
            .iter()
            .filter(|(_, c)| matches!(c, Conn::Udp(u) if u.is_expired(now)))
            .map(|(k, _)| k)
            .collect();
        for k in expired {
            self.remove_conn(k);
        }
        debug!(
            "{} clients, {} connections",
            self.clients.len(),
            self.conns.len()
        );
    }
}
