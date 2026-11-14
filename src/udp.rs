//! UDP "connection": one connected OS UDP socket per (src, dst) flow.
//! Datagrams are relayed 1:1 in both directions; nothing to acknowledge.

use std::io;
use std::time::{Duration, Instant};

use log::{debug, trace};
use mio::net::UdpSocket;
use mio::{Interest, Registry, Token};

use crate::packet::{self, IPV4_HEADER_LEN, MAX_UDP_PAYLOAD, UDP_HEADER_LEN};
use crate::relay::{ClientOut, FlowKey};

/// UDP flows are never "closed"; forget them after this much inactivity.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const HEADERS: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;

pub struct UdpConn {
    pub key: FlowKey,
    pub client: usize,
    pub closed: bool,
    socket: UdpSocket,
    last_active: Instant,
    readable: bool,
}

impl UdpConn {
    pub fn open(
        key: FlowKey,
        client: usize,
        registry: &Registry,
        token: Token,
    ) -> io::Result<Self> {
        let mut socket = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
        socket.connect(key.upstream())?;
        registry.register(&mut socket, token, Interest::READABLE)?;
        debug!("{key} open");
        Ok(Self {
            key,
            client,
            closed: false,
            socket,
            last_active: Instant::now(),
            readable: false,
        })
    }

    pub fn socket_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_active) > IDLE_TIMEOUT
    }

    /// Phone -> network.
    pub fn on_device(&mut self, payload: &[u8]) {
        self.last_active = Instant::now();
        match self.socket.send(payload) {
            Ok(_) => {}
            // UDP is allowed to lose packets; don't buffer.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!("{} send would block, dropped", self.key)
            }
            Err(e) => debug!("{} send: {e}", self.key),
        }
    }

    pub fn on_readable(&mut self, out: &mut ClientOut) {
        self.readable = true;
        self.pump_read(out);
    }

    /// Network -> phone.
    pub fn pump_read(&mut self, out: &mut ClientOut) {
        while self.readable {
            // +1 so we can detect datagrams that would not fit in the phone's MTU.
            let room = HEADERS + MAX_UDP_PAYLOAD + 1;
            if !out.has_room(room) {
                out.starved = true;
                return;
            }
            let start = out.buf.len();
            out.buf.resize(start + room, 0);
            match self.socket.recv(&mut out.buf[start + HEADERS..]) {
                Ok(n) if n > MAX_UDP_PAYLOAD => {
                    out.buf.truncate(start);
                    debug!("{} datagram too large ({n} bytes), dropped", self.key);
                }
                Ok(n) => {
                    out.buf.truncate(start + HEADERS + n);
                    packet::finish_udp(&mut out.buf[start..], self.key.dst, self.key.src);
                    self.last_active = Instant::now();
                }
                Err(e) => {
                    out.buf.truncate(start);
                    match e.kind() {
                        io::ErrorKind::WouldBlock => self.readable = false,
                        io::ErrorKind::Interrupted => {}
                        // e.g. ECONNREFUSED from an ICMP port-unreachable: reported
                        // once by the kernel and not fatal; keep draining.
                        _ => debug!("{} recv: {e}", self.key),
                    }
                }
            }
        }
    }
}
