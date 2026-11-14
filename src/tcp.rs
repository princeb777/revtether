//! TCP connection: terminates the phone's TCP connection here and relays the
//! byte stream over a normal OS socket to the real destination.
//!
//! We do not implement retransmission. Instead:
//!  * phone -> network: if we cannot buffer a segment we simply drop it; the
//!    phone's TCP stack will retransmit it. We only ACK bytes once they have
//!    been written to the network socket.
//!  * network -> phone: we NEVER drop data. We only `read()` from the network
//!    socket when the phone's advertised window and the client output buffer
//!    both have room, so every byte we read is guaranteed to be delivered (the
//!    link to the phone is itself a reliable adb TCP stream).

use std::io::{self, Read, Write};
use std::net::Shutdown;

use log::{debug, trace, warn};
use mio::event::Event;
use mio::net::TcpStream;
use mio::{Interest, Registry, Token};

use crate::packet::{self, ACK, FIN, MAX_TCP_PAYLOAD, PSH, RST, SYN, Tcp, TcpOut};
use crate::relay::{ClientOut, FlowKey};

/// How much phone->network data we buffer per connection.
const TO_NET_CAP: usize = 4 * packet::MTU;
const HEADERS: usize = packet::IPV4_HEADER_LEN + packet::TCP_HEADER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Phone sent SYN; we are connecting to the real server.
    SynSent,
    /// Connected upstream and sent SYN+ACK to the phone; waiting for its ACK.
    SynReceived,
    Established,
    /// Phone sent FIN (we shut down our write side upstream); upstream may still send.
    CloseWait,
    /// Both sides closed; waiting for the phone to ACK our FIN.
    LastAck,
    /// Upstream hit EOF, we sent FIN to the phone.
    FinWait1,
    /// Phone ACKed our FIN, waiting for its FIN.
    FinWait2,
    /// Both FINs sent, waiting for the ACK of ours.
    Closing,
}

pub struct TcpConn {
    pub key: FlowKey,
    pub client: usize,
    pub closed: bool,
    stream: TcpStream,
    state: State,
    /// Next sequence number we send to the phone.
    seq: u32,
    /// Next sequence number we expect from the phone *after* what is buffered,
    /// i.e. everything before `ack` has been written to the network.
    ack: u32,
    syn_seq: u32,
    /// Last ACK number received from the phone and its advertised window.
    their_ack: u32,
    their_window: u16,
    /// Seq number of the FIN we sent, once sent.
    fin_seq: Option<u32>,
    /// Phone sent FIN that we will process once `to_net` is flushed.
    fin_pending: bool,
    to_net: Vec<u8>,
    readable: bool,
    writable: bool,
}

impl TcpConn {
    /// Called for the first packet of an unknown TCP flow. Returns `None` if no
    /// connection should be created (a RST has been queued for the phone).
    pub fn open(
        key: FlowKey,
        client: usize,
        tcp: &Tcp,
        registry: &Registry,
        token: Token,
        out: &mut ClientOut,
    ) -> Option<Self> {
        if !tcp.has(SYN) || tcp.has(ACK) {
            // Segment for a connection we don't know (e.g. relay restarted).
            if !tcp.has(RST) {
                let seq = if tcp.has(ACK) { tcp.ack } else { 0 };
                let ack = tcp.seq.wrapping_add(tcp.payload.len() as u32);
                reply(out, &key, seq, ack, RST | ACK, 0);
            }
            return None;
        }

        let reset = |out: &mut ClientOut| {
            reply(out, &key, 0, tcp.seq.wrapping_add(1), RST | ACK, 0);
        };
        let mut stream = match TcpStream::connect(key.upstream()) {
            Ok(s) => s,
            Err(e) => {
                debug!("{key} connect failed: {e}");
                reset(out);
                return None;
            }
        };
        if let Err(e) =
            registry.register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
        {
            warn!("{key} register failed: {e}");
            reset(out);
            return None;
        }
        debug!("{key} open");
        Some(Self {
            key,
            client,
            closed: false,
            stream,
            state: State::SynSent,
            seq: rand::random::<u32>(),
            ack: tcp.seq.wrapping_add(1),
            syn_seq: tcp.seq,
            their_ack: 0,
            their_window: tcp.window,
            fin_seq: None,
            fin_pending: false,
            to_net: Vec::new(),
            readable: false,
            writable: false,
        })
    }

    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    // ----------------------------------------------------------------------
    // Packets from the phone
    // ----------------------------------------------------------------------

    pub fn on_device(&mut self, tcp: &Tcp, out: &mut ClientOut) {
        if tcp.has(SYN) {
            self.on_duplicate_syn(tcp, out);
            return;
        }

        let expected = self.ack.wrapping_add(self.to_net.len() as u32);
        if tcp.seq != expected {
            // Retransmission of something we already have, or a segment after
            // one we dropped. Either way the phone will sort it out.
            trace!(
                "{} ignoring seq {} (expected {expected})",
                self.key, tcp.seq
            );
            return;
        }

        if tcp.has(RST) {
            debug!("{} reset by phone", self.key);
            self.close();
            return;
        }
        if !tcp.has(ACK) {
            return;
        }
        self.their_ack = tcp.ack;
        self.their_window = tcp.window;

        if self.state == State::SynReceived {
            self.state = State::Established;
            trace!("{} established", self.key);
        }

        let mut accepted = true;
        if !tcp.payload.is_empty() {
            let receiving = matches!(
                self.state,
                State::Established | State::FinWait1 | State::FinWait2
            );
            if !receiving {
                accepted = false;
            } else if self.to_net.len() + tcp.payload.len() > TO_NET_CAP {
                debug!(
                    "{} buffer full, dropping {} bytes",
                    self.key,
                    tcp.payload.len()
                );
                accepted = false;
            } else {
                self.to_net.extend_from_slice(tcp.payload);
            }
        }

        if accepted && tcp.has(FIN) && !self.fin_pending {
            self.fin_pending = true;
        }

        if let Some(fin_seq) = self.fin_seq
            && tcp.ack == fin_seq.wrapping_add(1)
        {
            self.on_fin_acked();
            if self.closed {
                return;
            }
        }

        self.pump_write(out);
        if !self.closed && self.fin_pending && self.to_net.is_empty() {
            self.on_fin_received(out);
        }
        if !self.closed {
            // The phone's ACK may have opened its receive window.
            self.pump_read(out);
        }
    }

    fn on_duplicate_syn(&mut self, tcp: &Tcp, out: &mut ClientOut) {
        match self.state {
            State::SynSent => {
                self.syn_seq = tcp.seq;
                self.ack = tcp.seq.wrapping_add(1);
            }
            State::SynReceived if tcp.seq == self.syn_seq => {
                // Our SYN+ACK may not have been seen yet; send it again.
                self.send(out, self.seq.wrapping_sub(1), SYN | ACK);
            }
            _ if tcp.seq == self.syn_seq => {}
            _ => {
                self.send(out, self.seq, RST | ACK);
                self.close();
            }
        }
    }

    /// The phone closed its sending side and all its data reached the network.
    fn on_fin_received(&mut self, out: &mut ClientOut) {
        self.fin_pending = false;
        self.ack = self.ack.wrapping_add(1); // FIN consumes one sequence number
        match self.state {
            State::Established | State::SynReceived => {
                // Half-close: tell upstream we are done sending, keep reading.
                let _ = self.stream.shutdown(Shutdown::Write);
                self.send(out, self.seq, ACK);
                self.state = State::CloseWait;
            }
            State::FinWait1 => {
                self.send(out, self.seq, ACK);
                self.state = State::Closing;
            }
            State::FinWait2 => {
                self.send(out, self.seq, ACK);
                self.close();
            }
            s => warn!("{} FIN in unexpected state {s:?}", self.key),
        }
        trace!("{} state {:?}", self.key, self.state);
    }

    fn on_fin_acked(&mut self) {
        match self.state {
            State::LastAck | State::Closing => self.close(),
            State::FinWait1 => self.state = State::FinWait2,
            _ => {}
        }
    }

    // ----------------------------------------------------------------------
    // Socket readiness
    // ----------------------------------------------------------------------

    pub fn on_event(&mut self, ev: &Event, out: &mut ClientOut) {
        if ev.is_readable() || ev.is_read_closed() || ev.is_error() {
            self.readable = true;
        }
        if ev.is_writable() || ev.is_write_closed() || ev.is_error() {
            self.writable = true;
        }

        if self.state == State::SynSent {
            if !self.writable {
                return;
            }
            match self.stream.take_error() {
                Ok(None) => {}
                Ok(Some(e)) | Err(e) => {
                    debug!("{} connect failed: {e}", self.key);
                    self.send(out, self.seq, RST | ACK);
                    self.close();
                    return;
                }
            }
            match self.stream.peer_addr() {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotConnected => {
                    self.writable = false; // spurious, still connecting
                    return;
                }
                Err(e) => {
                    debug!("{} connect failed: {e}", self.key);
                    self.send(out, self.seq, RST | ACK);
                    self.close();
                    return;
                }
            }
            self.send(out, self.seq, SYN | ACK);
            self.seq = self.seq.wrapping_add(1); // SYN consumes one sequence number
            self.their_ack = self.seq;
            self.state = State::SynReceived;
            trace!("{} upstream connected, SYN+ACK sent", self.key);
            return;
        }

        self.pump_write(out);
        if !self.closed && self.fin_pending && self.to_net.is_empty() {
            self.on_fin_received(out);
        }
        if !self.closed {
            self.pump_read(out);
        }
    }

    /// Phone -> network.
    fn pump_write(&mut self, out: &mut ClientOut) {
        let mut wrote = false;
        while self.writable && !self.to_net.is_empty() {
            match self.stream.write(&self.to_net) {
                Ok(0) => {
                    self.abort(out, "upstream write returned 0");
                    return;
                }
                Ok(n) => {
                    self.to_net.drain(..n);
                    self.ack = self.ack.wrapping_add(n as u32);
                    wrote = true;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => self.writable = false,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.abort(out, &format!("upstream write: {e}"));
                    return;
                }
            }
        }
        // Acknowledge what reached the network (also advertises the new window).
        // A pending FIN is acknowledged by on_fin_received instead.
        if wrote && !(self.fin_pending && self.to_net.is_empty()) {
            self.send(out, self.seq, ACK);
        }
    }

    /// Network -> phone. Only reads what we can deliver.
    pub fn pump_read(&mut self, out: &mut ClientOut) {
        while self.readable && !self.closed {
            if !matches!(self.state, State::Established | State::CloseWait) {
                return;
            }
            let window = self.remaining_window();
            if window == 0 {
                return; // phone's ACK will call us again
            }
            let max = window.min(MAX_TCP_PAYLOAD);
            if !out.has_room(HEADERS + max) {
                out.starved = true; // flushing the client will call us again
                return;
            }
            let start = out.buf.len();
            out.buf.resize(start + HEADERS + max, 0);
            match self.stream.read(&mut out.buf[start + HEADERS..]) {
                Ok(0) => {
                    out.buf.truncate(start);
                    self.readable = false;
                    self.on_upstream_eof(out);
                    return;
                }
                Ok(n) => {
                    out.buf.truncate(start + HEADERS + n);
                    let o = self.tcp_out(self.seq, ACK | PSH);
                    packet::finish_tcp(&mut out.buf[start..], &o);
                    self.seq = self.seq.wrapping_add(n as u32);
                }
                Err(e) => {
                    out.buf.truncate(start);
                    match e.kind() {
                        io::ErrorKind::WouldBlock => self.readable = false,
                        io::ErrorKind::Interrupted => {}
                        _ => {
                            self.abort(out, &format!("upstream read: {e}"));
                            return;
                        }
                    }
                }
            }
        }
    }

    fn on_upstream_eof(&mut self, out: &mut ClientOut) {
        self.send(out, self.seq, FIN | ACK);
        self.fin_seq = Some(self.seq);
        self.seq = self.seq.wrapping_add(1);
        self.state = if self.state == State::CloseWait {
            State::LastAck
        } else {
            State::FinWait1
        };
        trace!("{} upstream EOF, state {:?}", self.key, self.state);
    }

    // ----------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------

    /// Bytes the phone is still willing to receive.
    fn remaining_window(&self) -> usize {
        let in_flight = self.seq.wrapping_sub(self.their_ack);
        (self.their_window as u32).saturating_sub(in_flight) as usize
    }

    /// Our receive window, advertised to the phone.
    fn our_window(&self) -> u16 {
        (TO_NET_CAP - self.to_net.len()).min(u16::MAX as usize) as u16
    }

    fn tcp_out(&self, seq: u32, flags: u8) -> TcpOut {
        TcpOut {
            src: self.key.dst,
            dst: self.key.src,
            seq,
            ack: self.ack,
            flags,
            window: self.our_window(),
        }
    }

    fn send(&self, out: &mut ClientOut, seq: u32, flags: u8) {
        packet::push_tcp(&mut out.buf, &self.tcp_out(seq, flags), &[]);
    }

    fn abort(&mut self, out: &mut ClientOut, why: &str) {
        debug!("{} aborting: {why}", self.key);
        self.send(out, self.seq, RST | ACK);
        self.close();
    }

    pub fn close(&mut self) {
        if !self.closed {
            debug!("{} close", self.key);
            self.closed = true;
        }
    }
}

/// Send a bare TCP segment for a flow that has no connection object.
fn reply(out: &mut ClientOut, key: &FlowKey, seq: u32, ack: u32, flags: u8, window: u16) {
    let o = TcpOut {
        src: key.dst,
        dst: key.src,
        seq,
        ack,
        flags,
        window,
    };
    packet::push_tcp(&mut out.buf, &o, &[]);
}
