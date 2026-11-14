# revtether

Reverse tethering over USB: an Android phone uses your **PC's** internet
connection through `adb`, with no root on either side. Works on Linux and Windows.

This is a Rust rewrite of the relay server from
[Genymobile/gnirehtet](https://github.com/Genymobile/gnirehtet). It speaks the
same protocol and drives the unmodified gnirehtet Android app, which is
embedded in the executable.

## Download

Get the zip for your system from [Releases](https://github.com/princeb777/revtether/releases/latest).
Each zip contains:
- `revtether`: the relay, with the phone app built in
- Google's official `adb`
- `gnirehtet.apk`: the phone app, also as a separate file
- the license files

## Quick start

1. On the phone, enable **Developer options → USB debugging**. Connect the phone
   by USB and accept the *Allow USB debugging?* prompt.
2. Start revtether:
   - **Windows:** extract the zip and double-click **`revtether-run.cmd`**.
   - **Linux:** extract the zip, then run:
     ```bash
     ./revtether
     ```
3. The first time, tap **OK** on the VPN request on the phone. A key icon in the
   status bar means the phone is online through the PC.

To stop, press **Ctrl+C** or close the window. This also turns the VPN off.

What `revtether` (= `revtether run`) does:
1. Checks that a phone is connected.
2. Installs the embedded app if it isn't installed yet.
3. Runs `adb reverse localabstract:gnirehtet tcp:31416`.
4. Starts the VPN with the PC's own DNS servers.
5. Runs the relay.

### Linux notes
- If `adb devices` shows `no permissions`, install your distro's Android udev
  rules (Arch: `android-udev`, Debian/Ubuntu: `android-sdk-platform-tools-common`),
  then replug the phone.
- revtether uses the `adb` next to it. Otherwise it uses `adb` from `PATH`, or
  `$ADB` if set.

## Commands

| command | does |
|---|---|
| `run [-d DNS] [-r CIDRS] [-s SERIAL] [-p PORT]` | everything above (default command) |
| `relay` | relay server only |
| `start` / `stop` | start/stop the VPN on the phone |
| `install` / `uninstall` | manage the phone app (`$REVTETHER_APK` overrides the embedded APK) |
| `-v` / `-vv` | per-connection / per-packet logs |

From the phone, `10.0.2.2` reaches the PC's `localhost`.

## Building from source

```bash
cargo build --release
cargo test
```

The release binary is at `target/release/revtether`. Pushing a tag `vX.Y.Z`
makes GitHub Actions do the following:
1. Test on Linux and Windows.
2. Build a static Linux (musl) binary and a Windows binary.
3. Bundle each with Google's platform-tools `adb`.
4. Publish both zips as a release.

## How it works

```
 Phone                                         PC
 ┌───────────────────────────────┐            ┌──────────────────────────────────┐
 │ apps ─► kernel ─► tun (VPN)   │            │ revtether relay (127.0.0.1:31416) │
 │                    │ raw IPv4 │            │   ├─ parses IPv4/TCP/UDP          │
 │ gnirehtet app (VpnService)    │   USB      │   ├─ one real socket per flow ──► Internet
 │   └─ localabstract:gnirehtet ─┼── adb ────►│   └─ forges reply packets         │
 └───────────────────────────────┘  reverse   └──────────────────────────────────┘
```

1. **Phone side.** The app registers an Android `VpnService` with address
   `10.0.0.2/32`, route `0.0.0.0/0`, DNS `8.8.8.8` and MTU 16384. All IPv4
   traffic from every app now comes out of a tun file descriptor as raw packets.
   The app copies them, back to back, into a unix socket named `gnirehtet`.
   It also writes every packet it receives from that socket back into the tun.
2. **The tunnel.** `adb reverse localabstract:gnirehtet tcp:31416` makes that
   socket land on the PC's `127.0.0.1:31416`, carried over USB.
3. **Handshake.** The relay immediately writes a 4-byte big-endian client id.
   The app waits for it, which proves the relay is really running and not just
   the adb forward.
4. **The relay acts as a user-space NAT.** It splits the byte stream into
   packets using the IPv4 *total length* field. Then it looks up the flow
   `(protocol, src ip:port, dst ip:port)`:
   - **UDP** (`src/udp.rs`): it opens a connected UDP socket to the destination
     and relays each datagram as-is. Replies are wrapped in new IPv4/UDP headers
     with source and destination swapped. Flows expire after 2 minutes idle.
     DNS goes through this path.
   - **TCP** (`src/tcp.rs`): the hard part. The relay *terminates* the phone's
     TCP connection and opens a normal socket upstream, so it must act as a TCP
     endpoint itself:
     - SYN → non-blocking `connect()` → SYN+ACK on success, or RST on failure.
     - Phone data is ACKed only once it has been written upstream. If our buffer
       is full we drop the segment, and the phone retransmits it.
     - Network data is **never dropped**. We only `read()` upstream when the
       phone's advertised window *and* our output buffer have room. Because the
       USB link is itself reliable TCP, that is enough. No retransmission
       timers needed.
     - FIN handling: when the phone sends FIN we `shutdown(Write)` upstream (a
       half-close), and when upstream reaches EOF we send FIN to the phone.
   - ICMP and anything else is dropped, so `ping` does not work through the tunnel.
5. **Checksums** (`src/packet.rs`) must be exact. The phone silently discards
   packets with a bad IPv4 or TCP/UDP checksum.

The relay is a single-threaded `mio` event loop (`src/relay.rs`), like the
original. Edge-triggered readiness is tracked per socket, so a connection
paused by a full window resumes when the phone's ACK arrives or when the USB
buffer drains.

## Tests

`cargo test` runs the checksum vectors (ported from gnirehtet's tests) and
end-to-end tests. In those, a fake "phone" sends hand-built IP packets to the
relay, which talks to local servers:
- handshake, echo and FIN teardown
- a 1 MB download under a 6000-byte window
- connection refused → RST
- UDP
- 100 parallel downloads to a phone that reads slowly, which forces the output
  buffer to fill and connections to pause and resume, with no byte lost
- a 24 MB upload to a server that starts reading late, which fills the relay's
  buffer and makes the phone wait on the advertised window

## Checking it really works on the phone

`ping` is not relayed (ICMP), so it proves nothing. Instead, turn off Wi-Fi
and mobile data, then browse, or open a "what is my IP" page and compare it
with the PC's public IP.
