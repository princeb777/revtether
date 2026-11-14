//! Driving the phone through `adb`.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use log::{debug, info};

use crate::StartArgs;

const PACKAGE: &str = "com.genymobile.gnirehtet";
const ACTIVITY: &str = "com.genymobile.gnirehtet/.GnirehtetActivity";
/// The app connects to this abstract unix socket on the phone; `adb reverse`
/// forwards it to our TCP port on the PC.
const SOCKET_NAME: &str = "localabstract:gnirehtet";

/// The client app, embedded in the executable so a single file is enough.
/// Official gnirehtet v2.5.1 release (Apache-2.0, by Genymobile).
static EMBEDDED_APK: &[u8] = include_bytes!("../apk/gnirehtet.apk");

/// Which adb to run: $ADB, else one shipped next to our executable (release
/// zips bundle it), else whatever `adb` is in PATH.
fn adb_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("ADB") {
        return p.into();
    }
    let name = if cfg!(windows) { "adb.exe" } else { "adb" };
    if let Ok(exe) = std::env::current_exe() {
        let bundled = exe.with_file_name(name);
        if bundled.is_file() {
            return bundled;
        }
    }
    name.into()
}

fn adb(serial: Option<&str>, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(adb_bin());
    if let Some(s) = serial {
        cmd.args(["-s", s]);
    }
    cmd.args(args);
    debug!(
        "exec: {} {}",
        cmd.get_program().to_string_lossy(),
        args.join(" ")
    );
    let out = cmd
        .output()
        .context("cannot run adb: put it next to revtether, in PATH, or set $ADB")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        bail!(
            "adb {} failed: {}{}",
            args.join(" "),
            stdout.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(stdout)
}

fn is_installed(serial: Option<&str>) -> Result<bool> {
    let out = adb(serial, &["shell", "pm", "list", "packages", PACKAGE])?;
    Ok(out
        .lines()
        .any(|l| l.trim() == format!("package:{PACKAGE}")))
}

/// Fail early with a helpful message if no phone is reachable.
fn check_device(serial: Option<&str>) -> Result<()> {
    let state = adb(serial, &["get-state"]).map(|s| s.trim().to_string());
    match state.as_deref() {
        Ok("device") => Ok(()),
        Ok(other) => {
            bail!("phone is in state '{other}' (accept the USB debugging prompt on the phone)")
        }
        Err(e) => bail!(
            "no phone found: connect it by USB, enable USB debugging and accept the prompt on the phone \
             (if several are connected, pick one with -s SERIAL)\n  {e:#}"
        ),
    }
}

/// Install the client app. Uses $REVTETHER_APK if set, otherwise the APK
/// embedded in this executable (written to a temporary file for adb).
pub fn install(serial: Option<&str>) -> Result<()> {
    if let Some(p) = std::env::var_os("REVTETHER_APK") {
        let p = PathBuf::from(p);
        info!("Installing client app from {}...", p.display());
        adb(serial, &["install", "-r", &p.to_string_lossy()])?;
        return Ok(());
    }
    let tmp = std::env::temp_dir().join(format!("revtether-gnirehtet-{}.apk", std::process::id()));
    std::fs::write(&tmp, EMBEDDED_APK)
        .with_context(|| format!("cannot write {}", tmp.display()))?;
    info!("Installing client app on the phone (confirm on the phone if asked)...");
    let result = adb(serial, &["install", "-r", &tmp.to_string_lossy()]);
    let _ = std::fs::remove_file(&tmp);
    result?;
    Ok(())
}

pub fn uninstall(serial: Option<&str>) -> Result<()> {
    adb(serial, &["uninstall", PACKAGE])?;
    Ok(())
}

pub fn start(a: &StartArgs) -> Result<()> {
    let serial = a.device.serial.as_deref();
    check_device(serial)?;
    if is_installed(serial)? {
        info!("Client app already installed");
    } else {
        install(serial)?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    info!("Setting up adb reverse {SOCKET_NAME} -> tcp:{}", a.port);
    adb(
        serial,
        &["reverse", SOCKET_NAME, &format!("tcp:{}", a.port)],
    )?;

    let mut args = vec![
        "shell",
        "am",
        "start",
        "-a",
        "com.genymobile.gnirehtet.START",
        "-n",
        ACTIVITY,
    ];
    // Default to the PC's own DNS servers: many networks block public
    // resolvers like 8.8.8.8 (the app's built-in default).
    let dns = a.dns.clone().or_else(host_dns);
    if let Some(d) = &dns {
        info!("Phone DNS: {d}");
        args.extend(["--esa", "dnsServers", d]);
    }
    if let Some(r) = &a.routes {
        args.extend(["--esa", "routes", r]);
    }
    info!("Starting the VPN on the phone (accept the dialog on first use)");
    adb(serial, &args)?;
    Ok(())
}

/// IPv4 nameservers the PC itself uses, comma-separated. Loopback stubs
/// (e.g. systemd-resolved's 127.0.0.53) are unreachable from the phone, so
/// fall back to systemd's list of real upstream servers.
#[cfg(not(windows))]
fn host_dns() -> Option<String> {
    for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let servers = parse_nameservers(&text);
        if !servers.is_empty() {
            return Some(servers.join(","));
        }
    }
    None
}

/// Windows: DNS servers of the network adapters that are up and have a
/// default gateway (i.e. the ones actually used for internet access).
#[cfg(windows)]
fn host_dns() -> Option<String> {
    let script = "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } \
                  | ForEach-Object { $_.DNSServer.ServerAddresses }";
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let servers = parse_ip_list(&text);
    (!servers.is_empty()).then(|| servers.join(","))
}

/// Usable IPv4 addresses from whitespace-separated text, deduplicated.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_ip_list(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for ip in text
        .split_whitespace()
        .filter_map(|w| w.parse::<std::net::Ipv4Addr>().ok())
    {
        if !ip.is_loopback() && !ip.is_unspecified() && !v.contains(&ip.to_string()) {
            v.push(ip.to_string());
        }
    }
    v
}

#[cfg_attr(windows, allow(dead_code))]
fn parse_nameservers(resolv_conf: &str) -> Vec<String> {
    resolv_conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|s| s.trim().parse::<std::net::Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .collect()
}

pub fn stop(serial: Option<&str>) -> Result<()> {
    adb(
        serial,
        &[
            "shell",
            "am",
            "start",
            "-a",
            "com.genymobile.gnirehtet.STOP",
            "-n",
            ACTIVITY,
        ],
    )?;
    let _ = adb(serial, &["reverse", "--remove", SOCKET_NAME]);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_resolv_conf() {
        let s = "# comment\nnameserver 127.0.0.53\nnameserver 10.1.2.3\nnameserver fe80::1\nsearch lan\nnameserver 9.9.9.9\n";
        assert_eq!(super::parse_nameservers(s), ["10.1.2.3", "9.9.9.9"]);
    }

    #[test]
    fn parses_powershell_dns_list() {
        let s = "10.1.2.3\r\nfec0:0:0:ffff::1\r\n8.8.8.8\r\n10.1.2.3\r\n";
        assert_eq!(super::parse_ip_list(s), ["10.1.2.3", "8.8.8.8"]);
    }

    #[test]
    fn embedded_apk_is_an_apk() {
        assert!(
            super::EMBEDDED_APK.starts_with(b"PK"),
            "APK must be a zip archive"
        );
    }
}
