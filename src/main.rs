//! revtether: reverse tethering for Android over USB (adb), in Rust.
//!
//! Speaks the same wire protocol as Genymobile's gnirehtet, so it drives the
//! gnirehtet Android client app (apk/gnirehtet.apk).

mod adb;
#[cfg(test)]
mod e2e_tests;
mod packet;
mod relay;
mod tcp;
mod udp;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info};

const DEFAULT_PORT: u16 = 31416;

#[derive(Parser)]
#[command(
    version,
    about = "Share your PC's internet with an Android phone over USB (adb)",
    after_help = "With no command, `revtether` behaves like `revtether run`."
)]
struct Cli {
    /// More logs (-v: per-connection, -vv: per-packet)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Args, Clone)]
struct DeviceArgs {
    /// Device serial (needed only if several devices are connected)
    #[arg(short, long)]
    serial: Option<String>,
}

#[derive(clap::Args, Clone)]
struct StartArgs {
    #[command(flatten)]
    device: DeviceArgs,
    /// DNS servers for the phone, comma-separated (default: the PC's own DNS servers)
    #[arg(short, long)]
    dns: Option<String>,
    /// Only route these CIDRs through the PC, comma-separated (default 0.0.0.0/0)
    #[arg(short, long)]
    routes: Option<String>,
    /// Local relay port
    #[arg(short, long, default_value_t = DEFAULT_PORT)]
    port: u16,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install the client if needed, set up the tunnel, start the VPN and run the relay (Ctrl+C stops everything)
    Run(StartArgs),
    /// Only run the relay server
    Relay {
        #[arg(short, long, default_value_t = DEFAULT_PORT)]
        port: u16,
    },
    /// Install the client app on the phone
    Install(DeviceArgs),
    /// Uninstall the client app
    Uninstall(DeviceArgs),
    /// Set up `adb reverse` and start the VPN on the phone (relay must run separately)
    Start(StartArgs),
    /// Stop the VPN on the phone
    Stop(DeviceArgs),
}

fn main() {
    let cli = Cli::parse();
    let level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format_target(false)
        .init();

    let cmd = cli.cmd.unwrap_or(Cmd::Run(StartArgs {
        device: DeviceArgs { serial: None },
        dns: None,
        routes: None,
        port: DEFAULT_PORT,
    }));
    if let Err(e) = dispatch(cmd) {
        error!("{e:#}");
        std::process::exit(1);
    }
}

fn dispatch(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Run(a) => {
            // Bind first so the phone finds the relay ready when it connects.
            let mut relay = relay::Relay::bind(a.port)?;
            adb::start(&a)?;
            let serial = a.device.serial.clone();
            ctrlc::set_handler(move || {
                info!("Stopping...");
                let _ = adb::stop(serial.as_deref());
                std::process::exit(0);
            })?;
            relay.run()
        }
        Cmd::Relay { port } => relay::Relay::bind(port)?.run(),
        Cmd::Install(d) => adb::install(d.serial.as_deref()),
        Cmd::Uninstall(d) => adb::uninstall(d.serial.as_deref()),
        Cmd::Start(a) => adb::start(&a),
        Cmd::Stop(d) => adb::stop(d.serial.as_deref()),
    }
}
