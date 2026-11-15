//! How long the bypass strategy search takes through byedpi, and what each strategy scores: every strategy's
//! engine runs on a port of its own and is probed the way the app's search probes it, `parallel` at a time.
//! Run on a machine without a VPN (the probe would test the VPN instead):
//! `cargo run --release -p prism-connect --example dpi_bench -- <path to byedpi> [parallel]`
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use prism_connect::{byedpi, zapret};

const BASE_PORT: u16 = 10890;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bin = args.get(1).expect("usage: dpi_bench <byedpi> [parallel]").clone();
    let parallel: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let all = byedpi::strategies();
    // the video server a YouTube page names, kept between strategies as the app's search keeps it
    let mut node: Option<String> = None;
    let t = Instant::now();
    for (round, chunk) in all.chunks(parallel).enumerate() {
        let runs = chunk.iter().enumerate().map(|(i, s)| {
            let port = BASE_PORT + i as u16;
            let mut node = node.clone();
            let bin = bin.clone();
            async move {
                let mut child = Command::new(&bin)
                    .args(["-i", "127.0.0.1", "-p", &port.to_string()])
                    .args(&s.args)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("byedpi");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let started = Instant::now();
                let got = zapret::probe(&mut node, Some(&format!("socks5h://127.0.0.1:{port}")), &[]).await;
                let _ = child.kill();
                let _ = child.wait();
                (s.name.clone(), got, started.elapsed(), node)
            }
        });
        for (name, got, took, found) in futures_util::future::join_all(runs).await {
            if node.is_none() {
                node = found;
            }
            println!(
                "round {round}: {name:<32} YouTube {}/{} Discord {}/{}  {:.1}s",
                got.youtube, got.youtube_of, got.discord, got.discord_of, took.as_secs_f32()
            );
        }
    }
    println!("all {} strategies, {parallel} at a time: {:.1}s", all.len(), t.elapsed().as_secs_f32());
}
