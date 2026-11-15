//! byedpi: the DPI engine on Android and macOS, where Zapret's WinDivert driver does not exist. It is a
//! local SOCKS5 proxy (vendored in third_party/byedpi, MIT) that changes the start of each connection;
//! in the free mode the core sends YouTube, Discord and the user's own sites to it. It needs no root and
//! no administrator rights.

use crate::zapret::Strategy;

/// Where the engine listens, on 127.0.0.1.
pub const PORT: u16 = 10880;

/// What the free mode sends to the engine, besides the user's own sites: YouTube and Discord, as in
/// Zapret's own lists. Spelled out, so it works without geosite.dat (the phone app does not download it).
pub const SITES: [&str; 16] = [
    "youtube.com",
    "youtu.be",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "youtube-nocookie.com",
    "youtubei.googleapis.com",
    "youtubekids.com",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "discord.media",
    "discordcdn.com",
    "discord-attachments-uploads-prd.storage.googleapis.com",
    "dis.gd",
];

/// Shown as the engine's version.
pub const VERSION: &str = "byedpi e268477";

/// What the auto-search tries; it keeps the best score. The provider measured on 12 November 2026 changed
/// its filter from hour to hour and from server to server, and the YouTube app sends a big TLS hello (two
/// TCP segments) to video caches inside the provider (about 6 hops: a fake with TTL 6 can reach them). So
/// most sets are byedpi's auto chains: start with one set and, when a server resets, redirects, breaks TLS
/// or does not connect (`-At,r,s,c`), use the next one for that address. Every group sends one zero-filled
/// fake before UDP (`-a1`), which upsets a filter that reads QUIC. The ideas come from ByeByeDPI's tester and
/// Flowseal's Zapret strategies (fakes as google.com, out-of-band bytes, TLS records, long chains of
/// splits across the hello); `--md5sig` is left out, as Android kernels may not have it.
const STRATEGIES: [(&str, &str); 13] = [
    (
        "Auto",
        "-o1 -a1 -At,r,s,c -d1 -s1+s -r1+s -a1 -At,r,s,c -f-1 -t5 -n google.com -Qr -a1 -At,r,s,c -s1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -a1",
    ),
    ("Out-of-band and TLS record", "-o1 -r1+s -Mh,d,r -a1"),
    ("Out-of-band byte", "-o1 -a1"),
    ("Splits across the hello", "-d1 -s1+s -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -d25+s -s30+s -a1"),
    ("Fake as google.com at the end", "-f-1 -t5 -n google.com -Qr -a1"),
    ("Auto, fakes first", "-f-1 -t5 -n google.com -Qr -a1 -At,r,s,c -o1 -a1 -At,r,s,c -d1 -s1+s -r1+s -a1"),
    ("Fake as google.com, TTL 4", "-f1+s -t4 -n google.com -Qr -a1"),
    ("Fake, TTL 6", "-f1+s -t6 -a1"),
    ("Double disorder", "-d1 -d1+s -a1"),
    ("TLS records", "-r1+s -s1+s -r5+s -a1"),
    ("Out-of-band disorder", "-q1+s -a1"),
    ("Middle of the name", "-s1+sm -d3+sm -r1+s -a1"),
    // for macOS, where byedpi has no fakes
    ("Auto without fakes", "-o1 -a1 -At,r,s,c -d1 -s1+s -r1+s -a1 -At,r,s,c -s1 -d3+s -s6+s -d9+s -s12+s -d15+s -s20+s -a1"),
];

/// The sets this build of the engine runs. byedpi makes fakes (`-f`, `-n`) only on Linux (Android) and
/// Windows: on macOS it refuses to start with them, so those sets are left out there.
pub fn strategies() -> Vec<Strategy> {
    STRATEGIES
        .iter()
        .map(|(name, args)| Strategy { name: name.to_string(), args: args.split(' ').map(String::from).collect() })
        .filter(|s| !cfg!(target_os = "macos") || !uses_fakes(s))
        .collect()
}

fn uses_fakes(s: &Strategy) -> bool {
    s.args.iter().any(|a| a.starts_with("-f") || a == "-n")
}

pub fn names() -> Vec<String> {
    strategies().into_iter().map(|s| s.name).collect()
}

/// The engine's command line for one strategy.
pub fn command_args(strat: &Strategy) -> Vec<String> {
    command_args_on(strat, PORT)
}

/// The same on another port: the search runs a few engines side by side, each on a port of its own.
pub fn command_args_on(strat: &Strategy, port: u16) -> Vec<String> {
    let mut args = vec!["-i".to_string(), "127.0.0.1".into(), "-p".into(), port.to_string()];
    args.extend(strat.args.iter().cloned());
    args
}

/// The proxy URL the probe uses to test a strategy through the engine.
pub fn probe_proxy() -> String {
    format!("socks5h://127.0.0.1:{PORT}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_strategy_becomes_a_command_line() {
        let all = strategies();
        assert_eq!(all.len(), names().len());
        // by name: macOS drops the sets with fakes, so positions differ between platforms
        let oob = all.iter().find(|s| s.name == "Out-of-band byte").unwrap();
        assert_eq!(&command_args(oob)[..], ["-i", "127.0.0.1", "-p", "10880", "-o1", "-a1"]);
        // every group of every set sends the UDP fake
        for st in &all {
            let groups = st.args.iter().filter(|a| *a == "-At,r,s,c").count() + 1;
            assert_eq!(st.args.iter().filter(|a| *a == "-a1").count(), groups, "{}", st.name);
        }
        assert!(all.iter().all(|s| s.args.first().is_some_and(|a| a.starts_with('-'))));
        // macOS keeps the sets without fakes, the auto chain among them
        let no_fakes: Vec<_> = all.iter().filter(|s| !uses_fakes(s)).map(|s| s.name.as_str()).collect();
        assert!(no_fakes.contains(&"Auto without fakes") && no_fakes.contains(&"Splits across the hello"));
        let table: Vec<_> = STRATEGIES.iter().map(|(n, a)| Strategy { name: n.to_string(), args: a.split(' ').map(String::from).collect() }).collect();
        assert!(uses_fakes(&table[0]) && !uses_fakes(&table[1]));
        assert!(!cfg!(target_os = "macos") || all.iter().all(|s| !uses_fakes(s)));
    }
}
