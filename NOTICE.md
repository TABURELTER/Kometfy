# Notice and credits

Copyright (c) 2026 Dmitriy (TABURELTER). Kometfy's network core (`crates/prism-connect`) is free software under the
GNU General Public License, version 3 only (GPL-3.0-only), published at https://github.com/TABURELTER/Kometfy. The
app's interface is proprietary.

## What is not part of this project

- **mihomo** (Clash.Meta core), GPL-3.0, https://github.com/MetaCubeX/mihomo.
  PrismRoute does not bundle it. The app downloads the official release on request (with a SHA-256 check)
  and runs it as a separate program, talking to it over its REST API.
- **Xray-core** (MPL-2.0), https://github.com/XTLS/Xray-core.
  Not bundled either: the app downloads the official release on request (SHA-256 checked) and runs it as a separate
  program on a private loopback port. Its geodata and `wintun.dll` are not used.
- **Clash Verge Rev** (GPL-3.0) was the inspiration for the feature set. No code was taken from it.
- **Zapret**: the engine `winws.exe` by bol-van (https://github.com/bol-van/zapret, MIT) in the Windows build and with the
  strategies and site lists of Flowseal (https://github.com/Flowseal/zapret-discord-youtube, MIT), with the WinDivert driver
  (https://github.com/basil00/WinDivert, LGPL-3.0 or GPL-2.0). Not bundled: the app downloads the official release on
  request, refuses it without a published SHA-256 and checks it against that, and runs `winws.exe` as a separate program.
  Only the arguments of the release's `general*.bat` files are used; the batch files themselves are not run.
- **byedpi** (MIT, Copyright (c) 2024 hufrea), https://github.com/hufrea/byedpi. Its source is vendored unchanged in
  `third_party/byedpi` (with its LICENSE) and built into the Android and macOS apps as the DPI engine of the free mode.
- **tg-ws-proxy** (MIT, Copyright (c) 2026 Flowseal), https://github.com/Flowseal/tg-ws-proxy.
  The Telegram bridge (`crates/prism-connect/src/tgbridge.rs`) is our own Rust code that follows its method:
  a local MTProto proxy that reaches Telegram through its web gateways. Its Cloudflare relay domains are not used.
- The free mode's YouTube list comes from https://github.com/hydraponique/roscomvpn-geosite (through jsDelivr), the
  Discord list and the `category-ads-all` ad list from https://github.com/MetaCubeX/meta-rules-dat; the core downloads them.
- **HaGeZi's DNS blocklists** (GPL-3.0), https://github.com/hagezi/dns-blocklists: with ad blocking on, the app
  downloads the "Multi PRO mini" list at run time and has the core pack it; the list is not shipped with the app.
- Geodata (`geoip.dat`, `geosite.dat`, `Country.mmdb`) comes from
  https://github.com/MetaCubeX/meta-rules-dat and is downloaded by the app.

## Libraries used

- Tauri 2 and its plugins (MIT / Apache-2.0), Svelte 5 and Vite (MIT), Three.js (MIT) for the light on Home.
- Rust crates: tokio, reqwest, serde, serde_yaml, zip, sha2, base64, windows-sys, winreg, rsa, rustls, tokio-tungstenite, aes, ctr and others, each under its own permissive license (MIT / Apache-2.0).
- Fonts: Geologica and JetBrains Mono (SIL Open Font License 1.1) via Fontsource.
- Flag emoji: `country-flag-emoji-polyfill` with Twemoji graphics (CC-BY 4.0, Copyright Twitter, Inc and other contributors).

## Commercial use

The license forbids commercial use. If you want to use the code in a paid product or service,
ask the author first: https://github.com/TABURELTER
