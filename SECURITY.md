# Security · Безопасность

## Reporting a vulnerability · Сообщить об уязвимости

**Do not open a public issue for a vulnerability.** Use GitHub's private reporting:
[Report a vulnerability](https://github.com/TABURELTER/Kometfy/security/advisories/new)
(repository → Security → Advisories → Report a vulnerability).

**Не создавайте публичный issue об уязвимости.** Используйте закрытую форму GitHub по ссылке выше.

PrismRoute is maintained by one person: replies are best-effort. Please include the version, what you did, what happened and what you expected; a diagnostic report (Settings → Diagnostics) helps, but read it first and remove anything private.

Only the newest release is supported: fixes are shipped as a new release, not backported.

## How the app protects you

- **The core's controller listens on `127.0.0.1` only** and requires a random secret generated on first start. The mixed HTTP/SOCKS5 port also listens on `127.0.0.1` only.
- **Updates are signed.** Before anything is installed or opened, the app checks the update's minisign signature against the public key built into it: the installer on Windows, the DMG on macOS and the APK on Android (where Android also refuses an APK signed by anyone else).
- **Cores are verified.** A downloaded mihomo or Xray is checked against the SHA-256 digest GitHub publishes for the release file. If GitHub published no digest, Windows installs the core without that check; macOS refuses to.
- **Administrator rights are asked once, and only where it is safe.** The one-time setup registers a Windows scheduled task that starts the app elevated. It is offered only when the program sits under `%ProgramFiles%`, where a user without administrator rights cannot replace the executable.
- **The system proxy is given back** after a crash or a normal exit, and the cores are tied to the app (Windows job object), so a killed app does not leave a dead proxy or an orphaned TUN adapter behind.
- **Nothing is sent without consent.** Statistics, the network type, subscription names, ad views and network checks each wait for their own switch, all off until you say yes. Your IP, servers, the sites you open, keys and subscription links are never sent. See [the privacy page](docs/PRIVACY.md) for every network request the app makes.

## What you should know

- **"Allow other devices" opens the proxy to your whole network, with no password.** The HTTP/SOCKS5 port then listens on all interfaces, and anyone on that network can send traffic through your server. Turn it on only on a network you trust.
- **Subscription links are stored in plain text** in `profiles/` in the data folder. A link is often a personal key: do not publish that folder.
- **Diagnostic reports are cleaned by patterns**, which can miss something unusual. Read a report before you share it.
- **macOS is a preview** (Apple Silicon, limited testing). Windows is the supported platform. System proxy and TUN there go through a network helper that macOS installs after its own administrator prompt; PrismRoute never asks for your password itself.
- **Android is a beta** (tested on two devices). The core is the official mihomo `linux-arm64` build inside the APK, checked against its published SHA-256 when the APK is built. The app and the core run in the app's sandbox and stay outside their own VPN tunnel.
- **On Android every app on the phone can reach `127.0.0.1`.** The core's controller still needs its secret, but the mixed HTTP/SOCKS5 port on `127.0.0.1` has no password: another app on the same phone could send its traffic through your server that way.
- **TUN mode needs administrator rights**, because it creates a virtual network adapter and changes routes.
- PrismRoute is a client. It does not make an unreliable or logging VPN server safe: the server you connect to still sees your traffic.
