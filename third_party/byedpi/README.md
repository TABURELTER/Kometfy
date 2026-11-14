# byedpi (vendored)

Source of [hufrea/byedpi](https://github.com/hufrea/byedpi), commit `e268477` (4 November 2026),
MIT (see LICENSE). Kometfy runs it as the DPI engine on Android and macOS, where Zapret's WinDivert
driver does not exist: a local SOCKS5 proxy that changes the start of YouTube and Discord connections
(fake packets with a low TTL, splits, TLS records). The core routes those sites to it in the free mode.

Only the files the Unix build needs are kept (`win_service.*` is Windows only and left out; `main.c`
includes it under `_WIN32` only). The code is not changed.

Built by:
- Android: `node scripts/android-byedpi.mjs` (NDK clang, into `jniLibs/arm64-v8a/libbyedpi.so`);
- macOS: `app/scripts/build-macos-helper-preview.sh` (clang, bundled as `Contents/MacOS/byedpi`).
