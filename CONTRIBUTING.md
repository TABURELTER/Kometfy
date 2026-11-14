# Contributing · Участие

Issues are welcome: bugs, sites that do not open, ideas. Use the forms in Issues; vulnerabilities go through
[SECURITY.md](SECURITY.md), never in public.

Pull requests are welcome too, with one condition. The core is GPL-3.0-only, and the same author also ships it inside
the Kometfy app, whose interface is closed. That is only possible while one person holds the copyright of the whole
core. So by opening a pull request you agree that your change is licensed under GPL-3.0-only **and** that the author of
Kometfy may also use it in Kometfy under other terms. If you do not agree, open an issue describing the change instead.

Before a pull request: `cargo test -p prism-connect --lib` passes, and the change keeps the core free of addresses of
its own (the app supplies them, see `src/builtin.rs`).

---

Issues приветствуются: ошибки, сайты, которые не открываются, идеи. Об уязвимостях — по [SECURITY.md](SECURITY.md),
не публично.

Pull request тоже, с одним условием. Ядро под GPL-3.0-only, и тот же автор встраивает его в приложение Kometfy с
закрытым интерфейсом. Так можно, только пока авторские права на всё ядро у одного человека. Поэтому, открывая pull
request, вы соглашаетесь, что изменение распространяется под GPL-3.0-only **и** что автор Kometfy может использовать
его в Kometfy и на других условиях. Если не согласны, опишите изменение в issue.
