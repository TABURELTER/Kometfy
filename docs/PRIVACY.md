# Конфиденциальность PrismRoute · Privacy

*English version below.*

PrismRoute (Kometfy) — клиент для вашего собственного VPN или прокси. Учётных записей у проекта нет. У него есть свой сервер (бэкенд Kometfy на Cloudflare; его адрес в приложении зашифрован). С него программа берёт удалённые настройки и рекламу; запрос этот ничего о вас не сообщает. Статистику и итоги проверок сети программа отправляет туда **только после выбора на экране знакомства**. При первой установке пункты на экране предложены включёнными: можно выключить любой или продолжить без них; выбор сохраняется при завершении знакомства. Ответ можно поменять в любой момент: Настройки → Конфиденциальность. Ниже — всё, к чему программа обращается, и всё, что она хранит на вашем ПК.

## Куда программа обращается по сети

| Что | Когда | Куда | Как отключить |
| --- | --- | --- | --- |
| Проверка обновлений | при запуске и раз в несколько часов | файл `latest.json`: `kometfy.com/latest.json`, если не ответил, — `github.com/TABURELTER/Kometfy/releases` | Настройки → Обновления → «Проверять автоматически» |
| Версии и загрузка ядер mihomo и Xray | только когда вы нажимаете «Скачать» или «Проверить обновления» ядра | `api.github.com` (репозитории MetaCubeX/mihomo и XTLS/Xray-core), файлы релизов; базы geoip/geosite — `github.com/MetaCubeX/meta-rules-dat` | не нажимать |
| Ваша подписка | когда вы добавляете или обновляете подписку | адрес, который вы сами ввели | не добавлять подписку |
| Определение внешнего адреса | при открытии главного экрана | `ipwho.is` (при подключении — через ваш прокси, поэтому показывает адрес выхода) | Настройки → Подключение → «Показывать мой адрес на главной» |
| Проверка задержки серверов | когда вы запускаете проверку | `www.gstatic.com/generate_204` через выбранный сервер (адрес меняется в настройках) | не запускать проверку |
| DNS-запросы при подключении | всегда, пока ядро работает | по умолчанию DNS-over-HTTPS `dns.google` и `1.1.1.1`; меняется в Настройки → DNS | Настройки → DNS |
| Запасной поиск адреса | только если системный DNS не дал адреса сервера Kometfy или шлюза Telegram (так бывает с AdGuard DNS) | имя этого сервера или шлюза — и только оно — уходит в DNS-over-HTTPS Cloudflare (`1.1.1.1`) или Google (`8.8.8.8`) | Настройки DNS системы |
| Удалённые настройки и реклама | при запуске и раз в 6 часов | `/v1/config` на сервере Kometfy: в запросе только платформа; картинки рекламы — с того же адреса | — |
| Статистика подключений | раз в 6 часов, **только с согласия** «Статистика подключений» | `/v1/stats` на сервере Kometfy: случайный id установки (создаётся при первом согласии и стирается, когда выключены и статистика, и проверки сети), платформа, версия, режим, за вчера и сегодня — число подключений, удачных и сорвавшихся по причинам, падения, нагрузка на процессор и память приложения (медиана и P95), память сетевого ядра (P95), среднее время запуска. С версии 1.0.1 ещё то, на чём работает приложение: версия системы, объём памяти устройства, округлённый до гигабайта, и число ядер процессора; модель устройства и его идентификаторы не отправляются. Страну определяет край Cloudflare; IP-адрес не сохраняется | Настройки → Конфиденциальность |
| Сеть и оператор | вместе со статистикой, **только с отдельным согласием** «Сеть и оператор» | тип сети (Wi‑Fi, мобильная, кабель), на телефоне в мобильной сети — название оператора SIM. Только с этим согласием сервер определяет оператора (например, «МТС») по AS запроса, когда запрос ушёл не через VPN | Настройки → Конфиденциальность |
| Названия подписок | вместе со статистикой, **только с отдельным согласием** «Названия подписок» | число подписок и названия, которые дали им провайдеры (`profile-title` или имя файла); свои названия, которые вы дали подписке, не уходят. Название хранится открытым текстом, только когда его прислали не меньше трёх разных установок; до того — лишь хеш | Настройки → Конфиденциальность |
| Показы и нажатия рекламы | раз в 10 минут, **только с согласия** «Показы рекламы» | `/v1/ads` на сервере Kometfy: счётчики по объявлению, варианту и дню, без id устройства | Настройки → Конфиденциальность |
| Проверки сети | раз в 4 часа, **только с согласия** | задания берутся с `/v1/tasks` на сервере Kometfy и, если подписка прислала адреса `kometfy-tasks` / `kometfy-reports`, у вашего VPN-провайдера (для него — отдельный id, по которому эти два канала не связать). Отчёт: открылись ли заданные сайты напрямую, через обход и через VPN, за сколько мс и на каком шаге оборвалось (DNS, TCP, TLS); ответы системного DNS против DNS-over-HTTPS Cloudflare для заданных доменов; доходит ли TCP до заданных адресов; скорость загрузки заданного файла (в мобильной сети — только если задание это разрешает: тратит трафик); для подписки, которую дало само задание, — загрузилась ли она (без ваших данных устройства) и отвечают ли её серверы, через отдельное временное ядро, ваш VPN не трогается; подобранная стратегия обхода; диагностический отчёт (очищенный, см. ниже). К отчёту добавляются тип сети и режим программы. Провайдеру — ещё задержки его собственных серверов. Страну и провайдера (номер AS) сервер определяет сам; IP-адрес не сохраняется | Настройки → Конфиденциальность |

Ваш собственный трафик идёт на серверы, которые вы выбрали. У PrismRoute нет промежуточных серверов, и он не видит содержимое трафика.

### Подписка и ID устройства (HWID)

Когда вы добавляете или обновляете подписку, запрос идёт напрямую на адрес подписки (или через ваш прокси, если вы подключены). Провайдер видит IP-адрес, с которого пришёл запрос. Если включено «Отправлять ID устройства», вместе с запросом уходят заголовки `x-hwid`, `x-device-os`, `x-ver-os` и `x-device-model` — их ждут провайдеры, которые ограничивают число устройств (Remnawave, Happ, v2RayTun).

- `x-hwid` — не идентификатор Windows, а хэш: первые 16 байт SHA-256 от `prismroute-hwid-v1:` и `MachineGuid`. Сам `MachineGuid` не отправляется, и по хэшу нельзя найти этот ПК в других программах.
- Остальные заголовки: название и версия ОС и модель устройства из BIOS.
- Выключить: Настройки → Подписки → «Отправлять ID устройства». Некоторые провайдеры без него откажут.

## Что хранится на вашем ПК

Папка данных: `%APPDATA%\dev.prismroute.console\connect` (Настройки → Ядро → кнопка «Открыть» у папки данных; на macOS — `~/Library/Application Support/dev.prismroute.console/connect`).

| Файл | Что внутри |
| --- | --- |
| `settings.json` | настройки программы и случайный пароль локального контроллера ядра |
| `profiles/` | ваши подписки **вместе со ссылками на них** в открытом виде, список серверов |
| `rules.json`, `chains.json` | ваши правила и цепочки |
| `metrics.json` | локальная статистика (см. ниже) |
| `app.log`, `app.log.1`, `app.log.2` | журнал программы; всего не больше 3 МБ, старое удаляется |
| `diagnostics/` | сохранённые диагностические отчёты; остаются пять последних |
| `session.lock` | пометка «программа работает», нужна для подсчёта аварийных завершений |

Ссылка на подписку часто содержит ваш личный ключ. Файлы не шифруются, их защищают права вашей учётной записи Windows. Не отправляйте папку данных целиком и не публикуйте `profiles/`.

Языки Windows (языки интерфейса, раскладки клавиатуры, региональный формат и домашний регион) программа читает только у себя на ПК, чтобы решить, показывать ли в настройках переключатель «Показывать серверы в Украине». Никуда они не отправляются.

## Локальная статистика

Программа считает на вашем ПК, как она работает: сколько попыток подключения удалось, как быстро идут подключение, запуск TUN, применение правил и старт окна, сколько памяти и процессора занимают приложение и ядра, были ли падения и неожиданные остановки ядер.

- **Не хранится каждое событие.** Для каждого дня — счётчики и гистограммы (количество, среднее, медиана P50, P95, максимум). Хранится 90 дней, файл занимает десятки килобайт. Последние 40 заметных событий записаны только как вид и короткий код (например, `connect_failed` / `network`), без текста ошибок.
- **Без согласия ничего не отправляется.** Статистика лежит в `metrics.json` и попадает в диагностический отчёт, который вы сохраняете и показываете сами. С согласием «Статистика подключений» раз в несколько часов на бэкенд Kometfy уходят только итоги дня (см. таблицу выше), а не события и не тексты ошибок.
- **Ошибки различаются.** Сбои приложения, сбои ядра, проблемы подписки, сетевые таймауты и ваши собственные решения (не дали права администратора) считаются отдельно. В «долю сбоев PrismRoute» входят только сбои приложения и ядра: недоступность чужого сервера или отказ провайдера не портят статистику надёжности.
- **«Падение» — это паника программы без чистого выхода.** Если программу просто закрыли через Диспетчер задач или выключили питание, это считается отдельно («закрыто извне»), как не доказательство ошибки.
- Выключить и стереть: Настройки → Диагностика → «Вести локальную статистику» и «Очистить статистику».

## Диагностический отчёт

Настройки → Диагностика → «Сохранить диагностический отчёт». Это текстовый файл: версии, настройки без секретов, сводка статистики, хвосты журналов. Из журналов вырезаются IP-адреса, имена сайтов и серверов, ссылки, e-mail, идентификаторы, длинные ключи и имя пользователя Windows в путях; строки журнала ядра с адресами посещённых сайтов (`a --> b`) выбрасываются целиком.

Очистка работает по шаблонам и **может пропустить** что-то необычное. Поэтому отчёт сначала показывается вам, и вы отправляете его сами (например, прикладываете к обращению на GitHub). Программа не отправляет отчёт и не делает этого автоматически.

## Android

Android-версия (бета) делает то же самое, с такими отличиями:

- **Системный VPN.** При первом подключении Android спрашивает разрешение на VPN. Пока VPN включён, трафик всех приложений телефона идёт через туннель в ядро mihomo на этом же телефоне, а оттуда — на ваш сервер или напрямую, по правилам. Содержимое трафика не записывается; в журнал ядра попадают только адреса соединений, как и на ПК. Само приложение и его ядро в туннель не входят.
- **Обновления и ядро не скачиваются.** Ядро (официальная сборка mihomo) лежит внутри APK, проверки обновлений нет: новые версии выходят как APK на странице релизов.
- **ID устройства.** `x-hwid` — тот же хэш с солью, но от `ANDROID_ID`: системного идентификатора, который Android выдаёт этому приложению на этом устройстве (другие приложения получают другой). Сам `ANDROID_ID` не отправляется. `x-ver-os` — версия Android, `x-device-model` — производитель и модель.
- **Данные** лежат в личной папке приложения (`/data/data/dev.prismroute.console`), которую другие приложения без root прочитать не могут. При удалении приложения Android стирает её целиком.
- **Отчёт** можно не сохранять в файл, а сразу отправить кнопкой «Поделиться»: текст уходит только в то приложение, которое вы выберете.

## Рекламный блок

Карточка «Здесь могла быть реклама вашего VPN» — статичный элемент интерфейса со ссылкой на автора. Она не загружает ничего из сети и не следит за вами. Её можно закрыть или выключить в Настройки → Внешний вид.

## Вопросы

Вопросы о конфиденциальности — в [Issues](https://github.com/TABURELTER/Kometfy/issues/new/choose). Об уязвимостях — по [SECURITY.md](../SECURITY.md), не публично.

---

# PrismRoute privacy (English)

PrismRoute (Kometfy) is a client for your own VPN or proxy. The project has no accounts. Its own server (Kometfy's backend on Cloudflare; the app keeps its address veiled) hands out remote settings and ads; fetching them says nothing about you. Statistics and network check results are sent **only after you choose on the welcome screen**. On a first installation, the options are suggested on; you can turn off any of them or continue without them. Your selection is saved when you finish the welcome screen and can be changed any time under Settings → Privacy.

## Network requests

| What | When | Where | How to stop it |
| --- | --- | --- | --- |
| Update check | at start and every few hours | `latest.json` from `kometfy.com/latest.json`, else from `github.com/TABURELTER/Kometfy/releases` | Settings → Updates → "Check automatically" |
| mihomo and Xray versions and downloads | only when you press Download or Check for updates for a core | `api.github.com` (MetaCubeX/mihomo, XTLS/Xray-core) and the release files; geoip/geosite from `github.com/MetaCubeX/meta-rules-dat` | do not press it |
| Your subscription | when you add or update one | the address you entered | do not add one |
| External address lookup | when Home opens | `ipwho.is` (through your proxy when connected) | Settings → Connection → "Show my address on Home" |
| Server latency test | when you start it | `www.gstatic.com/generate_204` through the chosen server (editable) | do not start it |
| DNS while connected | always while the core runs | DNS-over-HTTPS `dns.google` and `1.1.1.1` by default; editable under Settings → DNS | Settings → DNS |
| Fallback address lookup | only when the system's DNS gave no address for Kometfy's server or a Telegram gateway (AdGuard DNS does that) | that server's or gateway's name, and only it, goes to Cloudflare's (`1.1.1.1`) or Google's (`8.8.8.8`) DNS-over-HTTPS | the system's DNS settings |
| Remote settings and ads | at start and every 6 hours | `/v1/config` on Kometfy's server with the platform only; the ads' pictures from the same host | — |
| Connection statistics | every 6 hours, **only with the consent** "Connection statistics" | `/v1/stats` on Kometfy's server: a random install id (made at the first consent, erased when both the statistics and the network checks are off), platform, version, mode, and for yesterday and today the number of connections, successful and failed by cause, crashes, the app's CPU load and memory (median and 95th percentile), the network core's memory (95th percentile), the median start time. Since 1.0.1 also what the app runs on: the system's version, the device's memory rounded to a gigabyte and the number of processor cores; never the device's model or its identifiers. Cloudflare's edge tells the country; no IP address is stored | Settings → Privacy |
| Network and operator | with the statistics, **only with its own consent** "Network and operator" | the kind of network (Wi‑Fi, mobile, cable) and, on a phone's mobile link, the SIM operator's name. Only with this consent does the server tell the operator (e.g. "MTS") from the request's AS, when the request did not go through the VPN | Settings → Privacy |
| Subscription names | with the statistics, **only with its own consent** "Subscription names" | how many subscriptions you have and the names their providers gave them (`profile-title` or the file name); a name you gave a subscription yourself is never sent. A name is stored in clear only once at least three different installs have sent it; until then only its hash | Settings → Privacy |
| Ad views and clicks | every 10 minutes, **only with the consent** "Ad views" | `/v1/ads` on Kometfy's server: counts per ad, variant and day, no device id | Settings → Privacy |
| Network checks | every 4 hours, **only with consent** | tasks from `/v1/tasks` on Kometfy's server and, if the subscription sends `kometfy-tasks` / `kometfy-reports`, from your VPN provider (with a separate id, so the two cannot be matched). Reports: whether given sites opened directly, through the bypass and through the VPN, in how many ms and at which step they broke (DNS, TCP, TLS); the system DNS's answers against Cloudflare's DNS-over-HTTPS for given domains; whether TCP reaches given addresses; a given file's download speed (on a mobile link only if the task allows it: it costs traffic); for a subscription the task itself gives, whether it loads (without your device's ids) and whether its servers answer, through a separate temporary core, without touching your VPN; the bypass strategy found; the scrubbed diagnostic report. The kind of network and the app's mode come with each report. The provider may also ask for its own servers' delays. The server tells country and provider (AS number) itself; no IP address is stored | Settings → Privacy |

Your own traffic goes to the servers you picked. PrismRoute has no relay servers and cannot see your traffic.

**Device ID (HWID).** If "Send the device ID" is on, subscription requests carry `x-hwid`, `x-device-os`, `x-ver-os` and `x-device-model`, as providers that limit devices expect. `x-hwid` is the first 16 bytes of SHA-256 over `prismroute-hwid-v1:` and the Windows `MachineGuid`; the GUID itself is never sent. Switch it off under Settings → Subscriptions (some providers will refuse the subscription without it).

## What is stored on your PC

In `%APPDATA%\dev.prismroute.console\connect` (macOS: `~/Library/Application Support/dev.prismroute.console/connect`): settings (with a random controller password), profiles **with their subscription links in plain text**, rules and chains, `metrics.json`, `app.log` (at most 3 MiB in total), the last five diagnostic reports and a `session.lock` marker. Nothing is encrypted; Windows account permissions protect it. Never publish `profiles/`.

The Windows languages (interface languages, keyboard layouts, regional format and home location) are read on the PC only, to decide whether Settings shows the "Show servers in Ukraine" switch. They are not sent anywhere.

## Local statistics

Kept on this PC: per day, counters and histograms (count, average, P50, P95, max) of connect time, TUN start, rule reload and window start, memory and CPU of the app and the cores, crashes and unexpected core exits. Individual operations are not stored; 90 days are kept. Failures are told apart (app, core, subscription, network, your own choice) and **only app and core failures count against PrismRoute**: someone else's server being down does not. A "crash" is a panic without a clean exit; a process killed from outside is counted separately. Nothing is sent without consent; with "Connection statistics" only the day's totals listed above go to Kometfy's backend. Turn it off and erase it under Settings → Diagnostics.

## Diagnostic report

Settings → Diagnostics → Save diagnostic report: versions, settings without secrets, a statistics summary and log tails with IP addresses, site and server names, links, e-mails, ids, long keys and user names removed; core log lines naming visited sites are dropped. The cleanup is pattern-based and may miss something unusual, so you read the report first and share it yourself. The app never sends it.

## Android

The Android beta works the same way, except:

- **System VPN.** Android asks for the VPN permission on the first connection. While the VPN is on, the traffic of every app on the phone goes through the tunnel into the mihomo core on the same phone and from there to your server or directly, by your rules. Traffic content is not recorded; the core log holds connection addresses only, as on the PC. The app itself and its core stay outside the tunnel.
- **Nothing is downloaded for updates or cores.** The core (the official mihomo build) ships inside the APK and there is no update check: new versions come out as an APK on the releases page.
- **Device ID.** `x-hwid` is the same salted hash, over `ANDROID_ID`: the id Android gives this app on this device (other apps get a different one). `ANDROID_ID` itself is never sent. `x-ver-os` is the Android version, `x-device-model` the maker and model.
- **Data** lives in the app's private folder (`/data/data/dev.prismroute.console`), which other apps cannot read without root. Uninstalling the app erases it.
- **The report** can go straight to an app you pick with Share, without saving a file.

## Questions

[Issues](https://github.com/TABURELTER/Kometfy/issues/new/choose) for questions; vulnerabilities go through [SECURITY.md](../SECURITY.md), not in public.
