# Сторонние сервисы и SDK — аудит

Проверено 24 ноября 2026 г. Сканер `pip-audit`: известных уязвимостей не найдено. При каждой сборке на GitHub он запускается заново.

## Библиотеки внутри программы
Ядро Provenio написано только на стандартной библиотеке Python. Сторонние пакеты нужны для окна программы, ИИ-сводки и сборки.

| Пакет | Версия | Лицензия | Зачем | Отправляет данные? |
|---|---|---|---|---|
| pywebview | 6.2 | BSD-3 | окно программы (движок Edge WebView2) | нет |
| pythonnet, clr_loader | 3.2 / 0.3 | MIT | связь pywebview с WebView2 | нет |
| bottle, proxy_tools | 0.13 / 0.1 | MIT | зависимости pywebview | нет |
| anthropic | 2.13 | Apache-2.0 | ИИ-сводка кейса (Claude) | только когда вы нажимаете «Составить сводку», в api.anthropic.com |
| httpx2, httpcore2, h11, anyio, sniffio, idna, truststore | — | BSD/MIT | HTTP-клиент для anthropic | нет, используется только для запроса выше |
| pydantic, pydantic_core, jiter, annotated-types, typing-inspection, typing_extensions, docstring_parser, distro | — | MIT/PSF | разбор ответов anthropic | нет |
| opentelemetry-api | 1.45 | Apache-2.0 | интерфейс трассировки в anthropic. Экспортёр не подключён, поэтому **телеметрия не отправляется** | нет |
| PyInstaller (загрузчик) | 6.22 | GPL-2 с исключением | упаковка в exe, загрузчик собирается из исходников | нет |
| certifi | — | MPL-2.0 | корневые сертификаты (iPhone) | нет |
| Toga, Briefcase | 0.5 / 0.4 | BSD-3 | приложение для iPhone | нет |

**Чего в программе нет:** SDK аналитики (Google Analytics, Firebase, Sentry, Mixpanel), рекламных сетей, сборщиков отчётов о сбоях и фоновых «пингов».

## Внешние сервисы, к которым обращаются инструменты
Запросы уходят только по вашему действию, и отправляется только то, что вы ввели.

| Группа | Сервисы |
|---|---|
| Домены и DNS | rdap.org, crt.sh, CertSpotter, Cloudflare DNS (DoH), HackerTarget, RIPEstat, bgp.he.net, Wayback Machine (archive.org) |
| IP и угрозы | ip-api.com, Shodan InternetDB, StopForumSpam, AlienVault OTX, AbuseIPDB*, VirusTotal*, urlscan.io*, списки FireHOL, Spamhaus, IPsum, abuse.ch, DShield, blocklist.de, GreenSnow, CINS, Emerging Threats, Binary Defense, Tor Project, AWS, Fastly, Cloudflare IP ranges |
| Утечки | XposedOrNot (k-anonymity для паролей), Pwned Passwords (k-anonymity) |
| Люди и аккаунты | профили на публичных сайтах (поиск по нику), GitHub API*, Gravatar, Keybase |
| Уязвимости | NVD (NIST), CISA KEV, FIRST EPSS |
| Криптовалюта | Blockstream, mempool.space, Blockscout |
| Глобус | OpenSky Network, airplanes.live, CelesTrak, USGS, NASA EONET, OpenStreetMap Nominatim |
| Угрозы | ransomware.live (поиск жертв вымогателей — уходит только ваш запрос), журналы Certificate Transparency Let's Encrypt и список логов Google (CT-поток — только скачивание, о вас ничего не передаётся; ~90 МБ/ч, пока поток включён) |
| Доказательства | службы времени RFC 3161: DigiCert, Sectigo, FreeTSA, SSL.com (только хэш) |
| ИИ | Anthropic API* (только по кнопке, с предупреждением) |
| Обновления | api.github.com (только если включено) |

\* — нужен ваш ключ API. Ключ хранится зашифрованным (DPAPI) и отправляется только своему сервису.

## Как проверить самостоятельно
```
pip install pip-audit
pip-audit -r requirements-build.txt
```
