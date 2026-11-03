# mtg-multi

Fork of [9seconds/mtg](https://github.com/9seconds/mtg) with multi-secret support and per-user stats.

[English](#whats-different) | [Русский](#чем-отличается)

---

## What's different

**Multiple secrets.** Upstream mtg allows only one secret per instance. mtg-multi lets you define named secrets in the config — one per user. Secrets may use different hostnames for per-user domain fronting.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

**Reload users without a restart.** Send `SIGHUP` and mtg re-reads the config file and applies the `[secrets]` section (or `secret`) on the fly. New users can connect right away; live sessions of unchanged users are kept; sessions of removed users and of users whose secret has changed are closed. If the file cannot be read or is invalid, the current secrets are kept and a warning is logged. Other options are not reloaded: they still need a restart. Not available on Windows.

```console
kill -HUP $(pidof mtg-multi)
# or with systemd: ExecReload=/bin/kill -HUP $MAINPID, then
systemctl reload mtg-multi
```

Write the new config atomically (to a temporary file, then `mv`), so mtg never reads a half-written file: a truncated file that still parses is applied as is, and every user missing from it is disconnected.

If a new hostname does not resolve, the secrets are still applied and a warning is logged.

Note: `SIGHUP` no longer terminates mtg, both for `run` and `simple-run`, including a foreground process when its terminal is closed. Stop it with `SIGINT` or `SIGTERM`.

**Stats API.** A lightweight HTTP endpoint that shows live per-user traffic.

```toml
api-bind-to = "127.0.0.1:9090"
```

```
GET /stats
```

```json
{
  "started_at": "2026-03-29T10:30:00Z",
  "uptime_seconds": 3600,
  "total_connections": 15,
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-03-29T11:25:30Z",
      "active_ips": ["198.51.100.4", "203.0.113.7", "2001:db8::1"]
    }
  }
}
```

`active_ips` lists the client addresses that have live sessions of the user right now, each address once however many sessions it has (`connections` counts the sessions), sorted with IPv4 first; `[]` when there are none. It is the address mtg sees as the client: the one from the PROXY protocol header with `proxy-protocol-listener`, `X-Forwarded-For` for WEB streams, otherwise the TCP peer, so clients behind a relay show up with the relay's address. An address is added when a session passes the handshake and removed with the last one, so a user removed by `SIGHUP` disappears together with its addresses.

DC labels in Prometheus/StatsD preserve the sign requested by the client: media DCs are negative (`-2`, `-4`, ...). Dashboards that match only positive DC numbers must include the negative ones too.

**Connection throttling.** Automatic per-user connection limits to protect the server from overload. A background goroutine recomputes caps every few seconds using a fair-share algorithm: small users keep their connections, remaining budget is split equally among heavy consumers. New connections from over-cap users are rejected; existing connections are not killed.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Example: limit = 100, users A=1, B=1, C=90, D=110.
A and B stay at 1. Remaining budget 98 is split: C and D are capped at 49 each.

Throttle state is exposed via the Stats API:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

**Public IP override.** Useful when auto-detection via ifconfig.co is unavailable.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

**WEB mode.** MTProto inside a real HTTPS session, compatible with the WEB proxy type of Telegram Desktop (`tg://webproxy` links). mtg serves plain HTTP on loopback; a reverse proxy with a real certificate terminates TLS in front of it. Everyone who is not a client gets the static decoy site. Users and secrets are the same as for regular MTProto, only the link differs. Disabled by default:

```toml
[web]
bind-to = "127.0.0.1:18080"
host = "proxy.example.com"
decoy-dir = "/var/www/decoy"
```

**WEB connection link.** Open this form in a Telegram Desktop version with WEB proxy support:

```text
tg://webproxy?server=proxy.example.com&secret=dd<32 hex digits of the user's key>
```

The server is `[web].host`, and HTTPS uses port 443. The WEB secret uses the same 16-byte key as that user's `[secrets]` entry: replace the `ee` prefix with `dd` and leave out the encoded FakeTLS hostname. If `[web].secret-mode = "plain"`, leave out the `dd` prefix too. The hostname inside the original secret does not have to match `[web].host`. The client computes the bridge capability itself.

For either hex or base64url config secrets, this local command prints the link for `alice` (Python 3.11+, no extra packages):

```sh
python3 - /etc/mtg/config.toml alice <<'PY'
import base64
import sys
import tomllib
from urllib.parse import urlencode

with open(sys.argv[1], "rb") as source:
    config = tomllib.load(source)
web = config["web"]
secret = config["secrets"][sys.argv[2]]
try:
    raw = bytes.fromhex(secret)
except ValueError:
    raw = base64.b64decode(secret + "=" * (-len(secret) % 4), altchars=b"-_", validate=True)
if len(raw) <= 17 or raw[0] != 0xee:
    raise SystemExit("Expected an ee secret with a 16-byte key and hostname")
mode = web.get("secret-mode", "dd")
if mode not in ("dd", "plain"):
    raise SystemExit("Expected web.secret-mode dd or plain")
key = ("dd" if mode == "dd" else "") + raw[1:17].hex()
print("tg://webproxy?" + urlencode({"server": web["host"].strip().lower(), "secret": key}))
PY
```

Give the resulting link only to that user: it contains their proxy password. It can also use the `https://t.me/webproxy?` prefix. The link format follows [Telegram Desktop's WEB proxy design](https://github.com/telegramdesktop/tdesktop/blob/dev/docs/web-proxy-plan.md#11-settings-and-app-integration).

```nginx
# In the http context, outside the server block. The bridge link carries the
# user's capability in the query string, so log without it.
log_format no_query '$remote_addr [$time_local] "$request_method $uri" $status';

server {
    listen 443 ssl http2;
    server_name proxy.example.com;
    ssl_certificate     /etc/letsencrypt/live/proxy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/proxy.example.com/privkey.pem;

    access_log /var/log/nginx/proxy.access.log no_query;

    # The decoy error pages say "nginx" without a version.
    server_tokens off;

    location / {
        proxy_pass http://127.0.0.1:18080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        # Exactly one address. Not $proxy_add_x_forwarded_for: it appends to
        # whatever the client sent, and mtg refuses such requests.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_buffering off;
        proxy_read_timeout 60s;
        # Upload bodies: at least mtg's limit on one /up body (32 MB). The
        # bridge page sends at most 512 KB per request, but a 413 from here
        # ends the session.
        client_max_body_size 32m;
    }
}
```

Origin: the WEB protocol was first implemented server side in [telemt](https://github.com/telemt/telemt). The bridge page and its HTML, CSP and Permissions-Policy (`web/bridge.go`, `web/bridge/runtime.js`) are adapted from telemt, and the capability test vectors are taken from it; those parts are used under the TELEMT LICENSE 3.3 (see [`web/LICENSE.telemt`](web/LICENSE.telemt)), and the adapted files list their changes. The Go server side is written anew after telemt's protocol. For operators: the bridge page your server sends to clients is adapted from telemt and licensed under the TELEMT LICENSE 3.3 ([`web/LICENSE.telemt`](web/LICENSE.telemt)), so you may state this in your service description (section 7 of that licence recommends such attribution for a public network service).

Notes:

- `X-Forwarded-For` is the only source of the client address (mtg listens on loopback, so the peer is always 127.0.0.1). It must hold exactly one address. A missing, repeated or comma-separated header is refused with the decoy and logged (at most once a minute), instead of letting the client through as 127.0.0.1, where the allowlist and the blocklist would not see it. With `$proxy_add_x_forwarded_for` this breaks every client that sends its own header, so use `$remote_addr`.
- The capability in `/?bridge=...` works like a password for the WEB link of that user. Keep it out of logs (`log_format` above) and out of `Referer`.
- Set `client_max_body_size` at least to mtg's limit on one `/up` body (32 MB), as in the example. The bridge page itself sends at most 512 KB per request, so it also fits nginx's default of 1m, but a proxy limit below that answers 413, and the page treats a failed upload as the end of the session.
- One user cannot take the whole server: by default a user has at most 4 live sessions and 8 bridge tokens not used yet (`max-sessions-per-user`, `max-pending-per-user`); past that, the user's oldest one gives way.
- `SIGHUP` reloads the WEB users together with the proxy ones: they are the same `[secrets]`. A new user's WEB link works right away. WEB sessions of a removed user, or of a user whose secret has changed, are closed together with their streams, their unused bridge tokens are dropped, and their old link gets the decoy. Sessions of unchanged users go on. The `[web]` section itself (`bind-to`, `host`, `secret-mode`, `decoy-dir`, the limits, `diag`) is read only at startup: changing it needs a restart.

Everything else — domain fronting, doppelganger, proxy chaining, blocklists, metrics — works exactly as in upstream. See the [upstream README](https://github.com/9seconds/mtg) for details.

## Quick start

Download a binary from [Releases](https://github.com/dolonet/mtg-multi/releases) or build from source:

```console
git clone https://github.com/dolonet/mtg-multi.git
cd mtg-multi
mise install && mise tasks run build
```

Generate secrets:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Minimal config:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] must be the last section in the global scope —
# in TOML, all keys after a [section] become part of that table.
[secrets]
alice = "ee..."
bob   = "ee..."
```

Run:

```console
mtg-multi run /etc/mtg/config.toml
```

See [example.config.toml](example.config.toml) for all available options.

---

## Чем отличается

**Несколько секретов.** В оригинальном mtg — один секрет на инстанс. mtg-multi позволяет задать именованные секреты в конфиге, по одному на пользователя. Секреты могут использовать разные hostname для per-user domain fronting.

```toml
[secrets]
alice = "ee367a189aee18fa31c190054efd4a8e9573746f726167652e676f6f676c65617069732e636f6d"
bob   = "ee0123456789abcdef0123456789abcd9573746f726167652e676f6f676c65617069732e636f6d"
```

**Смена пользователей без рестарта.** По `SIGHUP` mtg перечитывает файл конфига и применяет раздел `[secrets]` (или `secret`) на лету. Новые пользователи подключаются сразу; живые сессии неизменённых пользователей сохраняются; сессии удалённых пользователей и тех, у кого сменился секрет, закрываются. Если файл не читается или неверен, текущие секреты остаются, в лог пишется предупреждение. Остальные настройки так не перечитываются - для них по-прежнему нужен рестарт. На Windows недоступно.

```console
kill -HUP $(pidof mtg-multi)
# или в systemd: ExecReload=/bin/kill -HUP $MAINPID, затем
systemctl reload mtg-multi
```

Новый конфиг записывайте атомарно (во временный файл, затем `mv`), чтобы mtg не прочитал его наполовину записанным: обрезанный файл, который всё же разбирается, применяется как есть, и все пользователи, которых в нём нет, отключаются.

Если новый hostname не резолвится, секреты всё равно применяются, в лог пишется предупреждение.

Внимание: `SIGHUP` больше не завершает mtg - ни `run`, ни `simple-run`, в том числе процесс на переднем плане при закрытии терминала. Останавливайте его через `SIGINT` или `SIGTERM`.

**Stats API.** HTTP-эндпоинт с live-статистикой трафика по пользователям.

```toml
api-bind-to = "127.0.0.1:9090"
```

```
GET /stats
```

```json
{
  "started_at": "2026-03-29T10:30:00Z",
  "uptime_seconds": 3600,
  "total_connections": 15,
  "users": {
    "alice": {
      "connections": 8,
      "bytes_in": 1048576,
      "bytes_out": 2097152,
      "last_seen": "2026-03-29T11:25:30Z",
      "active_ips": ["198.51.100.4", "203.0.113.7", "2001:db8::1"]
    }
  }
}
```

`active_ips` - адреса клиентов, у которых сейчас есть живые сессии пользователя, каждый адрес один раз, сколько бы сессий с него ни было (сессии считает `connections`), IPv4 впереди; `[]`, если сессий нет. Это адрес, который mtg видит как клиента: из заголовка PROXY protocol при `proxy-protocol-listener`, из `X-Forwarded-For` для WEB-потоков, иначе TCP-адрес собеседника, так что клиенты за релеем видны с адресом релея. Адрес добавляется, когда сессия прошла рукопожатие, и уходит вместе с последней, поэтому пользователь, удалённый через `SIGHUP`, исчезает вместе со своими адресами.

Метки DC в Prometheus/StatsD сохраняют знак из запроса клиента: медиа DC имеют отрицательные номера (`-2`, `-4`, ...). Фильтры дашбордов только по положительным DC должны учитывать и отрицательные.

**Троттлинг подключений.** Автоматические per-user лимиты для защиты сервера от перегрузки. Фоновая горутина каждые несколько секунд пересчитывает капы по алгоритму fair-share: маленькие пользователи сохраняют свои подключения, оставшийся бюджет делится поровну между крупными потребителями. Новые подключения сверх капа отклоняются; существующие не разрываются.

```toml
[throttle]
max-connections = 5000
check-interval = "5s"
```

Пример: лимит = 100, пользователи A=1, B=1, C=90, D=110.
A и B остаются на 1. Оставшийся бюджет 98 делится: C и D получают кап 49.

Состояние троттлинга доступно через Stats API:

```json
{
  "throttle": {
    "active": true,
    "limit": 5000,
    "caps": { "heavy-user": 2450 }
  }
}
```

**Ручное указание публичного IP.** Для случаев, когда ifconfig.co недоступен с сервера.

```toml
public-ipv4 = "1.2.3.4"
public-ipv6 = "2001:db8::1"
```

**Режим WEB.** MTProto внутри настоящей HTTPS-сессии, совместим с типом прокси WEB в Telegram Desktop (ссылки `tg://webproxy`). mtg отдаёт простой HTTP на loopback, TLS с настоящим сертификатом терминирует reverse proxy перед ним. Всем, кто не является клиентом, отдаётся статический сайт-заглушка. Пользователи и секреты те же, что для обычного MTProto, отличается только ссылка. По умолчанию выключен:

```toml
[web]
bind-to = "127.0.0.1:18080"
host = "proxy.example.com"
decoy-dir = "/var/www/decoy"
```

**Ссылка подключения WEB.** Откройте в Telegram Desktop с поддержкой WEB-прокси:

```text
tg://webproxy?server=proxy.example.com&secret=dd<32 hex-символа ключа пользователя>
```

В `server` указывается `[web].host`, HTTPS работает на порту 443. Из секрета пользователя в `[secrets]` берётся тот же 16-байтовый ключ: префикс `ee` заменяется на `dd`, закодированное имя FakeTLS-домена отбрасывается. При `[web].secret-mode = "plain"` префикс `dd` тоже не нужен. Домен внутри исходного секрета может отличаться от `[web].host`. Capability для страницы-моста клиент вычисляет сам.

Команда Python 3.11+ в английском разделе выше читает конфиг и печатает готовую ссылку для `alice`; она поддерживает секреты в hex и base64url и не требует дополнительных пакетов. Замените путь к конфигу и имя пользователя. Полученная ссылка содержит пароль прокси: передавайте её только этому пользователю. Вместо `tg://webproxy?` можно использовать `https://t.me/webproxy?`.

Происхождение: протокол WEB впервые реализован на стороне сервера в [telemt](https://github.com/telemt/telemt). Страница-мост и её HTML, CSP и Permissions-Policy (`web/bridge.go`, `web/bridge/runtime.js`) адаптированы из telemt, тестовые векторы capability взяты оттуда же; эти части используются по лицензии TELEMT LICENSE 3.3 (см. [`web/LICENSE.telemt`](web/LICENSE.telemt)), изменения перечислены в заголовках файлов. Серверная часть на Go написана заново по протоколу telemt. Для операторов: страница-мост, которую ваш сервер отдаёт клиентам, адаптирована из telemt и распространяется по лицензии TELEMT LICENSE 3.3 ([`web/LICENSE.telemt`](web/LICENSE.telemt)), и это можно указать в описании сервиса (раздел 7 лицензии рекомендует такую атрибуцию для публичного сетевого сервиса).

Пример nginx - в английской части выше. Важно:

- `X-Forwarded-For` - единственный источник адреса клиента (mtg слушает loopback, соединение всегда от 127.0.0.1). В нём должен быть ровно один адрес: `proxy_set_header X-Forwarded-For $remote_addr`, а не `$proxy_add_x_forwarded_for`. Запрос без пригодного заголовка получает заглушку и пишется в лог (не чаще раза в минуту), а не проходит как 127.0.0.1 мимо allowlist и blocklist.
- Capability в `/?bridge=...` - это пароль WEB-ссылки пользователя. Не пишите её в access_log (`log_format` без query string, как в примере) и включите `server_tokens off`.
- `client_max_body_size` - не ниже лимита mtg на одно тело `/up` (32 МБ), как в примере. Сама страница-мост отправляет не больше 512 КБ за запрос и укладывается и в дефолтный 1m nginx, но лимит прокси ниже этого даёт 413, а неудачная отправка для страницы - конец сессии.
- Один пользователь не займёт весь сервер: по умолчанию у него не больше 4 живых сессий и 8 неиспользованных токенов моста (`max-sessions-per-user`, `max-pending-per-user`), сверх этого вытесняются его же самые старые.
- `SIGHUP` перечитывает WEB-пользователей вместе с обычными: это тот же `[secrets]`. WEB-ссылка нового пользователя работает сразу. WEB-сессии удалённого пользователя и пользователя со сменённым секретом закрываются вместе с их потоками, его неиспользованные токены моста сбрасываются, а старая ссылка получает заглушку. Сессии неизменённых пользователей продолжаются. Сам раздел `[web]` (`bind-to`, `host`, `secret-mode`, `decoy-dir`, лимиты, `diag`) читается только при старте: для его изменения нужен рестарт.

Всё остальное — domain fronting, doppelganger, цепочки прокси, блоклисты, метрики — работает как в оригинале. Подробности в [README upstream](https://github.com/9seconds/mtg).

## Быстрый старт

Скачайте бинарник из [Releases](https://github.com/dolonet/mtg-multi/releases) или соберите из исходников:

```console
git clone https://github.com/dolonet/mtg-multi.git
cd mtg-multi
mise install && mise tasks run build
```

Генерация секрета:

```console
mtg-multi generate-secret --hex storage.googleapis.com
```

Минимальный конфиг:

```toml
bind-to = "0.0.0.0:443"
api-bind-to = "127.0.0.1:9090"

[throttle]
max-connections = 5000

# [secrets] должен быть последней секцией в глобальном scope —
# в TOML все ключи после [section] становятся частью этой таблицы.
[secrets]
alice = "ee..."
bob   = "ee..."
```

Запуск:

```console
mtg-multi run /etc/mtg/config.toml
```

Все доступные опции — в [example.config.toml](example.config.toml).
