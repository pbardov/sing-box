!!! question "Experimental"

`naive-xhttp` outbound uses the Chromium/Cronet network stack from NaiveProxy
outbound, but opens an XHTTP `packet-up` style tunnel instead of HTTP CONNECT.

!!! warning "Platform Support"

    `naive-xhttp` outbound is only available in builds with
    `with_naive_outbound`.

    On Linux amd64/arm64, use `with_purego` for a CGO-free build and distribute
    `libcronet.so` next to the sing-box binary or in the system library path.
    Linux CGO builds require the Chromium toolchain; see
    [Build from source](/installation/build-from-source/#with_naive_outbound).

### Structure

```json
{
  "type": "naive-xhttp",
  "tag": "naive-xhttp-out",

  "server": "127.0.0.1",
  "server_port": 443,
  "username": "sekai",
  "password": "password",
  "path": "/naive-xhttp",
  "host": "",
  "extra_headers": {},
  "sc_max_each_post_bytes": 1000000,
  "sc_min_posts_interval_ms": 0,
  "stream_receive_window": "",
  "udp_over_tcp": false | {},
  "quic": false,
  "quic_congestion_control": "",
  "quic_session_receive_window": "",
  "tls": {},

  ... // Dial Fields
}
```

### Wire Format

The downlink is a long-lived `GET <path>/<session>` request.

Upload packets are `POST <path>/<session>/<seq>` requests with raw payload in
the request body. `seq` starts at `0`; the inbound reorders packets by sequence.

The downlink `GET` carries Naive-style proxy metadata:

| Header | Description |
|--------|-------------|
| `-connect-authority` | Destination address. |
| `Proxy-Authorization` | Basic authentication. |
| `Padding` | Naive-style padding. |
| `Referer` | XHTTP-style `x_padding` query padding. |

There are no CGI compatibility frames or EOF frames. Session lifetime is tied to
the downlink `GET` request.

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### username

Authentication username.

#### password

Authentication password.

#### path

Base path for XHTTP requests.

#### host

HTTP authority and TLS identity host. If set together with `tls.server_name`,
both values must match.

#### extra_headers

Extra headers to send in HTTP requests.

#### sc_max_each_post_bytes

Maximum raw payload size for each upload `POST`.

Default: `1000000`.

#### sc_min_posts_interval_ms

Minimum interval between upload `POST` requests.

#### stream_receive_window

Cronet stream receive window.

#### udp_over_tcp

UDP over TCP protocol settings.

See [UDP Over TCP](/configuration/shared/udp-over-tcp/) for details.

#### quic

Use QUIC instead of HTTP/2.

#### quic_congestion_control

QUIC congestion control algorithm.

| Algorithm | Description |
|-----------|-------------|
| `bbr` | BBR |
| `bbr2` | BBRv2 |
| `cubic` | CUBIC |
| `reno` | New Reno |

#### quic_session_receive_window

Cronet QUIC session receive window.

#### tls

==Required==

TLS configuration, see [TLS](/configuration/shared/tls/#outbound).

Only `server_name`, `certificate`, `certificate_path` and `ech` are supported.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
