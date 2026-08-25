!!! question "Experimental"

`naive-xhttp` inbound accepts XHTTP `packet-up` style GET/POST tunnels from
the `naive-xhttp` outbound.

### Structure

```json
{
  "type": "naive-xhttp",
  "tag": "naive-xhttp-in",

  ... // Listen Fields

  "users": [
    {
      "username": "sekai",
      "password": "password"
    }
  ],
  "network": "tcp",
  "path": "/naive-xhttp",
  "host": "",
  "sc_max_each_post_bytes": 1000000,
  "sc_max_buffered_posts": 30,
  "no_sse_header": false,
  "tls": {}
}
```

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### users

==Required==

Naive XHTTP users.

#### network

Listen network. Only `tcp` is supported.

#### path

Base path for XHTTP requests.

The inbound expects:

| Request | Purpose |
|---------|---------|
| `GET <path>/<session>` | Downlink stream. |
| `POST <path>/<session>/<seq>` | Uplink packet. |

#### host

Expected HTTP host. Empty disables host validation.

#### sc_max_each_post_bytes

Maximum raw payload size for each upload `POST`.

Default: `1000000`.

#### sc_max_buffered_posts

Maximum number of out-of-order upload packets buffered per session.

Default: `30`.

#### no_sse_header

Do not set `Content-Type: text/event-stream` on the downlink response.

#### tls

TLS configuration, see [TLS](/configuration/shared/tls/#inbound).
