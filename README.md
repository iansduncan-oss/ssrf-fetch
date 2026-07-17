# ssrf-fetch

A drop-in `fetch()` that stops [SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery). It refuses to connect to internal network targets **and** pins the connection to the IP it just validated, so a hostile DNS server can't rebind the hostname to an internal address after the check (TOCTOU).

Zero config. One dependency (`undici`). Works with Node's native `fetch`.

```ts
import { safeFetch } from 'ssrf-fetch';

// Same signature as fetch(). Throws instead of connecting to an internal host.
const res = await safeFetch(userProvidedUrl);
const body = await res.text();
```

## Why

Any time your server fetches a URL it didn't author — a webhook target, an avatar URL from a user profile, a link-preview/OpenGraph crawl, an "import from URL" feature — an attacker can point that URL inward:

- `http://169.254.169.254/latest/meta-data/` — cloud instance metadata (IAM creds)
- `http://localhost:6379/` — Redis, Postgres, or any local service
- `http://10.0.0.5/admin` — a private service with no auth because it's "internal"

Plain `fetch()` will happily make those requests from inside your network. That's SSRF, and it's [#10 on the OWASP Top 10](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/).

## What it does

`safeFetch()`:

1. **Requires `http(s)`** — no `file:`, `gopher:`, `ftp:`, etc.
2. **Resolves the hostname and blocks internal addresses** — if *any* resolved address is loopback, link-local, private, unique-local, or CGNAT, the request is refused:

   | Range | Example |
   |---|---|
   | `0.0.0.0/8` | `0.0.0.0` |
   | `10.0.0.0/8` | private |
   | `127.0.0.0/8` | loopback |
   | `169.254.0.0/16` | link-local incl. `169.254.169.254` metadata |
   | `172.16.0.0/12` | private |
   | `192.168.0.0/16` | private |
   | `100.64.0.0/10` | CGNAT |
   | `::1`, `::` | IPv6 loopback / unspecified |
   | `fe80::/10` | IPv6 link-local |
   | `fc00::/7` | IPv6 unique-local |
   | `::ffff:a.b.c.d` | IPv4-mapped (the embedded v4 is re-checked) |

3. **Disables redirects** — a public URL must not `30x`-bounce into an internal one.
4. **Closes the DNS-rebinding hole (TOCTOU)** — this is the part most guards miss. Checking the DNS record and *then* calling `fetch()` re-resolves the name, so a hostile DNS server can return a public IP on the check and an internal IP on the connect. `ssrf-fetch` pins the request to the exact addresses it just validated via a custom [undici](https://github.com/nodejs/undici) `Agent` lookup, so the connection can only go where the check passed. The `Host` header and TLS SNI stay the original hostname, so certificate validation is unaffected.

## Install

```sh
npm install ssrf-fetch
```

Requires Node.js **20+** (uses global `fetch` and undici v7).

## API

### `safeFetch(url, init?): Promise<Response>`

A drop-in replacement for `fetch()`. Same arguments, returns a standard `Response`.

- `redirect` is always forced to `'error'`.
- A 5-second timeout is applied unless you pass your own `signal`.
- **Throws** if the protocol isn't `http(s)` or the host resolves to any internal address. Wrap in `try/catch` and fall back as needed:

```ts
import { safeFetch } from 'ssrf-fetch';

try {
  const res = await safeFetch(url);
  // ...use res
} catch (err) {
  // blocked protocol, blocked host, redirect, or timeout
}
```

### `addressIsBlocked(ip): boolean`

Classifies a resolved IP string as internal (`true`) or public (`false`). Useful if you resolve DNS yourself or want to validate an address without making a request.

```ts
import { addressIsBlocked } from 'ssrf-fetch';

addressIsBlocked('169.254.169.254'); // true
addressIsBlocked('1.1.1.1');         // false
```

## Limitations & scope

- **This is an egress guard, not an allowlist.** It blocks known-internal ranges. For the strongest posture, combine it with an explicit allowlist of hostnames you intend to reach.
- It does not proxy or sandbox the request body; it controls *where the connection is allowed to go*.
- It intentionally blocks all redirects. If you need to follow redirects to public hosts, resolve and re-validate each hop yourself.
- DNS resolution uses the system resolver (`node:dns`). Pinning defeats rebinding *between the check and the connect*; it does not defend against a fully compromised resolver returning a public IP for a genuinely internal name you meant to reach.

## License

MIT © Ian Duncan
