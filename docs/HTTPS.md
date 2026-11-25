# Serving the dashboard over HTTPS

The dashboard speaks plain HTTP and does not terminate TLS. It prints its
listening address at startup and defaults to `http://127.0.0.1:8787`. Put a
reverse proxy in front of it when browsers reach it over a network, and keep the
dashboard itself on loopback.

Sample configurations are shipped for
[nginx](../deploy/reverse-proxy/nginx/cvebeacon.conf) and
[Caddy](../deploy/reverse-proxy/caddy/Caddyfile). Treat every example
hostname, address, bind, certificate path and email address as a placeholder.
Replace `cvebeacon.example.com` with the dashboard's hostname, certificate
paths with the files on your server, and `you@example.com` with the ACME
contact address. `127.0.0.1` and `[::1]` stand for the server's loopback
addresses; keep the dashboard on loopback when the proxy is on the same
server. `0.0.0.0` is shown only as an unsafe wildcard bind. The documentation
address `203.0.113.10` is a placeholder; replace it with your server's
internal address for the reachability test below.

## When HTTPS is needed

Use HTTPS whenever a browser reaches the dashboard over anything other than a
trusted local connection. Account passwords, session cookies, CSRF tokens and
observation data all cross that connection.

- A dashboard used only from the same host over `127.0.0.1` can stay on plain
  HTTP. The default loopback bind is not reachable from other hosts.
- Use HTTPS for every remote or multi-user deployment, including one on an
  internal network. Internal network traffic is not automatically trusted.
- Use HTTPS before enabling account login or the optional shared password for
  remote users. Built-in authentication does not encrypt credentials or cookies.
- HTTPS protects transport only. Keep authentication, permissions, host
  firewalling and operating-system updates in place as well.

The proxy must preserve the application at the URL root. The dashboard has no
prefix or subpath setting, so use a dedicated hostname such as
`https://cvebeacon.example.com/`, not `https://example.com/cvebeacon/`.

## Choose a certificate

### Internal network with an internal CA

An internal certificate authority avoids a public DNS dependency and keeps the
service private.

- With Caddy, `tls internal` in the sample issues from Caddy's local CA. Trust
  that root certificate on every client that uses the dashboard. `caddy trust`
  installs it in the local trust store where supported; otherwise export the
  local root certificate and install it through your normal endpoint management.
- With nginx, obtain a certificate and key for the dashboard hostname from your
  internal PKI, install them at the `ssl_certificate` and
  `ssl_certificate_key` paths, and distribute the issuing CA certificate to
  clients.
- The certificate must include the hostname clients use (a subject alternative
  name), and that hostname must resolve to the proxy.
- Internal certificates expire too. Track renewal the same way as public
  certificates.

### Certificate from your organisation's own CA

Your organisation's certificate authority can issue a certificate for the
dashboard hostname and deliver it as a PFX/PKCS#12 file. Extract its chain and
private key on the proxy server. Replace the example paths with your
certificate directory and bundle path, and replace `proxy` with the group your
proxy process runs under. The commands prompt for the bundle's password. They
create the private key as root-only first, then let only root and the proxy
group read the installed files:

```console
sudo install -d -o root -g proxy -m 0750 /path/to/cvebeacon-certs
sudo sh -c 'umask 077; openssl pkcs12 -in /path/to/organisation-certificate.pfx -clcerts -nokeys -out /path/to/cvebeacon-certs/dashboard-cert.pem'
sudo sh -c 'umask 077; openssl pkcs12 -in /path/to/organisation-certificate.pfx -cacerts -nokeys -out /path/to/cvebeacon-certs/organisation-chain.pem'
sudo sh -c 'umask 077; openssl pkcs12 -in /path/to/organisation-certificate.pfx -nocerts -noenc -out /path/to/cvebeacon-certs/dashboard-key.pem'
sudo sh -c 'umask 077; cat /path/to/cvebeacon-certs/dashboard-cert.pem /path/to/cvebeacon-certs/organisation-chain.pem > /path/to/cvebeacon-certs/fullchain.pem'
sudo chown root:proxy /path/to/cvebeacon-certs/fullchain.pem /path/to/cvebeacon-certs/dashboard-key.pem
sudo chmod 0640 /path/to/cvebeacon-certs/fullchain.pem /path/to/cvebeacon-certs/dashboard-key.pem
sudo rm /path/to/cvebeacon-certs/dashboard-cert.pem /path/to/cvebeacon-certs/organisation-chain.pem
```

Check that the public key derived from the certificate matches the one from
the private key. The two hashes must be identical:

OpenSSL versions older than 3.0 use `-nodes` instead of `-noenc`.

```console
openssl x509 -in /path/to/cvebeacon-certs/fullchain.pem -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
openssl pkey -in /path/to/cvebeacon-certs/dashboard-key.pem -pubout -outform DER | sha256sum
```

Check that the certificate covers the hostname clients use. Replace the
placeholder hostname with the dashboard's actual hostname:

```console
openssl x509 -in /path/to/cvebeacon-certs/fullchain.pem -noout -checkhost cvebeacon.example.com
```

Point nginx's `ssl_certificate` and `ssl_certificate_key`, or Caddy's `tls`, at
the full chain and key. Client trust is managed separately: install your
organisation's CA in the trust store on every client that uses the dashboard.
Installing the certificate on the proxy does not make client browsers trust
the issuing CA.

### Public Let's Encrypt certificate

Use a publicly trusted certificate when clients cannot install a private CA.

- Point a public DNS name at the proxy and allow inbound TCP 80 and 443. Caddy
  obtains and renews certificates automatically by default; remove the
  `tls internal` line from the sample and set a real ACME email address.
- With nginx, use an ACME client such as certbot to obtain and renew the
  certificate, then point `ssl_certificate` and `ssl_certificate_key` at the
  resulting files. Reload nginx after renewal.
- A public certificate publishes the hostname in certificate transparency logs.
  Use an internal CA if the dashboard hostname itself is sensitive.
- Use the HTTP challenge only when port 80 is reachable. A DNS challenge avoids
  exposing port 80 but needs DNS provider credentials.

## Keep the backend on loopback

Run the dashboard with its default bind:

```console
cvebeacon --config /var/lib/cvebeacon/cvebeacon.toml serve
```

Do not pass `--host 0.0.0.0` when a proxy is in front of it. If the dashboard
runs in a container, publish the port on loopback only, for example
`127.0.0.1:8787:8787`. The samples proxy only to `127.0.0.1:8787`.

The dashboard does not trust `X-Forwarded-For`, `X-Forwarded-Host`,
`X-Forwarded-Proto` or any other forwarded header. The samples send no forwarded
values and clear the client-supplied `Forwarded`, `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Port`, `X-Forwarded-Proto` and `X-Real-IP`
headers. The dashboard continues to use the directly connected peer address. Two
consequences matter:

- Every browser behind the proxy appears as the proxy's loopback address. Login
  backoff and origin limits are shared by all remote clients. Do not try to
  restore per-client limits with forwarded headers; the application ignores
  them by design.
- The dashboard checks the request `Host` header against the trusted host set
  for its bind address. For the default loopback bind that set is the bind host
  plus `localhost`, `127.0.0.1` and `[::1]`. The samples send
  `Host: 127.0.0.1:8787` to the backend, which is accepted. Forwarding the
  public hostname instead causes `Invalid request host.` responses. The
  dashboard ignores `X-Forwarded-Host`, so setting it does not repair a wrong
  `Host` header.

The dashboard also decides whether `/bootstrap` is local from the directly
connected peer address. A local reverse proxy makes every remote visitor appear
local. Create the first administrator account from the console or over a
trusted direct connection **before** exposing an empty account store through a
proxy. Never publish a dashboard whose account store is still empty. The shipped
samples return `404` for `/bootstrap` as an extra guard; create the first
administrator with `cvebeacon users add NAME --admin`, or remove that guard
temporarily while bootstrapping from a trusted local connection.

## Keep the updater health endpoint private

The dashboard's `/healthz` response includes its process ID, which the updater
checks through a direct loopback request. Keep this endpoint off the public
proxy by returning 404 for the exact path. The updater's check still reaches
the dashboard directly. If external uptime monitoring is needed, expose a
separate check deliberately.

For Caddy, add an exact path response inside the site block:

```caddyfile
cvebeacon.example.com {
    respond /healthz 404
    reverse_proxy 127.0.0.1:8787
}
```

For nginx, add an exact-match location in the server block:

```nginx
location = /healthz {
    return 404;
}
```

## Enable secure cookies

Set the cookie flag in the configuration used by `serve`:

```toml
[dashboard]
secure_cookie = true
```

Then restart the dashboard. The setting adds the `Secure` attribute to both the
session cookie and the account cookie. `HttpOnly` and `SameSite=Strict` are
always set. The flag does not enable TLS on the dashboard and does not change
session lifetimes.

- Leave `secure_cookie = true` whenever browsers use the HTTPS proxy.
- If a user reaches the same dashboard over plain HTTP while the flag is true,
  the browser will not send the cookie and login will appear to loop. Fix the
  access path or the proxy redirect rather than turning the flag off.
- A configuration-editor save reloads the dashboard, but host and port are
  `serve` command-line options; restart the service after changing them.

## Install a proxy sample

### nginx

1. Copy `deploy/reverse-proxy/nginx/cvebeacon.conf` to
   `/etc/nginx/conf.d/cvebeacon.conf`.
2. Replace `cvebeacon.example.com` and the `/etc/ssl/cvebeacon/...` certificate
   paths with your own values.
3. Run `sudo nginx -t` and reload nginx.

The sample redirects HTTP to HTTPS, enables TLS 1.2 and 1.3 with Mozilla
intermediate ECDHE ciphers, adds HSTS and the other security headers, limits
ordinary request bodies to 6 MB and client inventory uploads to 34 MB, and
allows 300 seconds for slow manual queries and report generation.
The nested upload location repeats `proxy_pass` because nginx does not inherit
that directive there; its other proxy settings are inherited from the parent.

### Caddy

1. Copy `deploy/reverse-proxy/caddy/Caddyfile` to `/etc/caddy/Caddyfile`, or
   import the file from an existing Caddyfile. The sample has no global options
   block, so it can be imported alongside one without a merge.
2. Replace `cvebeacon.example.com`.
3. Choose `tls internal` or remove it for a public certificate. For a public
   certificate, put `email you@example.com` in the Caddyfile's global options
   block. A Caddyfile has at most one global block and it must be first; if the
   existing file has none, add one before the site blocks.
4. Run `sudo caddy validate --config /etc/caddy/Caddyfile` and reload Caddy.

Caddy's reverse proxy has no short default response timeout, and the sample sets
explicit 300-second response-header, read and write timeouts, a 6 MB body limit
for ordinary requests and a 34 MB limit for client inventory uploads.

### HSTS

Send `Strict-Transport-Security` from exactly one HTTPS layer. The samples add
`max-age=31536000` without `includeSubDomains` or `preload`. Add
`includeSubDomains` only when every subdomain is served over HTTPS, and add
`preload` only after checking the domain against the HSTS preload list
requirements. Preload is difficult to undo and affects every subdomain.

Do not add HSTS in both the proxy and another load balancer, CDN or upstream
application. Duplicate values are unnecessary and make expiry or rollback
confusing.

## Firewall

Allow only the proxy ports, and confirm the dashboard port is not reachable from
other hosts. For example, with ufw:

```console
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Adjust the SSH rule to match the administrative access this host actually uses.
Do not add a rule for 8787. Confirm the listener:

```console
ss -ltnp | grep 8787
```

The output must show `127.0.0.1:8787` (or `[::1]:8787`), not `0.0.0.0:8787`.
Container runtimes can bypass host firewall rules for published ports; binding
the published port to loopback is what keeps the backend private.

## Test the result

Check the redirect and the TLS response:

```console
curl -I http://cvebeacon.example.com/
curl -I https://cvebeacon.example.com/
```

The HTTP request should return `301` (or `308`) with a `Location` header using
`https://`. The HTTPS response should return `200` for the dashboard or a login
redirect, and should include:

- `Strict-Transport-Security: max-age=31536000`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- a `Content-Security-Policy` that includes `frame-ancestors 'none'`
- no certificate warning in the browser

With an internal CA, pass the CA explicitly:

```console
curl --cacert /etc/ssl/cvebeacon/internal-ca.crt -I https://cvebeacon.example.com/
```

Inspect the login response headers to confirm the cookie flags:

```console
curl --cacert /etc/ssl/cvebeacon/internal-ca.crt -sS -D - -o /dev/null \
  https://cvebeacon.example.com/login
```

Use the same `--cacert` flag as above when the CA is not in the system trust
store; omit it for a publicly trusted certificate.

After a successful login, the `Set-Cookie` lines must include `Secure`,
`HttpOnly` and `SameSite=Strict`. Also confirm that canonical redirects stay on
the public origin. Request a route without its trailing slash, for example
`https://cvebeacon.example.com/operations`. The `308` response must not contain
`127.0.0.1:8787` in its `Location` header; the samples rewrite the backend origin
to the public origin or a relative path and keep any query string.

Also confirm that the backend is not reachable from another host:

```console
curl -I --max-time 3 http://203.0.113.10:8787/
```

Replace `203.0.113.10` with the proxy host's address. That request must fail or
time out. `203.0.113.10` is a documentation-range placeholder; replace it
with your server's internal address.

## Troubleshooting

Check the three connections in order so each result points to one part of the
path:

1. **Proxy listener on the server.** From the server, send HTTPS to the local
   proxy address while keeping the dashboard hostname for TLS:

   ```console
   curl --max-time 5 --resolve cvebeacon.example.com:443:127.0.0.1 \
     --cacert /path/to/organisation-ca.pem -sS -o /dev/null -w '%{http_code}\n' \
     https://cvebeacon.example.com/
   ```

   For a publicly trusted certificate, omit `--cacert`. A connection refusal
   or timeout points to the proxy service or listener. An HTTP response means
   the local listener answered.
2. **Client network reachability.** From a client machine, check TCP port 443:

   ```console
   nc -vz -w 3 cvebeacon.example.com 443
   ```

   A failed connection points to name resolution, routing or a firewall between
   that client and the proxy.
3. **Certificate trust on that client.** Open the dashboard in the browser, or
   check the certificate chain from the same client with `openssl s_client`:

   ```console
   openssl s_client -connect cvebeacon.example.com:443 \
     -servername cvebeacon.example.com -verify_return_error \
     -CAfile /path/to/organisation-ca.pem </dev/null
   ```

   Trust is per client. A browser on a managed machine may trust your
   organisation's CA while `curl` on another host reports a certificate error
   and prints
   `000`, because that client has no trusted issuer and received no HTTP
   response. For a certificate issued by your organisation's CA, that trust
   error means the client needs that CA; it does not mean the network route is
   broken. Test by passing the CA to curl:

   ```console
   curl --cacert /path/to/organisation-ca.pem --max-time 20 -sS \
     -o /dev/null -w '%{http_code}\n' https://cvebeacon.example.com/
   ```

   Install the organisation's CA through normal device management so browsers
   and other clients trust it without a per-command option.

## Common mistakes

- **Exposing 8787.** Leaving `--host 0.0.0.0`, publishing a container port
  without a loopback address, or allowing 8787 in the firewall bypasses the TLS
  proxy entirely. The dashboard then serves plain HTTP with credentials.
- **Double HSTS.** Adding HSTS in the proxy, the CDN and the upstream application
  makes the effective policy unclear. Keep one source.
- **Wrong Host header.** `proxy_set_header Host $host` or Caddy's `{host}`
  sends the public hostname to a loopback-bound dashboard and produces
  `Invalid request host.` Use the backend address. The dashboard ignores
  `X-Forwarded-Host`, so setting it neither causes nor fixes that check.
- **Serving under a subpath.** The dashboard has no prefix setting. A `/cvebeacon/`
  location breaks links, static assets, form actions and redirects. Use a
  dedicated hostname at the root.
- **Forgetting `secure_cookie = true`.** Cookies can travel over plain HTTP if
  the backend is accidentally reached directly. Set the flag for every
  browser-facing HTTPS deployment.
- **Setting `secure_cookie = true` while still testing over HTTP.** The browser
  drops the cookie and login loops. Test through the HTTPS URL.
- **Exposing an empty account store.** Bootstrap accepts only loopback peers, so
  remote visitors appear local through the proxy. The samples return `404` for
  `/bootstrap` as defense in depth, but create the first administrator with
  `cvebeacon users add NAME --admin` before opening the proxy.
- **Trusting forwarded addresses.** The dashboard ignores them. Per-client login
  throttling behind one proxy is shared by design; do not weaken or bypass it.
- **A proxy body limit below the upload size.** Statement uploads need at least
  5 MiB plus framing. Client inventory uploads need 32 MiB plus multipart
  framing at `/watch/clients/<key>/upload`. The samples keep other requests at
  6 MB and allow 34 MB on that inventory route.
- **Short proxy timeouts.** Manual queries and report generation can run for
  several minutes. Both samples allow 300 seconds; keep equivalent limits in any
  other proxy.
- **Plain HTTP on the internal network.** Internal networks are not inherently
  trusted. Use an internal CA rather than skipping TLS.
