# gdns2tcp

DNS tunnel that moves files and proxies TCP traffic through TXT records.

- **File transfer** — upload / download files up to 32 / 256 MiB
- **Client self-distribution** — server serves its own client binaries via DNS, no pre-installed tooling required
- **Reverse SOCKS5** — agent inside a private network polls the server; operator connects to the server's SOCKS5 port and exits from the agent

All payloads are gzip + AES-256-CBC (PBKDF2-SHA256, 100 k iter) with HMAC-SHA256.
Every DNS query carries a per-minute HMAC token.

| Component | Platform | Notes |
|---|---|---|
| `gdns2tcp` | Linux, macOS | Authoritative DNS server |
| `gdns2tcp-client` | Linux, macOS, Windows | ~3 MB, static, no CGO |
| `gdns2tcp-client.ps1` | Windows (PS 5.1+) | Single self-contained script, no .exe needed |
| `gdns2tcp-client-proxy` | Linux, macOS, Windows | Reverse SOCKS5 agent |

---

## Throughput

10 MiB end-to-end throughput over a real VPS (client → authoritative NS
over the Internet, ~50 ms RTT). Incompressible random fixture; every
transfer is SHA256-verified.

| Client                        | Direction | DNS                  | Size   | Elapsed  | Throughput |
| ----------------------------- | --------- | -------------------- | ------ | -------- | ---------- |
| `gdns2tcp-client`             | Download  | UDP direct           | 10 MiB |    8.19s |  9.77 Mbps |
| `gdns2tcp-client`             | Download  | TCP direct           | 10 MiB |    8.76s |  9.13 Mbps |
| `gdns2tcp-client`             | Download  | UDP public resolver¹ | 10 MiB |  191.13s |  0.42 Mbps |
| `gdns2tcp-client`             | Download  | TCP public resolver  | 10 MiB |   27.58s |  2.90 Mbps |
| `gdns2tcp-client`             | Upload    | UDP direct           | 10 MiB |  317.88s |  0.25 Mbps |
| `gdns2tcp-client`             | Upload    | TCP direct           | 10 MiB |  153.35s |  0.52 Mbps |
| `gdns2tcp-client`             | Upload    | UDP public resolver  | 10 MiB |  322.48s |  0.25 Mbps |
| `gdns2tcp-client`             | Upload    | TCP public resolver  | 10 MiB |  196.28s |  0.41 Mbps |
| `gdns2tcp-client.ps1`         | Download  | UDP direct           | 10 MiB |   11.02s |  7.26 Mbps |
| `gdns2tcp-client.ps1`         | Download  | TCP direct           | 10 MiB |   13.31s |  6.01 Mbps |
| `gdns2tcp-client.ps1`         | Upload    | UDP direct           | 10 MiB |  207.67s |  0.39 Mbps |
| `gdns2tcp-client.ps1`         | Upload    | TCP direct           | 10 MiB |  174.09s |  0.46 Mbps |
| `gdns2tcp-client-proxy`       | Download  | UDP direct           | 10 MiB |   78.28s |  1.02 Mbps |
| `gdns2tcp-client-proxy`       | Download  | TCP direct           | 10 MiB |  221.35s |  0.36 Mbps |

- **Direct** — `-ds` points at the authoritative server IP, bypassing recursion.
  **Public resolver** — queries go through 1.1.1.1; most resolvers rate-limit bulk TXT lookups. TCP is ~2–6× faster than UDP through public resolvers.
- ¹ Public resolver UDP downloads require `-batch 1` (default batch of 14 exceeds the UDP response size through recursion).
- Downloads use 32 parallel workers × 14-chunk batches. Uploads use 32 parallel workers, one chunk per query, out-of-order delivery.
- **Proxy** rows are curl through the reverse-SOCKS5 tunnel (operator → server:9050 → DNS → agent → target).

---

## Quick start

### 1. Build

```sh
make clients servers     # cross-compile all binaries → ./clients + ./servers
make build               # current platform only → ./servers/gdns2tcp, ./gdns2tcp-client, ./gdns2tcp-client-proxy
```
### 2. Run the server

```sh
sudo ./servers/gdns2tcp -domain files.example.com -p "change-me"
```

Listens on UDP+TCP :53 and serves client binaries from `./clients`.

### 3. Delegate the DNS zone

Add NS + A records in the **parent** zone so that recursive resolvers
forward queries for `files.example.com` to your server:

| Type | Name | Value |
|---|---|---|
| `NS` | `files.example.com.` | `ns1.example.com.` |
| `A`  | `ns1.example.com.` | `<server-ip>` |

After starting the server (step 3), verify that delegation works:

```sh
dig +short TXT EnCoDiNg.test.files.example.com    # → "base64"
```

If you see `"base64"` — the recursive resolver successfully reached
gdns2tcp through the delegation. gdns2tcp only answers TXT queries;
`dig NS` against it will return an empty response — that is expected.

For local/private testing without delegation, pass `-ds <server-ip>` to
every client instead.

### 4. Fetch a client over DNS

The server returns a bootstrap shell script as a DNS TXT record — no
pre-installed client needed:

```sh
# Go file client — auto-detects OS/arch
dig +short +tcp TXT boot.files.example.com | tr -d '" ' | base64 -d | sh

# Go proxy agent
dig +short +tcp TXT boot-proxy.files.example.com | tr -d '" ' | base64 -d | sh

# PowerShell client
dig +short +tcp TXT boot-ps1.files.example.com | tr -d '" ' | base64 -d | sh
```

**Windows PowerShell** (no `dig` needed — uses `Resolve-DnsName` or
`nslookup`):

```powershell
# Go file client (.exe) — auto-detects arch
$t=(Resolve-DnsName pboot.files.example.com -Type TXT -TcpOnly).Strings -join ""
iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)))

# PowerShell client (.ps1)
$t=(Resolve-DnsName pboot-ps1.files.example.com -Type TXT -TcpOnly).Strings -join ""
iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)))

# Proxy agent (.exe)
$t=(Resolve-DnsName pboot-proxy.files.example.com -Type TXT -TcpOnly).Strings -join ""
iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)))
```

To query the server directly (before delegation is live):

```sh
dig +short +tcp @<server-ip> TXT boot.files.example.com | tr -d '" ' | base64 -d | S=<server-ip> sh
```

```powershell
$t=(Resolve-DnsName pboot.files.example.com -Type TXT -TcpOnly -Server <server-ip>).Strings -join ""
$S="<server-ip>"; iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)))
```

### 5. Transfer files

```sh
# Linux / macOS
./gdns2tcp-client -d files.example.com -p "change-me" --list
./gdns2tcp-client -d files.example.com -p "change-me" --upload ./sample.txt
./gdns2tcp-client -d files.example.com -p "change-me" --download sample.txt -out ./sample.copy.txt
```

```powershell
# Windows — Go client (.exe) or PowerShell (.ps1)
.\gdns2tcp-client-windows-amd64.exe -d files.example.com -p "change-me" --list
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode List
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Upload -InFile .\sample.txt
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Download -Filename sample.txt -OutFile .\sample.copy.txt
```

Add `-tcp` (Go) or `-Tcp` (PowerShell) if UDP is blocked.

---

## Reverse SOCKS5

```
operator ── TCP/SOCKS5 ──> server:9050 ── DNS tunnel ──> agent ──> upstream
```

The agent polls the server from inside a private network. The operator
connects to the server's SOCKS5 port; traffic exits from the agent.
Tunnel encryption: AES-256-GCM keyed by `(secret, cid)`.

### Setup

```sh
# Server — enable proxy and expose SOCKS5
sudo ./servers/gdns2tcp -domain files.example.com -p "change-me" \
  -allow-proxy -socks-listen 0.0.0.0:9050 -socks-no-auth
```

```sh
# Agent (Linux / macOS) — fetch and run
dig +short +tcp TXT boot-proxy.files.example.com | tr -d '" ' | base64 -d | sh
./gdns2tcp-client-proxy -d files.example.com -p "change-me"
```

```powershell
# Agent (Windows) — fetch and run
$t=(Resolve-DnsName pboot-proxy.files.example.com -Type TXT -TcpOnly).Strings -join ""
iex([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)))
.\gdns2tcp-client-proxy-windows-amd64.exe -d files.example.com -p "change-me"
```

SOCKS5 binds `127.0.0.1:9050` by default after the first agent connects.
Add `-socks-no-auth=false` to enable RFC 1929 auth (user `gdns2tcp`,
password = `-p` value).

---

## Advanced

### Deploy to a remote host

```sh
make clients servers
HOST=root@<server-ip>
ssh $HOST 'mkdir -p ~/gdns2tcp/clients ~/gdns2tcp/data'
scp servers/gdns2tcp-server-linux-amd64 $HOST:~/gdns2tcp/gdns2tcp
scp clients/* $HOST:~/gdns2tcp/clients/
ssh $HOST '~/gdns2tcp/gdns2tcp \
  -domain files.example.com \
  -p "change-me" \
  -listen 0.0.0.0 \
  -data-dir ~/gdns2tcp/data \
  -clients-dir ~/gdns2tcp/clients'
```

For ARM64 hosts, replace `linux-amd64` with `linux-arm64`. Add
`-allow-proxy -socks-listen 0.0.0.0:9050 -socks-no-auth` to enable
the reverse SOCKS5 tunnel.

### Multi-domain sharding

Public resolvers rate-limit per authoritative zone. Delegating several
zones to the same server lets clients round-robin QNAME suffixes:

| Type | Name | Value |
|---|---|---|
| `NS` | `files.example.com.`  | `ns1.example.com.` |
| `NS` | `files1.example.com.` | `ns1.example.com.` |
| `NS` | `files2.example.com.` | `ns1.example.com.` |
| `A`  | `ns1.example.com.`    | `<server-ip>` |

```sh
sudo ./gdns2tcp -domain files.example.com,files1.example.com,files2.example.com -p "change-me"
```

The first domain is canonical (HMAC signatures are computed under it).
Clients accept the same CSV form in their `-domain` flag.

### Transfer limits

| Parameter | Default | Flag |
|---|---|---|
| Max upload size | 32 MiB | `-max-upload-bytes` |
| Max download source | 256 MiB | `-max-download-bytes` |
| Server cache | 1 GiB, 24 h TTL | `-cache-max-bytes`, `-cache-ttl` |

Downloads are compressed and encrypted as streaming disk spools — neither
side holds the full transfer in RAM. The Go client resumes incomplete
downloads automatically (`-no-resume` to disable).
