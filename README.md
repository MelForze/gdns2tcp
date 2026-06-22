# gdns2tcp

File-transfer utility that tunnels uploads and downloads through DNS TXT
records.

- **Server** (Go) — authoritative DNS handler that stores files and serves
  client binaries
- **Unix client** (Go) — ~3 MB stripped, no CGO, no external dependencies
- **Windows client** (PowerShell 5.1+) — single self-contained script

All payloads are gzip-compressed, AES-256-CBC encrypted with PBKDF2-SHA256
(100k iterations), and HMAC-SHA256 authenticated. Every DNS query carries an
HMAC token tied to the current minute.

---

## Quick start

The steps below take you from a fresh clone to a working file transfer.
All commands assume the working directory is the repo root and that the
server runs on a host reachable on UDP+TCP port 53.

### 1. Build everything

```sh
make clients servers
```

Produces:

- `clients/gdns2tcp-client-linux-amd64`, `…-linux-arm64`,
  `…-darwin-amd64`, `…-darwin-arm64`, `gdns2tcp-client.ps1`
- `servers/gdns2tcp-server-linux-amd64`, `…-linux-arm64`,
  `…-darwin-amd64`, `…-darwin-arm64`

For only the current platform:

```sh
make build      # → ./gdns2tcp and ./gdns2tcp-client
```

### 2. Run the server

```sh
sudo ./servers/gdns2tcp-server-linux-amd64 -domain files.example.com -secret "change-me"
```

The server listens on **both UDP and TCP** at `0.0.0.0:53` and serves
client binaries from `./clients` automatically. Pick the matching server
binary for your OS/arch, or use `./gdns2tcp` if you ran `make build`.
Binding to port 53 requires root.

### 3. Fetch the client over DNS

The server publishes its own client binaries through public DNS endpoints
(no secret required) so a fresh host can bootstrap. Replace `<server-ip>`
with the host running gdns2tcp. Pick one snippet below.

**Linux / macOS** — auto-detects OS+arch. Uses only default utilities
(`dig`, `base64`, `shasum`). Fetches 14 chunks per query via the batched
`clb-` endpoint and runs 16 batches in parallel via background jobs:

```sh
D=files.example.com S=<server-ip> B=14 P=16 sh <<'EOF'
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="$os-$a"
NL=$(printf '\n')
q(){ for i in 1 2 3 4 5; do o=$(dig +short +time=5 +tries=1 @$S "$1" TXT | tr -d "\"$NL "); [ -n "$o" ] && { printf %s "$o"; return; }; sleep 0.4; done; echo "no TXT for $1" >&2; return 1; }
m=$(q "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
TOTAL=$(( (N + B - 1) / B ))
T=$(mktemp -d); i=0; k=0
while [ $i -lt $N ]; do
    c=$B; [ $((i + c)) -gt $N ] && c=$((N - i))
    (q "$i.$c.clb-$A.$D" > "$T/$k" || touch "$T/.err") &
    i=$((i + c)); k=$((k + 1))
    [ $((k % P)) -eq 0 ] && { wait; printf "\rfetched %d/%d batches" "$k" "$TOTAL" >&2; }
done
wait
printf "\rfetched %d/%d batches\n" "$k" "$TOTAL" >&2
[ -f "$T/.err" ] && { rm -rf "$T"; echo "fetch failed" >&2; exit 1; }
F=$(mktemp); j=0
while [ $j -lt $k ]; do cat "$T/$j" >> "$F"; j=$((j + 1)); done
rm -rf "$T"
base64 -d < "$F" > "$NAME" 2>/dev/null || base64 -D < "$F" > "$NAME"
rm "$F"
printf "%s  %s\n" "$SHA" "$NAME" | shasum -a 256 -c - || { rm -f "$NAME"; exit 1; }
chmod +x "$NAME"; echo "saved ./$NAME"
EOF
```

**Windows PowerShell** — requires `nslookup`. Uses TCP (`-vc`) so the larger
batched responses are not capped by Windows' default 512-byte UDP DNS buffer:

```powershell
$D="files.example.com"; $S="<server-ip>"; $B=14
function q($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
$man=q "client-win.$D"; $p=$man.Split('|')
$name=$p[0]; $n=[int]$p[1]; $sha=$p[2].ToLower()
$total = [int][Math]::Ceiling($n / $B)
$b64=''; $i=0; $j=0
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    $b64 += q "$i.$c.clb-win.$D"
    $i += $c; $j++
    Write-Progress -Activity "Fetching client" -Status "$j of $total batches" -PercentComplete ([Math]::Min(100, [Math]::Round($j * 100 / $total, 1)))
}
Write-Progress -Activity "Fetching client" -Completed
$out=Join-Path (Get-Location) $name
[IO.File]::WriteAllBytes($out, [Convert]::FromBase64String($b64))
if((Get-FileHash $out -Algorithm SHA256).Hash.ToLower() -ne $sha){
    Remove-Item $out -Force; throw "sha256 mismatch" }
"Saved $out"
```

After this step you have an executable client in the current directory:
`gdns2tcp-client-<os>-<arch>` or `gdns2tcp-client.ps1`.

### 4. List files on the server

#### Linux / macOS

```sh
./gdns2tcp-client-linux-amd64 -domain files.example.com -pass "change-me" -mode list
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode List
```

### 5. Upload a file to the server

#### Linux / macOS

```sh
./gdns2tcp-client-linux-amd64 -domain files.example.com -pass "change-me" -mode upload -in ./sample.txt
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Upload -InFile .\sample.txt
```

### 6. Download a file from the server

#### Linux / macOS

```sh
./gdns2tcp-client-linux-amd64 -domain files.example.com -pass "change-me" -mode download -filename sample.txt -out ./sample.copy.txt
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Download -Filename sample.txt -OutFile .\sample.copy.txt
```

Add `-tcp` (Go) or `-Tcp` (PowerShell) to force DNS over TCP — useful when
intermediate resolvers truncate large UDP responses or block UDP/53.

---

## Reverse SOCKS5 — browse the agent's network

The reverse mode turns gdns2tcp into a way to **see what the agent sees**: an
internal-network machine runs `gdns2tcp-client-proxy` (the *agent*), polls
the public server through DNS, and dials upstream services locally. Your
host connects to `socks5://server:9050` as a normal SOCKS5 proxy — no DNS
client involved — and traffic emerges from the agent's vantage point.

```
operator ── TCP/SOCKS5 ──> server:9050 ── DNS tunnel ──> agent ──> upstream
(your host)                (rendezvous)                  (inside)   (target net)
```

The server holds plaintext bytes only briefly (just queueing for the next
agent poll); the agent↔server DNS traffic is encrypted with AES-256-GCM
keyed by `(secret, cid)`. Multiple concurrent SOCKS5 sessions are
multiplexed via 16-hex `cid` per tunnel.

### Enable on the server

Add `-allow-proxy` to your server invocation. Off by default:

```sh
sudo ./servers/gdns2tcp-server-linux-amd64 -domain files.example.com -secret "change-me" -allow-proxy
```

This starts a TCP SOCKS5 listener on **`0.0.0.0:9050`**. SOCKS5
**username/password authentication is required** (RFC 1929): username =
`gdns2tcp`, password = the `-secret` value, so the open port is not
actually usable without the secret.

| Flag | Default | Description |
|---|---|---|
| `-allow-proxy` | `false` | enable reverse SOCKS5 + agent endpoints |
| `-socks-listen` | `0.0.0.0:9050` | TCP address for the operator-facing SOCKS5 listener |
| `-proxy-max-conn` | `64` | global cap on concurrent tunnel connections |
| `-proxy-buf-bytes` | `1048576` | per-tunnel buffer cap in each direction |

### Fetch the agent binary over DNS

The agent is distributed under `client-proxy-<os>-<arch>` aliases (Linux
amd64/arm64, macOS amd64/arm64, Windows amd64/arm64 `.exe`).

**Linux / macOS** — auto-detects OS+arch:

```sh
D=files.example.com S=<server-ip> B=14 P=16 sh <<'EOF'
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="client-proxy-$os-$a"
NL=$(printf '\n')
q(){ for i in 1 2 3 4 5; do o=$(dig +short +time=5 +tries=1 @$S "$1" TXT | tr -d "\"$NL "); [ -n "$o" ] && { printf %s "$o"; return; }; sleep 0.4; done; echo "no TXT for $1" >&2; return 1; }
m=$(q "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
TOTAL=$(( (N + B - 1) / B ))
T=$(mktemp -d); i=0; k=0
while [ $i -lt $N ]; do
    c=$B; [ $((i + c)) -gt $N ] && c=$((N - i))
    (q "$i.$c.clb-$A.$D" > "$T/$k" || touch "$T/.err") &
    i=$((i + c)); k=$((k + 1))
    [ $((k % P)) -eq 0 ] && { wait; printf "\rfetched %d/%d batches" "$k" "$TOTAL" >&2; }
done
wait
printf "\rfetched %d/%d batches\n" "$k" "$TOTAL" >&2
[ -f "$T/.err" ] && { rm -rf "$T"; echo "fetch failed" >&2; exit 1; }
F=$(mktemp); j=0
while [ $j -lt $k ]; do cat "$T/$j" >> "$F"; j=$((j + 1)); done
rm -rf "$T"
base64 -d < "$F" > "$NAME" 2>/dev/null || base64 -D < "$F" > "$NAME"
rm "$F"
printf "%s  %s\n" "$SHA" "$NAME" | shasum -a 256 -c - || { rm -f "$NAME"; exit 1; }
chmod +x "$NAME"; echo "saved ./$NAME"
EOF
```

**Windows PowerShell** — pulls `client-proxy-windows-amd64.exe` (or `arm64`):

```powershell
$D="files.example.com"; $S="<server-ip>"; $B=14
$ARCH = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "arm64" }
$A = "client-proxy-windows-$ARCH"
function q($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
$man=q "client-$A.$D"; $p=$man.Split('|')
$name=$p[0]; $n=[int]$p[1]; $sha=$p[2].ToLower()
$total = [int][Math]::Ceiling($n / $B)
$b64=''; $i=0; $j=0
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    $b64 += q "$i.$c.clb-$A.$D"
    $i += $c; $j++
    Write-Progress -Activity "Fetching agent" -Status "$j of $total batches" -PercentComplete ([Math]::Min(100, [Math]::Round($j * 100 / $total, 1)))
}
Write-Progress -Activity "Fetching agent" -Completed
$out=Join-Path (Get-Location) $name
[IO.File]::WriteAllBytes($out, [Convert]::FromBase64String($b64))
if((Get-FileHash $out -Algorithm SHA256).Hash.ToLower() -ne $sha){
    Remove-Item $out -Force; throw "sha256 mismatch" }
"Saved $out"
```

### Run the agent (on the internal-network machine)

```sh
# Linux / macOS
./gdns2tcp-client-proxy-linux-amd64 -domain files.example.com -pass "change-me"
```

```powershell
# Windows
.\gdns2tcp-client-proxy-windows-amd64.exe -domain files.example.com -pass "change-me"
```

The agent has no flags for the SOCKS5 port — it doesn't listen at all. It
just polls the server and dials whatever target the operator's SOCKS5
session asks for.

### Use the tunnel

Point any SOCKS5 client at `<server-ip>:9050` (user `gdns2tcp`,
password `<-secret>`); browsers and ssh's `ProxyCommand=ncat --proxy`
both work the same way.

```sh
curl --socks5-hostname --proxy-user "gdns2tcp:change-me" \
     socks5h://<server-ip>:9050 https://internal-service.corp/
```

### Throughput limits

The proxy is fundamentally throughput-limited by the DNS wire format. Each
`awrite` chunk goes inside a single DNS query name (RFC 1035 caps QNAME at
253 chars total), which after the `cid . seq . chunks . smac . cmd .
domain` overhead leaves ~96 bytes of plaintext per round-trip. This limit
applies to **both UDP and TCP DNS transports** — the QNAME ceiling is part
of the DNS message format, not the transport layer.

At 30 ms RTT × 16 parallel workers the theoretical ceiling is ~50 KB/s on
write-heavy direction (operator→upstream); in practice expect **20–30 KB/s**
on a typical WAN. Aggregate download speed through the proxy will not
significantly exceed this regardless of transport.

#### What `-tcp` actually changes

`-tcp` swaps the agent's DNS transport from UDP to TCP. This helps only on
**responses** (server→agent): `MaxReadBytesTCP=48000` vs `MaxReadBytes=5600`
on UDP. That lifts the **read-heavy direction** (upstream→operator pulls,
e.g. file uploads through the proxy) by ~8×.

| Direction | Bottleneck | UDP | TCP |
|---|---|---|---|
| operator→upstream (write to remote via proxy) | response size | 30 KB/s | **~240 KB/s** |
| upstream→operator (response body, download) | QNAME 253-char limit | 30 KB/s | 30 KB/s (same) |
| interactive (SSH keystrokes) | RTT, not throughput | ~RTT | ~RTT |
| port-scan | many small queries | better (UDP mux) | worse (TCP HoL) |

**Rule of thumb:**
- Bulk **upload** through the proxy → `-tcp` helps a lot.
- Bulk **download** through the proxy → roughly the same on either transport (QNAME-bound).
- SSH, REPL, port-scan → UDP is the right default.

If you need real bulk download speed through this tunnel, the DNS protocol
isn't the right transport for that workload — that's the cost of using DNS
as the only allowed channel.

---

## Reference

### Server flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Authoritative domain, e.g. `files.example.com` |
| `-secret` | *(required)* | Shared secret for HMAC auth and payload encryption |
| `-listen` | `0.0.0.0` | Listen address (all interfaces by default) |
| `-port` | `53` | Listen port (UDP and TCP both bound) |
| `-data-dir` | `.` | Directory for uploaded/downloaded files |
| `-clients-dir` | `clients` | Directory of client artifacts served over DNS |
| `-max-upload-bytes` | 33 MiB | Maximum protected upload payload accepted |
| `-max-download-bytes` | 33 MiB | Maximum source file size for downloads |
| `-disable-list` | `false` | Disable the `list` (catalog) command |
| `-allow-proxy` | `false` | Enable reverse SOCKS5 listener + agent DNS endpoints |
| `-socks-listen` | `0.0.0.0:9050` | TCP address for the operator-facing SOCKS5 listener |
| `-proxy-max-conn` | `64` | Maximum concurrent tunnel connections |
| `-proxy-buf-bytes` | 1 MiB | Per-tunnel buffer cap in each direction |

### Go client flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Server's authoritative domain |
| `-mode` | *(required)* | `test`, `list`, `upload`, or `download` |
| `-pass` | *(required for list/upload/download)* | Shared secret (must match server) |
| `-dns-server` | resolves `-domain` | DNS server IP |
| `-dns-port` | `53` | DNS server port |
| `-tcp` | `false` | Use DNS over TCP instead of UDP |
| `-in` | — | Local file to upload (`-mode upload`) |
| `-out` | — | Local destination for download (`-mode download`) |
| `-filename` | — | Remote filename to download (`-mode download`) |
| `-chunk-size` | `180` | Maximum encoded upload chunk size |
| `-retries` | `3` | DNS query attempts before failing |
| `-parallelism` | `32` | Concurrent DNS queries during download (1–64) |
| `-batch` | `14` | Chunks per DNS response when downloading (1–32) |
| `-max-download-bytes` | 32 MiB | Maximum decompressed download size |

### PowerShell client parameters

| Parameter | Default | Description |
|---|---|---|
| `-Domain` | *(required)* | Server's authoritative domain |
| `-Mode` | *(required)* | `test`, `list`, `upload`, or `download` |
| `-Pass` | *(required for list/upload/download)* | Shared secret (must match server) |
| `-DnsServer` | resolves `-Domain` | DNS server IP |
| `-DnsPort` | `53` | DNS server port |
| `-Tcp` | `false` | Use DNS over TCP instead of UDP |
| `-InFile` | — | Local file to upload (`-Mode upload`) |
| `-OutFile` | — | Local destination for download (`-Mode download`) |
| `-Filename` | — | Remote filename to download (`-Mode download`) |
| `-ChunkSize` | `180` | Maximum encoded upload chunk size |
| `-Retries` | `3` | DNS query attempts before failing |
| `-RetryDelaySeconds` | `2` | Sleep between retry attempts |
| `-LogPath` | — | Optional log file path |
| `-Parallelism` | `32` | Concurrent DNS queries during download (1–64) |
| `-BatchSize` | `14` | Chunks per DNS response when downloading (1–32) |
| `-MaxDownloadBytes` | 32 MiB | Maximum decompressed download size |

### Agent flags (`gdns2tcp-client-proxy`)

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Server's authoritative domain |
| `-pass` | *(required)* | Shared secret (must match server) |
| `-dns-server` | resolves `-domain` | DNS server IP |
| `-dns-port` | `53` | DNS server port |
| `-tcp` | `false` | Use DNS over TCP instead of UDP |
| `-poll-min` | `20ms` | Minimum `apoll`/`axchg` interval when active |
| `-poll-max` | `200ms` | Maximum interval after consecutive idle responses |
| `-max-conn` | `32` | Maximum concurrent local tunnels (1–512) |
| `-retries` | `3` | DNS query attempts before failing (apoll only — `axchg` uses fresh nonces, so no retry) |
| `-target-dial-timeout` | `1s` | TCP dial timeout when the agent connects to the host the operator's SOCKS5 CONNECT requested. Lower values speed up port-scan workflows (filtered ports release their cid faster); raise for legitimately slow upstreams |
