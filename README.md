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
sudo mkdir -p ./data && sudo ./servers/gdns2tcp-server-linux-amd64 -domain files.example.com -secret "change-me" -listen 0.0.0.0 -port 53 -data-dir ./data
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
D=files.example.com S=<server-ip> B=14 P=16 sh -c '
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="$os-$a"
q(){ for i in 1 2 3 4 5; do o=$(dig +short +time=5 +tries=1 @$S "$1" TXT | tr -d "\" \n"); [ -n "$o" ] && { printf %s "$o"; return; }; sleep 0.4; done; echo "no TXT for $1" >&2; return 1; }
m=$(q "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
T=$(mktemp -d); i=0; k=0
while [ $i -lt $N ]; do
    c=$B; [ $((i + c)) -gt $N ] && c=$((N - i))
    (q "$i.$c.clb-$A.$D" > "$T/$k" || touch "$T/.err") &
    i=$((i + c)); k=$((k + 1))
    [ $((k % P)) -eq 0 ] && wait
done
wait
[ -f "$T/.err" ] && { rm -rf "$T"; echo "fetch failed" >&2; exit 1; }
F=$(mktemp); j=0
while [ $j -lt $k ]; do cat "$T/$j" >> "$F"; j=$((j + 1)); done
rm -rf "$T"
base64 -d < "$F" > "$NAME" 2>/dev/null || base64 -D < "$F" > "$NAME"
rm "$F"
printf "%s  %s\n" "$SHA" "$NAME" | shasum -a 256 -c - || { rm -f "$NAME"; exit 1; }
chmod +x "$NAME"; echo "saved ./$NAME"
'
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
$b64=''; $i=0
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    $b64 += q "$i.$c.clb-win.$D"
    $i += $c
}
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

## Reference

### Server flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Authoritative domain, e.g. `files.example.com` |
| `-secret` | *(required)* | Shared secret for HMAC auth and payload encryption |
| `-listen` | *(required)* | Listen address, e.g. `0.0.0.0` |
| `-port` | `53` | Listen port (UDP and TCP both bound) |
| `-data-dir` | `.` | Directory for uploaded/downloaded files |
| `-clients-dir` | `clients` | Directory of client artifacts served over DNS |
| `-max-upload-bytes` | 33 MiB | Maximum protected upload payload accepted |
| `-max-download-bytes` | 33 MiB | Maximum source file size for downloads |
| `-disable-list` | `false` | Disable the `list` (catalog) command |

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

Mirror the Go flags with PascalCase names: `-Domain`, `-Mode`, `-Pass`,
`-DnsServer`, `-DnsPort`, `-Tcp`, `-InFile`, `-OutFile`, `-Filename`,
`-ChunkSize`, `-Retries`, `-RetryDelaySeconds`, `-LogPath`,
`-MaxDownloadBytes`, `-Parallelism`, `-BatchSize`.

### DNS endpoints

Client manifests return `filename|chunk_count|sha256`:

```
client-<alias>.<domain>          manifest
<idx>.cl-<alias>.<domain>        one chunk per query (legacy / fallback)
<from>.<count>.clb-<alias>.<domain>   up to 14 chunks per query (preferred)
```

`<alias>` is one of `win`, `linux-amd64`, `linux-arm64`, `darwin-amd64`,
`darwin-arm64`. These endpoints are unauthenticated by design so a new host
can bootstrap a client without already knowing the secret. The transfer
endpoints (`uinit`/`u` for upload, `dinit`/`d`/`db` for download, `c` for
catalog) all require the HMAC token derived from `-secret`.
