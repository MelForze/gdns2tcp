# gdns2tcp

File-transfer utility that tunnels uploads and downloads through DNS TXT
records. Designed for authorized administration of owned infrastructure,
lab/CTF setups, and training environments.

- **Server** (Go) — authoritative DNS handler that stores files and serves
  client binaries
- **Unix client** (Go) — ~3 MB stripped, no CGO, no external dependencies
- **Windows client** (PowerShell 5.1+) — single self-contained script

All payloads are gzip-compressed, AES-256-CBC encrypted with PBKDF2-SHA256
(100k iterations), and HMAC-SHA256 authenticated. Every DNS query carries an
HMAC token tied to the current minute.

---

## Quick start

The steps below take you from a fresh clone to a working file transfer on a
single host. All commands assume the working directory is the repo root.

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
mkdir -p ./data && ./servers/gdns2tcp-server-darwin-arm64 -domain files.example.test -secret "change-me" -listen 127.0.0.1 -port 5353 -data-dir ./data
```

The server listens on **both UDP and TCP** at `127.0.0.1:5353` and serves
client binaries from `./clients` automatically. Pick the matching server
binary for your OS/arch, or use `./gdns2tcp` if you ran `make build`.

> Port 53 requires root. Use 5353 for local testing — the clients accept
> `-dns-port 5353` (Go) or `-DnsPort 5353` (PowerShell).

### 3. Fetch the client over DNS

The server publishes its own client binaries through public DNS endpoints
(no secret required) so a fresh host can bootstrap. Pick one snippet below.

**Linux / macOS** — auto-detects OS+arch. Uses only default utilities
(`dig`, `base64`, `shasum`):

```sh
D=files.example.test S=127.0.0.1 P=5353 sh -c '
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="$os-$a"
q(){ for i in 1 2 3 4 5; do o=$(dig +short +time=5 +tries=1 -p $P @$S "$1" TXT | tr -d "\"\n"); [ -n "$o" ] && { printf %s "$o"; return; }; sleep 0.4; done; echo "no TXT for $1" >&2; return 1; }
m=$(q "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
T=$(mktemp); i=0
while [ $i -lt $N ]; do q "$i.cl-$A.$D" >> "$T" || exit 1; i=$((i+1)); done
base64 -d < "$T" > "$NAME" 2>/dev/null || base64 -D < "$T" > "$NAME"
rm "$T"
printf "%s  %s\n" "$SHA" "$NAME" | shasum -a 256 -c - || { rm -f "$NAME"; exit 1; }
chmod +x "$NAME"; echo "saved ./$NAME"
'
```

**Windows PowerShell** — requires `nslookup`:

```powershell
$D="files.example.test"; $S="127.0.0.1"; $P=5353
function q($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -type=TXT -port=$P $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
$man=q "client-win.$D"; $p=$man.Split('|')
$name=$p[0]; $n=[int]$p[1]; $sha=$p[2].ToLower()
$b64=''; 0..($n-1) | %{ $b64 += q "$_.cl-win.$D" }
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
./gdns2tcp-client-darwin-arm64 -domain files.example.test -pass "change-me" -dns-server 127.0.0.1 -dns-port 5353 -mode list
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.test -Pass "change-me" -DnsServer 127.0.0.1 -DnsPort 5353 -Mode List
```

### 5. Upload a file to the server

#### Linux / macOS

```sh
./gdns2tcp-client-darwin-arm64 -domain files.example.test -pass "change-me" -dns-server 127.0.0.1 -dns-port 5353 -mode upload -in ./sample.txt
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.test -Pass "change-me" -DnsServer 127.0.0.1 -DnsPort 5353 -Mode Upload -InFile .\sample.txt
```

### 6. Download a file from the server

#### Linux / macOS

```sh
./gdns2tcp-client-darwin-arm64 -domain files.example.test -pass "change-me" -dns-server 127.0.0.1 -dns-port 5353 -mode download -filename sample.txt -out ./sample.copy.txt
```

#### Windows

```powershell
.\gdns2tcp-client.ps1 -Domain files.example.test -Pass "change-me" -DnsServer 127.0.0.1 -DnsPort 5353 -Mode Download -Filename sample.txt -OutFile .\sample.copy.txt
```

Add `-tcp` (Go) or `-Tcp` (PowerShell) to force DNS over TCP — useful when
intermediate resolvers truncate large UDP responses or block UDP/53.

---

## Reference

### Server flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | Authoritative domain, e.g. `files.example.test` |
| `-secret` | *(required)* | Shared secret for HMAC auth and payload encryption |
| `-listen` | *(required)* | Listen address, e.g. `0.0.0.0`, `127.0.0.1` |
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
| `-max-download-bytes` | 32 MiB | Maximum decompressed download size |

### PowerShell client parameters

Mirror the Go flags with PascalCase names: `-Domain`, `-Mode`, `-Pass`,
`-DnsServer`, `-DnsPort`, `-Tcp`, `-InFile`, `-OutFile`, `-Filename`,
`-ChunkSize`, `-Retries`, `-RetryDelaySeconds`, `-LogPath`,
`-MaxDownloadBytes`.

### DNS endpoints

Client manifests return `filename|chunk_count|sha256`:

```
client-win.<domain>                       <n>.cl-win.<domain>
client-linux-amd64.<domain>               <n>.cl-linux-amd64.<domain>
client-linux-arm64.<domain>               <n>.cl-linux-arm64.<domain>
client-darwin-amd64.<domain>              <n>.cl-darwin-amd64.<domain>
client-darwin-arm64.<domain>              <n>.cl-darwin-arm64.<domain>
```

These endpoints are unauthenticated by design so a new host can bootstrap a
client without already knowing the secret. The transfer endpoints
(`uinit`/`u` for upload, `dinit`/`d` for download, `c` for catalog) all
require the HMAC token derived from `-secret`.

---

## Notes

- Port 53 normally requires administrator/root privileges; 5353 is easier
  for local testing.
- Unix artifact endpoints return `Client artifact is not configured.` until
  the matching files are built under `clients/` or supplied through
  `-clients-dir`.
- The server rejects download sources larger than `-max-download-bytes`
  (default 33,554,432). Go clients enforce `-max-download-bytes`; the
  PowerShell client enforces `-MaxDownloadBytes`.
- Clients built before the authenticated `sid` protocol are incompatible;
  rebuild and re-fetch clients after updating the server.
- The project does not install persistence, elevate privileges, alter
  monitoring controls, or automatically execute code received over DNS.

## Development

```sh
make test           # go test -race ./...
make cover          # coverage report (CI gate: ≥80%)
make clean          # remove built binaries
```

CI runs build → vet → staticcheck → test → coverage on every push.
