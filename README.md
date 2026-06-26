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
  `…-darwin-amd64`, `…-darwin-arm64`, `gdns2tcp-client.ps1`,
  and matching `gdns2tcp-client-proxy-*` agent binaries
- `servers/gdns2tcp-server-linux-amd64`, `…-linux-arm64`,
  `…-darwin-amd64`, `…-darwin-arm64`

For only the current platform:

```sh
make build      # → ./gdns2tcp, ./gdns2tcp-client, ./gdns2tcp-client-proxy
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
qm(){ for i in 1 2 3 4 5; do
        o=$(dig +short +time=5 +tries=1 +tcp @$S "$1" TXT | tr -d "\"$NL ")
        [ -n "$o" ] && { printf %s "$o"; return; }
        sleep 0.4
    done
    echo "no TXT for $1" >&2; return 1
}
qb(){ for i in 1 2 3 4 5; do
        raw=$(dig +short +time=5 +tries=1 +tcp @$S "$1" TXT | tr -d \" | tr "$NL" ' ')
        s=$(printf %s "$raw" | awk '{print $1}')
        d=$(printf %s "$raw" | awk '{for(i=2;i<=NF;i++) printf "%s",$i}')
        if [ -n "$s" ] && [ -n "$d" ] && [ "${s%${s#s:}}" = "s:" ]; then
            actual=$(printf %s "$d" | sha256sum | awk '{print $1}')
            if [ "${s#s:}" = "$actual" ]; then printf %s "$d"; return; fi
        fi
        sleep 0.4
    done
    echo "batch verify failed for $1" >&2; return 1
}
m=$(qm "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
TOTAL=$(( (N + B - 1) / B ))
T=$(mktemp -d); i=0; k=0
while [ $i -lt $N ]; do
    c=$B; [ $((i + c)) -gt $N ] && c=$((N - i))
    (qb "$i.$c.clb-$A.$D" > "$T/$k" || touch "$T/.err") &
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
function qm($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
function qb($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count -ge 2 -and $m[0].Groups[1].Value.StartsWith("s:")){
    $expected = $m[0].Groups[1].Value.Substring(2).ToLower()
    $data = ($m | Select-Object -Skip 1 | %{ $_.Groups[1].Value }) -join ""
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
    $actual = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | %{ "{0:x2}" -f $_ })
    if($expected -eq $actual){ return $data }
  }
  Start-Sleep -Milliseconds 400 }; throw "batch verify failed for $n" }
$man=qm "client-win.$D"; $p=$man.Split('|')
$name=$p[0]; $n=[int]$p[1]; $sha=$p[2].ToLower()
$total = [int][Math]::Ceiling($n / $B)
$b64=''; $i=0; $j=0
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    $b64 += qb "$i.$c.clb-win.$D"
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
host connects to the server's SOCKS5 listener as a normal SOCKS5 proxy — no
DNS client involved — and traffic emerges from the agent's vantage point.

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

This enables the agent endpoints. The TCP SOCKS5 listener binds on
**`127.0.0.1:9050`** only after the first authenticated agent `apoll`.
Use `-socks-listen 0.0.0.0:9050` only when you intentionally want to expose
it to remote operators; pair public binds with `-socks-no-auth=false` if you
want RFC 1929 username/password authentication (`gdns2tcp` / the `-secret`
value).

| Flag | Default | Description |
|---|---|---|
| `-allow-proxy` | `false` | enable reverse SOCKS5 + agent endpoints |
| `-socks-listen` | `127.0.0.1:9050` | TCP address for the operator-facing SOCKS5 listener |
| `-socks-no-auth` | `true` | disable SOCKS5 username/password auth; pass `-socks-no-auth=false` to require auth |
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
qm(){ for i in 1 2 3 4 5; do
        o=$(dig +short +time=5 +tries=1 +tcp @$S "$1" TXT | tr -d "\"$NL ")
        [ -n "$o" ] && { printf %s "$o"; return; }
        sleep 0.4
    done
    echo "no TXT for $1" >&2; return 1
}
qb(){ for i in 1 2 3 4 5; do
        raw=$(dig +short +time=5 +tries=1 +tcp @$S "$1" TXT | tr -d \" | tr "$NL" ' ')
        s=$(printf %s "$raw" | awk '{print $1}')
        d=$(printf %s "$raw" | awk '{for(i=2;i<=NF;i++) printf "%s",$i}')
        if [ -n "$s" ] && [ -n "$d" ] && [ "${s%${s#s:}}" = "s:" ]; then
            actual=$(printf %s "$d" | sha256sum | awk '{print $1}')
            if [ "${s#s:}" = "$actual" ]; then printf %s "$d"; return; fi
        fi
        sleep 0.4
    done
    echo "batch verify failed for $1" >&2; return 1
}
m=$(qm "client-$A.$D") || exit 1
NAME=${m%%|*}; rest=${m#*|}; N=${rest%%|*}; SHA=${rest#*|}
TOTAL=$(( (N + B - 1) / B ))
T=$(mktemp -d); i=0; k=0
while [ $i -lt $N ]; do
    c=$B; [ $((i + c)) -gt $N ] && c=$((N - i))
    (qb "$i.$c.clb-$A.$D" > "$T/$k" || touch "$T/.err") &
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
function qm($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
function qb($n){ for($i=1;$i -le 5;$i++){ $r=nslookup -vc -type=TXT $n $S 2>$null
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count -ge 2 -and $m[0].Groups[1].Value.StartsWith("s:")){
    $expected = $m[0].Groups[1].Value.Substring(2).ToLower()
    $data = ($m | Select-Object -Skip 1 | %{ $_.Groups[1].Value }) -join ""
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
    $actual = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | %{ "{0:x2}" -f $_ })
    if($expected -eq $actual){ return $data }
  }
  Start-Sleep -Milliseconds 400 }; throw "batch verify failed for $n" }
$man=qm "client-$A.$D"; $p=$man.Split('|')
$name=$p[0]; $n=[int]$p[1]; $sha=$p[2].ToLower()
$total = [int][Math]::Ceiling($n / $B)
$b64=''; $i=0; $j=0
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    $b64 += qb "$i.$c.clb-$A.$D"
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

