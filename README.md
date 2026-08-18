# gdns2tcp

File-transfer utility that tunnels uploads and downloads through DNS TXT
records.

- **Server** (Go) — authoritative DNS handler that stores files and serves
  client binaries
- **Unix client** (Go) — ~3 MB stripped, no CGO, no external dependencies
- **Windows client** (PowerShell 5.1+) — single self-contained script

Payloads are gzip+AES-256-CBC (PBKDF2-SHA256, 100k iterations) with
HMAC-SHA256. Every DNS query carries a per-minute HMAC token.

---

## Throughput

100 MiB (≈ 838 Mbit) end-to-end throughput on macOS (Apple Silicon)
loopback, 2026-08-17. Incompressible random fixture; every transfer is
SHA256-verified against the source.

| Mode              | Direction | DNS | Cache | Elapsed  | Throughput  | MiB/s |
| ----------------- | --------- | --- | ----- | -------- | ----------- | ----- |
| File client       | Download  | UDP | Cold  |   5.76s  | 145.64 Mbps | 17.36 |
| File client       | Download  | UDP | Warm  |   4.42s  | 189.88 Mbps | 22.64 |
| File client       | Download  | TCP | Cold  |   5.07s  | 165.56 Mbps | 19.74 |
| File client       | Download  | TCP | Warm  |   3.65s  | 229.79 Mbps | 27.39 |
| File client       | Upload    | UDP | —     |  86.38s  |   9.71 Mbps |  1.16 |
| File client       | Upload    | TCP | —     |  36.98s  |  22.69 Mbps |  2.70 |
| Proxy (SOCKS5)    | Bidir echo| UDP | —     |  22.30s  |  75.24 Mbps |  4.48 |
| Proxy (SOCKS5)    | Bidir echo| TCP | —     | 147.99s  |  11.34 Mbps |  0.68 |

- **Cold / Warm** — server built the encoded spool from scratch on first
  request vs. served it from the LRU cache on the second (steady state).
- **Upload** is chunk-serial in the client protocol (each chunk waits for
  its ack); throughput plateaus regardless of size. Download uses 32
  parallel workers × batches of 14 chunks and scales.
- **Proxy** row is a synchronous echo through the reverse-SOCKS5 tunnel
  (operator writes 100 MiB → agent forwards → upstream echoes → agent
  forwards back → operator reads). Every axchg round-trip carries data
  in both directions, so the numbers are the worst case for a
  request/response tunnel. Reported throughput is the effective
  one-direction rate; the tunnel actually moves 2× that in bytes/sec.
  On this workload UDP DNS beats TCP DNS by ~7× because the agent runs
  96 UDP workers vs. 32 TCP workers, and loopback UDP round-trip is
  ~0.1 ms vs. ~0.3 ms for TCP DNS through the framed pool.

Reproduce with (both take ~5 min combined):

```sh
go test -tags bench_e2e -run TestThroughputMatrix       -v -timeout 30m ./cmd/gdns2tcp-client
go test -tags bench_e2e -run TestReverseSocksThroughput -v -timeout 60m ./cmd/gdns2tcp-client-proxy
```

---

## Quick start

### 1. Build

```sh
make clients servers     # cross-compile everything into ./clients + ./servers
make build               # current platform → ./gdns2tcp, ./gdns2tcp-client, ./gdns2tcp-client-proxy
```

### 2. Delegate the DNS zone

The parent zone must delegate the subzone to the host running gdns2tcp:

| Type | Name | Value |
|---|---|---|
| `NS` | `files.example.com.` | `ns1.example.com.` |
| `A`  | `ns1.example.com.` | `11.11.11.11` |

gdns2tcp answers TXT queries for names under `-domain` and marks those
responses authoritative (`AA`). Other record types below the delegated zone
receive authoritative NODATA rather than NXDOMAIN, so recursive resolvers do
not negatively cache a valid tunnel name. Resolvers follow the parent
delegation and send tunnel TXT queries on UDP+TCP port 53.

```sh
dig +short NS files.example.com
dig +short TXT EnCoDiNg.test.files.example.com    # → "base64" (or "base32")
```

The proxy agent discovers this delegation through the system resolver and
then sends tunnel traffic directly to the authoritative IP. For local/private
testing without real DNS, add `-ds <server-ip>` to every client.

#### Multi-domain sharding (optional)

Public resolvers (`1.1.1.1`, `8.8.8.8`, …) rate-limit queries **per
authoritative zone**. Delegating several zones to the same nameserver
and passing them as a CSV list to `-domain` lets clients rotate QNAME
suffixes round-robin, so each shard eats its own rate-limit budget.

Zone records add one line per shard; the same A-record for `ns1`
serves all of them:

| Type | Name | Value |
|---|---|---|
| `NS` | `files.example.com.`  | `ns1.example.com.` |
| `NS` | `files1.example.com.` | `ns1.example.com.` |
| `NS` | `files2.example.com.` | `ns1.example.com.` |
| `A`  | `ns1.example.com.`    | `11.11.11.11` |

The **first** domain in the CSV is *canonical* — HMAC signatures are
always computed under it, so a query routed through any shard still
authenticates. Non-canonical shards are pure suffix rotation; there is
no per-shard state.

### 3. Run the server

```sh
sudo ./gdns2tcp -domain files.example.com -p "change-me"

# multi-domain sharding: canonical + 2 shards
sudo ./gdns2tcp -domain files.example.com,files1.example.com,files2.example.com -p "change-me"
```

Listens on UDP+TCP port 53 and serves client binaries from `./clients`.
Port 53 requires root.

Clients (`gdns2tcp-client`, `gdns2tcp-client-proxy`) accept the same
CSV form for their `-domain` flag; single-domain configs remain fully
backward compatible.

### 4. Fetch a client over DNS

The server publishes its own client binaries under public DNS endpoints —
no secret required. `S=<dns-server>` is optional: leave unset to use the
system resolver, set to hit a specific server directly (useful before
delegation is live or on private networks).

**Linux / macOS** (needs `dig`, `base64`, `shasum`):

```sh
D=files.example.com S= B=14 P=16 sh <<'EOF'
# S="" → system resolver; S=192.0.2.10 → send queries straight to that IP
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="$os-$a"
NL=$(printf '\n')
qm(){ for i in 1 2 3 4 5; do
        o=$(dig +short +time=5 +tries=1 +tcp ${S:+@$S} "$1" TXT | tr -d "\"$NL ")
        [ -n "$o" ] && { printf %s "$o"; return; }
        sleep 0.4
    done
    echo "no TXT for $1" >&2; return 1
}
qb(){ for i in 1 2 3 4 5; do
        raw=$(dig +short +time=5 +tries=1 +tcp ${S:+@$S} "$1" TXT | tr -d \" | tr "$NL" ' ')
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

**Windows PowerShell** — uses TCP DNS (`nslookup -vc`) to bypass the
512-byte UDP cap. `$S=""` uses the system resolver; set it to an IP to
target a specific server:

```powershell
$D="files.example.com"; $S=""; $B=14
function qm($n){ for($i=1;$i -le 5;$i++){ $r = if ($S) { nslookup -vc -type=TXT $n $S 2>$null } else { nslookup -vc -type=TXT $n 2>$null }
  $m=[regex]::Matches(($r -join "`n"),'"([^"]*)"')
  if($m.Count){ return (($m | %{ $_.Groups[1].Value }) -join "") }
  Start-Sleep -Milliseconds 400 }; throw "no TXT for $n" }
function qb($n){ for($i=1;$i -le 5;$i++){ $r = if ($S) { nslookup -vc -type=TXT $n $S 2>$null } else { nslookup -vc -type=TXT $n 2>$null }
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

### 5. Transfer files

```sh
# Linux / macOS
./gdns2tcp-client-linux-amd64 -d files.example.com -p "change-me" --list
./gdns2tcp-client-linux-amd64 -d files.example.com -p "change-me" --upload ./sample.txt
./gdns2tcp-client-linux-amd64 -d files.example.com -p "change-me" --download sample.txt -out ./sample.copy.txt
```

```powershell
# Windows
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode List
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Upload -InFile .\sample.txt
.\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" -Mode Download -Filename sample.txt -OutFile .\sample.copy.txt
```

Add `-tcp` (Go) or `-Tcp` (PowerShell) if UDP is blocked or truncates.

### Transfer limits, cache and resume

- The server accepts uploads up to **32 MiB** and serves source files up to
  **256 MiB** by default. Override these limits with
  `-max-upload-bytes` and `-max-download-bytes` only when both peers have
  enough disk space for the temporary spool files.
- Downloads are compressed, encrypted and encoded as streaming disk spools;
  neither endpoint holds the complete transfer in RAM. A server-side encoded
  cache is kept in `<data-dir>/.gdns2tcp-cache` for 24 hours, with a 1 GiB
  hard LRU quota that also reserves space for in-progress cache builds. A new
  build is rejected when inactive entries cannot free enough space. Use
  `-cache-dir`, `-cache-max-bytes` and `-cache-ttl` to change it.
- The Go client keeps incomplete downloads in the OS user cache (1 GiB,
  seven-day cleanup) and resumes them from one spool file plus a bitmap.
  It reserves quota before creating the spool and locks each transfer across
  processes. `-cache-dir <dir>` selects another location; `-no-resume` keeps
  all temporary state only for the current invocation.
- Direct PowerShell TCP downloads reuse a bounded pool of 16 DNS connections
  with connect/read/write timeouts; a broken stream is discarded without
  affecting the other pool entries.
- The legacy Go spellings `-pass`, `-in` and `-filename` remain accepted as
  aliases for `-password`, `-upload` and `-download`. PowerShell accepts
  `-in`, `-chunk-size` and `-max-download-bytes` alongside its canonical
  parameter names. The Go file client requires exactly one mode flag and
  rejects conflicting modes.

---

## Reverse SOCKS5 — browse the agent's network

An agent inside a private network polls the public server through DNS
and dials upstream services locally. You connect to the server's SOCKS5
listener; traffic exits from the agent.

```
operator ── TCP/SOCKS5 ──> server:9050 ── DNS tunnel ──> agent ──> upstream
```

Agent↔server DNS is AES-256-GCM under `(secret, cid)`. Sessions
multiplex via 16-hex `cid` per tunnel.

### Enable on the server

```sh
sudo ./gdns2tcp -domain files.example.com -p "change-me" -allow-proxy
```

The SOCKS5 listener binds `127.0.0.1:9050` after the first authenticated
agent poll. To expose it publicly use `-socks-listen 0.0.0.0:9050`
paired with `-socks-no-auth=false` (RFC 1929 user=`gdns2tcp` /
password=`-p` value).

### Fetch the agent binary

Same bootstrap pattern as the file client — swap the alias from
`$os-$arch` to `client-proxy-$os-$arch`. `S=<dns-server>` is optional
(see the file-client fetch above).

```sh
D=files.example.com S= B=14 P=16 sh <<'EOF'
os=$(uname -s | tr A-Z a-z); a=$(uname -m)
case "$a" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; *) echo "bad arch $a" >&2; exit 1;; esac
A="client-proxy-$os-$a"
NL=$(printf '\n')
qm(){ for i in 1 2 3 4 5; do
        o=$(dig +short +time=5 +tries=1 +tcp ${S:+@$S} "$1" TXT | tr -d "\"$NL ")
        [ -n "$o" ] && { printf %s "$o"; return; }
        sleep 0.4
    done
    echo "no TXT for $1" >&2; return 1
}
qb(){ for i in 1 2 3 4 5; do
        raw=$(dig +short +time=5 +tries=1 +tcp ${S:+@$S} "$1" TXT | tr -d \" | tr "$NL" ' ')
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

```powershell
# Windows — uses Resolve-DnsName when available, falls back to nslookup -vc.
# $S="" = system resolver; set to an IP to target a specific server.
$D="files.example.com"; $S=""; $B=14
$ARCH = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "arm64" }
$A = "client-proxy-windows-$ARCH"
$ProgressPreference='SilentlyContinue'
$rdn = $null -ne (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)
function qraw($n){
  if($rdn){
    $p = @{Name=$n; Type='TXT'; TcpOnly=$true; DnsOnly=$true; NoHostsFile=$true; QuickTimeout=$true; ErrorAction='Stop'}
    if ($S) { $p['Server'] = $S }
    $r = Resolve-DnsName @p
    return @(foreach($rec in $r){ if($rec.Strings){ $rec.Strings } })
  }
  $r = if ($S) { nslookup -vc -type=TXT $n $S 2>$null } else { nslookup -vc -type=TXT $n 2>$null }
  return @([regex]::Matches(($r -join "`n"),'"([^"]*)"') | %{ $_.Groups[1].Value })
}
function qm($n){ for($k=1;$k -le 5;$k++){
  try { $m = qraw $n; if($m.Count){ return ($m -join "") } } catch {}
  Start-Sleep -Milliseconds 400 }
  throw "no TXT for $n (is TCP:53 through the configured resolver reachable?)" }
function qb($n){ for($k=1;$k -le 5;$k++){
  try {
    $m = qraw $n
    if($m.Count -ge 2 -and $m[0].StartsWith("s:")){
      $expected = $m[0].Substring(2).ToLower()
      $data = ($m | Select-Object -Skip 1) -join ""
      $bytes = [System.Text.Encoding]::ASCII.GetBytes($data)
      $actual = -join ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | %{ "{0:x2}" -f $_ })
      if($expected -eq $actual){ return $data }
    }
  } catch {}
  Start-Sleep -Milliseconds 400 }
  throw "batch verify failed for $n (is TCP:53 through the configured resolver reachable?)" }
$manifestName="client-$A.$D"
$man=qm $manifestName; $p=@($man.Split('|')); [int]$n=0
if($p.Count -ne 3 -or [string]::IsNullOrWhiteSpace($p[0]) -or
   -not [int]::TryParse($p[1],[ref]$n) -or $n -lt 1 -or
   $p[2] -notmatch '^[0-9a-fA-F]{64}$'){
  throw "Unexpected TXT response for ${manifestName}: $man. Check D and NS delegation."
}
$name=[IO.Path]::GetFileName($p[0])
if($name -ne $p[0]){ throw "Unsafe artifact filename in manifest: $($p[0])" }
$sha=$p[2].ToLowerInvariant()
$total = [int][Math]::Ceiling($n / $B)
$b64 = [System.Text.StringBuilder]::new($n * 260)
$i=0; $j=0; $tick=[DateTime]::UtcNow
Write-Host "Fetching $name ($total batches over TCP:53 via $(if($rdn){'Resolve-DnsName'}else{'nslookup'}))..."
while ($i -lt $n) {
    $c = [Math]::Min($B, $n - $i)
    [void]$b64.Append((qb "$i.$c.clb-$A.$D"))
    $i += $c; $j++
    if(([DateTime]::UtcNow - $tick).TotalMilliseconds -ge 500){
        Write-Host -NoNewline ("`r  {0}/{1} batches" -f $j, $total)
        $tick = [DateTime]::UtcNow
    }
}
Write-Host ("`r  {0}/{0} batches done" -f $total)
$out=Join-Path (Get-Location) $name
[IO.File]::WriteAllBytes($out, [Convert]::FromBase64String($b64.ToString()))
if((Get-FileHash $out -Algorithm SHA256).Hash.ToLower() -ne $sha){
    Remove-Item $out -Force; throw "sha256 mismatch" }
"Saved $out"
```

### Run the agent

```sh
./gdns2tcp-client-proxy-linux-amd64 -d files.example.com -p "change-me"
```

```powershell
.\gdns2tcp-client-proxy-windows-amd64.exe -d files.example.com -p "change-me"
```

The agent doesn't listen — it polls the server and dials whatever
target the operator's SOCKS5 CONNECT requests.

When `-ds` is omitted, the proxy agent uses the system resolver only to
discover the zone's parent delegation, then validates and connects directly
to the authoritative gdns2tcp server. The selected IP must return an
authoritative (`AA`) TXT probe for every configured shard. If delegation
discovery fails (for example, for a private undelegated zone), the agent warns
and falls back to the system recursive resolver with a conservative worker
profile and extra retries. An explicit `-ds <gdns2tcp-server-ip>` skips
discovery and remains useful for private networks and non-standard DNS ports.

If the network permits DNS only through an internal recursive server, the
fallback remains cache-safe: dynamic proxy operations carry unique poll IDs,
stream nonces and sequence numbers in their QNAMEs, while gdns2tcp answers
with TTL 0. A retry intentionally repeats the same QNAME to obtain the same
idempotent response after packet loss. Startup probes include an additional
random label so a cached `encoding.test` response cannot masquerade as a live
authoritative path.
