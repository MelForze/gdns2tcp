<#
.SYNOPSIS
gdns2tcp PowerShell file-transfer client.

.DESCRIPTION
Runs one of four modes against an authoritative gdns2tcp DNS zone: Test, List,
Upload, or Download. Domain and Mode are always required. Pass is required for
List, Upload, and Download. Use DnsServer/DnsPort/Tcp when you want to bypass
the system resolver or force TCP DNS.

.PARAMETER Domain
Authoritative gdns2tcp DNS zone, for example files.example.com.

.PARAMETER Mode
Operation to run: Test, List, Upload, or Download.

.PARAMETER Pass
Shared secret. Required for List, Upload, and Download.

.PARAMETER InFile
Local file path for Upload.

.PARAMETER Filename
Remote filename for Download.

.PARAMETER OutFile
Local output path for Download. Defaults to Filename.

.PARAMETER DnsServer
DNS server address. Empty uses the system resolver.

.PARAMETER DnsPort
DNS server port. Default: 53.

.PARAMETER Tcp
Use TCP instead of UDP for DNS queries.

.PARAMETER ChunkSize
Maximum encoded upload chunk size. Default: 180.

.PARAMETER MaxDownloadBytes
Maximum decompressed download size. Default: 268435456.

.PARAMETER Parallelism
Concurrent DNS queries during parallel downloads. Default: 32.

.PARAMETER BatchSize
Chunks requested per DNS response during parallel downloads. Default: 14.

.PARAMETER Retries
DNS query attempts before failing. Default: 3.

.PARAMETER RetryDelaySeconds
Delay between retry attempts. Default: 2.

.PARAMETER LogPath
Optional log file path.

.EXAMPLE
./gdns2tcp-client.ps1 -Domain files.example.com -Mode Test -DnsServer 203.0.113.10

.EXAMPLE
./gdns2tcp-client.ps1 -Domain files.example.com -Mode List -Pass $env:GDNS_PASS

.EXAMPLE
./gdns2tcp-client.ps1 -Domain files.example.com -Mode Upload -Pass $env:GDNS_PASS -InFile .\payload.bin

.EXAMPLE
./gdns2tcp-client.ps1 -Domain files.example.com -Mode Download -Pass $env:GDNS_PASS -Filename payload.bin -OutFile .\payload.bin -Tcp
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter(Mandatory = $true)]
    [ValidateSet('Download', 'Upload', 'List', 'Test')]
    [string]$Mode,

    [Parameter()]
    [Alias('password')]
    [string]$Pass = '',

    [Parameter()]
    [Alias('in')]
    [string]$InFile = '',

    [Parameter()]
    [string]$Filename = '',

    [Parameter()]
    [string]$OutFile = '',

    [Parameter()]
    [string]$DnsServer = '',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$DnsPort = 53,

    [Parameter()]
    [Alias('chunk-size')]
    [ValidateRange(32, 180)]
    [int]$ChunkSize = 180,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$Retries = 3,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$RetryDelaySeconds = 2,

    [Parameter()]
    [string]$LogPath = '',

    [Parameter()]
    [Alias('max-download-bytes')]
    [ValidateRange(1, 2147483647)]
    [int64]$MaxDownloadBytes = 268435456,

    [Parameter()]
    [switch]$Tcp,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$Parallelism = 32,

    [Parameter()]
    [ValidateRange(1, 32)]
    [int]$BatchSize = 14
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:DomainName = ''
$script:DnsTool = $null
$script:LogPath = $LogPath

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format o), $Level, $Message
    if ($Level -eq 'ERROR') {
        [Console]::Error.WriteLine($line)
    }
    else {
        [Console]::Out.WriteLine($line)
    }
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Add-Content -LiteralPath $script:LogPath -Value $line
    }
}

function Normalize-Domain {
    param([Parameter(Mandatory = $true)][string]$Value)
    $normalized = $Value.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw 'Domain is empty.'
    }
    $wireLength = [System.Text.Encoding]::UTF8.GetByteCount($normalized)
    if ($wireLength -gt 253) {
        throw "Domain is $wireLength bytes; DNS limit is 253."
    }
    foreach ($label in $normalized.Split('.')) {
        $labelLength = [System.Text.Encoding]::UTF8.GetByteCount($label)
        if ($labelLength -lt 1 -or $labelLength -gt 63) {
            throw "Invalid DNS domain label: '$label'."
        }
    }
    return $normalized
}


function Get-DnsTool {
    $resolveDnsName = Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue
    if ($null -ne $resolveDnsName -and $DnsPort -eq 53) {
        return [pscustomobject]@{ Name = 'Resolve-DnsName'; Path = $resolveDnsName.Source }
    }

    foreach ($candidate in @('dig', 'drill', 'host', 'nslookup')) {
        $command = Get-Command -Name $candidate -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return [pscustomobject]@{ Name = $candidate; Path = $command.Source }
        }
    }

    throw 'No DNS TXT query tool found. Install dig/drill/host/nslookup or run on Windows with Resolve-DnsName.'
}

function ConvertFrom-QuotedTxtLine {
    param([Parameter(Mandatory = $true)][string]$Line)
    $regexMatches = [regex]::Matches($Line, '"([^"]*)"')
    if ($regexMatches.Count -eq 0) {
        return $Line.Trim()
    }
    $parts = foreach ($match in $regexMatches) {
        $match.Groups[1].Value
    }
    return ($parts -join '')
}

function Invoke-NativeDnsTool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $arguments = @()
    switch ($script:DnsTool.Name) {
        'dig' {
            $arguments = @('+time=5', '+tries=1', '+short')
            if ($Tcp) { $arguments += '+tcp' }
            if ($DnsPort -ne 53) {
                $arguments += @('-p', [string]$DnsPort)
            }
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $arguments += "@$DnsServer"
            }
            $arguments += @($Name, 'TXT')
        }
        'drill' {
            $arguments = @('-Q')
            if ($Tcp) { $arguments += '-t' }
            if ($DnsPort -ne 53) {
                $arguments += @('-p', [string]$DnsPort)
            }
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $arguments += "@$DnsServer"
            }
            $arguments += @($Name, 'TXT')
        }
        'host' {
            $arguments = @('-t', 'TXT', $Name)
            if ($Tcp) { $arguments += '-T' }
            if ($DnsPort -ne 53) {
                $arguments += @('-p', [string]$DnsPort)
            }
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $arguments += $DnsServer
            }
        }
        'nslookup' {
            $arguments = @('-type=TXT')
            if ($Tcp) { $arguments += '-vc' }
            if ($DnsPort -ne 53) {
                $arguments += "-port=$DnsPort"
            }
            $arguments += $Name
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $arguments += $DnsServer
            }
        }
        default {
            throw "Unsupported DNS tool $($script:DnsTool.Name)."
        }
    }

    $output = & $script:DnsTool.Path @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "DNS tool $($script:DnsTool.Name) failed with exit code $LASTEXITCODE."
    }

    $records = New-Object System.Collections.Generic.List[string]
    foreach ($line in @($output)) {
        $text = [string]$line
        if ([string]::IsNullOrWhiteSpace($text)) {
            continue
        }
        if ($script:DnsTool.Name -eq 'host' -and $text -match 'text "(.+)"$') {
            [void]$records.Add($Matches[1])
            continue
        }
        if ($script:DnsTool.Name -eq 'nslookup' -and $text -notmatch '"') {
            continue
        }
        [void]$records.Add((ConvertFrom-QuotedTxtLine -Line $text))
    }
    return $records.ToArray()
}

function Invoke-TxtQuery {
    param([Parameter(Mandatory = $true)][string]$Name)

    $queryName = $Name.TrimEnd('.')
    for ($attempt = 1; $attempt -le $Retries; $attempt++) {
        try {
            if ($script:DnsTool.Name -eq 'Resolve-DnsName') {
                $parameters = @{
                    Name        = $queryName
                    Type        = 'TXT'
                    DnsOnly     = $true
                    ErrorAction = 'Stop'
                }
                if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                    $parameters.Server = $DnsServer
                }
                if ($Tcp) {
                    $parameters.TcpOnly = $true
                }
                $records = @(Resolve-DnsName @parameters)
                $values = New-Object System.Collections.Generic.List[string]
                foreach ($record in @($records)) {
                    $stringsProperty = $record.PSObject.Properties['Strings']
                    $textProperty = $record.PSObject.Properties['DescriptiveText']
                    if ($null -ne $stringsProperty -and $null -ne $stringsProperty.Value) {
                        [void]$values.Add((@($stringsProperty.Value) -join ''))
                    }
                    elseif ($null -ne $textProperty -and $null -ne $textProperty.Value) {
                        [void]$values.Add(([string]$textProperty.Value).Trim('"'))
                    }
                }
                if ($values.Count -gt 0) {
                    return $values.ToArray()
                }
            }
            else {
                $values = @(Invoke-NativeDnsTool -Name $queryName)
                if ($values.Length -gt 0) {
                    return $values
                }
            }
            throw "No TXT records returned for $queryName."
        }
        catch {
            if ($attempt -eq $Retries) {
                throw
            }
            Write-Log -Level 'WARN' -Message "DNS query failed for $queryName; retry $attempt of $Retries."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
    throw "No TXT response for $queryName after $Retries attempts."
}

function Invoke-TxtQueryOne {
    param([Parameter(Mandatory = $true)][string]$Name)
    $records = @(Invoke-TxtQuery -Name $Name)
    if ($records.Length -lt 1) {
        throw "No TXT response for $Name."
    }
    return [string]$records[0]
}

$script:Pbkdf2CSharpLoaded = $false

function Invoke-Pbkdf2Sha256Fast {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Password,
        [Parameter(Mandatory = $true)][byte[]]$Salt,
        [Parameter(Mandatory = $true)][int]$Iterations,
        [Parameter(Mandatory = $true)][int]$Length
    )
    if (-not $script:Pbkdf2CSharpLoaded) {
        Add-Type -TypeDefinition @'
using System;
using System.Security.Cryptography;
public static class Gdns2TcpPbkdf2 {
    public static byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int length) {
        using (var hmac = new HMACSHA256(password)) {
            var output = new byte[length];
            int generated = 0, blockIndex = 1;
            while (generated < length) {
                var saltBlock = new byte[salt.Length + 4];
                Array.Copy(salt, saltBlock, salt.Length);
                saltBlock[salt.Length]     = (byte)(blockIndex >> 24);
                saltBlock[salt.Length + 1] = (byte)(blockIndex >> 16);
                saltBlock[salt.Length + 2] = (byte)(blockIndex >> 8);
                saltBlock[salt.Length + 3] = (byte) blockIndex;
                byte[] u = hmac.ComputeHash(saltBlock);
                byte[] t = (byte[])u.Clone();
                for (int i = 2; i <= iterations; i++) {
                    u = hmac.ComputeHash(u);
                    for (int j = 0; j < t.Length; j++) t[j] ^= u[j];
                }
                int copy = Math.Min(t.Length, length - generated);
                Array.Copy(t, 0, output, generated, copy);
                generated += copy;
                blockIndex++;
            }
            return output;
        }
    }
}
'@ -ErrorAction Stop
        $script:Pbkdf2CSharpLoaded = $true
    }
    return [Gdns2TcpPbkdf2]::DeriveKey($Password, $Salt, $Iterations, $Length)
}

function Get-KeyMaterial {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][byte[]]$Salt
    )
    $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $derive = $null
    try {
        $derive = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $secretBytes,
            $Salt,
            100000,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256
        )
        return $derive.GetBytes(64)
    }
    catch [System.Management.Automation.MethodException] {
        Write-Log -Level 'WARN' -Message 'Using compiled PBKDF2-SHA256 fallback for Windows PowerShell 5.1 compatibility.'
        try {
            return Invoke-Pbkdf2Sha256Fast -Password $secretBytes -Salt $Salt -Iterations 100000 -Length 64
        }
        catch {
            Write-Log -Level 'WARN' -Message "C# compile unavailable, falling back to pure-PowerShell PBKDF2 (slow): $_"
            return Invoke-Pbkdf2Sha256 -Password $secretBytes -Salt $Salt -Iterations 100000 -Length 64
        }
    }
    finally {
        if ($null -ne $derive) {
            $derive.Dispose()
        }
    }
}

$script:DownloadCSharpLoaded = $false

function Import-DownloadCSharp {
    if ($script:DownloadCSharpLoaded) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class Gdns2TcpDownload {
    private static readonly char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
    private const int TcpDnsPoolSize = 16;

    private sealed class TcpDnsSlot {
        public readonly object Gate = new object();
        public TcpClient Client;
        public NetworkStream Stream;
        public string Server;
        public int Port;
    }

    private static readonly TcpDnsSlot[] TcpDnsPool = CreateTcpDnsPool();
    private static int TcpDnsCursor = -1;

    private static TcpDnsSlot[] CreateTcpDnsPool() {
        var slots = new TcpDnsSlot[TcpDnsPoolSize];
        for (int i = 0; i < slots.Length; i++) slots[i] = new TcpDnsSlot();
        return slots;
    }

    private static TcpDnsSlot NextTcpDnsSlot() {
        int cursor = Interlocked.Increment(ref TcpDnsCursor) & int.MaxValue;
        return TcpDnsPool[cursor % TcpDnsPool.Length];
    }

    private static void CloseTcpDnsSlot(TcpDnsSlot slot) {
        try { if (slot.Stream != null) slot.Stream.Dispose(); } catch {}
        try { if (slot.Client != null) slot.Client.Close(); } catch {}
        slot.Stream = null;
        slot.Client = null;
        slot.Server = null;
        slot.Port = 0;
    }

    private static void EnsureTcpDnsSlot(TcpDnsSlot slot, string server, int port, int timeoutMs) {
        if (slot.Client != null && slot.Stream != null &&
            string.Equals(slot.Server, server, StringComparison.OrdinalIgnoreCase) && slot.Port == port) return;
        CloseTcpDnsSlot(slot);
        var tcp = new TcpClient();
        IAsyncResult connect = tcp.BeginConnect(server, port, null, null);
        try {
            if (!connect.AsyncWaitHandle.WaitOne(timeoutMs)) {
                tcp.Close();
                throw new TimeoutException("TCP DNS connect timeout");
            }
            tcp.EndConnect(connect);
        } finally { connect.AsyncWaitHandle.Close(); }
        tcp.ReceiveTimeout = timeoutMs;
        tcp.SendTimeout = timeoutMs;
        tcp.NoDelay = true;
        slot.Client = tcp;
        slot.Stream = tcp.GetStream();
        slot.Server = server;
        slot.Port = port;
    }

    private static string BuildAuthToken(string secret, string domain, string command, string ts, string[] args) {
        var parts = new List<string>(args.Length + 4);
        parts.Add("gdns2tcp-auth-v1");
        parts.Add(domain.ToLowerInvariant().TrimEnd('.'));
        parts.Add(command);
        parts.Add(ts);
        // DNS names are case-insensitive and the Go protocol canonicalises
        // every argument to lowercase before calculating the HMAC.  Keep
        // the native fast path byte-for-byte compatible with requests sent
        // through New-AuthenticatedName (notably when a resolver changes
        // label case in transit).
        for (int i = 0; i < args.Length; i++) parts.Add(args[i].ToLowerInvariant());
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret))) {
            byte[] h = hmac.ComputeHash(Encoding.UTF8.GetBytes(string.Join("|", parts)));
            var sb = new StringBuilder(26);
            int buf = 0, bits = 0;
            for (int i = 0; i < 16; i++) {
                buf = (buf << 8) | h[i]; bits += 8;
                while (bits >= 5) { bits -= 5; sb.Append(B32[(buf >> bits) & 31]); }
            }
            if (bits > 0) sb.Append(B32[(buf << (5 - bits)) & 31]);
            return sb.ToString();
        }
    }

    private static string CurrentMinute() {
        long min = (long)Math.Floor(
            (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds / 60.0);
        return min.ToString();
    }

    private static string BuildName(string secret, string domain, string sid, string idx) {
        string ts = CurrentMinute();
        string token = BuildAuthToken(secret, domain, "d", ts, new[] { sid, idx });
        return string.Format("{0}.{1}.{2}.{3}.d.{4}", sid, idx, ts, token, domain.TrimEnd('.'));
    }

    private static string BuildBatchName(string secret, string domain, string sid, int from, int count) {
        string ts = CurrentMinute();
        string fromStr = from.ToString();
        string countStr = count.ToString();
        string token = BuildAuthToken(secret, domain, "db", ts, new[] { sid, fromStr, countStr });
        return string.Format("{0}.{1}.{2}.{3}.{4}.db.{5}", sid, fromStr, countStr, ts, token, domain.TrimEnd('.'));
    }

    private static byte[] BuildQuery(string name, ushort id) {
        string normalizedName = name.TrimEnd('.');
        int presentationBytes = Encoding.ASCII.GetByteCount(normalizedName);
        if (presentationBytes == 0 || presentationBytes > 253) {
            throw new ArgumentException("DNS QNAME must be between 1 and 253 bytes.", "name");
        }
        var b = new List<byte>(256);
        b.Add((byte)(id >> 8)); b.Add((byte)id);
        b.Add(0x01); b.Add(0x00);
        b.Add(0x00); b.Add(0x01);                       // QDCOUNT=1
        b.Add(0x00); b.Add(0x00);                       // ANCOUNT=0
        b.Add(0x00); b.Add(0x00);                       // NSCOUNT=0
        b.Add(0x00); b.Add(0x01);                       // ARCOUNT=1 (EDNS0 OPT)
        foreach (string label in normalizedName.Split('.')) {
            byte[] lb = Encoding.ASCII.GetBytes(label);
            if (lb.Length == 0 || lb.Length > 63) {
                throw new ArgumentException("DNS label must be between 1 and 63 bytes.", "name");
            }
            b.Add((byte)lb.Length);
            b.AddRange(lb);
        }
        b.Add(0x00);                                    // QNAME terminator
        b.Add(0x00); b.Add(0x10);                       // QTYPE=TXT
        b.Add(0x00); b.Add(0x01);                       // QCLASS=IN
        // EDNS0 OPT pseudo-RR: tells the server we accept up to 4096-byte UDP
        // responses so batched downloads can fit in a single packet.
        b.Add(0x00);                                    // root name
        b.Add(0x00); b.Add(0x29);                       // type=OPT (41)
        b.Add(0x10); b.Add(0x00);                       // class=4096 UDP payload
        b.Add(0x00); b.Add(0x00); b.Add(0x00); b.Add(0x00); // ext-rcode/version/flags
        b.Add(0x00); b.Add(0x00);                       // RDLEN=0
        return b.ToArray();
    }

    private static string ParseTxt(byte[] r, ushort id) {
        if (r.Length < 12) throw new Exception("Response too short");
        if (((r[0] << 8) | r[1]) != id) throw new Exception("ID mismatch");
        if ((r[3] & 0x0F) != 0) throw new Exception("RCODE " + (r[3] & 0x0F));
        if ((r[2] & 0x02) != 0) throw new Exception("DNS response truncated (TC=1); reduce -BatchSize or use -Tcp");
        int ancount = (r[6] << 8) | r[7];
        if (ancount == 0) throw new Exception("No answers");
        int pos = 12;
        while (pos < r.Length) {
            if (r[pos] == 0) { pos++; break; }
            if ((r[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += r[pos] + 1;
        }
        pos += 4;
        var sb = new StringBuilder();
        for (int a = 0; a < ancount && pos + 10 <= r.Length; a++) {
            while (pos < r.Length) {
                if ((r[pos] & 0xC0) == 0xC0) { pos += 2; break; }
                if (r[pos] == 0) { pos++; break; }
                pos += r[pos] + 1;
            }
            int rtype = (r[pos] << 8) | r[pos + 1];
            pos += 8;
            int rdlen = (r[pos] << 8) | r[pos + 1]; pos += 2;
            int end = pos + rdlen;
            if (rtype == 16) {
                while (pos < end) { int sl = r[pos++]; sb.Append(Encoding.ASCII.GetString(r, pos, sl)); pos += sl; }
            } else { pos = end; }
        }
        if (sb.Length == 0) throw new Exception("Empty TXT");
        return sb.ToString();
    }

    private static string QueryOnceUdp(string name, string server, int port, int timeoutMs, ushort id) {
        byte[] q = BuildQuery(name, id);
        using (var udp = new UdpClient()) {
            udp.Connect(server, port);
            udp.Client.SendTimeout = timeoutMs;
            udp.Client.ReceiveTimeout = timeoutMs;
            udp.Send(q, q.Length);
            var ep = new IPEndPoint(IPAddress.Any, 0);
            return ParseTxt(udp.Receive(ref ep), id);
        }
    }

    private static string QueryOnceTcp(string name, string server, int port, int timeoutMs, ushort id) {
        byte[] q = BuildQuery(name, id);
        TcpDnsSlot slot = NextTcpDnsSlot();
        lock (slot.Gate) {
            try {
                EnsureTcpDnsSlot(slot, server, port, timeoutMs);
                NetworkStream ns = slot.Stream;
                // DNS over TCP: 2-byte big-endian length prefix. A slot is
                // locked for the whole request/response, so frames cannot
                // interleave while independent slots still run in parallel.
                ns.WriteByte((byte)(q.Length >> 8));
                ns.WriteByte((byte)(q.Length & 0xFF));
                ns.Write(q, 0, q.Length);
                ns.Flush();
                byte[] lenBuf = new byte[2];
                int nread = 0;
                while (nread < 2) {
                    int got = ns.Read(lenBuf, nread, 2 - nread);
                    if (got <= 0) throw new Exception("TCP connection closed before length prefix");
                    nread += got;
                }
                int rlen = (lenBuf[0] << 8) | lenBuf[1];
                if (rlen < 12) throw new Exception("TCP DNS response length is invalid");
                byte[] resp = new byte[rlen];
                nread = 0;
                while (nread < rlen) {
                    int got = ns.Read(resp, nread, rlen - nread);
                    if (got <= 0) throw new Exception("TCP connection closed before response body");
                    nread += got;
                }
                return ParseTxt(resp, id);
            } catch {
                // A timeout, partial frame or remote close makes stream
                // alignment unknowable. Discard only this slot; the outer
                // retry loop can reconnect it without disturbing other work.
                CloseTcpDnsSlot(slot);
                throw;
            }
        }
    }

    // Updated by Interlocked.Increment from worker tasks; read by PowerShell
    // to render Write-Progress while the parallel download is in flight.
    public static int CompletedChunks;

    // Downloads `count` chunks, batching `batchSize` chunks per DNS query.
    // Returns an array of length ceil(count/batchSize); each element is the
    // concatenated base64 of its batch, which the caller appends in order.
    public static string[] DownloadChunks(
        string secret, string domain, string sid, int count,
        string server, int port, int timeoutMs, int retries, int retryDelayMs,
        int concurrency, bool tcp, int batchSize)
    {
        if (batchSize < 1) batchSize = 1;
        int nBatches = (count + batchSize - 1) / batchSize;
        var results = new string[nBatches];
        int workerCount = Math.Min(Math.Max(1, concurrency), nBatches);
        var tasks = new Task[workerCount];
        var errorLock = new object();
        int nextBatch = -1;
        Exception failure = null;
        for (int worker = 0; worker < workerCount; worker++) {
            tasks[worker] = Task.Run(() => {
                while (true) {
                    lock (errorLock) {
                        if (failure != null) return;
                    }
                    int batchIdx = Interlocked.Increment(ref nextBatch);
                    if (batchIdx >= nBatches) return;
                    int from = batchIdx * batchSize;
                    int batchCount = Math.Min(batchSize, count - from);
                    ushort id = (ushort)((batchIdx % 65534) + 1);
                    Exception last = null;
                    for (int att = 0; att < retries; att++) {
                        try {
                            string qname = batchSize == 1
                                ? BuildName(secret, domain, sid, from.ToString())
                                : BuildBatchName(secret, domain, sid, from, batchCount);
                            results[batchIdx] = tcp
                                ? QueryOnceTcp(qname, server, port, timeoutMs, id)
                                : QueryOnceUdp(qname, server, port, timeoutMs, id);
                            Interlocked.Add(ref CompletedChunks, batchCount);
                            last = null;
                            break;
                        } catch (Exception ex) {
                            last = ex;
                            if (att < retries - 1) Thread.Sleep(retryDelayMs);
                        }
                    }
                    if (last != null) {
                        lock (errorLock) {
                            if (failure == null) failure = last;
                        }
                        return;
                    }
                }
            });
        }
        Task.WaitAll(tasks);
        if (failure != null)
            throw new Exception("parallel chunk download: " + failure.Message, failure);
        return results;
    }

    // Async wrapper used by PowerShell to poll CompletedChunks while the
    // download runs on a background thread.
    public static Task<string[]> BeginDownloadChunks(
        string secret, string domain, string sid, int count,
        string server, int port, int timeoutMs, int retries, int retryDelayMs,
        int concurrency, bool tcp, int batchSize)
    {
        CompletedChunks = 0;
        return Task.Run(() => DownloadChunks(
            secret, domain, sid, count, server, port, timeoutMs,
            retries, retryDelayMs, concurrency, tcp, batchSize));
    }

    // Streaming counterpart to DownloadChunks.  Responses are written at
    // their fixed chunk offsets into one preallocated base64 spool; only one
    // batch string is retained per worker, not the entire artifact.
    public static void DownloadChunksToSpool(
        string secret, string domain, string sid, int count, long encodedSize,
        string spoolPath, string server, int port, int timeoutMs, int retries,
        int retryDelayMs, int concurrency, bool tcp, int batchSize)
    {
        if (encodedSize <= 0) throw new ArgumentException("encodedSize");
        if (batchSize < 1) batchSize = 1;
        int nBatches = (count + batchSize - 1) / batchSize;
        int workerCount = Math.Min(Math.Max(1, concurrency), nBatches);
        var tasks = new Task[workerCount];
        var writeLock = new object();
        var errorLock = new object();
        int nextBatch = -1;
        Exception failure = null;
        using (var spool = new FileStream(spoolPath, FileMode.Create, FileAccess.Write, FileShare.None)) {
            spool.SetLength(encodedSize);
            for (int worker = 0; worker < workerCount; worker++) {
                tasks[worker] = Task.Run(() => {
                    while (true) {
                        lock (errorLock) {
                            if (failure != null) return;
                        }
                        int batchIdx = Interlocked.Increment(ref nextBatch);
                        if (batchIdx >= nBatches) return;
                        int from = batchIdx * batchSize;
                        int batchCount = Math.Min(batchSize, count - from);
                        ushort id = (ushort)((batchIdx % 65534) + 1);
                        Exception last = null;
                        for (int att = 0; att < retries; att++) {
                            try {
                                string qname = batchSize == 1
                                    ? BuildName(secret, domain, sid, from.ToString())
                                    : BuildBatchName(secret, domain, sid, from, batchCount);
                                string data = tcp
                                    ? QueryOnceTcp(qname, server, port, timeoutMs, id)
                                    : QueryOnceUdp(qname, server, port, timeoutMs, id);
                                long offset = (long)from * 254L;
                                int expected = (int)Math.Min((long)batchCount * 254L, encodedSize - offset);
                                if (data.Length != expected) throw new Exception("DNS batch length mismatch");
                                byte[] bytes = Encoding.ASCII.GetBytes(data);
                                lock (writeLock) {
                                    spool.Position = offset;
                                    spool.Write(bytes, 0, bytes.Length);
                                }
                                Interlocked.Add(ref CompletedChunks, batchCount);
                                last = null;
                                break;
                            } catch (Exception ex) {
                                last = ex;
                                if (att < retries - 1) Thread.Sleep(retryDelayMs);
                            }
                        }
                        if (last != null) {
                            lock (errorLock) {
                                if (failure == null) failure = last;
                            }
                            return;
                        }
                    }
                });
            }
            Task.WaitAll(tasks);
            if (failure != null)
                throw new Exception("parallel chunk download: " + failure.Message, failure);
        }
    }

    public static Task BeginDownloadChunksToSpool(
        string secret, string domain, string sid, int count, long encodedSize,
        string spoolPath, string server, int port, int timeoutMs, int retries,
        int retryDelayMs, int concurrency, bool tcp, int batchSize)
    {
        CompletedChunks = 0;
        return Task.Run(() => DownloadChunksToSpool(
            secret, domain, sid, count, encodedSize, spoolPath, server, port,
            timeoutMs, retries, retryDelayMs, concurrency, tcp, batchSize));
    }

    private static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int length) {
        using (var hmac = new HMACSHA256(password)) {
            var output = new byte[length]; int generated = 0, block = 1;
            while (generated < length) {
                var saltBlock = new byte[salt.Length + 4];
                Array.Copy(salt, saltBlock, salt.Length);
                saltBlock[salt.Length] = (byte)(block >> 24);
                saltBlock[salt.Length + 1] = (byte)(block >> 16);
                saltBlock[salt.Length + 2] = (byte)(block >> 8);
                saltBlock[salt.Length + 3] = (byte)block;
                byte[] u = hmac.ComputeHash(saltBlock);
                byte[] t = (byte[])u.Clone();
                for (int i = 2; i <= iterations; i++) {
                    u = hmac.ComputeHash(u);
                    for (int j = 0; j < t.Length; j++) t[j] ^= u[j];
                }
                int copy = Math.Min(t.Length, length - generated);
                Array.Copy(t, 0, output, generated, copy); generated += copy; block++;
            }
            return output;
        }
    }

    // Decode the base64 DNS spool, authenticate/decrypt GDT2, and gunzip
    // straight into outputPath.  No full payload-sized managed array exists.
    public static void DecodeSpoolToOutput(string spoolPath, string secret, string outputPath, long maxBytes) {
        string protectedPath = outputPath + ".protected-" + Guid.NewGuid().ToString("N");
        try {
            using (var input = new FileStream(spoolPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var decoded = new FileStream(protectedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces))
            using (var crypto = new CryptoStream(decoded, transform, CryptoStreamMode.Write)) {
                var buf = new byte[65536]; int n;
                while ((n = input.Read(buf, 0, buf.Length)) > 0) crypto.Write(buf, 0, n);
                crypto.FlushFinalBlock();
            }
            using (var protectedFile = new FileStream(protectedPath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                if (protectedFile.Length < 84) throw new Exception("Protected payload is too short");
                byte[] header = new byte[36]; ReadExactly(protectedFile, header, 0, header.Length);
                if (Encoding.ASCII.GetString(header, 0, 4) != "GDT2") throw new Exception("Unsupported protected payload");
                byte[] expectedMac = new byte[32]; ReadExactly(protectedFile, expectedMac, 0, expectedMac.Length);
                byte[] salt = new byte[16]; Array.Copy(header, 4, salt, 0, 16);
                byte[] iv = new byte[16]; Array.Copy(header, 20, iv, 0, 16);
                byte[] material = Pbkdf2Sha256(Encoding.UTF8.GetBytes(secret), salt, 100000, 64);
                byte[] encKey = new byte[32], macKey = new byte[32];
                Array.Copy(material, 0, encKey, 0, 32); Array.Copy(material, 32, macKey, 0, 32);
                byte[] actualMac;
                using (var hmac = new HMACSHA256(macKey))
                using (var sink = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write)) {
                    sink.Write(header, 0, header.Length);
                    var buf = new byte[65536]; int n;
                    while ((n = protectedFile.Read(buf, 0, buf.Length)) > 0) sink.Write(buf, 0, n);
                    sink.FlushFinalBlock(); actualMac = hmac.Hash;
                }
                if (!FixedTimeEquals(expectedMac, actualMac)) throw new Exception("Protected payload authentication failed");
                protectedFile.Position = 68;
                using (var aes = Aes.Create()) {
                    aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.KeySize = 256; aes.Key = encKey; aes.IV = iv;
                    using (var decrypt = new CryptoStream(protectedFile, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (var gzip = new System.IO.Compression.GZipStream(decrypt, System.IO.Compression.CompressionMode.Decompress))
                    using (var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                        var buf = new byte[65536]; int n; long written = 0;
                        while ((n = gzip.Read(buf, 0, buf.Length)) > 0) {
                            written += n;
                            if (written > maxBytes) throw new Exception("Decompressed download exceeds configured limit");
                            output.Write(buf, 0, n);
                        }
                    }
                }
            }
        } finally { try { if (File.Exists(protectedPath)) File.Delete(protectedPath); } catch {} }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count) {
        while (count > 0) { int n = stream.Read(buffer, offset, count); if (n <= 0) throw new EndOfStreamException(); offset += n; count -= n; }
    }
    private static bool FixedTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.Length != b.Length) return false;
        int diff = 0; for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i]; return diff == 0;
    }

    // Builds the existing GDT2 container from a file via gzip/CBC/HMAC
    // spools, then emits DNS base64/base32 without materialising the file.
    public static long PrepareUploadToSpool(string inputPath, string secret, string encoding, string spoolPath) {
        string root = Path.GetDirectoryName(spoolPath);
        string gzipPath = Path.Combine(root, ".gdns2tcp-gzip-" + Guid.NewGuid().ToString("N"));
        string cipherPath = Path.Combine(root, ".gdns2tcp-cipher-" + Guid.NewGuid().ToString("N"));
        string protectedPath = Path.Combine(root, ".gdns2tcp-protected-" + Guid.NewGuid().ToString("N"));
        try {
            using (var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var gzipFile = new FileStream(gzipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var gzip = new System.IO.Compression.GZipStream(gzipFile, System.IO.Compression.CompressionMode.Compress)) {
                input.CopyTo(gzip);
            }
            byte[] salt = new byte[16], iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(salt); rng.GetBytes(iv); }
            byte[] material = Pbkdf2Sha256(Encoding.UTF8.GetBytes(secret), salt, 100000, 64);
            byte[] encKey = new byte[32], macKey = new byte[32];
            Array.Copy(material, 0, encKey, 0, 32); Array.Copy(material, 32, macKey, 0, 32);
            using (var aes = Aes.Create()) {
                aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7; aes.KeySize = 256; aes.Key = encKey; aes.IV = iv;
                using (var gzipInput = new FileStream(gzipPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var cipherFile = new FileStream(cipherPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var encrypt = new CryptoStream(cipherFile, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
                    gzipInput.CopyTo(encrypt); encrypt.FlushFinalBlock();
                }
            }
            byte[] header = new byte[36]; Encoding.ASCII.GetBytes("GDT2").CopyTo(header, 0);
            Array.Copy(salt, 0, header, 4, 16); Array.Copy(iv, 0, header, 20, 16);
            byte[] mac;
            using (var hmac = new HMACSHA256(macKey))
            using (var sink = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write))
            using (var cipherInput = new FileStream(cipherPath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                sink.Write(header, 0, header.Length); cipherInput.CopyTo(sink); sink.FlushFinalBlock(); mac = hmac.Hash;
            }
            using (var protectedOut = new FileStream(protectedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var cipherInput = new FileStream(cipherPath, FileMode.Open, FileAccess.Read, FileShare.Read)) {
                protectedOut.Write(header, 0, header.Length); protectedOut.Write(mac, 0, mac.Length); cipherInput.CopyTo(protectedOut);
            }
            if (string.Equals(encoding, "base32", StringComparison.OrdinalIgnoreCase)) {
                EncodeBase32File(protectedPath, spoolPath);
            } else if (string.Equals(encoding, "base64", StringComparison.OrdinalIgnoreCase)) {
                using (var src = new FileStream(protectedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var dst = new FileStream(spoolPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var transform = new ToBase64Transform())
                using (var output = new CryptoStream(dst, transform, CryptoStreamMode.Write)) {
                    src.CopyTo(output); output.FlushFinalBlock();
                }
            } else throw new Exception("Unsupported DNS encoding " + encoding);
            return new FileInfo(spoolPath).Length;
        } finally {
            try { if (File.Exists(gzipPath)) File.Delete(gzipPath); } catch {}
            try { if (File.Exists(cipherPath)) File.Delete(cipherPath); } catch {}
            try { if (File.Exists(protectedPath)) File.Delete(protectedPath); } catch {}
        }
    }

    private static void EncodeBase32File(string srcPath, string dstPath) {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        using (var src = new FileStream(srcPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var dst = new StreamWriter(new FileStream(dstPath, FileMode.Create, FileAccess.Write, FileShare.None), Encoding.ASCII)) {
            int value = 0, bits = 0, next;
            while ((next = src.ReadByte()) >= 0) {
                value = (value << 8) | next; bits += 8;
                while (bits >= 5) { bits -= 5; dst.Write(alphabet[(value >> bits) & 31]); }
            }
            if (bits > 0) dst.Write(alphabet[(value << (5 - bits)) & 31]);
        }
    }
}
'@ -ErrorAction Stop
    $script:DownloadCSharpLoaded = $true
}

function ConvertTo-BigEndianUInt32 {
    param([Parameter(Mandatory = $true)][int]$Value)
    return [byte[]]@(
        [byte](($Value -shr 24) -band 0xff),
        [byte](($Value -shr 16) -band 0xff),
        [byte](($Value -shr 8) -band 0xff),
        [byte]($Value -band 0xff)
    )
}

function Invoke-Pbkdf2Sha256 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Password,
        [Parameter(Mandatory = $true)][byte[]]$Salt,
        [Parameter(Mandatory = $true)][int]$Iterations,
        [Parameter(Mandatory = $true)][int]$Length
    )

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Password
    $output = New-Object byte[] $Length
    $generated = 0
    $blockIndex = 1

    try {
        while ($generated -lt $Length) {
            $saltAndIndex = New-ByteList
            Add-ByteArray -List $saltAndIndex -Bytes $Salt
            Add-ByteArray -List $saltAndIndex -Bytes (ConvertTo-BigEndianUInt32 -Value $blockIndex)

            [byte[]]$u = $hmac.ComputeHash($saltAndIndex.ToArray())
            [byte[]]$t = Copy-ByteRange -Bytes $u -Offset 0 -Count $u.Length

            for ($i = 2; $i -le $Iterations; $i++) {
                $u = $hmac.ComputeHash($u)
                for ($j = 0; $j -lt $t.Length; $j++) {
                    $t[$j] = [byte]($t[$j] -bxor $u[$j])
                }
            }

            $copyLength = [Math]::Min($t.Length, $Length - $generated)
            [Array]::Copy($t, 0, $output, $generated, $copyLength)
            $generated += $copyLength
            $blockIndex++
        }
        return $output
    }
    finally {
        $hmac.Dispose()
    }
}

function New-RandomBytes {
    param([Parameter(Mandatory = $true)][int]$Length)
    [byte[]]$bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    }
    finally {
        $rng.Dispose()
    }
    return $bytes
}

function Add-ByteArray {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[byte]]$List,

        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )
    $List.AddRange($Bytes)
}

function Copy-ByteRange {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Count
    )
    [byte[]]$output = New-Object byte[] $Count
    [Array]::Copy($Bytes, $Offset, $output, 0, $Count)
    return $output
}


function New-ByteList {
    Write-Output -NoEnumerate ([System.Collections.Generic.List[byte]]::new())
}

function New-AesCbcObject {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$InitVector
    )
    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.BlockSize = 128
    $aes.KeySize = 256
    $aes.Key = $Key
    $aes.IV = $InitVector
    return $aes
}

function Get-HmacSha256 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][byte[]]$Ciphertext
    )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $Key
    $payload = New-ByteList
    Add-ByteArray -List $payload -Bytes $Header
    Add-ByteArray -List $payload -Bytes $Ciphertext
    try {
        return $hmac.ComputeHash($payload.ToArray())
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-ByteArrayEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )
    if ($Left.Length -ne $Right.Length) {
        return $false
    }
    [int]$diff = 0
    for ($i = 0; $i -lt $Left.Length; $i++) {
        $diff = $diff -bor ($Left[$i] -bxor $Right[$i])
    }
    return ($diff -eq 0)
}

function Protect-Bytes {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][byte[]]$Plaintext
    )

    [byte[]]$salt = New-RandomBytes -Length 16
    [byte[]]$iv = New-RandomBytes -Length 16

    [byte[]]$keyMaterial = Get-KeyMaterial -Secret $Secret -Salt $salt
    [byte[]]$encKey = Copy-ByteRange -Bytes $keyMaterial -Offset 0 -Count 32
    [byte[]]$macKey = Copy-ByteRange -Bytes $keyMaterial -Offset 32 -Count 32
    $aes = New-AesCbcObject -Key $encKey -InitVector $iv
    $encryptor = $null
    try {
        $encryptor = $aes.CreateEncryptor()
        [byte[]]$ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
    }
    finally {
        if ($null -ne $encryptor) {
            $encryptor.Dispose()
        }
        $aes.Dispose()
    }

    $headerList = New-ByteList
    Add-ByteArray -List $headerList -Bytes ([System.Text.Encoding]::ASCII.GetBytes('GDT2'))
    Add-ByteArray -List $headerList -Bytes $salt
    Add-ByteArray -List $headerList -Bytes $iv
    [byte[]]$header = $headerList.ToArray()
    [byte[]]$mac = Get-HmacSha256 -Key $macKey -Header $header -Ciphertext $ciphertext
    $out = New-ByteList
    Add-ByteArray -List $out -Bytes $header
    Add-ByteArray -List $out -Bytes $mac
    Add-ByteArray -List $out -Bytes $ciphertext
    return $out.ToArray()
}

function Unprotect-Bytes {
    param(
        [Parameter(Mandatory = $true)][string]$Secret,
        [Parameter(Mandatory = $true)][byte[]]$Protected
    )

    $minimumLength = 4 + 16 + 16 + 32 + 16
    if ($Protected.Length -lt $minimumLength) {
        throw 'Protected payload is too short.'
    }
    $magic = [System.Text.Encoding]::ASCII.GetString((Copy-ByteRange -Bytes $Protected -Offset 0 -Count 4))
    if ($magic -ne 'GDT2') {
        throw 'Protected payload has an unsupported format.'
    }

    $offset = 4
    [byte[]]$salt = Copy-ByteRange -Bytes $Protected -Offset $offset -Count 16
    $offset += 16
    [byte[]]$iv = Copy-ByteRange -Bytes $Protected -Offset $offset -Count 16
    $offset += 16
    [byte[]]$expectedMac = Copy-ByteRange -Bytes $Protected -Offset $offset -Count 32
    $offset += 32
    [byte[]]$ciphertext = Copy-ByteRange -Bytes $Protected -Offset $offset -Count ($Protected.Length - $offset)
    if (($ciphertext.Length % 16) -ne 0) {
        throw 'Protected payload has invalid block size.'
    }

    [byte[]]$keyMaterial = Get-KeyMaterial -Secret $Secret -Salt $salt
    [byte[]]$encKey = Copy-ByteRange -Bytes $keyMaterial -Offset 0 -Count 32
    [byte[]]$macKey = Copy-ByteRange -Bytes $keyMaterial -Offset 32 -Count 32
    [byte[]]$header = Copy-ByteRange -Bytes $Protected -Offset 0 -Count (4 + 16 + 16)
    [byte[]]$actualMac = Get-HmacSha256 -Key $macKey -Header $header -Ciphertext $ciphertext
    if (-not (Test-ByteArrayEqual -Left $expectedMac -Right $actualMac)) {
        throw 'Protected payload authentication failed.'
    }

    $aes = New-AesCbcObject -Key $encKey -InitVector $iv
    $decryptor = $null
    try {
        $decryptor = $aes.CreateDecryptor()
        return $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    }
    finally {
        if ($null -ne $decryptor) {
            $decryptor.Dispose()
        }
        $aes.Dispose()
    }
}

function ConvertTo-Base32 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $output = New-Object System.Text.StringBuilder
    $buffer = 0
    $bitsLeft = 0
    foreach ($byte in $Bytes) {
        $buffer = ($buffer -shl 8) -bor $byte
        $bitsLeft += 8
        while ($bitsLeft -ge 5) {
            $bitsLeft -= 5
            [void]$output.Append($alphabet[($buffer -shr $bitsLeft) -band 0x1F])
        }
    }
    if ($bitsLeft -gt 0) {
        [void]$output.Append($alphabet[($buffer -shl (5 - $bitsLeft)) -band 0x1F])
    }
    $padding = switch ($Bytes.Length % 5) {
        1 { '======' }
        2 { '====' }
        3 { '===' }
        4 { '=' }
        default { '' }
    }
    [void]$output.Append($padding)
    return $output.ToString()
}

function ConvertTo-WireEncoding {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Encoding
    )
    if ($Encoding -eq 'base32') {
        return ConvertTo-Base32 -Bytes $Bytes
    }
    if ($Encoding -eq 'base64') {
        return [Convert]::ToBase64String($Bytes)
    }
    throw "Unsupported encoding $Encoding."
}

function ConvertFrom-Base32 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    $output = New-Object System.Collections.Generic.List[byte]
    $buffer = 0
    $bitsLeft = 0
    foreach ($char in $Text.ToUpperInvariant().TrimEnd('=').ToCharArray()) {
        $index = $alphabet.IndexOf($char)
        if ($index -lt 0) {
            throw "Invalid base32 character: $char"
        }
        $buffer = ($buffer -shl 5) -bor $index
        $bitsLeft += 5
        if ($bitsLeft -ge 8) {
            $bitsLeft -= 8
            [void]$output.Add([byte](($buffer -shr $bitsLeft) -band 0xFF))
        }
    }
    return $output.ToArray()
}

function ConvertFrom-WireEncoding {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Encoding
    )
    if ($Encoding -eq 'base32') {
        return ConvertFrom-Base32 -Text $Text
    }
    if ($Encoding -eq 'base64') {
        $normalized = $Text.Replace('_', '+').Replace('-', '/')
        $rem = $normalized.Length % 4
        if ($rem -ne 0) { $normalized += '=' * (4 - $rem) }
        return [Convert]::FromBase64String($normalized)
    }
    throw "Unsupported encoding $Encoding."
}

function Get-UnixMinute {
    $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01T00:00:00', [DateTimeKind]::Utc)
    return [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalSeconds / 60)
}

function New-HmacSha256Text {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    try {
        return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Message))
    }
    finally {
        $hmac.Dispose()
    }
}

function New-AuthToken {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Args,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )
    $parts = New-Object System.Collections.Generic.List[string]
    [void]$parts.Add('gdns2tcp-auth-v1')
    [void]$parts.Add($script:DomainName.ToLowerInvariant().TrimEnd('.'))
    [void]$parts.Add($Command.ToLowerInvariant())
    [void]$parts.Add($Timestamp)
    foreach ($arg in @($Args)) {
        # protocol.AuthToken canonicalises each DNS label.  Base64 upload
        # chunks contain mixed case, so signing their original spelling made
        # PowerShell uploads fail as soon as the payload contained A-Z.
        [void]$parts.Add($arg.ToLowerInvariant())
    }
    [byte[]]$hash = New-HmacSha256Text -Key $Pass -Message ($parts -join '|')
    [byte[]]$shortHash = Copy-ByteRange -Bytes $hash -Offset 0 -Count 16
    return (ConvertTo-Base32 -Bytes $shortHash).TrimEnd('=').ToLowerInvariant()
}

function New-AuthenticatedName {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Args
    )
    $timestamp = [string](Get-UnixMinute)
    $token = New-AuthToken -Command $Command -Args $Args -Timestamp $timestamp
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($arg in @($Args)) {
        [void]$labels.Add($arg)
    }
    [void]$labels.Add($timestamp)
    [void]$labels.Add($token)
    [void]$labels.Add($Command.ToLowerInvariant())
    [void]$labels.Add($script:DomainName)
    return ($labels -join '.')
}

function New-TransferId {
    return ([BitConverter]::ToString((New-RandomBytes -Length 8))).Replace('-', '').ToLowerInvariant()
}

function ConvertTo-FilenameLabels {
    param([Parameter(Mandatory = $true)][string]$Name)
    $baseName = [System.IO.Path]::GetFileName($Name)
    if ([string]::IsNullOrWhiteSpace($baseName)) {
        throw 'Filename is empty.'
    }
    $encoded = (ConvertTo-Base32 -Bytes ([System.Text.Encoding]::UTF8.GetBytes($baseName))).TrimEnd('=').ToLowerInvariant()
    $labels = New-Object System.Collections.Generic.List[string]
    [void]$labels.Add('f1')
    foreach ($part in @(Split-StringFixed -Value $encoded -Size 63)) {
        [void]$labels.Add($part)
    }
    return $labels.ToArray()
}

function ConvertTo-DnsSafeChunk {
    param(
        [Parameter(Mandatory = $true)][string]$Chunk,
        [Parameter(Mandatory = $true)][string]$Encoding
    )
    $safe = $Chunk.Replace('+', '_').Replace('/', '-').Replace('=', '')
    if ($Encoding -eq 'base32') {
        return $safe.ToLowerInvariant()
    }
    return $safe
}

function Get-UploadChunkSize {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$Requested
    )
    # Index placeholder must be at least as wide as the decimal form of
    # the server's maxTransferChunks-1 (currently 1_999_999 — 7 digits).
    # A narrower placeholder makes the returned chunk size fit the
    # 253-byte DNS name budget at low indices but overflow it once the
    # running chunkIndex crosses 10^placeholderWidth mid-upload; the
    # per-chunk guard at line ~1596 then aborts the transfer.
    # Kept in sync with the Go client's uploadIndexPlaceholderWidth
    # constant (see cmd/gdns2tcp-client/main.go).
    $uploadIndexPlaceholder = '99999999'
    $size = [Math]::Min($Requested, 180)
    for ($candidate = $size; $candidate -ge 32; $candidate--) {
        $dummy = 'a' * $candidate
        $labels = @(Split-StringFixed -Value $dummy -Size 63)
        $args = @($Sid, $uploadIndexPlaceholder) + $labels
        $name = New-AuthenticatedName -Command 'u' -Args $args
        if ($name.Length -le 253) {
            return $candidate
        }
    }
    throw 'Domain is too long for safe DNS upload chunks.'
}

function Compress-File {
    param([Parameter(Mandatory = $true)][string]$Path)

    $inputStream = [System.IO.File]::OpenRead($Path)
    $memoryStream = [System.IO.MemoryStream]::new()
    $gzipStream = [System.IO.Compression.GzipStream]::new(
        $memoryStream,
        [System.IO.Compression.CompressionMode]::Compress,
        $true
    )
    try {
        $inputStream.CopyTo($gzipStream)
    }
    finally {
        $gzipStream.Dispose()
        $inputStream.Dispose()
    }
    try {
        return $memoryStream.ToArray()
    }
    finally {
        $memoryStream.Dispose()
    }
}

function Expand-GzipBytes {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$LimitBytes
    )

    $inputStream = [System.IO.MemoryStream]::new($Bytes)
    $gzipStream = [System.IO.Compression.GzipStream]::new($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
    $outputStream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    $failed = $true
    try {
        [byte[]]$buffer = New-Object byte[] 8192
        [int64]$written = 0
        while ($true) {
            $read = $gzipStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) {
                break
            }
            $written += $read
            if ($written -gt $LimitBytes) {
                throw "Decompressed download exceeds $LimitBytes bytes."
            }
            $outputStream.Write($buffer, 0, $read)
        }
        $failed = $false
    }
    finally {
        $outputStream.Dispose()
        $gzipStream.Dispose()
        $inputStream.Dispose()
        if ($failed -and [System.IO.File]::Exists($Path)) {
            Remove-Item -LiteralPath $Path -Force
        }
    }
}

function Resolve-InputFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Input file is required.'
    }
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    }
    else {
        Join-Path -Path (Get-Location) -ChildPath $Path
    }
    $full = [System.IO.Path]::GetFullPath($candidate)
    if (-not [System.IO.File]::Exists($full)) {
        throw "Input file does not exist: $full"
    }
    return $full
}

function Resolve-OutputFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'Output file is required.'
    }
    $candidate = if ([System.IO.Path]::IsPathRooted($Path)) {
        $Path
    }
    else {
        Join-Path -Path (Get-Location) -ChildPath $Path
    }
    $full = [System.IO.Path]::GetFullPath($candidate)
    if ([System.IO.File]::Exists($full)) {
        throw "Output file already exists: $full"
    }
    return $full
}

function Split-StringFixed {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int]$Size
    )

    $parts = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Value.Length; $i += $Size) {
        $length = [Math]::Min($Size, $Value.Length - $i)
        [void]$parts.Add($Value.Substring($i, $length))
    }
    return $parts.ToArray()
}

function Format-TransferRate {
    param([Parameter(Mandatory = $true)][double]$BytesPerSecond)
    if ($BytesPerSecond -ge 1048576) { return ('{0:F1} MB/s' -f ($BytesPerSecond / 1048576)) }
    if ($BytesPerSecond -ge 1024)    { return ('{0:F1} KB/s' -f ($BytesPerSecond / 1024)) }
    return ('{0:F0} B/s' -f $BytesPerSecond)
}

function Format-ETA {
    param([Parameter(Mandatory = $true)][int]$Seconds)
    if ($Seconds -lt 60) { return "${Seconds}s" }
    [int]$m = [Math]::Floor($Seconds / 60); [int]$s = $Seconds % 60
    if ($m -lt 60) { return ('{0}m{1:D2}s' -f $m, $s) }
    [int]$h = [Math]::Floor($m / 60); [int]$m = $m % 60
    return ('{0}h{1:D2}m' -f $h, $m)
}

function Test-Gdns2Tcp {
    $response = Invoke-TxtQueryOne -Name "EnCoDiNg.test.$script:DomainName"
    if ($response -ne 'base32' -and $response -ne 'base64') {
        throw "Server did not return a supported encoding: $response"
    }
    Write-Log -Level 'INFO' -Message "Server selected $response upload encoding."
    return $response
}

function Invoke-List {
    Assert-Secret
    $firstPage = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'c' -Args @())
    Write-Output $firstPage
    if ($firstPage -match 'Catalog contains (\d+) pages') {
        $pages = [int]$Matches[1]
        for ($page = 0; $page -lt $pages; $page++) {
            Write-Output (Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'c' -Args @([string]($page))))
        }
    }
}

function Assert-Secret {
    if ([string]::IsNullOrWhiteSpace($Pass)) {
        throw 'Pass is required for List, Upload and Download modes.'
    }
}

function Invoke-Upload {
    Assert-Secret
    $encoding = Test-Gdns2Tcp
    $inputPath = Resolve-InputFile -Path $InFile
    $sid = New-TransferId
    $filenameLabels = @(ConvertTo-FilenameLabels -Name ([System.IO.Path]::GetFileName($inputPath)))

    $spoolPath = Join-Path ([System.IO.Path]::GetTempPath()) ("gdns2tcp-upload-" + [guid]::NewGuid().ToString('N') + '.txt')
    $spool = $null
    try {
        Write-Log -Level 'INFO' -Message "Compressing and encrypting $inputPath to a disk spool."
        Import-DownloadCSharp
        [int64]$encodedSize = [Gdns2TcpDownload]::PrepareUploadToSpool($inputPath, $Pass, $encoding, $spoolPath)
        $effectiveChunkSize = Get-UploadChunkSize -Sid $sid -Requested $ChunkSize
        [int]$chunkCount = [Math]::Ceiling($encodedSize / [double]$effectiveChunkSize)
        if ($chunkCount -le 0) { throw 'Upload has no encoded chunks.' }
        Write-Log -Level 'INFO' -Message "Prepared $chunkCount DNS chunks."

        $initArgs = @($sid, [string]$chunkCount, [string]($effectiveChunkSize), $encoding) + $filenameLabels
        $initName = New-AuthenticatedName -Command 'uinit' -Args $initArgs
        if ($initName.Length -gt 253) { throw "DNS upload init name is $($initName.Length) characters (limit 253). Use a shorter filename or domain." }
        $initResponse = Invoke-TxtQueryOne -Name $initName
        if ($initResponse -ne 'Ready to file uploading') { throw "Upload initialization failed: $initResponse" }

        $spool = [System.IO.File]::OpenRead($spoolPath)
        $uploadStart = Get-Date
        [int]$chunkIndex = 0
        while ($true) {
            if ($chunkIndex -eq -1) { break }
            if ($chunkIndex -lt 0) { throw "Server signaled upload failure with code $chunkIndex." }
            if ($chunkIndex -ge $chunkCount) { throw "Server requested chunk $chunkIndex outside prepared range." }
            [int64]$offset = [int64]$chunkIndex * $effectiveChunkSize
            [int]$want = [int][Math]::Min($effectiveChunkSize, $encodedSize - $offset)
            [byte[]]$buffer = New-Object byte[] $want
            $spool.Position = $offset
            [int]$read = 0
            while ($read -lt $want) {
                $n = $spool.Read($buffer, $read, $want - $read)
                if ($n -le 0) { throw "Unexpected end of upload spool at chunk $chunkIndex." }
                $read += $n
            }
            $safeChunk = ConvertTo-DnsSafeChunk -Chunk ([System.Text.Encoding]::ASCII.GetString($buffer)) -Encoding $encoding
            $labels = @(Split-StringFixed -Value $safeChunk -Size 63)
            $request = New-AuthenticatedName -Command 'u' -Args (@($sid, [string]($chunkIndex)) + $labels)
            if ($request.Length -gt 253) { throw "DNS query name for chunk $chunkIndex is $($request.Length) characters (limit 253). Reduce -ChunkSize or use a shorter domain." }
            $response = Invoke-TxtQueryOne -Name $request
            [int]$nextIndex = 0
            if (-not [int]::TryParse($response, [ref]$nextIndex)) { throw "Server returned an upload error: $response" }
            $chunkIndex = $nextIndex
            $completed = if ($chunkIndex -lt 0) { $chunkCount } else { $chunkIndex }
            $elapsed = ((Get-Date) - $uploadStart).TotalSeconds
            $status = "$completed of $chunkCount chunks"
            if ($elapsed -gt 0.5 -and $completed -gt 0) { $status += '  ' + (Format-TransferRate -BytesPerSecond ($completed * $effectiveChunkSize / $elapsed)) }
            Write-Progress -Activity 'Uploading file' -Status $status -PercentComplete ([Math]::Min(100, [Math]::Round(($completed / $chunkCount) * 100, 1)))
        }
        Write-Progress -Activity 'Uploading file' -Completed
        Write-Log -Level 'INFO' -Message 'Upload completed.'
    }
    finally {
        if ($null -ne $spool) { $spool.Dispose() }
        if ([System.IO.File]::Exists($spoolPath)) { Remove-Item -LiteralPath $spoolPath -Force }
    }
}

function Invoke-Download {
    Assert-Secret
    if ([string]::IsNullOrWhiteSpace($Filename)) {
        throw 'Filename is required for Download mode.'
    }
    $destination = if ([string]::IsNullOrWhiteSpace($OutFile)) { $Filename } else { $OutFile }
    $outputPath = Resolve-OutputFile -Path $destination
    $sid = New-TransferId
    $filenameLabels = @(ConvertTo-FilenameLabels -Name $Filename)

    $initName = New-AuthenticatedName -Command 'dinit' -Args (@($sid) + $filenameLabels)
    if ($initName.Length -gt 253) {
        throw "DNS download init name is $($initName.Length) characters (limit 253). Use a shorter filename or domain."
    }
    $chunkCountText = Invoke-TxtQueryOne -Name $initName
    [int]$chunkCount = 0
    if (-not [int]::TryParse($chunkCountText, [ref]$chunkCount) -or $chunkCount -le 0) {
        throw "Download initialization failed: $chunkCountText"
    }
    $metaText = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'dmeta' -Args @($sid))
    $meta = $metaText.Split('|')
    if ($meta.Count -ne 3) { throw "Download metadata is malformed: $metaText" }
    [int]$metaChunks = 0; [int64]$encodedSize = 0
    if (-not [int]::TryParse($meta[0], [ref]$metaChunks) -or $metaChunks -ne $chunkCount) { throw "Download metadata chunk count mismatch." }
    if ($meta[1] -notmatch '^[a-fA-F0-9]{64}$') { throw 'Download metadata digest is malformed.' }
    if (-not [int64]::TryParse($meta[2], [ref]$encodedSize) -or $encodedSize -le 0) { throw 'Download metadata encoded size is malformed.' }
    [int64]$maxEncoded = if ($MaxDownloadBytes -gt [int64]::MaxValue / 2) { [int64]::MaxValue } else { $MaxDownloadBytes * 2 }
    if ($encodedSize -gt $maxEncoded) { throw "Encoded download exceeds $MaxDownloadBytes byte limit." }
    [int64]$expectedChunks = [int64][Math]::Ceiling($encodedSize / 254.0)
    if ($expectedChunks -ne $chunkCount) { throw 'Download metadata size does not match chunk count.' }
    Write-Log -Level 'INFO' -Message "Downloading $Filename in $chunkCount chunks."

    $spoolPath = Join-Path ([System.IO.Path]::GetTempPath()) ("gdns2tcp-download-" + [guid]::NewGuid().ToString('N') + '.b64')
    $tempOutput = Join-Path ([System.IO.Path]::GetDirectoryName($outputPath)) ('.gdns2tcp-output-' + [guid]::NewGuid().ToString('N'))
    $parallelDone = $false
    try {
        if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
            try {
                Import-DownloadCSharp
                $proto = if ($Tcp) { 'TCP' } else { 'UDP' }
                Write-Log -Level 'INFO' -Message "Downloading to a disk spool over $proto (up to $Parallelism concurrent, $BatchSize chunks per query)."
                $dlStart = Get-Date
                $task = [Gdns2TcpDownload]::BeginDownloadChunksToSpool(
                    $Pass, $script:DomainName, $sid, $chunkCount, $encodedSize, $spoolPath,
                    $DnsServer, $DnsPort, 5000, $Retries, ($RetryDelaySeconds * 1000), $Parallelism, $Tcp.IsPresent, $BatchSize
                )
                while (-not $task.IsCompleted) {
                    $done = [Gdns2TcpDownload]::CompletedChunks
                    $elapsed = ((Get-Date) - $dlStart).TotalSeconds
                    $percent = [Math]::Min(100, [Math]::Round(($done / $chunkCount) * 100, 1))
                    $status = "$done of $chunkCount chunks"
                    if ($elapsed -gt 0.5 -and $done -gt 0) { $status += '  ' + (Format-TransferRate -BytesPerSecond ($done * 254 / $elapsed)) }
                    Write-Progress -Activity 'Downloading file' -Status $status -PercentComplete $percent
                    Start-Sleep -Milliseconds 250
                }
                $task.GetAwaiter().GetResult()
                Write-Progress -Activity 'Downloading file' -Completed
                $parallelDone = $true
            }
            catch { Write-Log -Level 'WARN' -Message "Parallel download failed, retrying sequentially: $_" }
        }

        if (-not $parallelDone) {
            $stream = [System.IO.FileStream]::new($spoolPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
            try {
                $stream.SetLength($encodedSize)
                $downloadStart = Get-Date
                for ($i = 0; $i -lt $chunkCount; $i++) {
                    $chunk = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'd' -Args @($sid, [string]($i)))
                    [int64]$offset = [int64]$i * 254
                    [int]$want = [int][Math]::Min(254, $encodedSize - $offset)
                    if ($chunk.Length -ne $want -or $chunk -match '\s' -or $chunk -notmatch '^[A-Za-z0-9+/=]+$') { throw "Server returned invalid chunk ${i}." }
                    [byte[]]$bytes = [System.Text.Encoding]::ASCII.GetBytes($chunk)
                    $stream.Position = $offset; $stream.Write($bytes, 0, $bytes.Length)
                    $elapsed = ((Get-Date) - $downloadStart).TotalSeconds
                    Write-Progress -Activity 'Downloading file' -Status "$($i + 1) of $chunkCount chunks" -PercentComplete ([Math]::Round((($i + 1) / $chunkCount) * 100, 1))
                }
            }
            finally { $stream.Dispose(); Write-Progress -Activity 'Downloading file' -Completed }
        }

        Import-DownloadCSharp
        [Gdns2TcpDownload]::DecodeSpoolToOutput($spoolPath, $Pass, $tempOutput, $MaxDownloadBytes)
        if ((Get-FileHash -LiteralPath $tempOutput -Algorithm SHA256).Hash.ToLowerInvariant() -ne $meta[1].ToLowerInvariant()) { throw 'Download source digest mismatch.' }
        [System.IO.File]::Move($tempOutput, $outputPath)
        Write-Log -Level 'INFO' -Message "Download written to $outputPath."
    }
    finally {
        if ([System.IO.File]::Exists($spoolPath)) { Remove-Item -LiteralPath $spoolPath -Force }
        if ([System.IO.File]::Exists($tempOutput)) { Remove-Item -LiteralPath $tempOutput -Force }
    }
}

try {
    $script:DomainName = Normalize-Domain -Value $Domain
    $script:DnsTool = Get-DnsTool
    if ([string]::IsNullOrWhiteSpace($DnsServer)) {
        Write-Log -Level 'INFO' -Message "Using system DNS resolver for $script:DomainName."
    }
    else {
        Write-Log -Level 'INFO' -Message "Using DNS server $($DnsServer):$DnsPort."
    }
    Write-Log -Level 'INFO' -Message "Using DNS resolver $($script:DnsTool.Name)."

    switch ($Mode) {
        'Test' {
            [void](Test-Gdns2Tcp)
        }
        'List' {
            Invoke-List
        }
        'Upload' {
            Invoke-Upload
        }
        'Download' {
            Invoke-Download
        }
    }
    exit 0
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    exit 1
}
