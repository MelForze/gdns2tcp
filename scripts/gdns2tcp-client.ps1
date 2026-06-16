<#
.SYNOPSIS
Transfers files through an explicitly configured gdns2tcp DNS TXT server.

.DESCRIPTION
gdns2tcp-client.ps1 is intended for authorized administration, lab testing, and
training environments. It uploads and downloads user-selected files through DNS
TXT requests. The script does not configure autorun, alter monitoring controls,
or execute code received from the network.

.PARAMETER Domain
Authoritative domain served by gdns2tcp, for example files.example.com.

.PARAMETER Mode
Operation to run: Upload, Download, List, or Test.

.PARAMETER InFile
Local file to upload when Mode is Upload.

.PARAMETER OutFile
Local destination path when Mode is Download. Existing files are not overwritten.

.PARAMETER Filename
Remote filename to download when Mode is Download.

.PARAMETER Pass
Shared encryption secret used by the server and client.

.PARAMETER DnsServer
Optional DNS server address. When omitted, the client resolves Domain and uses
the first returned IP address.

.PARAMETER DnsPort
DNS server port. Defaults to 53.

.PARAMETER ChunkSize
Maximum encoded upload chunk size. The default is conservative for long domains.

.PARAMETER Retries
Number of DNS query attempts before failing.

.PARAMETER RetryDelaySeconds
Delay between failed DNS query attempts.

.PARAMETER LogPath
Optional path for an append-only text log.

.PARAMETER MaxDownloadBytes
Maximum decompressed download size. Defaults to 33554432 bytes.

.EXAMPLE
.\gdns2tcp-client.ps1 -Domain files.example.com -Mode Test -Pass secret -DnsServer 192.0.2.10

.EXAMPLE
.\gdns2tcp-client.ps1 -Domain files.example.com -Mode Upload -Pass secret -InFile .\sample.txt

.EXAMPLE
.\gdns2tcp-client.ps1 -Domain files.example.com -Mode Download -Pass secret -Filename sample.txt -OutFile .\sample.txt
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
    [string]$InFile = '',

    [Parameter()]
    [string]$OutFile = '',

    [Parameter()]
    [string]$Filename = '',

    [Parameter()]
    [string]$Pass = '',

    [Parameter()]
    [string]$DnsServer = '',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$DnsPort = 53,

    [Parameter()]
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
    [ValidateRange(1, 2147483647)]
    [int64]$MaxDownloadBytes = 33554432,

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
    return $normalized
}

function Resolve-DomainServer {
    param([Parameter(Mandatory = $true)][string]$Value)
    try {
        $addresses = @([System.Net.Dns]::GetHostAddresses($Value))
    }
    catch {
        throw "Cannot resolve DNS server from domain $Value. Specify -DnsServer explicitly. $($_.Exception.Message)"
    }
    if ($addresses.Length -lt 1) {
        throw "Domain $Value did not resolve to an IP address. Specify -DnsServer explicitly."
    }
    $ipv4Addresses = @($addresses | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
    if ($ipv4Addresses.Length -gt 0) {
        return $ipv4Addresses[0].IPAddressToString
    }
    return $addresses[0].IPAddressToString
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
            if ($DnsPort -ne 53) {
                $arguments += @('-p', [string]$DnsPort)
            }
            if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
                $arguments += $DnsServer
            }
        }
        'nslookup' {
            $arguments = @('-type=TXT')
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

# Compiled C# PBKDF2-SHA256 fallback. Works on any .NET version (Framework 4.0+,
# Core, .NET 5+) and runs in ~milliseconds versus 1-3 minutes for the pure-PS loop.
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

# Compiled C# parallel DNS downloader. Works on .NET Framework 4.5+ and .NET Core/5+.
# Recomputes auth tokens per goroutine so timestamps stay fresh across minute boundaries.
function Import-DownloadCSharp {
    if ($script:DownloadCSharpLoaded) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class Gdns2TcpDownload {
    private static readonly char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();

    private static string BuildAuthToken(string secret, string domain, string command, string ts, string[] args) {
        var parts = new List<string>(args.Length + 4);
        parts.Add("gdns2tcp-auth-v1");
        parts.Add(domain.ToLowerInvariant().TrimEnd('.'));
        parts.Add(command);
        parts.Add(ts);
        parts.AddRange(args);
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
        var b = new List<byte>(256);
        b.Add((byte)(id >> 8)); b.Add((byte)id);
        b.Add(0x01); b.Add(0x00);
        b.Add(0x00); b.Add(0x01);                       // QDCOUNT=1
        b.Add(0x00); b.Add(0x00);                       // ANCOUNT=0
        b.Add(0x00); b.Add(0x00);                       // NSCOUNT=0
        b.Add(0x00); b.Add(0x01);                       // ARCOUNT=1 (EDNS0 OPT)
        foreach (string label in name.TrimEnd('.').Split('.')) {
            byte[] lb = Encoding.ASCII.GetBytes(label);
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
        using (var tcp = new System.Net.Sockets.TcpClient()) {
            tcp.Connect(server, port);
            tcp.ReceiveTimeout = timeoutMs;
            tcp.SendTimeout = timeoutMs;
            var ns = tcp.GetStream();
            // DNS over TCP: 2-byte big-endian length prefix
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
            byte[] resp = new byte[rlen];
            nread = 0;
            while (nread < rlen) {
                int got = ns.Read(resp, nread, rlen - nread);
                if (got <= 0) throw new Exception("TCP connection closed before response body");
                nread += got;
            }
            return ParseTxt(resp, id);
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
        var sem = new SemaphoreSlim(concurrency, concurrency);
        var tasks = new Task[nBatches];
        for (int i = 0; i < nBatches; i++) {
            int batchIdx = i;
            int from = i * batchSize;
            int batchCount = Math.Min(batchSize, count - from);
            tasks[batchIdx] = Task.Run(() => {
                sem.Wait();
                try {
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
                            return;
                        } catch (Exception ex) {
                            last = ex;
                            if (att < retries - 1) Thread.Sleep(retryDelayMs);
                        }
                    }
                    throw last;
                } finally { sem.Release(); }
            });
        }
        try { Task.WaitAll(tasks); }
        catch (AggregateException ae) {
            var m = new List<string>();
            foreach (var ex in ae.InnerExceptions) m.Add(ex.Message);
            throw new Exception("parallel chunk download: " + string.Join("; ", m));
        }
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
        [void]$parts.Add($arg)
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
    $size = [Math]::Min($Requested, 180)
    for ($candidate = $size; $candidate -ge 32; $candidate--) {
        $dummy = 'a' * $candidate
        $labels = @(Split-StringFixed -Value $dummy -Size 63)
        $args = @($Sid, '999999') + $labels
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

    Write-Log -Level 'INFO' -Message "Compressing and encrypting $inputPath."
    [byte[]]$compressed = Compress-File -Path $inputPath
    [byte[]]$protected = Protect-Bytes -Secret $Pass -Plaintext $compressed
    $encoded = ConvertTo-WireEncoding -Bytes $protected -Encoding $encoding
    if ($encoding -eq 'base32') {
        $encoded = $encoded.ToLowerInvariant()
    }

    $effectiveChunkSize = Get-UploadChunkSize -Sid $sid -Requested $ChunkSize
    $chunks = @(Split-StringFixed -Value $encoded -Size $effectiveChunkSize)
    Write-Log -Level 'INFO' -Message "Prepared $($chunks.Count) DNS chunks."

    $initArgs = @($sid, [string]($chunks.Count), [string]($effectiveChunkSize), $encoding) + $filenameLabels
    $initName = New-AuthenticatedName -Command 'uinit' -Args $initArgs
    if ($initName.Length -gt 253) {
        throw "DNS upload init name is $($initName.Length) characters (limit 253). Use a shorter filename or domain."
    }
    $initResponse = Invoke-TxtQueryOne -Name $initName
    if ($initResponse -ne 'Ready to file uploading') {
        throw "Upload initialization failed: $initResponse"
    }

    $uploadStart = Get-Date
    [int]$chunkIndex = 0
    while ($true) {
        if ($chunkIndex -eq -1) {
            break
        }
        if ($chunkIndex -lt 0) {
            throw "Server signaled upload failure with code $chunkIndex."
        }
        if ($chunkIndex -ge $chunks.Count) {
            throw "Server requested chunk $chunkIndex outside prepared range."
        }

        $safeChunk = ConvertTo-DnsSafeChunk -Chunk $chunks[$chunkIndex] -Encoding $encoding
        $labels = @(Split-StringFixed -Value $safeChunk -Size 63)
        $request = New-AuthenticatedName -Command 'u' -Args (@($sid, [string]($chunkIndex)) + $labels)
        if ($request.Length -gt 253) {
            throw "DNS query name for chunk $chunkIndex is $($request.Length) characters (limit 253). Reduce -ChunkSize or use a shorter domain."
        }
        $response = Invoke-TxtQueryOne -Name $request

        [int]$nextIndex = 0
        if (-not [int]::TryParse($response, [ref]$nextIndex)) {
            throw "Server returned an upload error: $response"
        }
        $chunkIndex = $nextIndex
        $completed = if ($chunkIndex -lt 0) { $chunks.Count } else { $chunkIndex }
        $percent = [Math]::Min(100, [Math]::Round(($completed / $chunks.Count) * 100, 1))
        $elapsed = ((Get-Date) - $uploadStart).TotalSeconds
        $status = "$completed of $($chunks.Count) chunks"
        if ($elapsed -gt 0.5 -and $completed -gt 0) {
            $bps = $completed * $effectiveChunkSize / $elapsed
            $status += '  ' + (Format-TransferRate -BytesPerSecond $bps)
            if ($completed -lt $chunks.Count -and $bps -gt 0) {
                $remSec = [int][Math]::Round(($chunks.Count - $completed) * $effectiveChunkSize / $bps)
                $status += '  ETA ' + (Format-ETA -Seconds $remSec)
            }
        }
        Write-Progress -Activity 'Uploading file' -Status $status -PercentComplete $percent
    }
    Write-Progress -Activity 'Uploading file' -Completed
    Write-Log -Level 'INFO' -Message 'Upload completed.'
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
    Write-Log -Level 'INFO' -Message "Downloading $Filename in $chunkCount chunks."

    # Server always encodes downloads as standard base64 via ProtectToBase64, regardless of upload encoding.
    $chunkPattern = '^[A-Za-z0-9+/=]+$'
    $builder = [System.Text.StringBuilder]::new($chunkCount * 254)
    $parallelDone = $false

    if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
        try {
            Import-DownloadCSharp
            $proto = if ($Tcp) { 'TCP' } else { 'UDP' }
            Write-Log -Level 'INFO' -Message "Downloading $chunkCount chunks in parallel over $proto (up to $Parallelism concurrent, $BatchSize chunks per query)."
            $dlStart = Get-Date
            $task = [Gdns2TcpDownload]::BeginDownloadChunks(
                $Pass, $script:DomainName, $sid, $chunkCount,
                $DnsServer, $DnsPort, 5000,
                $Retries, ($RetryDelaySeconds * 1000), $Parallelism, $Tcp.IsPresent, $BatchSize
            )
            while (-not $task.IsCompleted) {
                $done = [Gdns2TcpDownload]::CompletedChunks
                $elapsed = ((Get-Date) - $dlStart).TotalSeconds
                $percent = [Math]::Min(100, [Math]::Round(($done / $chunkCount) * 100, 1))
                $status = "$done of $chunkCount chunks"
                if ($elapsed -gt 0.5 -and $done -gt 0) {
                    $bps = $done * 254 / $elapsed
                    $status += '  ' + (Format-TransferRate -BytesPerSecond $bps)
                    if ($done -lt $chunkCount -and $bps -gt 0) {
                        $remSec = [int][Math]::Round(($chunkCount - $done) * 254 / $bps)
                        $status += '  ETA ' + (Format-ETA -Seconds $remSec)
                    }
                }
                Write-Progress -Activity 'Downloading file' -Status $status -PercentComplete $percent
                Start-Sleep -Milliseconds 250
            }
            [string[]]$batchResults = $task.Result
            for ($i = 0; $i -lt $batchResults.Length; $i++) {
                $batch = $batchResults[$i]
                if ($batch -match '\s' -or $batch -notmatch $chunkPattern) {
                    throw ("Server returned an error for batch starting at chunk {0}: {1}" -f ($i * $BatchSize), $batch)
                }
                [void]$builder.Append($batch)
            }
            Write-Progress -Activity 'Downloading file' -Completed
            $parallelDone = $true
        }
        catch {
            Write-Log -Level 'WARN' -Message "Parallel download failed, retrying sequentially: $_"
            $builder = [System.Text.StringBuilder]::new($chunkCount * 254)
        }
    }

    if (-not $parallelDone) {
        $downloadStart = Get-Date
        for ($i = 0; $i -lt $chunkCount; $i++) {
            $chunk = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'd' -Args @($sid, [string]($i)))
            if ($chunk -match '\s' -or $chunk -notmatch $chunkPattern) {
                throw "Server returned an error for chunk ${i}: $chunk"
            }
            [void]$builder.Append($chunk)
            $elapsed = ((Get-Date) - $downloadStart).TotalSeconds
            $percent = [Math]::Round((($i + 1) / $chunkCount) * 100, 1)
            $status = "$($i + 1) of $chunkCount chunks"
            if ($elapsed -gt 0.5 -and $i -gt 0) {
                $bps = ($i + 1) * 254 / $elapsed
                $status += '  ' + (Format-TransferRate -BytesPerSecond $bps)
                if ($bps -gt 0) {
                    $remSec = [int][Math]::Round(($chunkCount - $i - 1) * 254 / $bps)
                    $status += '  ETA ' + (Format-ETA -Seconds $remSec)
                }
            }
            Write-Progress -Activity 'Downloading file' -Status $status -PercentComplete $percent
        }
        Write-Progress -Activity 'Downloading file' -Completed
    }

    [byte[]]$protected = ConvertFrom-WireEncoding -Text $builder.ToString() -Encoding 'base64'
    [byte[]]$compressed = Unprotect-Bytes -Secret $Pass -Protected $protected
    Expand-GzipBytes -Bytes $compressed -Path $outputPath -LimitBytes $MaxDownloadBytes
    Write-Log -Level 'INFO' -Message "Download written to $outputPath."
}

try {
    $script:DomainName = Normalize-Domain -Value $Domain
    if ([string]::IsNullOrWhiteSpace($DnsServer)) {
        $DnsServer = Resolve-DomainServer -Value $script:DomainName
        Write-Log -Level 'INFO' -Message "Using DNS server $($DnsServer):$DnsPort resolved from $script:DomainName."
    }
    $script:DnsTool = Get-DnsTool
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
