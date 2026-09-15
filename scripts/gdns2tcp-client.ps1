#requires -Version 5.1
<#
.SYNOPSIS
    gdns2tcp PowerShell file-transfer client for Windows PowerShell 5.1+.

.DESCRIPTION
    Supports Test, List, Upload, and Download modes over DNS TXT records.

    This version optimizes large downloads by:
      * using the native Windows DNS resolver when -DnsServer is omitted;
      * using native Windows DNS calls for parallel system-resolver queries;
      * keeping TCP DNS connections alive in a connection pool;
      * requesting several file chunks per DNS query (db batches);
      * using the same 32 workers / 14-chunk download defaults as the Go client;
      * retrying only the failed/timed-out DNS query without changing
        transport, batch size, or parallelism;
      * showing transfer rate, ETA, and retry count.

    The script deliberately parses its own command line so both PowerShell
    style (-Domain, -Tcp) and GNU style (--domain, --tcp, --help) work.

.EXAMPLE
    .\gdns2tcp-client.ps1 --help

.EXAMPLE
    .\gdns2tcp-client.ps1 -Domain files.example.com -Mode Test

.EXAMPLE
    .\gdns2tcp-client.ps1 -Domain files.example.com -Pass $env:GDNS_PASS -Mode List

.EXAMPLE
    .\gdns2tcp-client.ps1 -Domain files.example.com -Pass $env:GDNS_PASS -Mode Upload -InFile .\payload.bin

.EXAMPLE
    .\gdns2tcp-client.ps1 -Domain files.example.com -Pass $env:GDNS_PASS -Mode Download -Filename payload.bin -Tcp

.EXAMPLE
    .\gdns2tcp-client.ps1 --domain files.example.com --pass $env:GDNS_PASS --download payload.bin --tcp
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptVersion = '2.2.1-go-resolver'

function Show-Help {
    @"
gdns2tcp-client.ps1 $ScriptVersion

Usage:
  .\gdns2tcp-client.ps1 -Domain <zone> -Mode <Test|List|Upload|Download> [options]
  .\gdns2tcp-client.ps1 --domain <zone> --test [options]
  .\gdns2tcp-client.ps1 --domain <zone> --pass <secret> --list [options]
  .\gdns2tcp-client.ps1 --domain <zone> --pass <secret> --upload <path> [options]
  .\gdns2tcp-client.ps1 --domain <zone> --pass <secret> --download <name> [options]

Modes:
  -Mode Test                     Probe the server.
  -Mode List                     List files on the server.
  -Mode Upload -InFile <path>    Upload a local file.
  -Mode Download -Filename <n>   Download a remote file.

  GNU-style shortcuts are also accepted:
    --test
    --list
    --upload <path>
    --download <name>

Connection and authentication:
  -Domain, --domain, -d <zone>       Authoritative gdns2tcp DNS zone.
  -Pass, --pass, --password, -p <s>  Shared secret.
  -DnsServer, --dns-server, -ds <s>  DNS server address. Optional.
  -DnsPort, --dns-port, -dp <port>   DNS server port. Default: 53.
  -Tcp, --tcp                         Use DNS over TCP.

Transfer options:
  -OutFile, --out <path>              Output path for Download.
  -ChunkSize, --chunk-size <n>        Upload encoded chunk size, 32..180.
  -MaxDownloadBytes <n>               Max decompressed size. Default: 268435456.
  -Parallelism, --parallelism <n>     Concurrent bulk DNS queries, 1..64. Default: 32.
  -BatchSize, --batch <n>             Download chunks per query, 1..32.
                                      Default: 14 (same as the Go client).
  -Retries, --retries <n>             Attempts for the SAME failed DNS query, 1..10.
                                      Default: 3. No transport/batch fallback.
  -RetryDelayMs, --retry-delay-ms <n> Base retry backoff in milliseconds.
                                      Default: 250; retries wait 250ms, 500ms, ... like Go.
  -LogPath <path>                     Optional log file.

Help:
  -Help, --help, -h, /?               Show this help.

Performance notes:
  * With no -DnsServer, bulk transfers use the Windows DNS API in parallel,
    matching the Go .exe on Windows (net.DefaultResolver -> DnsQuery).
  * Windows DNS_QUERY_STANDARD starts with UDP and retries that same DNS query
    over TCP when the UDP response is truncated (TC=1).
  * With explicit -DnsServer, the script uses the same raw direct DNS path as
    the Go client: UDP unless -Tcp is supplied; no transport fallback chain.
  * Downloads use 32 workers x 14-chunk batches by default. Failed/timed-out
    queries retry only their own batch with Go-style 250ms incremental backoff.

Examples:
  .\gdns2tcp-client.ps1 -Domain files.example.com -Mode Test

  .\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" `
      -Mode Download -Filename payload.bin -Tcp

  .\gdns2tcp-client.ps1 --domain files.example.com --pass "change-me" `
      --download payload.bin --tcp --parallelism 32 --batch 32

  .\gdns2tcp-client.ps1 -Domain files.example.com -Pass "change-me" `
      -Mode Download -Filename payload.bin -DnsServer 203.0.113.10 -Tcp
"@
}

function Get-OptionValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][ref]$Index,
        [Parameter(Mandatory = $true)][object[]]$Arguments,
        [Parameter(Mandatory = $true)][bool]$HasInlineValue,
        [AllowEmptyString()][string]$InlineValue
    )
    if ($HasInlineValue) {
        return $InlineValue
    }
    $Index.Value++
    if ($Index.Value -ge $Arguments.Count) {
        throw "Option $Name requires a value."
    }
    return [string]$Arguments[$Index.Value]
}

function ConvertTo-IntegerOption {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][int64]$Minimum,
        [Parameter(Mandatory = $true)][int64]$Maximum
    )
    [int64]$parsed = 0
    if (-not [int64]::TryParse($Value, [ref]$parsed)) {
        throw "Option $Name expects an integer, got '$Value'."
    }
    if ($parsed -lt $Minimum -or $parsed -gt $Maximum) {
        throw "Option $Name must be between $Minimum and $Maximum."
    }
    return $parsed
}

$cfg = [ordered]@{
    Domain                = ''
    Mode                  = ''
    Pass                  = ''
    InFile                = ''
    Filename              = ''
    OutFile               = ''
    DnsServer             = ''
    DnsPort               = 53
    Tcp                   = $false
    ChunkSize             = 180
    MaxDownloadBytes      = [int64]268435456
    Parallelism           = 32
    BatchSize             = 14
    Retries               = 3
    RetryDelayMs          = 250
    LogPath               = ''
    Help                  = $false
}

function Set-ModeValue {
    param([Parameter(Mandatory = $true)][string]$Value)
    if (-not [string]::IsNullOrWhiteSpace([string]$cfg.Mode) -and $cfg.Mode -ne $Value) {
        throw "Conflicting modes '$($cfg.Mode)' and '$Value'. Choose one mode."
    }
    $cfg.Mode = $Value
}

try {
    for ($i = 0; $i -lt $args.Count; $i++) {
        $token = [string]$args[$i]
        $name = $token
        $inlineValue = ''
        $hasInlineValue = $false
        if ($token -match '^(--?[^=]+)=(.*)$') {
            $name = $Matches[1]
            $inlineValue = $Matches[2]
            $hasInlineValue = $true
        }
        $key = $name.ToLowerInvariant()

        switch ($key) {
            '-help'  { $cfg.Help = $true; continue }
            '--help' { $cfg.Help = $true; continue }
            '-h'     { $cfg.Help = $true; continue }
            '/?'     { $cfg.Help = $true; continue }

            '-domain'  { $cfg.Domain = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--domain' { $cfg.Domain = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-d'       { $cfg.Domain = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }

            '-mode'  {
                $value = (Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue)
                switch ($value.ToLowerInvariant()) {
                    'test'     { Set-ModeValue 'Test' }
                    'list'     { Set-ModeValue 'List' }
                    'upload'   { Set-ModeValue 'Upload' }
                    'download' { Set-ModeValue 'Download' }
                    default    { throw "Unsupported mode '$value'." }
                }
                continue
            }
            '--mode' {
                $value = (Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue)
                switch ($value.ToLowerInvariant()) {
                    'test'     { Set-ModeValue 'Test' }
                    'list'     { Set-ModeValue 'List' }
                    'upload'   { Set-ModeValue 'Upload' }
                    'download' { Set-ModeValue 'Download' }
                    default    { throw "Unsupported mode '$value'." }
                }
                continue
            }
            '-test'     { Set-ModeValue 'Test'; continue }
            '--test'    { Set-ModeValue 'Test'; continue }
            '-list'     { Set-ModeValue 'List'; continue }
            '--list'    { Set-ModeValue 'List'; continue }
            '-upload'   { Set-ModeValue 'Upload'; $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--upload'  { Set-ModeValue 'Upload'; $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-download' { Set-ModeValue 'Download'; $cfg.Filename = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--download'{ Set-ModeValue 'Download'; $cfg.Filename = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }

            '-pass'       { $cfg.Pass = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--pass'      { $cfg.Pass = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-password'   { $cfg.Pass = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--password'  { $cfg.Pass = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-p'          { $cfg.Pass = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }

            '-infile'     { $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--infile'    { $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-in'         { $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--in'        { $cfg.InFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-filename'   { $cfg.Filename = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--filename'  { $cfg.Filename = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-outfile'    { $cfg.OutFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--outfile'   { $cfg.OutFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-out'        { $cfg.OutFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--out'       { $cfg.OutFile = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }

            '-dnsserver'    { $cfg.DnsServer = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--dns-server'  { $cfg.DnsServer = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-ds'           { $cfg.DnsServer = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '-dnsport'      { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.DnsPort = [int](ConvertTo-IntegerOption $name $raw 1 65535); continue }
            '--dns-port'    { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.DnsPort = [int](ConvertTo-IntegerOption $name $raw 1 65535); continue }
            '-dp'           { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.DnsPort = [int](ConvertTo-IntegerOption $name $raw 1 65535); continue }
            '-tcp'          { $cfg.Tcp = $true; continue }
            '--tcp'         { $cfg.Tcp = $true; continue }

            '-chunksize'    { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.ChunkSize = [int](ConvertTo-IntegerOption $name $raw 32 180); continue }
            '--chunk-size'  { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.ChunkSize = [int](ConvertTo-IntegerOption $name $raw 32 180); continue }
            '-maxdownloadbytes'   { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.MaxDownloadBytes = [int64](ConvertTo-IntegerOption $name $raw 1 2147483647); continue }
            '--max-download-bytes'{ $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.MaxDownloadBytes = [int64](ConvertTo-IntegerOption $name $raw 1 2147483647); continue }
            '-parallelism'       { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.Parallelism = [int](ConvertTo-IntegerOption $name $raw 1 64); continue }
            '--parallelism'      { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.Parallelism = [int](ConvertTo-IntegerOption $name $raw 1 64); continue }
            '-batchsize'         { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.BatchSize = [int](ConvertTo-IntegerOption $name $raw 1 32); continue }
            '--batch-size'       { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.BatchSize = [int](ConvertTo-IntegerOption $name $raw 1 32); continue }
            '-batch'             { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.BatchSize = [int](ConvertTo-IntegerOption $name $raw 1 32); continue }
            '--batch'            { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.BatchSize = [int](ConvertTo-IntegerOption $name $raw 1 32); continue }
            '-retries'           { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.Retries = [int](ConvertTo-IntegerOption $name $raw 1 10); continue }
            '--retries'          { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.Retries = [int](ConvertTo-IntegerOption $name $raw 1 10); continue }
            '-retrydelayms'       { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.RetryDelayMs = [int](ConvertTo-IntegerOption $name $raw 1 60000); continue }
            '--retry-delay-ms'      { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.RetryDelayMs = [int](ConvertTo-IntegerOption $name $raw 1 60000); continue }
            '-retrydelayseconds'    { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.RetryDelayMs = 1000 * [int](ConvertTo-IntegerOption $name $raw 1 60); continue }
            '--retry-delay-seconds' { $raw = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; $cfg.RetryDelayMs = 1000 * [int](ConvertTo-IntegerOption $name $raw 1 60); continue }
            '-logpath'           { $cfg.LogPath = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }
            '--log-path'         { $cfg.LogPath = Get-OptionValue $name ([ref]$i) $args $hasInlineValue $inlineValue; continue }

            default { throw "Unknown option '$token'. Run --help for usage." }
        }
    }

    if ($cfg.Help) {
        Show-Help
        exit 0
    }
}
catch {
    [Console]::Error.WriteLine("error: $($_.Exception.Message)")
    [Console]::Error.WriteLine('Run .\gdns2tcp-client.ps1 --help for usage.')
    exit 2
}

$Domain = [string]$cfg.Domain
$Mode = [string]$cfg.Mode
$Pass = [string]$cfg.Pass
$InFile = [string]$cfg.InFile
$Filename = [string]$cfg.Filename
$OutFile = [string]$cfg.OutFile
$DnsServer = [string]$cfg.DnsServer
$DnsPort = [int]$cfg.DnsPort
$Tcp = [bool]$cfg.Tcp
$ChunkSize = [int]$cfg.ChunkSize
$MaxDownloadBytes = [int64]$cfg.MaxDownloadBytes
$Parallelism = [int]$cfg.Parallelism
$BatchSize = [int]$cfg.BatchSize
$Retries = [int]$cfg.Retries
$RetryDelayMs = [int]$cfg.RetryDelayMs
$LogPath = [string]$cfg.LogPath

$script:LogPath = $LogPath
$script:DomainName = ''
$script:EffectiveDnsServer = ''
$script:NativeLoaded = $false

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO','WARN','ERROR')][string]$Level,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format o), $Level, $Message
    if ($Level -eq 'ERROR') { [Console]::Error.WriteLine($line) }
    else { [Console]::Out.WriteLine($line) }
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Add-Content -LiteralPath $script:LogPath -Value $line
    }
}

function Normalize-Domain {
    param([Parameter(Mandatory = $true)][string]$Value)
    $normalized = $Value.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($normalized)) { throw 'Domain is required.' }
    if ($normalized.Contains(',')) {
        throw 'The PowerShell client currently accepts one DNS domain at a time, not a CSV shard list.'
    }
    $wireLength = [Text.Encoding]::ASCII.GetByteCount($normalized)
    if ($wireLength -gt 253) { throw "Domain is $wireLength bytes; DNS limit is 253." }
    foreach ($label in $normalized.Split('.')) {
        $labelLength = [Text.Encoding]::ASCII.GetByteCount($label)
        if ($labelLength -lt 1 -or $labelLength -gt 63) { throw "Invalid DNS label '$label'." }
    }
    return $normalized
}

function Assert-Configuration {
    if ([string]::IsNullOrWhiteSpace($Domain)) { throw 'Domain is required. Run --help for usage.' }
    if ([string]::IsNullOrWhiteSpace($Mode)) { throw 'Mode is required. Use -Mode or --test/--list/--upload/--download.' }
    if ($Mode -in @('List','Upload','Download') -and [string]::IsNullOrWhiteSpace($Pass)) {
        throw 'Pass is required for List, Upload and Download modes.'
    }
    if ($Mode -eq 'Upload' -and [string]::IsNullOrWhiteSpace($InFile)) { throw 'InFile is required for Upload mode.' }
    if ($Mode -eq 'Download' -and [string]::IsNullOrWhiteSpace($Filename)) { throw 'Filename is required for Download mode.' }
    if ($DnsPort -ne 53 -and [string]::IsNullOrWhiteSpace($DnsServer)) {
        throw 'DnsServer is required when DnsPort is not 53.'
    }
}

function Import-GdnsNative {
    if ($script:NativeLoaded) { return }

    # Add-Type definitions live for the lifetime of the PowerShell process and
    # cannot be redefined. Reuse this exact native helper when the script is
    # executed more than once in the same PowerShell session. The versioned
    # type name also avoids collisions with older revisions of this script.
    $existingNativeType = ('Gdns2TcpNativeV20260915R3' -as [type])
    if ($null -ne $existingNativeType) {
        $script:NativeLoaded = $true
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;

public static class Gdns2TcpNativeV20260915R3
{
    private static readonly char[] B32 = "abcdefghijklmnopqrstuvwxyz234567".ToCharArray();
    private const int PoolSize = 64;

    private sealed class TcpSlot
    {
        public readonly object Gate = new object();
        public TcpClient Client;
        public NetworkStream Stream;
        public string Server;
        public int Port;
    }

    private sealed class UdpSlot
    {
        public readonly object Gate = new object();
        public UdpClient Client;
        public string Server;
        public int Port;
    }

    private static readonly TcpSlot[] TcpPool = CreateTcpPool();
    private static readonly UdpSlot[] UdpPool = CreateUdpPool();
    private static int TcpCursor = -1;
    private static int UdpCursor = -1;

    public static int CompletedChunks;
    public static int RetriedDownloadQueries;
    public static int CompletedUploadChunks;

    // Windows system resolver path. Go's net.DefaultResolver on Windows calls
    // dnsapi!DnsQuery for TXT lookups. DNS_QUERY_STANDARD uses the resolver
    // cache, sends UDP first, and retries the same query over TCP when TC=1.
    private const ushort DNS_TYPE_TEXT = 16;
    private const uint DNS_QUERY_STANDARD = 0x00000000;
    private const uint DNS_QUERY_USE_TCP_ONLY = 0x00000002;
    private const int DnsFreeRecordList = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DNS_RECORD_HEADER
    {
        public IntPtr pNext;
        public IntPtr pName;
        public ushort wType;
        public ushort wDataLength;
        public uint Flags;
        public uint dwTtl;
        public uint dwReserved;
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode, EntryPoint = "DnsQuery_W")]
    private static extern int DnsQueryW(
        string pszName,
        ushort wType,
        uint options,
        IntPtr pExtra,
        out IntPtr ppQueryResults,
        IntPtr pReserved);

    [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
    private static extern void DnsRecordListFreeNative(IntPtr pRecordList, int freeType);

    private static string QueryWindowsResolverOnce(string name, bool tcpOnly)
    {
        string fqdn = name.Trim().TrimEnd('.') + ".";
        IntPtr records = IntPtr.Zero;
        uint options = tcpOnly ? DNS_QUERY_USE_TCP_ONLY : DNS_QUERY_STANDARD;
        int status = DnsQueryW(fqdn, DNS_TYPE_TEXT, options, IntPtr.Zero, out records, IntPtr.Zero);
        if (status != 0)
            throw new Win32Exception(status, "Windows DNS query failed with status " + status);

        try
        {
            var result = new StringBuilder();
            IntPtr current = records;
            int headerSize = Marshal.SizeOf(typeof(DNS_RECORD_HEADER));
            int stringArrayOffset = IntPtr.Size == 8 ? 8 : 4;

            while (current != IntPtr.Zero)
            {
                DNS_RECORD_HEADER header = (DNS_RECORD_HEADER)Marshal.PtrToStructure(
                    current, typeof(DNS_RECORD_HEADER));

                if (header.wType == DNS_TYPE_TEXT)
                {
                    IntPtr data = IntPtr.Add(current, headerSize);
                    int count = Marshal.ReadInt32(data, 0);
                    if (count < 0 || count > 4096)
                        throw new Exception("Windows DNS returned an invalid TXT string count");

                    for (int i = 0; i < count; i++)
                    {
                        IntPtr textPtr = Marshal.ReadIntPtr(data, stringArrayOffset + i * IntPtr.Size);
                        if (textPtr != IntPtr.Zero)
                        {
                            string part = Marshal.PtrToStringUni(textPtr);
                            if (part != null) result.Append(part);
                        }
                    }
                }
                current = header.pNext;
            }

            if (result.Length == 0)
                throw new Exception("Windows DNS resolver returned no TXT answer for " + name);
            return result.ToString();
        }
        finally
        {
            if (records != IntPtr.Zero)
                DnsRecordListFreeNative(records, DnsFreeRecordList);
        }
    }

    private static string QueryWindowsResolverWithRetries(string name, int retries,
                                                          int retryBackoffMs, bool tcpOnly)
    {
        if (retries < 1) retries = 1;
        Exception last = null;
        for (int attempt = 0; attempt < retries; attempt++)
        {
            try
            {
                return QueryWindowsResolverOnce(name, tcpOnly);
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt + 1 < retries)
                    Thread.Sleep(retryBackoffMs * (attempt + 1));
            }
        }
        throw new Exception("Windows DNS query failed: " +
            (last == null ? "unknown error" : last.Message), last);
    }

    public static string QuerySystemTxt(string name, int retries, int retryBackoffMs, bool tcpOnly)
    {
        return QueryWindowsResolverWithRetries(name, retries, retryBackoffMs, tcpOnly);
    }

    private static TcpSlot[] CreateTcpPool()
    {
        var result = new TcpSlot[PoolSize];
        for (int i = 0; i < result.Length; i++) result[i] = new TcpSlot();
        return result;
    }

    private static UdpSlot[] CreateUdpPool()
    {
        var result = new UdpSlot[PoolSize];
        for (int i = 0; i < result.Length; i++) result[i] = new UdpSlot();
        return result;
    }

    private static TcpSlot NextTcpSlot()
    {
        int n = Interlocked.Increment(ref TcpCursor) & int.MaxValue;
        return TcpPool[n % TcpPool.Length];
    }

    private static UdpSlot NextUdpSlot()
    {
        int n = Interlocked.Increment(ref UdpCursor) & int.MaxValue;
        return UdpPool[n % UdpPool.Length];
    }

    private static IPEndPoint ResolveEndpoint(string server, int port)
    {
        IPAddress ip;
        if (IPAddress.TryParse(server, out ip)) return new IPEndPoint(ip, port);
        IPAddress[] addresses = Dns.GetHostAddresses(server);
        if (addresses == null || addresses.Length == 0) throw new Exception("Unable to resolve DNS server " + server);
        for (int i = 0; i < addresses.Length; i++)
            if (addresses[i].AddressFamily == AddressFamily.InterNetwork)
                return new IPEndPoint(addresses[i], port);
        return new IPEndPoint(addresses[0], port);
    }

    private static void CloseTcp(TcpSlot slot)
    {
        try { if (slot.Stream != null) slot.Stream.Dispose(); } catch { }
        try { if (slot.Client != null) slot.Client.Close(); } catch { }
        slot.Stream = null;
        slot.Client = null;
        slot.Server = null;
        slot.Port = 0;
    }

    private static void CloseUdp(UdpSlot slot)
    {
        try { if (slot.Client != null) slot.Client.Close(); } catch { }
        slot.Client = null;
        slot.Server = null;
        slot.Port = 0;
    }

    private static void EnsureTcp(TcpSlot slot, string server, int port, int timeoutMs)
    {
        if (slot.Client != null && slot.Stream != null &&
            string.Equals(slot.Server, server, StringComparison.OrdinalIgnoreCase) && slot.Port == port)
            return;

        CloseTcp(slot);
        IPEndPoint ep = ResolveEndpoint(server, port);
        var client = new TcpClient(ep.AddressFamily);
        IAsyncResult ar = client.BeginConnect(ep.Address, ep.Port, null, null);
        try
        {
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                client.Close();
                throw new TimeoutException("TCP DNS connect timeout");
            }
            client.EndConnect(ar);
        }
        finally
        {
            ar.AsyncWaitHandle.Close();
        }
        client.ReceiveTimeout = timeoutMs;
        client.SendTimeout = timeoutMs;
        client.NoDelay = true;
        slot.Client = client;
        slot.Stream = client.GetStream();
        slot.Server = server;
        slot.Port = port;
    }

    private static void EnsureUdp(UdpSlot slot, string server, int port, int timeoutMs)
    {
        if (slot.Client != null &&
            string.Equals(slot.Server, server, StringComparison.OrdinalIgnoreCase) && slot.Port == port)
            return;

        CloseUdp(slot);
        IPEndPoint ep = ResolveEndpoint(server, port);
        var client = new UdpClient(ep.AddressFamily);
        client.Connect(ep);
        client.Client.ReceiveTimeout = timeoutMs;
        client.Client.SendTimeout = timeoutMs;
        slot.Client = client;
        slot.Server = server;
        slot.Port = port;
    }

    private static ushort NextId()
    {
        byte[] b = new byte[2];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(b);
        ushort id = (ushort)((b[0] << 8) | b[1]);
        return id == 0 ? (ushort)1 : id;
    }

    private static byte[] BuildQuery(string name, ushort id)
    {
        string normalized = name.Trim().TrimEnd('.');
        if (normalized.Length == 0 || Encoding.ASCII.GetByteCount(normalized) > 253)
            throw new ArgumentException("DNS QNAME must be between 1 and 253 bytes");

        var b = new List<byte>(300);
        b.Add((byte)(id >> 8)); b.Add((byte)id);
        b.Add(0x01); b.Add(0x00);                 // RD=1
        b.Add(0x00); b.Add(0x01);                 // QDCOUNT
        b.Add(0x00); b.Add(0x00);                 // ANCOUNT
        b.Add(0x00); b.Add(0x00);                 // NSCOUNT
        b.Add(0x00); b.Add(0x01);                 // ARCOUNT (EDNS0)

        foreach (string label in normalized.Split('.'))
        {
            byte[] lb = Encoding.ASCII.GetBytes(label);
            if (lb.Length < 1 || lb.Length > 63) throw new ArgumentException("Invalid DNS label length");
            b.Add((byte)lb.Length);
            b.AddRange(lb);
        }
        b.Add(0x00);
        b.Add(0x00); b.Add(0x10);                 // TXT
        b.Add(0x00); b.Add(0x01);                 // IN

        b.Add(0x00);                              // OPT root
        b.Add(0x00); b.Add(0x29);                 // type OPT
        b.Add(0x10); b.Add(0x00);                 // UDP payload 4096
        b.Add(0x00); b.Add(0x00); b.Add(0x00); b.Add(0x00);
        b.Add(0x00); b.Add(0x00);
        return b.ToArray();
    }

    private static void SkipName(byte[] message, ref int pos)
    {
        while (true)
        {
            if (pos >= message.Length) throw new Exception("Malformed DNS name");
            byte len = message[pos];
            if (len == 0) { pos++; return; }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= message.Length) throw new Exception("Malformed DNS compression pointer");
                pos += 2;
                return;
            }
            if ((len & 0xC0) != 0) throw new Exception("Unsupported DNS label encoding");
            pos++;
            if (pos + len > message.Length) throw new Exception("Malformed DNS label");
            pos += len;
        }
    }

    private static string ParseTxt(byte[] response, ushort expectedId)
    {
        if (response == null || response.Length < 12) throw new Exception("DNS response too short");
        ushort id = (ushort)((response[0] << 8) | response[1]);
        if (id != expectedId) throw new Exception("DNS transaction ID mismatch");
        int rcode = response[3] & 0x0F;
        if (rcode != 0) throw new Exception("DNS RCODE " + rcode);
        if ((response[2] & 0x02) != 0) throw new Exception("DNS response truncated (TC=1); use TCP or reduce BatchSize");

        int qd = (response[4] << 8) | response[5];
        int an = (response[6] << 8) | response[7];
        if (an == 0) throw new Exception("DNS response has no answers");

        int pos = 12;
        for (int i = 0; i < qd; i++)
        {
            SkipName(response, ref pos);
            if (pos + 4 > response.Length) throw new Exception("Malformed DNS question");
            pos += 4;
        }

        for (int i = 0; i < an; i++)
        {
            SkipName(response, ref pos);
            if (pos + 10 > response.Length) throw new Exception("Malformed DNS answer");
            int type = (response[pos] << 8) | response[pos + 1];
            pos += 2;
            pos += 2; // class
            pos += 4; // ttl
            int rdlen = (response[pos] << 8) | response[pos + 1];
            pos += 2;
            if (pos + rdlen > response.Length) throw new Exception("Malformed DNS RDATA");
            int end = pos + rdlen;
            if (type == 16)
            {
                var sb = new StringBuilder(rdlen);
                while (pos < end)
                {
                    int partLen = response[pos++];
                    if (pos + partLen > end) throw new Exception("Malformed TXT string");
                    sb.Append(Encoding.ASCII.GetString(response, pos, partLen));
                    pos += partLen;
                }
                if (sb.Length > 0) return sb.ToString();
            }
            else
            {
                pos = end;
            }
        }
        throw new Exception("DNS response contains no TXT answer");
    }

    private static string QueryUdpOnce(string name, string server, int port, int timeoutMs, ushort id)
    {
        byte[] query = BuildQuery(name, id);
        UdpSlot slot = NextUdpSlot();
        lock (slot.Gate)
        {
            try
            {
                EnsureUdp(slot, server, port, timeoutMs);
                slot.Client.Send(query, query.Length);
                IPEndPoint remote = slot.Client.Client.AddressFamily == AddressFamily.InterNetworkV6
                    ? new IPEndPoint(IPAddress.IPv6Any, 0)
                    : new IPEndPoint(IPAddress.Any, 0);
                byte[] response = slot.Client.Receive(ref remote);
                return ParseTxt(response, id);
            }
            catch
            {
                CloseUdp(slot);
                throw;
            }
        }
    }

    private static void ReadExactly(Stream stream, byte[] buffer, int offset, int count)
    {
        while (count > 0)
        {
            int n = stream.Read(buffer, offset, count);
            if (n <= 0) throw new EndOfStreamException();
            offset += n;
            count -= n;
        }
    }

    private static string QueryTcpOnce(string name, string server, int port, int timeoutMs, ushort id)
    {
        byte[] query = BuildQuery(name, id);
        TcpSlot slot = NextTcpSlot();
        lock (slot.Gate)
        {
            try
            {
                EnsureTcp(slot, server, port, timeoutMs);
                NetworkStream stream = slot.Stream;
                stream.WriteByte((byte)(query.Length >> 8));
                stream.WriteByte((byte)(query.Length & 0xFF));
                stream.Write(query, 0, query.Length);
                stream.Flush();

                byte[] len = new byte[2];
                ReadExactly(stream, len, 0, 2);
                int responseLength = (len[0] << 8) | len[1];
                if (responseLength < 12) throw new Exception("Invalid TCP DNS response length");
                byte[] response = new byte[responseLength];
                ReadExactly(stream, response, 0, response.Length);
                return ParseTxt(response, id);
            }
            catch
            {
                // After a timeout/partial frame stream alignment is unknown.
                CloseTcp(slot);
                throw;
            }
        }
    }

    private static string QueryWithRetries(string name, string server, int port, int timeoutMs,
                                           int retries, int retryDelayMs, bool tcp)
    {
        if (retries < 1) retries = 1;
        Exception last = null;
        for (int attempt = 0; attempt < retries; attempt++)
        {
            try
            {
                ushort id = NextId();
                return tcp
                    ? QueryTcpOnce(name, server, port, timeoutMs, id)
                    : QueryUdpOnce(name, server, port, timeoutMs, id);
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt + 1 < retries) Thread.Sleep(retryDelayMs * (attempt + 1));
            }
        }
        throw new Exception("DNS query failed: " + (last == null ? "unknown error" : last.Message), last);
    }

    public static string QueryTxt(string name, string server, int port, int timeoutMs,
                                  int retries, int retryDelayMs, bool tcp)
    {
        return QueryWithRetries(name, server, port, timeoutMs, retries, retryDelayMs, tcp);
    }

    private static string Base32NoPad(byte[] bytes)
    {
        var sb = new StringBuilder((bytes.Length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (int i = 0; i < bytes.Length; i++)
        {
            buffer = (buffer << 8) | bytes[i];
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                sb.Append(B32[(buffer >> bits) & 31]);
                if (bits == 0) buffer = 0;
                else buffer &= (1 << bits) - 1;
            }
        }
        if (bits > 0) sb.Append(B32[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    private static string CurrentMinute()
    {
        var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        long minute = (long)Math.Floor((DateTime.UtcNow - epoch).TotalSeconds / 60.0);
        return minute.ToString();
    }

    private static string BuildAuthToken(string secret, string domain, string command,
                                         string timestamp, string[] args)
    {
        var parts = new List<string>(args.Length + 4);
        parts.Add("gdns2tcp-auth-v1");
        parts.Add(domain.ToLowerInvariant().TrimEnd('.'));
        parts.Add(command.ToLowerInvariant());
        parts.Add(timestamp);
        for (int i = 0; i < args.Length; i++) parts.Add(args[i].ToLowerInvariant());
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
        {
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(string.Join("|", parts.ToArray())));
            byte[] shortHash = new byte[16];
            Array.Copy(hash, 0, shortHash, 0, shortHash.Length);
            return Base32NoPad(shortHash).ToLowerInvariant();
        }
    }

    private static string BuildAuthenticatedName(string secret, string domain, string command, string[] args)
    {
        string ts = CurrentMinute();
        string token = BuildAuthToken(secret, domain, command, ts, args);
        var parts = new List<string>(args.Length + 4);
        parts.AddRange(args);
        parts.Add(ts);
        parts.Add(token);
        parts.Add(command.ToLowerInvariant());
        parts.Add(domain.TrimEnd('.'));
        return string.Join(".", parts.ToArray());
    }

    private static string BuildDownloadName(string secret, string domain, string sid, int index)
    {
        return BuildAuthenticatedName(secret, domain, "d", new[] { sid, index.ToString() });
    }

    private static string BuildBatchName(string secret, string domain, string sid, int from, int count)
    {
        return BuildAuthenticatedName(secret, domain, "db", new[] { sid, from.ToString(), count.ToString() });
    }

    private static bool IsBase64Text(string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') continue;
            return false;
        }
        return true;
    }

    private static string QueryDownloadWithRetries(string secret, string domain, string sid,
                                                   int from, int count, string server, int port,
                                                   int timeoutMs, int retries, int retryDelayMs, bool tcp)
    {
        if (retries < 1) retries = 1;
        // Match the Go client: authenticatedNames is built once for the batch,
        // then resolver.queryNames retries that same logical DNS name.
        string qname = count == 1
            ? BuildDownloadName(secret, domain, sid, from)
            : BuildBatchName(secret, domain, sid, from, count);
        Exception last = null;
        for (int attempt = 0; attempt < retries; attempt++)
        {
            try
            {
                ushort id = NextId();
                return tcp
                    ? QueryTcpOnce(qname, server, port, timeoutMs, id)
                    : QueryUdpOnce(qname, server, port, timeoutMs, id);
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt + 1 < retries)
                {
                    Interlocked.Increment(ref RetriedDownloadQueries);
                    Thread.Sleep(retryDelayMs * (attempt + 1));
                }
            }
        }
        throw new Exception("DNS download query failed after " + retries +
            " attempt(s) for chunks " + from + ".." + (from + count - 1) +
            ": " + (last == null ? "unknown error" : last.Message), last);
    }

    public static void DownloadChunksToSpool(string secret, string domain, string sid, int chunkCount,
                                             long encodedSize, string spoolPath, string server, int port,
                                             int timeoutMs, int retries, int retryDelayMs,
                                             int concurrency, bool tcp, int batchSize)
    {
        if (chunkCount <= 0) throw new ArgumentException("chunkCount");
        if (encodedSize <= 0) throw new ArgumentException("encodedSize");
        if (batchSize < 1) batchSize = 1;
        if (batchSize > 32) batchSize = 32;
        int batchCountTotal = (chunkCount + batchSize - 1) / batchSize;
        int workerCount = Math.Min(Math.Max(1, concurrency), batchCountTotal);
        var tasks = new Task[workerCount];
        var writeGate = new object();
        var errorGate = new object();
        int nextBatch = -1;
        Exception failure = null;

        using (var spool = new FileStream(spoolPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            spool.SetLength(encodedSize);
            for (int worker = 0; worker < workerCount; worker++)
            {
                tasks[worker] = Task.Run(() =>
                {
                    while (true)
                    {
                        lock (errorGate) { if (failure != null) return; }
                        int batchIndex = Interlocked.Increment(ref nextBatch);
                        if (batchIndex >= batchCountTotal) return;
                        int from = batchIndex * batchSize;
                        int count = Math.Min(batchSize, chunkCount - from);
                        try
                        {
                            string data = QueryDownloadWithRetries(secret, domain, sid, from, count,
                                server, port, timeoutMs, retries, retryDelayMs, tcp);
                            long offset = (long)from * 254L;
                            int expected = (int)Math.Min((long)count * 254L, encodedSize - offset);
                            if (data.Length != expected)
                                throw new Exception("DNS batch length mismatch at chunk " + from + ": got " + data.Length + ", expected " + expected);
                            if (!IsBase64Text(data)) throw new Exception("DNS batch contains invalid base64 characters at chunk " + from);
                            byte[] bytes = Encoding.ASCII.GetBytes(data);
                            lock (writeGate)
                            {
                                spool.Position = offset;
                                spool.Write(bytes, 0, bytes.Length);
                            }
                            Interlocked.Add(ref CompletedChunks, count);
                        }
                        catch (Exception ex)
                        {
                            lock (errorGate) { if (failure == null) failure = ex; }
                            return;
                        }
                    }
                });
            }
            Task.WaitAll(tasks);
            if (failure != null) throw new Exception("parallel chunk download: " + failure.Message, failure);
        }
    }

    public static Task BeginDownloadChunksToSpool(string secret, string domain, string sid, int chunkCount,
                                                  long encodedSize, string spoolPath, string server, int port,
                                                  int timeoutMs, int retries, int retryDelayMs,
                                                  int concurrency, bool tcp, int batchSize)
    {
        CompletedChunks = 0;
        RetriedDownloadQueries = 0;
        return Task.Run(() => DownloadChunksToSpool(secret, domain, sid, chunkCount, encodedSize,
            spoolPath, server, port, timeoutMs, retries, retryDelayMs, concurrency, tcp, batchSize));
    }


    private static string QueryWindowsDownloadWithRetries(string secret, string domain, string sid,
                                                          int from, int count, int retries,
                                                          int retryBackoffMs, bool tcpOnly)
    {
        if (retries < 1) retries = 1;
        string qname = count == 1
            ? BuildDownloadName(secret, domain, sid, from)
            : BuildBatchName(secret, domain, sid, from, count);
        Exception last = null;
        for (int attempt = 0; attempt < retries; attempt++)
        {
            try
            {
                return QueryWindowsResolverOnce(qname, tcpOnly);
            }
            catch (Exception ex)
            {
                last = ex;
                if (attempt + 1 < retries)
                {
                    Interlocked.Increment(ref RetriedDownloadQueries);
                    Thread.Sleep(retryBackoffMs * (attempt + 1));
                }
            }
        }
        throw new Exception("Windows DNS download query failed after " + retries +
            " attempt(s) for chunks " + from + ".." + (from + count - 1) +
            ": " + (last == null ? "unknown error" : last.Message), last);
    }

    public static void DownloadChunksToSpoolSystem(string secret, string domain, string sid,
                                                   int chunkCount, long encodedSize, string spoolPath,
                                                   int retries, int retryBackoffMs, int concurrency,
                                                   bool tcpOnly, int batchSize)
    {
        if (chunkCount <= 0) throw new ArgumentException("chunkCount");
        if (encodedSize <= 0) throw new ArgumentException("encodedSize");
        if (batchSize < 1) batchSize = 1;
        if (batchSize > 32) batchSize = 32;

        int batchCountTotal = (chunkCount + batchSize - 1) / batchSize;
        int workerCount = Math.Min(Math.Max(1, concurrency), batchCountTotal);
        var tasks = new Task[workerCount];
        var writeGate = new object();
        var errorGate = new object();
        int nextBatch = -1;
        Exception failure = null;

        using (var spool = new FileStream(spoolPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            spool.SetLength(encodedSize);
            for (int worker = 0; worker < workerCount; worker++)
            {
                tasks[worker] = Task.Run(() =>
                {
                    while (true)
                    {
                        lock (errorGate) { if (failure != null) return; }
                        int batchIndex = Interlocked.Increment(ref nextBatch);
                        if (batchIndex >= batchCountTotal) return;

                        int from = batchIndex * batchSize;
                        int count = Math.Min(batchSize, chunkCount - from);
                        try
                        {
                            string data = QueryWindowsDownloadWithRetries(
                                secret, domain, sid, from, count, retries, retryBackoffMs, tcpOnly);

                            long offset = (long)from * 254L;
                            int expected = (int)Math.Min((long)count * 254L, encodedSize - offset);
                            if (data.Length != expected)
                                throw new Exception("DNS batch length mismatch at chunk " + from +
                                    ": got " + data.Length + ", expected " + expected);
                            if (!IsBase64Text(data))
                                throw new Exception("DNS batch contains invalid base64 characters at chunk " + from);

                            byte[] bytes = Encoding.ASCII.GetBytes(data);
                            lock (writeGate)
                            {
                                spool.Position = offset;
                                spool.Write(bytes, 0, bytes.Length);
                            }
                            Interlocked.Add(ref CompletedChunks, count);
                        }
                        catch (Exception ex)
                        {
                            lock (errorGate) { if (failure == null) failure = ex; }
                            return;
                        }
                    }
                });
            }

            Task.WaitAll(tasks);
            if (failure != null)
                throw new Exception("parallel Windows-resolver download: " + failure.Message, failure);
        }
    }

    public static Task BeginDownloadChunksToSpoolSystem(string secret, string domain, string sid,
                                                        int chunkCount, long encodedSize, string spoolPath,
                                                        int retries, int retryBackoffMs, int concurrency,
                                                        bool tcpOnly, int batchSize)
    {
        CompletedChunks = 0;
        RetriedDownloadQueries = 0;
        return Task.Run(() => DownloadChunksToSpoolSystem(
            secret, domain, sid, chunkCount, encodedSize, spoolPath,
            retries, retryBackoffMs, concurrency, tcpOnly, batchSize));
    }

    private static string BuildUploadName(string secret, string domain, string sid, int index,
                                          string chunkData, string encoding)
    {
        string safe = chunkData.Replace("+", "_").Replace("/", "-").Replace("=", "");
        if (string.Equals(encoding, "base32", StringComparison.OrdinalIgnoreCase)) safe = safe.ToLowerInvariant();
        var labels = new List<string>();
        for (int i = 0; i < safe.Length; i += 63)
            labels.Add(safe.Substring(i, Math.Min(63, safe.Length - i)));
        var args = new List<string>();
        args.Add(sid);
        args.Add(index.ToString());
        args.AddRange(labels);
        return BuildAuthenticatedName(secret, domain, "u", args.ToArray());
    }

    public static void UploadChunksFromSpool(string secret, string domain, string sid, int chunkCount,
                                             int chunkSize, long encodedSize, string encoding, string spoolPath,
                                             string server, int port, int timeoutMs, int retries, int retryDelayMs,
                                             int concurrency, bool tcp)
    {
        int workers = Math.Min(Math.Max(1, concurrency), chunkCount);
        var tasks = new Task[workers];
        var readGate = new object();
        var errorGate = new object();
        int nextChunk = -1;
        int doneFlag = 0;
        Exception failure = null;

        using (var spool = new FileStream(spoolPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            for (int worker = 0; worker < workers; worker++)
            {
                tasks[worker] = Task.Run(() =>
                {
                    while (true)
                    {
                        lock (errorGate) { if (failure != null) return; }
                        if (doneFlag != 0) return;
                        int index = Interlocked.Increment(ref nextChunk);
                        if (index >= chunkCount) return;
                        try
                        {
                            long offset = (long)index * chunkSize;
                            int want = (int)Math.Min(chunkSize, encodedSize - offset);
                            byte[] buffer = new byte[want];
                            lock (readGate)
                            {
                                spool.Position = offset;
                                ReadExactly(spool, buffer, 0, want);
                            }
                            string qname = BuildUploadName(secret, domain, sid, index,
                                Encoding.ASCII.GetString(buffer), encoding);
                            if (qname.Length > 253) throw new Exception("Upload DNS name exceeds 253 bytes at chunk " + index);
                            string response = QueryWithRetries(qname, server, port, timeoutMs, retries, retryDelayMs, tcp);
                            int ack;
                            if (!int.TryParse(response, out ack)) throw new Exception("Server returned upload error: " + response);
                            if (ack == -1) Interlocked.Exchange(ref doneFlag, 1);
                            Interlocked.Increment(ref CompletedUploadChunks);
                        }
                        catch (Exception ex)
                        {
                            lock (errorGate) { if (failure == null) failure = ex; }
                            return;
                        }
                    }
                });
            }
            Task.WaitAll(tasks);
            if (failure != null) throw new Exception("parallel chunk upload: " + failure.Message, failure);
        }
    }

    public static Task BeginUploadChunksFromSpool(string secret, string domain, string sid, int chunkCount,
                                                  int chunkSize, long encodedSize, string encoding, string spoolPath,
                                                  string server, int port, int timeoutMs, int retries, int retryDelayMs,
                                                  int concurrency, bool tcp)
    {
        CompletedUploadChunks = 0;
        return Task.Run(() => UploadChunksFromSpool(secret, domain, sid, chunkCount, chunkSize,
            encodedSize, encoding, spoolPath, server, port, timeoutMs, retries, retryDelayMs, concurrency, tcp));
    }


    public static void UploadChunksFromSpoolSystem(string secret, string domain, string sid, int chunkCount,
                                                   int chunkSize, long encodedSize, string encoding, string spoolPath,
                                                   int retries, int retryBackoffMs, int concurrency, bool tcpOnly)
    {
        int workers = Math.Min(Math.Max(1, concurrency), chunkCount);
        var tasks = new Task[workers];
        var readGate = new object();
        var errorGate = new object();
        int nextChunk = -1;
        int doneFlag = 0;
        Exception failure = null;

        using (var spool = new FileStream(spoolPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            for (int worker = 0; worker < workers; worker++)
            {
                tasks[worker] = Task.Run(() =>
                {
                    while (true)
                    {
                        lock (errorGate) { if (failure != null) return; }
                        if (doneFlag != 0) return;

                        int index = Interlocked.Increment(ref nextChunk);
                        if (index >= chunkCount) return;

                        try
                        {
                            long offset = (long)index * chunkSize;
                            int want = (int)Math.Min(chunkSize, encodedSize - offset);
                            byte[] buffer = new byte[want];
                            lock (readGate)
                            {
                                spool.Position = offset;
                                ReadExactly(spool, buffer, 0, want);
                            }

                            string qname = BuildUploadName(secret, domain, sid, index,
                                Encoding.ASCII.GetString(buffer), encoding);
                            if (qname.Length > 253)
                                throw new Exception("Upload DNS name exceeds 253 bytes at chunk " + index);

                            string response = QueryWindowsResolverWithRetries(
                                qname, retries, retryBackoffMs, tcpOnly);

                            int ack;
                            if (!int.TryParse(response, out ack))
                                throw new Exception("Server returned upload error: " + response);
                            if (ack == -1) Interlocked.Exchange(ref doneFlag, 1);
                            Interlocked.Increment(ref CompletedUploadChunks);
                        }
                        catch (Exception ex)
                        {
                            lock (errorGate) { if (failure == null) failure = ex; }
                            return;
                        }
                    }
                });
            }

            Task.WaitAll(tasks);
            if (failure != null)
                throw new Exception("parallel Windows-resolver upload: " + failure.Message, failure);
        }
    }

    public static Task BeginUploadChunksFromSpoolSystem(string secret, string domain, string sid, int chunkCount,
                                                        int chunkSize, long encodedSize, string encoding, string spoolPath,
                                                        int retries, int retryBackoffMs, int concurrency, bool tcpOnly)
    {
        CompletedUploadChunks = 0;
        return Task.Run(() => UploadChunksFromSpoolSystem(
            secret, domain, sid, chunkCount, chunkSize, encodedSize, encoding, spoolPath,
            retries, retryBackoffMs, concurrency, tcpOnly));
    }

    private static byte[] Pbkdf2Sha256(byte[] password, byte[] salt, int iterations, int length)
    {
        using (var hmac = new HMACSHA256(password))
        {
            byte[] output = new byte[length];
            int generated = 0;
            int block = 1;
            while (generated < length)
            {
                byte[] saltBlock = new byte[salt.Length + 4];
                Array.Copy(salt, saltBlock, salt.Length);
                saltBlock[salt.Length] = (byte)(block >> 24);
                saltBlock[salt.Length + 1] = (byte)(block >> 16);
                saltBlock[salt.Length + 2] = (byte)(block >> 8);
                saltBlock[salt.Length + 3] = (byte)block;
                byte[] u = hmac.ComputeHash(saltBlock);
                byte[] t = (byte[])u.Clone();
                for (int i = 2; i <= iterations; i++)
                {
                    u = hmac.ComputeHash(u);
                    for (int j = 0; j < t.Length; j++) t[j] ^= u[j];
                }
                int copy = Math.Min(t.Length, length - generated);
                Array.Copy(t, 0, output, generated, copy);
                generated += copy;
                block++;
            }
            return output;
        }
    }

    private static bool FixedEquals(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public static void DecodeSpoolToOutput(string spoolPath, string secret, string outputPath, long maxBytes)
    {
        string protectedPath = outputPath + ".protected-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var input = new FileStream(spoolPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var decoded = new FileStream(protectedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var transform = new FromBase64Transform(FromBase64TransformMode.IgnoreWhiteSpaces))
            using (var crypto = new CryptoStream(decoded, transform, CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[65536];
                int n;
                while ((n = input.Read(buffer, 0, buffer.Length)) > 0) crypto.Write(buffer, 0, n);
                crypto.FlushFinalBlock();
            }

            using (var protectedFile = new FileStream(protectedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (protectedFile.Length < 84) throw new Exception("Protected payload is too short");
                byte[] header = new byte[36];
                ReadExactly(protectedFile, header, 0, header.Length);
                if (Encoding.ASCII.GetString(header, 0, 4) != "GDT2") throw new Exception("Unsupported protected payload");
                byte[] expectedMac = new byte[32];
                ReadExactly(protectedFile, expectedMac, 0, expectedMac.Length);
                byte[] salt = new byte[16];
                byte[] iv = new byte[16];
                Array.Copy(header, 4, salt, 0, 16);
                Array.Copy(header, 20, iv, 0, 16);
                byte[] material = Pbkdf2Sha256(Encoding.UTF8.GetBytes(secret), salt, 100000, 64);
                byte[] encKey = new byte[32];
                byte[] macKey = new byte[32];
                Array.Copy(material, 0, encKey, 0, 32);
                Array.Copy(material, 32, macKey, 0, 32);

                byte[] actualMac;
                using (var hmac = new HMACSHA256(macKey))
                using (var sink = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write))
                {
                    sink.Write(header, 0, header.Length);
                    byte[] buffer = new byte[65536];
                    int n;
                    while ((n = protectedFile.Read(buffer, 0, buffer.Length)) > 0) sink.Write(buffer, 0, n);
                    sink.FlushFinalBlock();
                    actualMac = hmac.Hash;
                }
                if (!FixedEquals(expectedMac, actualMac)) throw new Exception("Protected payload authentication failed");

                protectedFile.Position = 68;
                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 256;
                    aes.Key = encKey;
                    aes.IV = iv;
                    using (var decrypt = new CryptoStream(protectedFile, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    using (var gzip = new GZipStream(decrypt, CompressionMode.Decompress))
                    using (var output = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        byte[] buffer = new byte[65536];
                        int n;
                        long written = 0;
                        while ((n = gzip.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            written += n;
                            if (written > maxBytes) throw new Exception("Decompressed download exceeds configured limit");
                            output.Write(buffer, 0, n);
                        }
                    }
                }
            }
        }
        finally
        {
            try { if (File.Exists(protectedPath)) File.Delete(protectedPath); } catch { }
        }
    }

    private static void EncodeBase32File(string sourcePath, string destinationPath)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        using (var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var writer = new StreamWriter(new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None), Encoding.ASCII))
        {
            int buffer = 0;
            int bits = 0;
            int next;
            while ((next = source.ReadByte()) >= 0)
            {
                buffer = (buffer << 8) | next;
                bits += 8;
                while (bits >= 5)
                {
                    bits -= 5;
                    writer.Write(alphabet[(buffer >> bits) & 31]);
                    if (bits == 0) buffer = 0;
                    else buffer &= (1 << bits) - 1;
                }
            }
            if (bits > 0) writer.Write(alphabet[(buffer << (5 - bits)) & 31]);
        }
    }

    public static long PrepareUploadToSpool(string inputPath, string secret, string encoding, string spoolPath)
    {
        string root = Path.GetDirectoryName(spoolPath);
        if (string.IsNullOrEmpty(root)) root = Path.GetTempPath();
        string gzipPath = Path.Combine(root, ".gdns2tcp-gzip-" + Guid.NewGuid().ToString("N"));
        string cipherPath = Path.Combine(root, ".gdns2tcp-cipher-" + Guid.NewGuid().ToString("N"));
        string protectedPath = Path.Combine(root, ".gdns2tcp-protected-" + Guid.NewGuid().ToString("N"));
        try
        {
            using (var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var gzipFile = new FileStream(gzipPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var gzip = new GZipStream(gzipFile, CompressionMode.Compress))
                input.CopyTo(gzip);

            byte[] salt = new byte[16];
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create()) { rng.GetBytes(salt); rng.GetBytes(iv); }
            byte[] material = Pbkdf2Sha256(Encoding.UTF8.GetBytes(secret), salt, 100000, 64);
            byte[] encKey = new byte[32];
            byte[] macKey = new byte[32];
            Array.Copy(material, 0, encKey, 0, 32);
            Array.Copy(material, 32, macKey, 0, 32);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.Key = encKey;
                aes.IV = iv;
                using (var gzipInput = new FileStream(gzipPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var cipherFile = new FileStream(cipherPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var encrypt = new CryptoStream(cipherFile, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    gzipInput.CopyTo(encrypt);
                    encrypt.FlushFinalBlock();
                }
            }

            byte[] header = new byte[36];
            Encoding.ASCII.GetBytes("GDT2").CopyTo(header, 0);
            Array.Copy(salt, 0, header, 4, 16);
            Array.Copy(iv, 0, header, 20, 16);
            byte[] mac;
            using (var hmac = new HMACSHA256(macKey))
            using (var sink = new CryptoStream(Stream.Null, hmac, CryptoStreamMode.Write))
            using (var cipherInput = new FileStream(cipherPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sink.Write(header, 0, header.Length);
                cipherInput.CopyTo(sink);
                sink.FlushFinalBlock();
                mac = hmac.Hash;
            }

            using (var protectedOut = new FileStream(protectedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            using (var cipherInput = new FileStream(cipherPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                protectedOut.Write(header, 0, header.Length);
                protectedOut.Write(mac, 0, mac.Length);
                cipherInput.CopyTo(protectedOut);
            }

            if (string.Equals(encoding, "base32", StringComparison.OrdinalIgnoreCase))
            {
                EncodeBase32File(protectedPath, spoolPath);
            }
            else if (string.Equals(encoding, "base64", StringComparison.OrdinalIgnoreCase))
            {
                using (var source = new FileStream(protectedPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var destination = new FileStream(spoolPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var transform = new ToBase64Transform())
                using (var output = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                {
                    source.CopyTo(output);
                    output.FlushFinalBlock();
                }
            }
            else
            {
                throw new Exception("Unsupported DNS encoding " + encoding);
            }
            return new FileInfo(spoolPath).Length;
        }
        finally
        {
            try { if (File.Exists(gzipPath)) File.Delete(gzipPath); } catch { }
            try { if (File.Exists(cipherPath)) File.Delete(cipherPath); } catch { }
            try { if (File.Exists(protectedPath)) File.Delete(protectedPath); } catch { }
        }
    }
}
'@ -ErrorAction Stop

    $script:NativeLoaded = $true
}

function Invoke-TxtQueryOne {
    param([Parameter(Mandatory = $true)][string]$Name, [Nullable[bool]]$ForceTcp = $null)
    $queryName = $Name.TrimEnd('.')
    $useTcp = if ($null -eq $ForceTcp) { $Tcp } else { [bool]$ForceTcp }

    if (-not [string]::IsNullOrWhiteSpace($script:EffectiveDnsServer)) {
        Import-GdnsNative
        return [string][Gdns2TcpNativeV20260915R3]::QueryTxt(
            $queryName,
            $script:EffectiveDnsServer,
            $DnsPort,
            5000,
            $Retries,
            $RetryDelayMs,
            $useTcp
        )
    }

    if ($DnsPort -ne 53) { throw 'A DNS server is required when DnsPort is not 53.' }

    # This is the Windows equivalent of Go's net.DefaultResolver.LookupTXT:
    # call dnsapi!DnsQuery directly. With standard options Windows starts with
    # UDP and retries the SAME DNS query over TCP when the reply has TC=1.
    Import-GdnsNative
    return [string][Gdns2TcpNativeV20260915R3]::QuerySystemTxt(
        $queryName,
        $Retries,
        $RetryDelayMs,
        $useTcp
    )
}

function New-RandomBytes {
    param([Parameter(Mandatory = $true)][int]$Length)
    $bytes = New-Object byte[] $Length
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return $bytes
}

function ConvertTo-Base32NoPad {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $alphabet = 'abcdefghijklmnopqrstuvwxyz234567'
    $sb = New-Object Text.StringBuilder
    [int]$buffer = 0
    [int]$bits = 0
    foreach ($byte in $Bytes) {
        $buffer = (($buffer -shl 8) -bor [int]$byte)
        $bits += 8
        while ($bits -ge 5) {
            $bits -= 5
            [void]$sb.Append($alphabet[($buffer -shr $bits) -band 31])
            if ($bits -eq 0) { $buffer = 0 }
            else { $buffer = $buffer -band ((1 -shl $bits) - 1) }
        }
    }
    if ($bits -gt 0) { [void]$sb.Append($alphabet[($buffer -shl (5 - $bits)) -band 31]) }
    return $sb.ToString()
}

function Get-UnixMinute {
    $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01T00:00:00', [DateTimeKind]::Utc)
    return [int64][Math]::Floor(([DateTime]::UtcNow - $epoch).TotalSeconds / 60.0)
}

function New-AuthToken {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Args,
        [Parameter(Mandatory = $true)][string]$Timestamp
    )
    $parts = New-Object Collections.Generic.List[string]
    [void]$parts.Add('gdns2tcp-auth-v1')
    [void]$parts.Add($script:DomainName.ToLowerInvariant().TrimEnd('.'))
    [void]$parts.Add($Command.ToLowerInvariant())
    [void]$parts.Add($Timestamp)
    foreach ($arg in @($Args)) { [void]$parts.Add(([string]$arg).ToLowerInvariant()) }
    $hmac = New-Object Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Pass)
    try { [byte[]]$hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join '|'))) }
    finally { $hmac.Dispose() }
    [byte[]]$short = New-Object byte[] 16
    [Array]::Copy($hash, 0, $short, 0, 16)
    return (ConvertTo-Base32NoPad -Bytes $short).ToLowerInvariant()
}

function New-AuthenticatedName {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Args
    )
    $timestamp = [string](Get-UnixMinute)
    $token = New-AuthToken -Command $Command -Args $Args -Timestamp $timestamp
    $parts = New-Object Collections.Generic.List[string]
    foreach ($arg in @($Args)) { [void]$parts.Add([string]$arg) }
    [void]$parts.Add($timestamp)
    [void]$parts.Add($token)
    [void]$parts.Add($Command.ToLowerInvariant())
    [void]$parts.Add($script:DomainName)
    return ($parts -join '.')
}

function New-TransferId {
    return ([BitConverter]::ToString((New-RandomBytes -Length 8))).Replace('-', '').ToLowerInvariant()
}

function Split-StringFixed {
    param([Parameter(Mandatory = $true)][string]$Value, [Parameter(Mandatory = $true)][int]$Size)
    $parts = New-Object Collections.Generic.List[string]
    for ($i = 0; $i -lt $Value.Length; $i += $Size) {
        [void]$parts.Add($Value.Substring($i, [Math]::Min($Size, $Value.Length - $i)))
    }
    return $parts.ToArray()
}

function ConvertTo-FilenameLabels {
    param([Parameter(Mandatory = $true)][string]$Name)
    $baseName = [IO.Path]::GetFileName($Name)
    if ([string]::IsNullOrWhiteSpace($baseName)) { throw 'Filename is empty.' }
    $encoded = ConvertTo-Base32NoPad -Bytes ([Text.Encoding]::UTF8.GetBytes($baseName))
    $labels = New-Object Collections.Generic.List[string]
    [void]$labels.Add('f1')
    foreach ($part in @(Split-StringFixed -Value $encoded -Size 63)) { [void]$labels.Add($part.ToLowerInvariant()) }
    return $labels.ToArray()
}

function ConvertTo-DnsSafeChunk {
    param([Parameter(Mandatory = $true)][string]$Chunk, [Parameter(Mandatory = $true)][string]$Encoding)
    $safe = $Chunk.Replace('+','_').Replace('/','-').Replace('=','')
    if ($Encoding -eq 'base32') { return $safe.ToLowerInvariant() }
    return $safe
}

function Get-UploadChunkSize {
    param([Parameter(Mandatory = $true)][string]$Sid, [Parameter(Mandatory = $true)][int]$Requested)
    $placeholder = '99999999'
    for ($candidate = [Math]::Min($Requested, 180); $candidate -ge 32; $candidate--) {
        $labels = @(Split-StringFixed -Value ('a' * $candidate) -Size 63)
        $name = New-AuthenticatedName -Command 'u' -Args (@($Sid, $placeholder) + $labels)
        if ($name.Length -le 253) { return $candidate }
    }
    throw 'Domain is too long for safe DNS upload chunks.'
}

function Resolve-InputFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location) $Path }
    $full = [IO.Path]::GetFullPath($candidate)
    if (-not [IO.File]::Exists($full)) { throw "Input file does not exist: $full" }
    return $full
}

function Resolve-OutputFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location) $Path }
    $full = [IO.Path]::GetFullPath($candidate)
    if ([IO.File]::Exists($full)) { throw "Output file already exists: $full" }
    $parent = [IO.Path]::GetDirectoryName($full)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not [IO.Directory]::Exists($parent)) {
        throw "Output directory does not exist: $parent"
    }
    return $full
}

function Format-TransferRate {
    param([Parameter(Mandatory = $true)][double]$BytesPerSecond)
    if ($BytesPerSecond -ge 1048576) { return ('{0:F1} MB/s' -f ($BytesPerSecond / 1048576.0)) }
    if ($BytesPerSecond -ge 1024) { return ('{0:F1} KB/s' -f ($BytesPerSecond / 1024.0)) }
    return ('{0:F0} B/s' -f $BytesPerSecond)
}

function Format-ETA {
    param([Parameter(Mandatory = $true)][double]$Seconds)
    if ([double]::IsNaN($Seconds) -or [double]::IsInfinity($Seconds) -or $Seconds -lt 0) { $Seconds = 0 }

    # Windows PowerShell 5.1 can promote the result of arithmetic to Double.
    # The D2 format specifier only accepts integral types, which caused:
    #   "Error formatting a string: Format specifier was invalid."
    # Cast explicitly and format the two-digit fields as strings instead.
    [int64]$whole = [int64][Math]::Round($Seconds)
    if ($whole -lt 60) { return ("{0}s" -f $whole) }

    [int64]$minutesTotal = [int64][Math]::Floor($whole / 60.0)
    [int]$secondsPart = [int]($whole % 60)
    if ($minutesTotal -lt 60) {
        return ('{0}m{1}s' -f $minutesTotal, $secondsPart.ToString('00'))
    }

    [int64]$hours = [int64][Math]::Floor($minutesTotal / 60.0)
    [int]$minutesPart = [int]($minutesTotal % 60)
    return ('{0}h{1}m' -f $hours, $minutesPart.ToString('00'))
}

function Test-Gdns2Tcp {
    $response = Invoke-TxtQueryOne -Name "EnCoDiNg.test.$script:DomainName"
    if ($response -ne 'base32' -and $response -ne 'base64') {
        throw "Server did not return a supported upload encoding: $response"
    }
    Write-Log -Level 'INFO' -Message "Server selected $response upload encoding."
    return $response
}

function Invoke-List {
    $firstPage = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'c' -Args @())
    Write-Output $firstPage
    if ($firstPage -match 'Catalog contains (\d+) pages') {
        $pages = [int]$Matches[1]
        for ($page = 0; $page -lt $pages; $page++) {
            Write-Output (Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'c' -Args @([string]$page)))
        }
    }
}

function Invoke-NativeDownloadAttempt {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$ChunkCount,
        [Parameter(Mandatory = $true)][int64]$EncodedSize,
        [Parameter(Mandatory = $true)][string]$SpoolPath,
        [Parameter(Mandatory = $true)][bool]$UseTcp,
        [Parameter(Mandatory = $true)][int]$Batch,
        [Parameter(Mandatory = $true)][int]$Workers
    )
    Import-GdnsNative
    $proto = if ($UseTcp) { 'TCP' } else { 'UDP' }
    Write-Log -Level 'INFO' -Message "Fast download: $proto, $Workers workers, batch $Batch, resolver $script:EffectiveDnsServer`:$DnsPort."
    $started = Get-Date
    $task = [Gdns2TcpNativeV20260915R3]::BeginDownloadChunksToSpool(
        $Pass, $script:DomainName, $Sid, $ChunkCount, $EncodedSize, $SpoolPath,
        $script:EffectiveDnsServer, $DnsPort, 5000, $Retries, $RetryDelayMs,
        $Workers, $UseTcp, $Batch
    )

    try {
        while (-not $task.IsCompleted) {
            # Progress reporting must never abort the background transfer.
            # If UI formatting fails, keep waiting for the task so its FileStream
            # is closed before another retry is allowed to reuse the spool path.
            try {
                [int]$done = [Gdns2TcpNativeV20260915R3]::CompletedChunks
                [double]$elapsed = ((Get-Date) - $started).TotalSeconds
                [int64]$bytesDone = [Math]::Min(([int64]$done * 254), $EncodedSize)
                [double]$rate = if ($elapsed -gt 0) { $bytesDone / $elapsed } else { 0 }
                [int]$retryCount = [Gdns2TcpNativeV20260915R3]::RetriedDownloadQueries
                $status = "$done of $ChunkCount chunks"
                if ($retryCount -gt 0) { $status += "  retries $retryCount" }
                if ($rate -gt 0) {
                    $status += '  ' + (Format-TransferRate $rate)
                    if ($done -lt $ChunkCount) {
                        $status += '  ETA ' + (Format-ETA (($EncodedSize - $bytesDone) / $rate))
                    }
                }
                [double]$percent = [Math]::Min(100.0, [Math]::Round(($done / [double]$ChunkCount) * 100.0, 1))
                Write-Progress -Activity 'Downloading file' -Status $status -PercentComplete $percent
            }
            catch {
                # Do not turn a cosmetic progress-rendering problem into a failed
                # transfer. The real DNS result will be reported by GetResult().
                Write-Verbose "Progress update failed: $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 200
        }

        # Always observe the task result. Once this returns/throws, the native
        # downloader has left its using(FileStream) block and released the file.
        $task.GetAwaiter().GetResult()
        [int]$retryCount = [Gdns2TcpNativeV20260915R3]::RetriedDownloadQueries
        if ($retryCount -gt 0) {
            Write-Log -Level 'INFO' -Message "Recovered $retryCount transient DNS failure(s) by re-requesting only the same failed query; transport/batch/workers were unchanged."
        }
    }
    finally {
        Write-Progress -Activity 'Downloading file' -Completed
    }
}

function Invoke-SystemDownloadAttempt {
    param(
        [Parameter(Mandatory = $true)][string]$Sid,
        [Parameter(Mandatory = $true)][int]$ChunkCount,
        [Parameter(Mandatory = $true)][int64]$EncodedSize,
        [Parameter(Mandatory = $true)][string]$SpoolPath,
        [Parameter(Mandatory = $true)][bool]$UseTcp,
        [Parameter(Mandatory = $true)][int]$Batch,
        [Parameter(Mandatory = $true)][int]$Workers
    )
    Import-GdnsNative
    $resolverMode = if ($UseTcp) { 'Windows system resolver (TCP-only)' } else { 'Windows system resolver (standard)' }
    Write-Log -Level 'INFO' -Message "Fast download: $resolverMode, $Workers workers, batch $Batch."
    $started = Get-Date
    $task = [Gdns2TcpNativeV20260915R3]::BeginDownloadChunksToSpoolSystem(
        $Pass, $script:DomainName, $Sid, $ChunkCount, $EncodedSize, $SpoolPath,
        $Retries, $RetryDelayMs, $Workers, $UseTcp, $Batch
    )

    try {
        while (-not $task.IsCompleted) {
            try {
                [int]$done = [Gdns2TcpNativeV20260915R3]::CompletedChunks
                [double]$elapsed = ((Get-Date) - $started).TotalSeconds
                [int64]$bytesDone = [Math]::Min(([int64]$done * 254), $EncodedSize)
                [double]$rate = if ($elapsed -gt 0) { $bytesDone / $elapsed } else { 0 }
                [int]$retryCount = [Gdns2TcpNativeV20260915R3]::RetriedDownloadQueries
                $status = "$done of $ChunkCount chunks"
                if ($retryCount -gt 0) { $status += "  retries $retryCount" }
                if ($rate -gt 0) {
                    $status += '  ' + (Format-TransferRate $rate)
                    if ($done -lt $ChunkCount) {
                        $status += '  ETA ' + (Format-ETA (($EncodedSize - $bytesDone) / $rate))
                    }
                }
                [double]$percent = [Math]::Min(100.0, [Math]::Round(($done / [double]$ChunkCount) * 100.0, 1))
                Write-Progress -Activity 'Downloading file' -Status $status -PercentComplete $percent
            }
            catch {
                Write-Verbose "Progress update failed: $($_.Exception.Message)"
            }
            Start-Sleep -Milliseconds 200
        }

        $task.GetAwaiter().GetResult()
        [int]$retryCount = [Gdns2TcpNativeV20260915R3]::RetriedDownloadQueries
        if ($retryCount -gt 0) {
            Write-Log -Level 'INFO' -Message "Recovered $retryCount transient DNS failure(s) by retrying only the affected batch."
        }
    }
    finally {
        Write-Progress -Activity 'Downloading file' -Completed
    }
}

function Invoke-Download {
    $destination = if ([string]::IsNullOrWhiteSpace($OutFile)) { $Filename } else { $OutFile }
    $outputPath = Resolve-OutputFile -Path $destination
    $sid = New-TransferId
    $filenameLabels = @(ConvertTo-FilenameLabels -Name $Filename)
    $initName = New-AuthenticatedName -Command 'dinit' -Args (@($sid) + $filenameLabels)
    if ($initName.Length -gt 253) { throw "DNS download init name is $($initName.Length) characters; limit is 253." }

    $chunkCountText = Invoke-TxtQueryOne -Name $initName
    [int]$chunkCount = 0
    if (-not [int]::TryParse($chunkCountText, [ref]$chunkCount) -or $chunkCount -le 0) {
        throw "Download initialization failed: $chunkCountText"
    }

    $metaText = Invoke-TxtQueryOne -Name (New-AuthenticatedName -Command 'dmeta' -Args @($sid))
    $meta = $metaText.Split('|')
    if ($meta.Count -ne 3) { throw "Download metadata is malformed: $metaText" }
    [int]$metaChunks = 0
    [int64]$encodedSize = 0
    if (-not [int]::TryParse($meta[0], [ref]$metaChunks) -or $metaChunks -ne $chunkCount) { throw 'Download metadata chunk count mismatch.' }
    if ($meta[1] -notmatch '^[a-fA-F0-9]{64}$') { throw 'Download metadata digest is malformed.' }
    if (-not [int64]::TryParse($meta[2], [ref]$encodedSize) -or $encodedSize -le 0) { throw 'Download metadata encoded size is malformed.' }
    [int64]$maxEncoded = if ($MaxDownloadBytes -gt ([int64]::MaxValue / 2)) { [int64]::MaxValue } else { $MaxDownloadBytes * 2 }
    if ($encodedSize -gt $maxEncoded) { throw "Encoded download exceeds the configured $MaxDownloadBytes-byte limit." }
    [int64]$expectedChunks = [int64][Math]::Ceiling($encodedSize / 254.0)
    if ($expectedChunks -ne $chunkCount) { throw 'Download metadata size does not match chunk count.' }

    Write-Log -Level 'INFO' -Message "Downloading '$Filename': $chunkCount chunks, $encodedSize encoded bytes."
    $spoolPath = Join-Path ([IO.Path]::GetTempPath()) ("gdns2tcp-download-" + [guid]::NewGuid().ToString('N') + '.b64')
    $tempOutput = Join-Path ([IO.Path]::GetDirectoryName($outputPath)) ('.gdns2tcp-output-' + [guid]::NewGuid().ToString('N'))

    try {
        if (-not [string]::IsNullOrWhiteSpace($script:EffectiveDnsServer)) {
            # Explicit -DnsServer matches the Go client's raw direct resolver:
            # UDP unless -Tcp was requested, with no custom transport fallback.
            Invoke-NativeDownloadAttempt -Sid $sid -ChunkCount $chunkCount -EncodedSize $encodedSize `
                -SpoolPath $spoolPath -UseTcp $Tcp -Batch $BatchSize -Workers $Parallelism
        }
        else {
            # No -DnsServer matches gdns2tcp-client.exe on Windows:
            # 32 parallel WinDNS DnsQuery calls. DNS_QUERY_STANDARD itself
            # retries a truncated UDP query over TCP without changing the
            # download batch size or the worker plan.
            Invoke-SystemDownloadAttempt -Sid $sid -ChunkCount $chunkCount -EncodedSize $encodedSize `
                -SpoolPath $spoolPath -UseTcp $Tcp -Batch $BatchSize -Workers $Parallelism
        }

        Import-GdnsNative
        [Gdns2TcpNativeV20260915R3]::DecodeSpoolToOutput($spoolPath, $Pass, $tempOutput, $MaxDownloadBytes)
        $actualHash = (Get-FileHash -LiteralPath $tempOutput -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $meta[1].ToLowerInvariant()) { throw 'Download source digest mismatch.' }
        [IO.File]::Move($tempOutput, $outputPath)
        Write-Log -Level 'INFO' -Message "Download written to $outputPath."
    }
    finally {
        if ([IO.File]::Exists($spoolPath)) { Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue }
        if ([IO.File]::Exists($tempOutput)) { Remove-Item -LiteralPath $tempOutput -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-Upload {
    $encoding = Test-Gdns2Tcp
    $inputPath = Resolve-InputFile -Path $InFile
    $sid = New-TransferId
    $filenameLabels = @(ConvertTo-FilenameLabels -Name ([IO.Path]::GetFileName($inputPath)))
    $spoolPath = Join-Path ([IO.Path]::GetTempPath()) ("gdns2tcp-upload-" + [guid]::NewGuid().ToString('N') + '.txt')
    $spool = $null
    try {
        Import-GdnsNative
        Write-Log -Level 'INFO' -Message "Compressing and encrypting $inputPath to a disk spool."
        [int64]$encodedSize = [Gdns2TcpNativeV20260915R3]::PrepareUploadToSpool($inputPath, $Pass, $encoding, $spoolPath)
        $effectiveChunkSize = Get-UploadChunkSize -Sid $sid -Requested $ChunkSize
        [int]$chunkCount = [Math]::Ceiling($encodedSize / [double]$effectiveChunkSize)
        if ($chunkCount -le 0) { throw 'Upload has no encoded chunks.' }
        Write-Log -Level 'INFO' -Message "Prepared $chunkCount upload chunks."

        $initArgs = @($sid, [string]$chunkCount, [string]$effectiveChunkSize, $encoding) + $filenameLabels
        $initName = New-AuthenticatedName -Command 'uinit' -Args $initArgs
        if ($initName.Length -gt 253) { throw 'Upload init DNS name exceeds 253 bytes. Use a shorter filename or domain.' }
        $initResponse = Invoke-TxtQueryOne -Name $initName
        if ($initResponse -ne 'Ready to file uploading') { throw "Upload initialization failed: $initResponse" }

        $started = Get-Date
        $uploadTcp = $Tcp
        if (-not [string]::IsNullOrWhiteSpace($script:EffectiveDnsServer)) {
            $proto = if ($uploadTcp) { 'TCP' } else { 'UDP' }
            Write-Log -Level 'INFO' -Message "Fast upload: $proto, up to $Parallelism workers, resolver $script:EffectiveDnsServer`:$DnsPort."
            $task = [Gdns2TcpNativeV20260915R3]::BeginUploadChunksFromSpool(
                $Pass, $script:DomainName, $sid, $chunkCount, $effectiveChunkSize, $encodedSize,
                $encoding, $spoolPath, $script:EffectiveDnsServer, $DnsPort, 5000,
                $Retries, $RetryDelayMs, $Parallelism, $uploadTcp
            )
        }
        else {
            $resolverMode = if ($uploadTcp) { 'Windows DNS / TCP-only' } else { 'Windows DNS / standard UDP->TCP-on-TC' }
            Write-Log -Level 'INFO' -Message "Fast upload: $resolverMode, up to $Parallelism workers."
            $task = [Gdns2TcpNativeV20260915R3]::BeginUploadChunksFromSpoolSystem(
                $Pass, $script:DomainName, $sid, $chunkCount, $effectiveChunkSize, $encodedSize,
                $encoding, $spoolPath, $Retries, $RetryDelayMs, $Parallelism, $uploadTcp
            )
        }

        try {
            while (-not $task.IsCompleted) {
                try {
                    $done = [Gdns2TcpNativeV20260915R3]::CompletedUploadChunks
                    $elapsed = ((Get-Date) - $started).TotalSeconds
                    $bytesDone = [Math]::Min([int64]$done * $effectiveChunkSize, $encodedSize)
                    $rate = if ($elapsed -gt 0) { $bytesDone / $elapsed } else { 0 }
                    $status = "$done of $chunkCount chunks"
                    if ($rate -gt 0) {
                        $status += '  ' + (Format-TransferRate $rate)
                        if ($done -lt $chunkCount) {
                            $status += '  ETA ' + (Format-ETA (($encodedSize - $bytesDone) / $rate))
                        }
                    }
                    Write-Progress -Activity 'Uploading file' -Status $status `
                        -PercentComplete ([Math]::Min(100, [Math]::Round(($done / [double]$chunkCount) * 100, 1)))
                }
                catch {
                    Write-Verbose "Progress update failed: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 200
            }
            $task.GetAwaiter().GetResult()
        }
        finally {
            Write-Progress -Activity 'Uploading file' -Completed
        }

        Write-Log -Level 'INFO' -Message 'Upload completed.'
    }
    finally {
        if ($null -ne $spool) { $spool.Dispose() }
        if ([IO.File]::Exists($spoolPath)) { Remove-Item -LiteralPath $spoolPath -Force -ErrorAction SilentlyContinue }
    }
}

try {
    Assert-Configuration
    $script:DomainName = Normalize-Domain -Value $Domain

    if (-not [string]::IsNullOrWhiteSpace($DnsServer)) {
        $script:EffectiveDnsServer = $DnsServer.Trim()
        Write-Log -Level 'INFO' -Message "Using explicit DNS server $script:EffectiveDnsServer`:$DnsPort (raw direct DNS path)."
    }
    else {
        # Match gdns2tcp-client.exe on Windows: net.DefaultResolver uses the
        # native Windows DnsQuery resolver. DNS_QUERY_STANDARD automatically
        # retries the same truncated UDP query over TCP; this is not a custom
        # gdns2tcp fallback chain and does not change batch/parallelism.
        $script:EffectiveDnsServer = ''
        $resolverMode = if ($Tcp) { 'TCP-only' } else { 'standard' }
        Write-Log -Level 'INFO' -Message "Using native Windows system DNS resolver ($resolverMode)."
    }

    switch ($Mode) {
        'Test'     { [void](Test-Gdns2Tcp) }
        'List'     { Invoke-List }
        'Upload'   { Invoke-Upload }
        'Download' { Invoke-Download }
        default    { throw "Unsupported mode '$Mode'." }
    }
    exit 0
}
catch {
    Write-Log -Level 'ERROR' -Message $_.Exception.Message
    exit 1
}
