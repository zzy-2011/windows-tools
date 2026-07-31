# Watch-CmdPopups.ps1
# 监听系统中所有快速弹出又消失的 cmd.exe 窗口，并记录其作用
# 使用 WMI Win32_ProcessStartTrace 实时捕获进程启动事件

param(
    [int]$DurationSec = 300,
    [string]$LogFile = "$env:USERPROFILE\Desktop\CmdPopups_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

$host.UI.RawUI.WindowTitle = "[Listening] CMD Popup Detector - $(Get-Date -Format 'HH:mm:ss')"

function Get-CdpInfo {
    param([int]$PID)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction SilentlyContinue
        if ($proc) {
            $owner = try { $proc.GetOwner().User } catch { "?" }
            return @{ CommandLine = $proc.CommandLine; ParentPID = $proc.ParentProcessId; Owner = $owner }
        }
    } catch {}
    return @{ CommandLine = $null; ParentPID = $null; Owner = "?" }
}

function Get-ParentName {
    param([int]$PPID)
    try { return (Get-Process -Id $PPID -ErrorAction SilentlyContinue).ProcessName } catch { return "?" }
}

function Describe-Cmd {
    param([string]$CmdLine)
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return "(no command line info)" }
    $l = $CmdLine.ToLower()
    $rules = @(
        @{K=@('reg ','regedit');            D="Windows Registry Operation"},
        @{K=@('schtasks','at ');           D="Scheduled Task Registration"},
        @{K=@('netstat','/c net ');        D="Network Diagnosis / Connection"},
        @{K=@('ping ','tracert','nslookup');D="Network Connectivity Test"},
        @{K=@('ipconfig','/release','/renew');D="IP Config (DHCP Refresh)"},
        @{K=@('dir ','cd ','type ','copy ');D="File System Operation"},
        @{K=@('curl','wget','Invoke-WebRequest','Invoke-RestMethod');D="HTTP Request"},
        @{K=@('python','pip ','node ','npm ');D="Dev Tool Execution"},
        @{K=@('git ','svn ');              D="Version Control"},
        @{K=@('tasklist','taskkill','wmic process');D="Process Management"},
        @{K=@('powershell','-enc ','-EncodedCommand');D="PowerShell Script Execution"},
        @{K=@('mshta','wscript','cscript'); D="Windows Script Host / MSHTA"},
        @{K=@('rundll32');                 D="Rundll32 DLL Call"},
        @{K=@('cmd /c start','cmd /k');    D="Sub CMD Window"},
        @{K=@('del ','erase ','rmdir ','rm ');D="Delete Files/Dirs"},
        @{K=@('whoami','hostname','systeminfo');D="System Info Query"},
        @{K=@('diskpart','chkdsk','defrag');D="Disk Maintenance"},
        @{K=@('sc ','sc.exe ');            D="Windows Service Management"},
        @{K=@('certutil','MakeCert');       D="Certificate / Hash Operation"},
        @{K=@('ssh ','scp ','sftp ');     D="SSH Remote Connection"},
        @{K=@('xcopy','robocopy','move ');D="File Copy/Move"},
        @{K=@('shutdown','restart','logoff');D="System Shutdown/Restart"},
        @{K=@('clip ','clip.exe');         D="Clipboard Operation"},
        @{K=@('driverquery');             D="Driver List Query"},
        @{K=@('msiexec');                  D="MSI Installer"},
        @{K=@('wuauclt','WindowsUpdate','TrustedInstaller');D="Windows Update"},
        @{K=@('audiodg','svchost','RuntimeBroker');D="System Service / Background"}
    )
    foreach ($rule in $rules) {
        foreach ($kw in $rule.K) {
            if ($l.Contains($kw)) { return $rule.D }
        }
    }
    $s = if ($CmdLine.Length -gt 80) { $CmdLine.Substring(0,80)+"..." } else { $CmdLine }
    return "Unknown: $s"
}

$sep = "=" * 80
@"
$sep
  CMD Popup Listener  -  Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Duration: $DurationSec sec  |  Log: $LogFile
$sep
"@ | Out-File -FilePath $LogFile -Encoding UTF8
Write-Host ""
Write-Host $sep -ForegroundColor White
Write-Host "  CMD Popup Listener  -  Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Duration: $DurationSec sec  |  Log: $LogFile" -ForegroundColor Gray
Write-Host $sep -ForegroundColor White
Write-Host ""

$count = 0
$seen  = @{}

Write-Host "[INFO] Starting WMI event subscription (run as Admin recommended)..." -ForegroundColor Cyan
Write-Host ""

try {
    $null = Register-WmiEvent -Query `
        "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='cmd.exe'" `
        -Action {
            $ErrorActionPreference = 'SilentlyContinue'
            $pid  = $Event.SourceEventArgs.ProcessId
            if ($seen.ContainsKey($pid)) { return }
            $seen[$pid] = $true
            Start-Sleep -Milliseconds 500
            $info  = Get-CdpInfo -PID $pid
            $cmd   = $info.CommandLine
            $ppid  = $info.ParentPID
            $owner = $info.Owner
            $pname = Get-ParentName -PPID $ppid
            $desc  = Describe-Cmd -CmdLine $cmd
            $ts    = Get-Date -Format 'HH:mm:ss.fff'
            $global:count++
            $logLine = "$ts  [#$($global:count)] PID=$pid  Parent=$pname  Owner=$owner`n          Cmd: $cmd`n          Desc: $desc`n"
            $logLine | Out-File -FilePath $LogFile -Append -Encoding UTF8
            Write-Host "$ts  [#$($global:count)] PID=$pid  Parent=$pname" -ForegroundColor Green
            Write-Host "         Cmd  : $cmd" -ForegroundColor Gray
            Write-Host "         Desc : $desc" -ForegroundColor Yellow
            Write-Host ""
        } `
        -SourceIdentifier "CmdPopupWatcher" `
        -ErrorAction Stop

    Write-Host "[OK] Listening started. Press Ctrl+C to stop..." -ForegroundColor Green
    Write-Host ""

    $elapsed = 0
    while ($elapsed -lt $DurationSec) {
        Start-Sleep 5
        $elapsed += 5
        $rem = $DurationSec - $elapsed
        Write-Host "`r[$(Get-Date -Format 'HH:mm:ss')] Remaining $rem sec  |  Captured: $($global:count)" -NoNewline -ForegroundColor Cyan
    }

} finally {
    Unregister-Event -SourceIdentifier "CmdPopupWatcher" -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host ""
    Write-Host "[INFO] Listener stopped." -ForegroundColor Cyan
}

@"
$sep
  Done  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Total CMD windows captured: $($global:count)
$sep
"@ | Out-File -FilePath $LogFile -Append -Encoding UTF8

Write-Host ""
Write-Host $sep -ForegroundColor Cyan
Write-Host "  Done  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "  Total CMD windows captured: $($global:count)" -ForegroundColor Cyan
Write-Host $sep -ForegroundColor Cyan
Write-Host ""
Write-Host "Log saved to: $LogFile" -ForegroundColor White
