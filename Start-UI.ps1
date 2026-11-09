param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskSessionFile = Join-Path $taskRoot '.ui-session.json'
$taskHealthHeaders = @{}
$taskPublicFile = Join-Path $taskRoot '.ui-public.json'
if (Test-Path -LiteralPath $taskPublicFile) {
    $taskPublicConfig = Get-Content -LiteralPath $taskPublicFile -Raw | ConvertFrom-Json
    $taskBasicBytes = [Text.Encoding]::UTF8.GetBytes($taskPublicConfig.username + ':' + $taskPublicConfig.password)
    $taskHealthHeaders.Authorization = 'Basic ' + [Convert]::ToBase64String($taskBasicBytes)
}
function Get-ScannerSession {
    if (Test-Path -LiteralPath $taskSessionFile) {
        try {
            $taskSession = Get-Content -LiteralPath $taskSessionFile -Raw | ConvertFrom-Json
            if ($taskSession.url -match '^http://127\.0\.0\.1:[0-9]+$') {
                $taskHealth = Invoke-RestMethod -Uri ($taskSession.url + '/api/health') -Headers $taskHealthHeaders -TimeoutSec 1
                if ($taskHealth.application -eq 'security-scanner-ui') { return $taskSession }
            }
        } catch { }
    }
    return $null
}
$taskActiveSession = Get-ScannerSession
if ($taskActiveSession) {
    $taskBackendFiles = @(Get-Item -LiteralPath (Join-Path $taskRoot 'ui.mjs'))
    $taskBackendFiles += @(Get-ChildItem -LiteralPath (Join-Path $taskRoot 'src') -Filter '*.mjs' -File)
    if (Test-Path -LiteralPath $taskPublicFile) { $taskBackendFiles += Get-Item -LiteralPath $taskPublicFile }
    $taskLatestBackend = ($taskBackendFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
    $taskActiveProcess = Get-Process -Id ([int]$taskActiveSession.pid) -ErrorAction SilentlyContinue
    if (-not $taskActiveProcess -or $taskActiveProcess.ProcessName -ne 'node') { throw 'Khong xac dinh duoc tien trinh SrcAudit. Hay dong ban dang chay roi mo lai.' }
    if ($taskLatestBackend -gt $taskActiveProcess.StartTime.ToUniversalTime()) {
        $taskListener = [regex]::Escape(([uri]$taskActiveSession.url).Authority)
        $taskListenerPattern = '^\s*TCP\s+' + $taskListener + '\s+0\.0\.0\.0:0\s+\S+\s+' + $taskActiveProcess.Id + '\s*$'
        $taskOwnsListener = netstat.exe -ano -p tcp | Select-String -Pattern $taskListenerPattern -Quiet
        if (-not $taskOwnsListener -or (Get-Item -LiteralPath $taskSessionFile).LastWriteTimeUtc -lt $taskActiveProcess.StartTime.ToUniversalTime()) {
            throw 'Khong xac minh duoc tien trinh SrcAudit cu. Hay dong ban dang chay roi mo lai.'
        }
        Write-Host 'Dang khoi dong lai SrcAudit de nap ban moi...'
        Stop-Process -InputObject $taskActiveProcess
        $taskActiveProcess.WaitForExit(5000) | Out-Null
        if (-not $taskActiveProcess.HasExited) { throw 'Khong dung duoc tien trinh SrcAudit cu.' }
        $taskActiveSession = $null
    }
}
if (-not $taskActiveSession) {
    $taskNode = (Get-Command node -ErrorAction Stop).Source
    Start-Process -FilePath $taskNode -ArgumentList ('"' + (Join-Path $taskRoot 'ui.mjs') + '"') -WorkingDirectory $taskRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskRoot 'ui.log') -RedirectStandardError (Join-Path $taskRoot 'ui-error.log')
    for ($taskAttempt = 0; $taskAttempt -lt 40; $taskAttempt++) {
        Start-Sleep -Milliseconds 250
        $taskActiveSession = Get-ScannerSession
        if ($taskActiveSession) { break }
    }
}
if (-not $taskActiveSession) { throw 'Khong khoi dong duoc UI. Xem ui-error.log hoac chay node ui.mjs.' }
if ($NoBrowser) { Write-Output $taskActiveSession.url }
else { Start-Process -FilePath $taskActiveSession.url }
