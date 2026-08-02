param(
    [ValidateSet(
        "scan-once",
        "enroll",
        "status",
        "poll",
        "show-config"
    )]
    [string]$Mode = "scan-once",

    [string]$Config = ".\config.json",

    [string]$EnrollmentCode,

    [switch]$SkipSystem32,

    [switch]$PrintJson
)

$ErrorActionPreference = "Stop"

$AgentRoot = Split-Path `
    -Parent `
    $MyInvocation.MyCommand.Path

Set-Location $AgentRoot

$VenvPython = Join-Path `
    $AgentRoot `
    ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    $Python = $VenvPython
}
else {
    $Python = "python"
}

if (-not (Test-Path $Config)) {
    if (Test-Path ".\config.example.json") {
        Copy-Item `
            ".\config.example.json" `
            $Config

        Write-Host `
            "Đã tạo $Config từ config.example.json"
    }
    else {
        throw `
            "Không tìm thấy config.example.json"
    }
}

if (
    $Mode -eq "enroll" `
    -and [string]::IsNullOrWhiteSpace(
        $EnrollmentCode
    )
) {
    $EnrollmentCode = Read-Host `
        "Nhập mã liên kết CYRP"
}

$Arguments = @(
    "-m",
    "src.runtime",
    $Mode,
    "--config",
    $Config
)

if ($Mode -eq "enroll") {
    $Arguments += @(
        "--enrollment-code",
        $EnrollmentCode
    )
}

if ($SkipSystem32) {
    $Arguments += `
        "--skip-system32"
}

if ($PrintJson) {
    $Arguments += `
        "--print-json"
}

& $Python @Arguments

exit $LASTEXITCODE
