param(
    [string]$BaseUrl = "https://127.0.0.1:19201",

    [ValidatePattern('^\d{3,}$')]
    [string]$AgentId = "001",

    [int]$WindowHours = 24
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd('/')

$credential = Get-Credential `
    -UserName "admin" `
    -Message "Enter Wazuh Indexer admin password"

$networkCredential = New-Object `
    System.Net.NetworkCredential(
        "",
        $credential.Password
    )

$plainPassword = $networkCredential.Password

$basicValue = [Convert]::ToBase64String(
    [Text.Encoding]::UTF8.GetBytes(
        "admin:$plainPassword"
    )
)

$queryFile = Join-Path `
    $env:TEMP `
    "cyrp-wazuh-indexer-query.json"

try {
    $health = & curl.exe `
        --silent `
        --show-error `
        --fail `
        --insecure `
        --header "Authorization: Basic $basicValue" `
        "$BaseUrl/_cluster/health?pretty"

    if ($LASTEXITCODE -ne 0) {
        throw "Indexer health request failed."
    }

    Write-Host "Indexer health: OK"
    $health

    $query = @{
        size = 5
        track_total_hits = $true
        sort = @(
            @{
                timestamp = @{
                    order = "desc"
                }
            }
        )
        query = @{
            bool = @{
                filter = @(
                    @{
                        term = @{
                            "agent.id" = $AgentId
                        }
                    },
                    @{
                        range = @{
                            timestamp = @{
                                gte = "now-$($WindowHours)h"
                                lte = "now"
                            }
                        }
                    }
                )
            }
        }
    } | ConvertTo-Json -Depth 20

    [IO.File]::WriteAllText(
        $queryFile,
        $query,
        (New-Object Text.UTF8Encoding($false))
    )

    $search = & curl.exe `
        --silent `
        --show-error `
        --fail `
        --insecure `
        --header "Authorization: Basic $basicValue" `
        --header "Content-Type: application/json" `
        --request POST `
        "$BaseUrl/wazuh-alerts-*/_search" `
        --data-binary "@$queryFile"

    if ($LASTEXITCODE -ne 0) {
        throw "Indexer alert query failed."
    }

    Write-Host "Alert search: OK"

    $search |
        ConvertFrom-Json |
        ConvertTo-Json -Depth 20
}
finally {
    Remove-Item `
        $queryFile `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Variable `
        credential,
        networkCredential,
        plainPassword,
        basicValue `
        -ErrorAction SilentlyContinue
}
