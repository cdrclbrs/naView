<#
.SYNOPSIS
    Inventaire pour le SOC des extensions de navigateurs (Chrome, Edge, Brave, Firefox, Opera )
.DESCRIPTION
    - Parcourt tous les profils utilisateurs locaux (hors C:\Windows)
    - Détecte les navigateurs installés (profils présents)
    - Récupère les extensions par navigateur / profil
    - Envoie les données soit :
        * sur Azure Log Analytics (par défaut),
        * soit dans un fichier local (JSONL) si -OutputTarget Local specified
         -v 2 corriger bug export avec loga sur AZ

.PARAMETER OutputTarget
    Local  : écrit dans un fichier local JSONL (un objet JSON par ligne).
    Azure  : envoie vers Log Analytics (HTTP Data Collector API).
.PARAMETER OutputPath
    Chemin du fichier de sortie si OutputTarget = Local.
.PARAMETER WorkspaceId
    ID du workspace Log Analytics
.PARAMETER SharedKey
    ta Clé primaire 
.PARAMETER LogType
    Nom du type de log dans Log Analytics (par défaut : BrowserExtensions)
.PARAMETER Browser
    Permet de filtrer les navigateurs à scanner
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Azure','Local')]
    [string]$OutputTarget = 'Azure',
    [Parameter()]
    [string]$OutputPath,
    [Parameter()]
    [string]$WorkspaceId = $env:BROWSER_INV_WORKSPACEID,
    [Parameter()]
    [string]$SharedKey   = $env:BROWSER_INV_SHAREDKEY,
    [Parameter()]
    [string]$LogType = 'BrowserExtensions',
    [Parameter()]
    [ValidateSet('Chrome','Edge','Brave','Firefox','Opera','OperaGX')]
    [string[]]$Browser = @('Chrome','Edge','Brave','Firefox','Opera','OperaGX')
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (-not (Test-IsElevated)) {
        Write-Error "[Error] Run this script with Administrator privileges."
        exit 1
    }

    function Get-UserProfiles {
        Get-WmiObject Win32_UserProfile |
            Where-Object { $_.LocalPath -and $_.LocalPath -notlike 'C:\Windows*' } |
            Where-Object { Test-Path $_.LocalPath } |
            Select-Object LocalPath, SID
    }

    $Global:BrowserConfig = @{
        'Chrome' = @{
            Engine      = 'Chromium'
            BasePathRel = '\AppData\Local\Google\Chrome\User Data'
            Channel     = 'Stable'
        }
        'Edge' = @{
            Engine      = 'Chromium'
            BasePathRel = '\AppData\Local\Microsoft\Edge\User Data'
            Channel     = 'Stable'
        }
        'Brave' = @{
            Engine      = 'Chromium'
            BasePathRel = '\AppData\Local\BraveSoftware\Brave-Browser\User Data'
            Channel     = 'Stable'
        }
        'Opera' = @{
            Engine      = 'Chromium'
            BasePathRel = '\AppData\Roaming\Opera Software\Opera Stable'
            Channel     = 'Stable'
        }
        'OperaGX' = @{
            Engine      = 'Chromium'
            BasePathRel = '\AppData\Roaming\Opera Software\Opera GX Stable'
            Channel     = 'GX'
        }
        'Firefox' = @{
            Engine      = 'Gecko'
            BasePathRel = '\AppData\Roaming\Mozilla\Firefox\Profiles'
            Channel     = 'Stable'
        }
    }

    function Get-JsonSafe {
        param(
            [Parameter(Mandatory=$true)]
            [string]$Path
        )
        try {
            if (Test-Path $Path) {
                $content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
                if ($content) {
                    return $content | ConvertFrom-Json -ErrorAction Stop
                }
            }
        }
        catch {
            Write-Verbose "JSON read error: $Path - $($_.Exception.Message)"
        }
        return $null
    }

    function Resolve-ChromiumExtensionNameFromLocales {
        param(
            [Parameter(Mandatory=$true)]
            [string]$ExtensionRoot,
            [Parameter(Mandatory=$true)]
            [string]$MsgToken
        )

        $appId = ($MsgToken -replace '^__MSG_','').Trim('_')

        $localePaths = @(
            '_locales\en_US\messages.json',
            '_locales\en\messages.json'
        )

        foreach ($rel in $localePaths) {
            $full = Join-Path $ExtensionRoot $rel
            $messages = Get-JsonSafe -Path $full
            if ($null -ne $messages) {
                $candidates = @(
                    $messages.appName.message,
                    $messages.extName.message,
                    $messages.extensionName.message,
                    $messages.app_name.message,
                    $messages.application_title.message
                )
                if ($messages.PSObject.Properties.Name -contains $appId) {
                    $candidates += $messages.$appId.message
                }
                foreach ($c in $candidates) {
                    if ($c) { return $c }
                }
            }
        }
        return $MsgToken
    }

    function Get-ChromiumProfiles {
        param(
            [Parameter(Mandatory=$true)]
            [string]$UserDataPath
        )

        $profiles = @()
        $localStatePath = Join-Path $UserDataPath 'Local State'
        $localState = Get-JsonSafe -Path $localStatePath

        if ($localState -and $localState.profile -and $localState.profile.info_cache) {
            foreach ($prop in $localState.profile.info_cache.PSObject.Properties) {
                $profiles += [PSCustomObject]@{
                    Directory   = $prop.Name
                    ProfileName = $prop.Value.name
                }
            }
        }
        else {
            Get-ChildItem -Path $UserDataPath -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^Default$|^Profile \d+$' } |
                ForEach-Object {
                    $profiles += [PSCustomObject]@{
                        Directory   = $_.Name
                        ProfileName = $_.Name
                    }
                }
        }

        return $profiles
    }

    function Get-ChromiumExtensionsFromProfile {
        param(
            [Parameter(Mandatory=$true)][string]$BrowserName,
            [Parameter(Mandatory=$true)][string]$BrowserChannel,
            [Parameter(Mandatory=$true)][string]$UserName,
            [Parameter(Mandatory=$true)][string]$UserSid,
            [Parameter(Mandatory=$true)][string]$ProfileDirectory,
            [Parameter(Mandatory=$true)][string]$ProfileName,
            [Parameter(Mandatory=$true)][string]$ProfileRoot,
            [Parameter(Mandatory=$true)][string]$ComputerName,
            [Parameter(Mandatory=$true)][string]$RunId
        )

        $results = New-Object System.Collections.Generic.List[object]
        $extensionsRoot = Join-Path $ProfileRoot 'Extensions'
        if (-not (Test-Path $extensionsRoot)) { return $results }

        $extensionDirs = Get-ChildItem -Path $extensionsRoot -Directory -ErrorAction SilentlyContinue |
                         Where-Object { $_.Name -ne 'Temp' }

        foreach ($extDir in $extensionDirs) {
            $versionDirs = Get-ChildItem -Path $extDir.FullName -Directory -ErrorAction SilentlyContinue
            foreach ($v in $versionDirs) {
                $manifestPath = Join-Path $v.FullName 'manifest.json'
                $manifest = Get-JsonSafe -Path $manifestPath
                if (-not $manifest) { continue }

                $extName = $null
                if ($manifest.name -like '__MSG*') {
                    $extName = Resolve-ChromiumExtensionNameFromLocales -ExtensionRoot $v.FullName -MsgToken $manifest.name
                } else {
                    $extName = $manifest.name
                }

                $desc = $manifest.description
                if ($desc) {
                    $maxLen = 400
                    if ($desc.Length -gt $maxLen) {
                        $desc = $desc.Substring(0,$maxLen) + ' (...)'
                    }
                }

                $results.Add([PSCustomObject]@{
                    ComputerName   = $ComputerName
                    User           = $UserName
                    UserSid        = $UserSid
                    Browser        = $BrowserName
                    BrowserChannel = $BrowserChannel
                    ProfileName    = $ProfileName
                    ProfileDir     = $ProfileDirectory
                    ProfilePath    = $ProfileRoot
                    ExtensionId    = $extDir.Name
                    ExtensionName  = $extName
                    Version        = $manifest.version
                    Description    = $desc
                    Engine         = 'Chromium'
                    Timestamp      = (Get-Date).ToString('o')
                    RunId          = $RunId
                })
            }
        }

        return $results
    }

    function Get-FirefoxExtensionsFromProfile {
        param(
            [Parameter(Mandatory=$true)][string]$BrowserName,
            [Parameter(Mandatory=$true)][string]$BrowserChannel,
            [Parameter(Mandatory=$true)][string]$UserName,
            [Parameter(Mandatory=$true)][string]$UserSid,
            [Parameter(Mandatory=$true)][string]$ProfilePath,
            [Parameter(Mandatory=$true)][string]$ComputerName,
            [Parameter(Mandatory=$true)][string]$RunId
        )

        $results = New-Object System.Collections.Generic.List[object]
        $extensionsJson = Join-Path $ProfilePath 'extensions.json'
        $data = Get-JsonSafe -Path $extensionsJson
        if (-not $data -or -not $data.addons) { return $results }

        foreach ($ext in $data.addons) {
            $name = $ext.defaultLocale.name
            $desc = $ext.defaultLocale.description

            if ($desc) {
                $maxLen = 400
                if ($desc.Length -gt $maxLen) {
                    $desc = $desc.Substring(0,$maxLen) + ' (...)'
                }
            }

            $results.Add([PSCustomObject]@{
                ComputerName   = $ComputerName
                User           = $UserName
                UserSid        = $UserSid
                Browser        = $BrowserName
                BrowserChannel = $BrowserChannel
                ProfileName    = $ext.defaultLocale.name
                ProfileDir     = (Split-Path $ProfilePath -Leaf)
                ProfilePath    = $ProfilePath
                ExtensionId    = $ext.id
                ExtensionName  = $name
                Version        = $ext.version
                Description    = $desc
                Engine         = 'Gecko'
                Timestamp      = (Get-Date).ToString('o')
                RunId          = $RunId
            })
        }

        return $results
    }

    function Send-LogAnalyticsData {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$WorkspaceId,
            [Parameter(Mandatory = $true)]
            [string]$SharedKey,
            [Parameter(Mandatory = $true)]
            [string]$LogType,
            [Parameter(Mandatory = $true)]
            [object]$Data
        )

        $json  = $Data | ConvertTo-Json -Depth 10
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

        $method      = "POST"
        $contentType = "application/json"
        $resource    = "/api/logs"
        $rfc1123Date = [DateTime]::UtcNow.ToString("r")

        $stringToSign = "{0}`n{1}`n{2}`nx-ms-date:{3}`n{4}" -f $method, $bytes.Length, $contentType, $rfc1123Date, $resource
        $bytesToSign  = [Text.Encoding]::UTF8.GetBytes($stringToSign)
        $decodedKey   = [Convert]::FromBase64String($SharedKey)

        $hmacSha256     = New-Object System.Security.Cryptography.HMACSHA256
        $hmacSha256.Key = $decodedKey
        $hash           = $hmacSha256.ComputeHash($bytesToSign)
        $signature      = [Convert]::ToBase64String($hash)

        $authorization = "SharedKey $($WorkspaceId):$($signature)"
        $uri = "https://$WorkspaceId.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

        $headers = @{
            "Content-Type" = $contentType
            "Authorization" = $authorization
            "Log-Type"      = $LogType
            "x-ms-date"     = $rfc1123Date
        }

        Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $bytes -ErrorAction Stop
    }

    function Write-ExtensionsToLocalFile {
        param(
            [Parameter(Mandatory=$true)][string]$Path,
            [Parameter(Mandatory=$true)][object[]]$Data
        )

        $dir = Split-Path $Path -Parent
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }

        $Data | ForEach-Object {
            $_ | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $Path -Encoding UTF8 -Append
        }
    }

    $RunId = [guid]::NewGuid().ToString()
    $ComputerName = $env:COMPUTERNAME
    $AllExtensions = New-Object System.Collections.Generic.List[object]
}

process {
    $profiles = Get-UserProfiles
    foreach ($p in $profiles) {
        $userPath = $p.LocalPath
        $userSid  = $p.SID
        $userName = Split-Path $userPath -Leaf

        foreach ($b in $Browser) {
            if (-not $BrowserConfig.ContainsKey($b)) { continue }
            $cfg = $BrowserConfig[$b]
            $basePath = Join-Path $userPath $cfg.BasePathRel
            if (-not (Test-Path $basePath)) { continue }

            switch ($cfg.Engine) {
                'Chromium' {
                    if ($b -in @('Opera','OperaGX')) {
                        $profileDir  = Split-Path $basePath -Leaf
                        $profileName = $profileDir
                        $extensions = Get-ChromiumExtensionsFromProfile `
                            -BrowserName      $b `
                            -BrowserChannel   $cfg.Channel `
                            -UserName         $userName `
                            -UserSid          $userSid `
                            -ProfileDirectory $profileDir `
                            -ProfileName      $profileName `
                            -ProfileRoot      $basePath `
                            -ComputerName     $ComputerName `
                            -RunId            $RunId
                        if ($extensions -and $extensions.Count -gt 0) {
                            $AllExtensions.AddRange($extensions)
                        }
                    }
                    else {
                        $profilesBrowser = Get-ChromiumProfiles -UserDataPath $basePath
                        foreach ($pb in $profilesBrowser) {
                            $profDir  = $pb.Directory
                            $profName = $pb.ProfileName
                            $profRoot = Join-Path $basePath $profDir
                            if (-not (Test-Path $profRoot)) { continue }

                            $extensions = Get-ChromiumExtensionsFromProfile `
                                -BrowserName      $b `
                                -BrowserChannel   $cfg.Channel `
                                -UserName         $userName `
                                -UserSid          $userSid `
                                -ProfileDirectory $profDir `
                                -ProfileName      $profName `
                                -ProfileRoot      $profRoot `
                                -ComputerName     $ComputerName `
                                -RunId            $RunId
                            if ($extensions -and $extensions.Count -gt 0) {
                                $AllExtensions.AddRange($extensions)
                            }
                        }
                    }
                }
                'Gecko' {
                    if (-not (Test-Path $basePath)) { continue }
                    $ffProfiles = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue
                    foreach ($ff in $ffProfiles) {
                        $extensions = Get-FirefoxExtensionsFromProfile `
                            -BrowserName    'Firefox' `
                            -BrowserChannel $cfg.Channel `
                            -UserName       $userName `
                            -UserSid        $userSid `
                            -ProfilePath    $ff.FullName `
                            -ComputerName   $ComputerName `
                            -RunId          $RunId
                        if ($extensions -and $extensions.Count -gt 0) {
                            $AllExtensions.AddRange($extensions)
                        }
                    }
                }
            }
        }
    }
}

end {
    if ($AllExtensions.Count -eq 0) {
        Write-Host "No extensions detected."
        return
    }

    Write-Host "Extensions detected: $($AllExtensions.Count)"

    switch ($OutputTarget) {
        'Local' {
            if (-not $OutputPath) {
                $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                $OutputPath = "C:\Temp\browser-extensions_$($ComputerName)_$timestamp.jsonl"
            }
            Write-Host "Writing local file: $OutputPath"
            Write-ExtensionsToLocalFile -Path $OutputPath -Data $AllExtensions
        }
        'Azure' {
            if (-not $WorkspaceId -or -not $SharedKey) {
                Write-Error "WorkspaceId / SharedKey missing for Azure output."
                return
            }
            Write-Host "Sending to Azure Log Analytics (LogType = $LogType)..."
            Send-LogAnalyticsData -WorkspaceId $WorkspaceId -SharedKey $SharedKey -LogType $LogType -Data $AllExtensions
            Write-Host "Send complete."
        }
    }
}
