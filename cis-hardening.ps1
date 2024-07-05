<#
    .DESCRIPTION
    Windows Server 2019 and Windows Server 2022 CIS hardening script

    .NOTES
        Updated: 04/07/2024
        Author: Paul Martin & Dean Reynolds

    .EXAMPLE
    .\CIS_L1-Hardening.ps1 -level 1 -output

    .\CIS_L1-Hardening.ps1 -rollBack -rollBackCSV ".\cis-hardening-level-1-output.csv"
#>

[CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            if ($_ -match '^(http|https)://') {
                try {
                    $response = Invoke-WebRequest -Uri $_ -ErrorAction Stop
                    if ($response.StatusCode -eq 200) {
                        $true
                    }
                    else {
                        throw "URL is not accessible: $_"
                    }
                }
                catch {
                    throw "URL is not accessible: $_"
                }
            }
            elseif (Test-Path $_ -PathType 'Leaf') {
                $true
            }
            else {
                throw "The path provided is neither a valid URL nor a valid file path: $_"
            }
        })]
    [string] $controlsCSV,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet( 1, 2, 3)]
    [string] $level = 1,

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [Parameter(Mandatory = $false, ParameterSetName = 'RollBack')]
    [ValidateSet('true', 'false')]
    [string] $output = 'true',

    [Parameter(Mandatory = $true, ParameterSetName = 'RollBack')]
    [ValidateSet('true', 'false')]
    [string] $rollBack = 'false',

    [Parameter(Mandatory = $true, ParameterSetName = 'RollBack')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript( { If (Test-Path $_ -PathType 'Leaf') { $True } Else { Throw "Cannot find file $_" } })]
    [string] $rollBackCSV
)

begin {

    # Install required PowerShell module
    Install-PackageProvider -Name 'NuGet' -Scope CurrentUser -Confirm:$False -Force | Out-Null
    Install-Module -Name 'Carbon' -Scope CurrentUser -Confirm:$False -Force | Out-Null
    Install-Module -Name 'AuditPolicy' -Scope CurrentUser -Confirm:$False -Force | Out-Null

    # Convert string to booleon. This method is required due to not being able to pass switch parameters via Azure Run Command extensions.
    $outputBool = [System.Convert]::ToBoolean($output)
    $rollBackBool = [System.Convert]::ToBoolean($rollBack)

    function Write-Log {
        [CmdletBinding()]
        <#
            .SYNOPSIS
            Log function
        #>
        param (
            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $object,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [System.String] $message,

            [Parameter(Mandatory = $True)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Information', 'Warning', 'Error', 'Verbose', 'Debug')]
            [System.String] $severity,

            [Parameter(Mandatory = $False)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Host', 'File', 'Both')]
            [System.String] $logType = 'Both'
        )

        begin {
            $date = (Get-Date).ToLongTimeString()
        }
        process {
            if (($logType -eq 'Host') -or ($logType -eq 'Both')) {
                Write-Host $date -ForegroundColor Cyan -NoNewline
                Write-Host " - [" -ForegroundColor White -NoNewline
                Write-Host "$object" -ForegroundColor Yellow -NoNewline
                Write-Host "] " -ForegroundColor White -NoNewline
                if (!([string]::IsNullOrEmpty($category))) {
                    Write-Host ":: [" -ForegroundColor White -NoNewline
                    Write-Host "$category" -ForegroundColor DarkGray -NoNewline
                    Write-Host "] " -ForegroundColor White -NoNewline
                }
                Write-Host ":: " -ForegroundColor White -NoNewline

                Switch ($severity) {
                    'Information' {
                        Write-Host "$($message)" -ForegroundColor White
                    }
                    'Warning' {
                        Write-Host "$($message)" -ForegroundColor Yellow
                    }
                    'Error' {
                        Write-Host "$($message)" -ForegroundColor Red
                    }
                    'Verbose' {
                        Write-Verbose "$($message)"
                    }
                    'Debug' {
                        Write-Host "DEBUG: $($message)" -ForegroundColor Magenta
                    }
                }
            }

            if (($logType -eq 'File') -or ($logType -eq 'Both')) {
                switch ($severity) {
                    "Information" { [int]$type = 1 }
                    "Warning" { [int]$type = 2 }
                    "Error" { [int]$type = 3 }
                    'Verbose' { [int]$type = 4 }
                    'Debug' { [int]$type = 5 }
                }

                if (!(Test-Path (Split-Path $logPath -Parent))) { New-Item -Path (Split-Path $logPath -Parent) -ItemType Directory -Force | Out-Null }

                $content = "<![LOG[$message]LOG]!>" + `
                    "<time=`"$(Get-Date -Format "HH:mm:ss.ffffff")`" " + `
                    "date=`"$(Get-Date -Format "dd-MM-yyyy")`" " + `
                    "component=`"$object`" " + `
                    "context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
                    "type=`"$type`" " + `
                    "thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
                    "file=`"`">"

                Add-Content -Path $($logPath + ".log") -Value $content
            }
        }
        end {}
    }

    function Set-Registry {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $registryPath,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $registryProperty,

            [Parameter(Mandatory = $true)]
            [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString')]
            [string] $registryType,

            [Parameter(Mandatory = $true)]
            [string] $registryValue
        )

        begin {
            $type = 'Registry'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            if ($null -ne (Get-ItemProperty -Path $registryPath -Name $registryProperty -ErrorAction SilentlyContinue)) {
                $value = Get-ItemPropertyValue -Path $registryPath -Name $registryProperty
            }
            else {
                $value = 'N/A'
            }

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = $registryPath
                "RegistryProperty"    = $registryProperty
                "RegistryType"        = $registryType
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($registryValue -eq 'N/A') {
                    if ($PSCmdlet.ShouldProcess("$($registryPath)", "Remove registry property: $registryProperty")) {
                        Remove-ItemProperty -Path $registryPath -Name $registryProperty
                    }
                }
                elseif ($registryValue -eq 'ValueNeedsToBeCleared') {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Clear registry property: $registryProperty")) {
                        Clear-ItemProperty -Path $registryPath -Name $registryProperty
                    }
                }
                else {
                    if ($PSCmdlet.ShouldProcess($registryPath, "New registry property: $registryProperty of value: $registryValue and type: $registryType")) {
                        If (-not (Test-Path -Path $registryPath)) {
                            New-Item -Path $registryPath -Force | Out-Null
                        }
                        New-ItemProperty -Path $registryPath -Name $registryProperty -Value $registryValue -PropertyType $registryType -Force | Out-Null
                    }
                }
                if ($registryValue -eq 'ValueNeedsToBeCleared') {
                    $registryValue = ''
                }
                $obj.NewValue = $registryValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-NetAccounts {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateSet('MINPWLEN', 'MINPWAGE', 'uniquepw', 'lockoutduration', 'lockoutthreshold', 'lockoutwindow')]
            [string] $netAccountsType,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $netAccountsValue
        )

        begin {
            $type = 'NetAccounts'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            switch ($netAccountsType) {
                'MINPWLEN' { $index = 3 }
                'MINPWAGE' { $index = 1 }
                'uniquepw' { $index = 4 }
                'lockoutduration' { $index = 6 }
                'lockoutthreshold' { $index = 5 }
                'lockoutwindow' { $index = 7 }
            }

            $value = (net accounts)[$index].split(':')[1].trim()

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = $netAccountsType
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($netAccountsType)", "Set: $netAccountsValue")) {
                    net accounts /$($netAccountsType):$netAccountsValue
                }
                $obj.NewValue = $netAccountsValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-CPrivilege {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $identity,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $privilege,

            [Parameter(Mandatory = $true)]
            [ValidateSet('True', 'False')]
            [string] $requiredValue
        )

        begin {
            $type = 'CPrivilege'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            $value = Test-CPrivilege -Identity $identity -Privilege $privilege

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = $identity
                "CPrivilegePrivilege" = $privilege
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($requiredValue -eq 'True') {
                    if ($PSCmdlet.ShouldProcess("$($identity)", "Grant $privilege")) {
                        Grant-CPrivilege -Identity $identity -Privilege $privilege
                    }
                }
                if ($requiredValue -eq 'False') {
                    if ($PSCmdlet.ShouldProcess("$($identity)", "Revoke $privilege")) {
                        Revoke-CPrivilege -Identity $identity -Privilege $privilege
                    }
                }
                $obj.NewValue = $requiredValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Set-AuditPol {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $auditPolCategory,

            [Parameter(Mandatory = $true)]
            [ValidateSet('SuccessAndFailure', 'Success', 'Failure', 'NotConfigured')]
            [string] $auditPolValue
        )

        begin {
            $type = 'AuditPol'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            $value = (Get-SystemAuditPolicy -Policy $auditPolCategory).Value

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = $auditPolCategory
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($auditPolCategory)", "Set $auditPolValue")) {
                    Set-SystemAuditPolicy -Policy $auditPolCategory -Value $auditPolValue
                }
                $obj.NewValue = $auditPolValue
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    function Rename-Account {
        <#
            .DESCRIPTION
            Function to get current value, set the required value and log.
        #>

        [CmdletBinding(SupportsShouldProcess = $true)]
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $controlID,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $account,

            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $newName
        )

        begin {
            $type = 'Account'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            $obj = [PSCustomObject]@{
                "ControlID"           = $controlID
                "Type"                = $type
                "RegistryPath"        = 'N/A'
                "RegistryProperty"    = 'N/A'
                "RegistryType"        = 'N/A'
                "NetAccountsType"     = 'N/A'
                "CPrivilegeIdentity"  = 'N/A'
                "CPrivilegePrivilege" = 'N/A'
                "AuditPolCategory"    = 'N/A'
                "OldValue"            = $account
                "NewValue"            = ''
            }

            try {
                if ($PSCmdlet.ShouldProcess("$($account)", "Rename $newName")) {
                    Rename-LocalUser -Name $account -NewName $newName
                }
                $obj.NewValue = $newName
            }
            catch {
                $obj.NewValue = $_.Exception.Message
            }
        }

        end {
            $global:results += $obj
        }
    }

    $saveVerbosePreference = $VerbosePreference
    $VerbosePreference = 'continue'

    if ($controlsCSV -match '^(http|https)://') {
        try {
            $fileName = 'controls.csv'
            $downloadPath = Join-Path -Path (Get-Location).Path -ChildPath $fileName
            Invoke-WebRequest -Uri $controlsCSV -OutFile $fileName
            if (Test-Path $downloadPath -PathType 'Leaf') {
                $controlsCSV = $downloadPath
            }
            else {
                throw "Failed to download the file from URL: $controlsCSV"
            }
        }
        catch {
            throw "URL is not accessible or the file could not be downloaded: $controlsCSV"
        }
    }

    [array]$global:results = @()

    $global:logPath = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath "$([io.path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name))_log"

    # Determine environment
    try {
        $apiCall = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/versions"
        $apiVersion = $apiCall.apiVersions | Sort-Object -Descending | Select-Object -First 1
        $instance = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion"
    }
    catch {
        $instance = $null
    }
    # Azure
    if ($null -ne $instance.compute.azEnvironment) {
        $environment = "Azure"
    }
    # VMware
    elseif ((Get-CimInstance win32_computersystem | Select-Object Model).Model -like "VMware*") {
        $environment = "VMware"
    }
    # Hyper-V
    elseif ((Get-CimInstance win32_computersystem | Select-Object Model).Model -eq "Virtual Machine") {
        $environment = "Hyper-V"
    }

    Write-Log -Object "Hardening" -Message "Environment: $environment" -Severity Information -logType Host

}

process {
    # roll back settings
    if ($rollBackBool) {
        $contents = Import-Csv -Path $rollBackCSV
        foreach ($item in $contents) {
            if ($item.type -eq 'Registry') {
                $registryParams = @{
                    controlID        = $item.controlID
                    registryPath     = $item.registryPath
                    registryProperty = $item.registryProperty
                    registryType     = $item.registryType
                    registryValue    = if ([string]::IsNullOrEmpty($item.OldValue)) { 'ValueNeedsToBeCleared' } else { $item.OldValue }
                }
                Set-Registry @registryParams
            }
            if ($item.type -eq 'NetAccounts') {
                Set-NetAccounts -controlID $item.controlID -netAccountsType $item.netAccountsType -netAccountsValue $item.OldValue
            }
            if ($item.type -eq 'CPrivilege') {
                Set-CPrivilege -controlID $item.controlID -identity $item.CPrivilegeIdentity -privilege $item.CPrivilegePrivilege -requiredValue $item.OldValue
            }
            if ($item.type -eq 'AuditPol') {
                Set-AuditPol -controlID $item.controlID -auditPolCategory $item.auditPolCategory -auditPolValue $item.OldValue
            }
            if ($item.type -eq 'Account') {
                Rename-Account -controlID $item.controlID -account $item.NewValue -newName $item.OldValue
            }
        }
        $global:results | Export-Csv -Path (Join-Path (split-path -parent $MyInvocation.MyCommand.Definition) "CIS_L1-Hardening-rollback-output.csv") -Force -NoTypeInformation
    }
    # deploy settings
    else {
        # import controls based on environment
        $controls = Import-Csv -Path $controlsCSV | Where-Object { ($_.ENABLED -eq $true) -and ($_.$($environment) -eq $true) }

        # Registry section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "Registry") -and ([int]$_.Level -le $level) })) {
            if ($control.RegistryPath -like "HKEY_USERS*") {
                foreach ($user in (Get-LocalUser)) {
                    $sid = (Get-LocalUser -Name $user).SID.value
                    If (Test-Path "Registry::HKEY_USERS\$sid") {
                        Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath -replace '(?i).Default', $sid)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $control.Value
                    }
                }
            }
            Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $control.Value
        }

        # NetAccounts section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "NetAccounts") -and ([int]$_.Level -le $level) })) {
            Set-NetAccounts -controlID $control.ControlID -netAccountsType $control.netAccountsType -netAccountsValue $control.Value
        }

        # CPrivilege section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "CPrivilege") -and ([int]$_.Level -le $level) })) {
            Set-CPrivilege -controlID $control.ControlID -identity $control.CPrivilegeIdentity -privilege $control.CPrivilegePrivilege -requiredValue $control.Value
        }

        # Audit Policy section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "AuditPol") -and ([int]$_.Level -le $level) })) {
            Set-AuditPol -controlID $control.ControlID -auditPolCategory $control.AuditPolCategory -auditPolValue $control.Value
        }

        # Rename accounts section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "Account") -and ([int]$_.Level -le $level) })) {

            if ($control.ControlID -eq '8366') {
                if (($user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' }).Name -eq "Guest") {
                    Rename-Account -controlID $control.ControlID -account $user.Name -newName $control.Value
                }
            }

            if ($control.ControlID -eq '8367') {
                if (($user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-500' }).Name -eq "Administrator") {
                    Rename-Account -controlID $control.ControlID -account $user.Name -newName $control.Value
                }
            }
        }
        # Enable Ping rules for Flex/Azure Environments - Monitoring Tooling - PING (LogicMonitor)
        if ($environment -in 'VMWare', 'Azure') {
            Enable-NetFirewallRule -Name "FPS-ICMP4-ERQ-In"
            Enable-NetFirewallRule -Name "FPS-ICMP6-ERQ-In"
            Enable-NetFirewallRule -Name "FPS-ICMP4-ERQ-Out"
            Enable-NetFirewallRule -Name "FPS-ICMP6-ERQ-Out"
        }
        # Enable WMI rules for Flex/Azure Environments - Monitoring Tooling - WMI Parsing (LogicMonitor)
        if ($environment -in 'VMWare', 'Azure') {
            Enable-NetFirewallRule -Name "WMI-RPCSS-In-TCP"
            Enable-NetFirewallRule -Name "WMI-WINMGMT-In-TCP"
        }
        # Add Firewall Rules to support Veeam Backup Tooling
        if ($environment -eq 'VMWare') {
            $nics = Get-NetAdapter
            if ($nics.Name -eq "BUA") {
                New-NetFirewallRule -Name "Veeam Enfield In" -Direction Inbound -Action Allow -Enabled True -Profile Any -RemoteAddress 10.221.196.180-10.221.196.181 -DisplayName "Veeam Enfield In"
                New-NetFirewallRule -Name "Veeam Reading In" -Direction Inbound -Action Allow -Enabled True -Profile Any -RemoteAddress 10.251.196.180-10.251.196.181 -DisplayName "Veeam Reading In"
            }
        }
    }
}

end {
    # Output file
    Write-Host "Please reboot the server to ensure that all settings are correctly applied following completion of this script" -ForegroundColor Green
    if ($outputBool) {
        $WhatIfPreference = $false
        $global:results | Export-Csv -Path (Join-Path (split-path -parent $MyInvocation.MyCommand.Definition) "cis-hardening-level-$level-output.csv") -Force -NoTypeInformation
    }
    $VerbosePreference = $saveVerbosePreference
}
