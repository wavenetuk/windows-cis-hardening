<#
    .DESCRIPTION
    Windows Server 2025, Windows Server 2022 and Windows 11 CIS hardening script

    .NOTES
        Updated: 09/05/2025
        Author: Paul Martin & Dean Reynolds

    .EXAMPLE
    .\CIS_L1-Hardening.ps1 -level 1 -output "true"

    .\CIS_L1-Hardening.ps1 -rollBack "true" -rollBackCSV "$env:SYSTEMROOT\temp\cis-hardening-level-1-output.csv"
#>

[CmdletBinding(DefaultParameterSetName = 'Default', SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
            if ($_ -match '^(http|https)://') {
                if ([System.Uri]::IsWellFormedUriString($_, [System.UriKind]::Absolute)) {
                    $true
                }
                else {
                    throw "The URL provided is not valid: $_"
                }
            }
            elseif (Test-Path $_ -PathType 'Leaf') {
                $true
            }
            else {
                throw "The path provided is neither a valid URL nor a valid file path: $_"
            }
        })]
    [string] $controlsCSV = "https://raw.githubusercontent.com/wavenetuk/windows-cis-hardening/refs/heads/main/controls.csv",

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet('1', '2', '3')]
    [string] $level = '1',

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [string[]] $excludeControls = @(),

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
    [string] $rollBackCSV,

    [Parameter(Mandatory = $false, HelpMessage = 'Restart the virtual machine')]
    [ValidateSet('true', 'false')]
    [string] $restart = 'true'
)

begin {
    function Write-BootstrapMessage {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $message,

            [Parameter(Mandatory = $false)]
            [ValidateSet('Information', 'Warning', 'Error')]
            [string] $severity = 'Information'
        )

        $colour = switch ($severity) {
            'Information' { 'White' }
            'Warning' { 'Yellow' }
            'Error' { 'Red' }
        }

        Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Bootstrap] :: $message" -ForegroundColor $colour
    }

    function Resolve-PrivilegePrincipal {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $identity
        )

        $wellKnownPrincipals = @{
            'Local account' = '*S-1-5-113'
            'Local account and member of Administrators group' = '*S-1-5-114'
        }

        if ($wellKnownPrincipals.ContainsKey($identity)) {
            return $wellKnownPrincipals[$identity]
        }

        foreach ($candidate in @($identity, "BUILTIN\$identity", "NT AUTHORITY\$identity")) {
            try {
                $sid = ([System.Security.Principal.NTAccount]$candidate).Translate([System.Security.Principal.SecurityIdentifier]).Value
                return "*$sid"
            }
            catch {
                continue
            }
        }

        throw "Unable to resolve identity '$identity' to a security identifier"
    }

    function Get-PrivilegeAssignmentSet {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $privilege
        )

        if (-not $script:privilegeAssignments.ContainsKey($privilege)) {
            $script:privilegeAssignments[$privilege] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        return ,$script:privilegeAssignments[$privilege]
    }

    function Initialize-PrivilegeAssignments {
        if ($script:privilegeAssignmentsLoaded) {
            return
        }

        $script:privilegeAssignments = @{}
        $script:privilegeAssignmentsLoaded = $true
        $script:privilegeAssignmentsDirty = $false
        # Track only the privileges a control actually changes. secedit /configure is
        # declarative (it sets the EXACT membership of every privilege in the template),
        # so we must write back ONLY the privileges we modified. This preserves the
        # incremental/merge behaviour of the previous Carbon Grant/Revoke-CPrivilege
        # implementation and prevents unrelated rights (e.g. RDP logon) from being
        # rewritten and stripped of existing members.
        $script:modifiedPrivileges = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        $exportPath = Join-Path -Path $env:TEMP -ChildPath 'cis-hardening-user-rights-export.inf'
        & secedit.exe /export /cfg $exportPath /areas USER_RIGHTS | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to export current user rights assignments with secedit.exe"
        }

        $inPrivilegeSection = $false
        foreach ($line in (Get-Content -Path $exportPath -ErrorAction Stop)) {
            $trimmedLine = $line.Trim()

            if ($trimmedLine -eq '[Privilege Rights]') {
                $inPrivilegeSection = $true
                continue
            }

            if (-not $inPrivilegeSection) {
                continue
            }

            if ($trimmedLine.StartsWith('[')) {
                break
            }

            if ([string]::IsNullOrWhiteSpace($trimmedLine) -or $trimmedLine.StartsWith(';')) {
                continue
            }

            $name, $value = $trimmedLine -split '=', 2
            $assignmentSet = Get-PrivilegeAssignmentSet -privilege $name.Trim()
            foreach ($entry in (($value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                [void]$assignmentSet.Add($entry)
            }
        }

        Remove-Item -Path $exportPath -Force -ErrorAction SilentlyContinue
    }

    function Save-PrivilegeAssignments {
        if (-not $script:privilegeAssignmentsLoaded -or -not $script:privilegeAssignmentsDirty) {
            return
        }

        $policyPath = Join-Path -Path $env:TEMP -ChildPath 'cis-hardening-user-rights.inf'
        $databasePath = Join-Path -Path $env:TEMP -ChildPath 'cis-hardening-user-rights.sdb'

        $policyContent = @(
            '[Unicode]'
            'Unicode=yes'
            '[Version]'
            'signature="$CHICAGO$"'
            'Revision=1'
            '[Privilege Rights]'
        )

        foreach ($entry in ($script:privilegeAssignments.GetEnumerator() | Sort-Object Name)) {
            # Only write privileges we actually changed. Every privilege listed in the
            # template has its membership set to EXACTLY this value by secedit, so
            # emitting an unmodified privilege here risks clearing members that were not
            # captured during export. Leaving it out means secedit leaves it untouched.
            if (-not $script:modifiedPrivileges.Contains($entry.Key)) {
                continue
            }
            $assignments = $entry.Value | Sort-Object
            $policyContent += "{0} = {1}" -f $entry.Key, ($assignments -join ',')
        }

        Set-Content -Path $policyPath -Value $policyContent -Encoding ASCII
        & secedit.exe /configure /db $databasePath /cfg $policyPath /areas USER_RIGHTS | Out-Null

        if ($LASTEXITCODE -ne 0) {
            throw "Failed to apply updated user rights assignments with secedit.exe"
        }

        Remove-Item -Path $policyPath, $databasePath -Force -ErrorAction SilentlyContinue
        $script:privilegeAssignmentsDirty = $false
    }

    function Get-AuditPolicyValueNative {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $auditPolCategory
        )

        $auditPolicyOutput = & auditpol.exe /get /subcategory:"$auditPolCategory"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to read audit policy for subcategory '$auditPolCategory'"
        }

        $policyLine = $auditPolicyOutput |
            Where-Object { $_ -match '^(?<subcategory>.+?)\s{2,}(?<setting>No Auditing|Success and Failure|Success|Failure)\s*$' } |
            Where-Object { $_ -match "^\s*$([regex]::Escape($auditPolCategory))\s{2,}" } |
            Select-Object -Last 1

        if ($null -eq $policyLine) {
            throw "Unable to parse audit policy output for subcategory '$auditPolCategory'"
        }

        $setting = ([regex]::Match($policyLine, '^(?<subcategory>.+?)\s{2,}(?<setting>No Auditing|Success and Failure|Success|Failure)\s*$')).Groups['setting'].Value

        switch ($setting) {
            'Success and Failure' { return 'SuccessAndFailure' }
            'Success' { return 'Success' }
            'Failure' { return 'Failure' }
            'No Auditing' { return 'NotConfigured' }
            default { throw "Unsupported audit policy setting '$setting' for subcategory '$auditPolCategory'" }
        }
    }

    function Set-AuditPolicyValueNative {
        param (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [string] $auditPolCategory,

            [Parameter(Mandatory = $true)]
            [ValidateSet('SuccessAndFailure', 'Success', 'Failure', 'NotConfigured')]
            [string] $auditPolValue
        )

        $arguments = switch ($auditPolValue) {
            'SuccessAndFailure' { @('/set', "/subcategory:$auditPolCategory", '/success:enable', '/failure:enable') }
            'Success' { @('/set', "/subcategory:$auditPolCategory", '/success:enable', '/failure:disable') }
            'Failure' { @('/set', "/subcategory:$auditPolCategory", '/success:disable', '/failure:enable') }
            'NotConfigured' { @('/set', "/subcategory:$auditPolCategory", '/success:disable', '/failure:disable') }
        }

        & auditpol.exe @arguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set audit policy for subcategory '$auditPolCategory'"
        }
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Write-BootstrapMessage -Message 'Using built-in security policy commands for unattended execution' -Severity Information
    }
    catch {
        Write-BootstrapMessage -Message "Dependency bootstrap failed: $($_.Exception.Message)" -Severity Error
        throw
    }

    # Convert string to booleon. This method is required due to not being able to pass switch parameters via Azure Run Command extensions.
    $outputBool = [System.Convert]::ToBoolean($output)
    $rollBackBool = [System.Convert]::ToBoolean($rollBack)
    $restartParam = [System.Convert]::ToBoolean($restart)

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
                        Remove-ItemProperty -Path $registryPath -Name $registryProperty -ErrorAction SilentlyContinue
                    }
                }
                elseif ($registryValue -eq 'ValueNeedsToBeCleared') {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Clear registry property: $registryProperty")) {
                        if ($null -ne (Get-ItemProperty -Path $registryPath -Name $registryProperty -ErrorAction SilentlyContinue)) {
                            Clear-ItemProperty -Path $registryPath -Name $registryProperty -ErrorAction SilentlyContinue
                        }
                        else {
                            New-ItemProperty -Path $registryPath -Name $registryProperty -Value $null -PropertyType $registryType -Force | Out-Null
                        }
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
            [ValidateSet('MINPWAGE', 'MAXPWAGE', 'MINPWLEN', 'uniquepw', 'lockoutthreshold', 'lockoutduration', 'lockoutwindow')]
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
                'MINPWAGE' { $index = 1 }
                'MAXPWAGE' { $index = 2 }
                'MINPWLEN' { $index = 3 }
                'uniquepw' { $index = 4 }
                'lockoutthreshold' { $index = 5 }
                'lockoutduration' { $index = 6 }
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
                # net accounts DISPLAYS certain zero/unlimited states as words (e.g. uniquepw=None,
                # lockout=Never, maxpwage=Unlimited). Those words are captured verbatim into OldValue,
                # but net accounts /<option>: only accepts numbers/UNLIMITED, so translate on the way back.
                $normalisedValue = switch ($netAccountsValue) {
                    'None'      { '0' }
                    'Never'     { '0' }
                    'Unlimited' { 'UNLIMITED' }
                    default     { $netAccountsValue }
                }
                if ($PSCmdlet.ShouldProcess("$($netAccountsType)", "Set: $normalisedValue")) {
                    net accounts /$($netAccountsType):$normalisedValue
                }
                $obj.NewValue = $normalisedValue
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

            Initialize-PrivilegeAssignments
            $principal = Resolve-PrivilegePrincipal -identity $identity
            $assignmentSet = Get-PrivilegeAssignmentSet -privilege $privilege
            $value = if ($assignmentSet.Contains($principal)) { 'True' } else { 'False' }

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
                        if ($assignmentSet.Add($principal)) {
                            $script:privilegeAssignmentsDirty = $true
                            [void]$script:modifiedPrivileges.Add($privilege)
                        }
                    }
                }
                if ($requiredValue -eq 'False') {
                    if ($PSCmdlet.ShouldProcess("$($identity)", "Revoke $privilege")) {
                        if ($assignmentSet.Remove($principal)) {
                            $script:privilegeAssignmentsDirty = $true
                            [void]$script:modifiedPrivileges.Add($privilege)
                        }
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

            $value = Get-AuditPolicyValueNative -auditPolCategory $auditPolCategory

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
                    Set-AuditPolicyValueNative -auditPolCategory $auditPolCategory -auditPolValue $auditPolValue
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
            $type = 'AccountRename'
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

    function Set-AccountStatus {
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
            [ValidateSet('Enabled', 'Disabled')]
            [string] $status
        )

        begin {
            $type = 'AccountStatus'
        }

        process {
            Write-Log -Object "Hardening" -Message "Configuring ControlID: $controlID" -Severity Information -logType Host

            $value = Get-LocalUser -Name $account | Select-Object -ExpandProperty Enabled

            $value = switch ($value) {
                $true { 'Enabled' }
                $false { 'Disabled' }
            }

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
                "OldValue"            = $value
                "NewValue"            = ''
            }

            try {
                if ($value -ne $status) {
                    if ($PSCmdlet.ShouldProcess("$($account)", "Set status to $status")) {
                        if ($status -eq 'Enabled') {
                            Enable-LocalUser -Name $account
                        }
                        elseif ($status -eq 'Disabled') {
                            Disable-LocalUser -Name $account
                        }
                    }
                    $obj.NewValue = $status
                }
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
            $downloadPath = Join-Path -Path $env:SYSTEMROOT\temp -ChildPath $fileName
            Invoke-WebRequest -Uri $controlsCSV -OutFile $downloadPath -UseBasicParsing -TimeoutSec 60
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

    $global:logPath = Join-Path -Path $env:SYSTEMROOT\temp -ChildPath "cis-hardening-level-$($level)_log"

    # Determine environment
    try {
        $apiCall = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -TimeoutSec 5 -Uri "http://169.254.169.254/metadata/versions"
        $apiVersion = $apiCall.apiVersions | Sort-Object -Descending | Select-Object -First 1
        $instance = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -TimeoutSec 5 -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion"
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

    # Get OS Name
    $osName = (Get-ComputerInfo).OsName
    $os = if ($osName -match "Server \d+") {
        $matches[0].Replace(" ", "_").toupper()
    }
    elseif ($osName -match "Windows \d+") {
        $matches[0].Replace(" ", "_").toupper()
    }
    else {
        $osName
    }

    Write-Log -Object "Hardening" -Message "Operating System: $os" -Severity Information -logType Host
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
            if ($item.type -eq 'AccountRename') {
                Rename-Account -controlID $item.controlID -account $item.NewValue -newName $item.OldValue
            }
            if ($item.type -eq 'AccountStatus') {
                if ($control.ControlID -eq '8364') {
                    $user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' }
                    Set-AccountStatus -controlID $control.ControlID -account $user.Name -status $item.OldValue
                }
            }
        }
        Save-PrivilegeAssignments
        $global:results | Export-Csv -Path (Join-Path (split-path -parent $MyInvocation.MyCommand.Definition) "cis-hardening-rollback-output.csv") -Force -NoTypeInformation
    }
    # deploy settings
    else {
        # Check if Active Directory Domain Services (ADDS) role is installed (Windows Server only)
        $addsInstalled = $false

        if ($os -like "SERVER_*") {
            Write-Log -Object "Hardening" -Message "Checking for Active Directory Domain Services (ADDS) role..." -Severity Information -logType Host

            try {
                $addsFeature = Get-WindowsFeature -Name "AD-Domain-Services" -ErrorAction SilentlyContinue
                if ($null -ne $addsFeature -and $addsFeature.Installed) {
                    $addsInstalled = $true
                    Write-Log -Object "Hardening" -Message "ADDS role detected as installed" -Severity Information -logType Host

                    # Exclude controls marked as DISABLED in Domain_Controller column
                    $allControls = Import-Csv -Path $controlsCSV
                    $dcDisabledControls = $allControls | Where-Object { $_.Domain_Controller -eq "DISABLED" } | Select-Object -ExpandProperty ControlID

                    if ($dcDisabledControls.Count -gt 0) {
                        Write-Log -Object "Hardening" -Message "Found $($dcDisabledControls.Count) control(s) to exclude for Domain Controllers: $($dcDisabledControls -join ', ')" -Severity Information -logType Host
                        $excludeControls += $dcDisabledControls
                    }
                    else {
                        Write-Log -Object "Hardening" -Message "No additional controls to exclude for Domain Controllers" -Severity Information -logType Host
                    }
                }
            }
            catch {
                Write-Log -Object "Hardening" -Message "Unable to check ADDS feature: $($_.Exception.Message)" -Severity Warning -logType Host
            }
        }

        # import controls based on environment
        $controls = Import-Csv -Path $controlsCSV | Where-Object { ($_.ENABLED -eq "ENABLED") -and ($_.$($environment) -eq "ENABLED") -and ($_.$($os) -eq "ENABLED") -and ([int]$_.Level -le [int]$level) -and ($_.ControlID -notin $excludeControls) }

        # Registry section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "Registry") })) {
            if (![string]::IsNullOrEmpty($control.$($($os) + "_value"))) {
                $value = $control.$($($os) + "_value")
            }
            else {
                $value = $control.Value
            }
            if ($control.RegistryPath -like "HKEY_USERS*") {
                foreach ($user in (Get-LocalUser)) {
                    $sid = (Get-LocalUser -Name $user).SID.value
                    If (Test-Path "Registry::HKEY_USERS\$sid") {
                        Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath -replace '(?i).Default', $sid)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $value
                    }
                }
            }
            Set-Registry -controlID $control.ControlID -registryPath "Registry::$($control.RegistryPath)" -registryProperty $control.RegistryProperty -registryType $control.RegistryType -registryValue $value
        }

        # NetAccounts section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "NetAccounts") })) {
            if (![string]::IsNullOrEmpty($control.$($($os) + "_value"))) {
                $value = $control.$($($os) + "_value")
            }
            else {
                $value = $control.Value
            }
            Set-NetAccounts -controlID $control.ControlID -netAccountsType $control.netAccountsType -netAccountsValue $Value
        }

        # CPrivilege section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "CPrivilege") })) {
            if (![string]::IsNullOrEmpty($control.$($($os) + "_value"))) {
                $value = $control.$($($os) + "_value")
            }
            else {
                $value = $control.Value
            }
            Set-CPrivilege -controlID $control.ControlID -identity $control.CPrivilegeIdentity -privilege $control.CPrivilegePrivilege -requiredValue $Value
        }
        Save-PrivilegeAssignments

        # Audit Policy section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "AuditPol") })) {
            if (![string]::IsNullOrEmpty($control.$($($os) + "_value"))) {
                $value = $control.$($($os) + "_value")
            }
            else {
                $value = $control.Value
            }
            Set-AuditPol -controlID $control.ControlID -auditPolCategory $control.AuditPolCategory -auditPolValue $Value
        }

        # Rename accounts section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "AccountRename") })) {

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

        # Account status section
        foreach ($control in ($controls | Where-Object { ($_.Type -eq "AccountStatus") })) {

            if ($control.ControlID -eq '8364') {
                $user = Get-LocalUser | Where-Object { $_.SID -like 'S-1-5-*-501' }
                Set-AccountStatus -controlID $control.ControlID -account $user.Name -status $control.Value
            }
        }
    }
}

end {
    # Remove controls CSV
    Remove-item -Path $controlsCSV -Force

    # Output file
    Write-Host "Please reboot the server to ensure that all settings are correctly applied following completion of this script" -ForegroundColor Green
    if ($outputBool) {
        $WhatIfPreference = $false
        $global:results | Export-Csv -Path (Join-Path -Path $env:SYSTEMROOT\temp -ChildPath "cis-hardening-level-$level-output.csv") -Force -NoTypeInformation
    }
    $VerbosePreference = $saveVerbosePreference

    # Restart Computer
    if ($restartParam) {
        Restart-Computer -Force
    }
}
