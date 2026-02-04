[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
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
    [string] $controlsCSV = "https://raw.githubusercontent.com/wavenetuk/windows-cis-hardening/refs/heads/main/controls.csv",

    [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet( 1, 2, 3)]
    [string] $level = 1
)

begin {
    if ($controlsCSV -match '^(http|https)://') {
        try {
            $fileName = 'controls.csv'
            $downloadPath = Join-Path -Path $env:SYSTEMROOT\temp -ChildPath $fileName
            Invoke-WebRequest -Uri $controlsCSV -OutFile $downloadPath -UseBasicParsing
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

    # Determine the environment: Azure, VMware or Hyper-V
    try {
        $apiCall = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/versions"
        $apiVersion = $apiCall.apiVersions | Sort-Object -Descending | Select-Object -First 1
        $instance = Invoke-RestMethod -Headers @{"Metadata" = "true" } -Method GET -Proxy $Null -Uri "http://169.254.169.254/metadata/instance?api-version=$apiVersion"
    }
    catch {
        $instance = $null
    }

    # Get Computer details
    $script:Computer = Get-CimInstance -Class Win32_ComputerSystem #Name, PartOfDomain
    # Get OS details
    $script:OS = Get-CimInstance -Class Win32_OperatingSystem #Caption, ProductType (DC or not)
    # Get BUA IP Address
    $script:BUA = Get-NetIPAddress -InterfaceAlias "BUA" -AddressFamily "IPv4" -ErrorAction SilentlyContinue

    Switch ($Computer.Manufacturer) {
        { $BUA.IPAddress -like "10.221*" -or $BUA.IPAddress -like "10.251*" } { $script:Platform = "Flex" }
        { $_ -like "*VMware*" -and $null -eq $BUA } { $script:Platform = "VMware" }
        { $_ -like "*Virtual Machine*" -and $null -eq $BUA } { $script:Platform = "Hyper-V" }
        { $instance.compute.azEnvironment -like "Azure*" } { $script:Platform = "Azure" }
        Default { $script:Platform = "Physical" }
    }

    $osName = (Get-ComputerInfo).OsName
    $script:os = if ($osName -match "Server \d+") {
        $matches[0].Replace(" ", "_").toupper()
    }
    elseif ($osName -match "Windows \d+") {
        $matches[0].Replace(" ", "_").toupper()
    }
    else {
        $osName
    }

    # import controls based on environment
    $controls = Import-Csv -Path $controlsCSV | Where-Object { ($_.ENABLED -eq "ENABLED") -and ($_.$($platform) -eq "ENABLED") -and ($_.$($os) -eq "ENABLED") -and ([int]$_.Level -le $level) }
}

process {
    Describe "CIS - level $level" {
        Context "Control ID: <_.ControlID> - <_.Description>" -ForEach ($controls | Where-Object { ($_.Type -eq "Registry") }) {
            BeforeEach {
                if (![string]::IsNullOrEmpty($_.$($($os) + "_value"))) {
                    $expectedValue = $_.$($($os) + "_value")
                }
                else {
                    $expectedValue = $_.Value
                }

                $script:value = Get-ItemPropertyValue -Path "Registry::$($_.RegistryPath)" -Name $_.RegistryProperty -ErrorAction SilentlyContinue
            }
            It "should have the registry key '$($_.RegistryPath)\$($_.RegistryProperty)' set to '$($expectedValue)'" {
                $value | Should -Be $expectedValue
            }
        }
    }
}
