# cis-hardening

## Getting started

The cis-hardening.ps1 script will implement CIS L1 controls onto a Windows Server 2025, Windows Server 2022 or Windows 11 machine.

The controls.csv can be amended with additional controls and set to apply to specific environments. To do so:
- Select the development branch
- Add the required control and appropriate settings, ie:
    - ControlID
    - Description
    - CIS level
    - Applicable environment(s)
    - Type of control
    - Registry details/Net Account Type/CPrivilege/Audit Pol
    - Value
    - Notes

## Usage

### Parameters:
- `controlsCSV`: *string* - URL or UNC path to the controls.csv file.
- `level`: *string* - The CIS control level, defaults to 1.
- `output`: *string* - true/false - Indicates whether the script should output changes to a csv into the script invocation directory.
- `rollBack`: *string* - true/false - Indicates whether the script is to be rolled back.
- `rollBackCSV`: *string* - UNC path to the csv file to be used as rollback (the output for the previous script execution)

### Usage Example:
```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>"
```

```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>" `
    -level "<level>" `
    -output "<true>"
```

```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>" `
    -rollBack "<true>" `
    -rollBackCSV "<rollBackCSV>"
```
