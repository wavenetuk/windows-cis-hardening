# cis-hardening

## Getting started

The cis-hardening.ps1 script will implement CIS L1-3 controls onto the Windows Server 2019 or Windows Server 2022 machine.

The controls.csv can be amended with additional controls and set to apply to specific environments

## Usage

### Parameters:
- `controlsCSV`: *string* - URL or UNC path to the controls.csv file.
- `level`: *string* - The CIS control level, defaults to 1.
- `output`: *switch* - Indicates whether the script should output changes to a csv into the script invocation directory.
- `rollBack`: *switch* - Indicates whether the script is to be rolled back.
- `rollBackCSV`: *string* - UNC path to the csv file to be used as rollback (the output for the previous script execution)

### Usage Example:
```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>"
```

```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>" `
    -level "<level>" `
    -output
```

```powershell-interactive
cis-hardening.ps1 -controlsCSV "<controlsCSV>" `
    -rollBack `
    -rollBackCSV "<rollBackCSV>"
```
