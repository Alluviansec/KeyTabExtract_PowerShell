<#
.SYNOPSIS
    KeyTabExtract - Extract encryption keys from Kerberos keytab files
    
.DESCRIPTION
    Extracts NTLM hashes (RC4-HMAC), AES256, and AES128 keys from keytab files.
    PowerShell implementation by Luke Brown, Senior Solutions Architect at Extrahop.
    Based on the original Python script by sosdave: https://github.com/sosdave/KeyTabExtract
    
.PARAMETER KeytabFile
    Path to the keytab file to extract keys from
    
.EXAMPLE
    .\KeyTabExtract.ps1 -KeytabFile .\service.keytab
    
.EXAMPLE
    .\KeyTabExtract.ps1 .\service.keytab
    
.NOTES
    Author: Luke Brown, Senior Solutions Architect at Extrahop
    Original Python version: sosdave (https://github.com/sosdave/KeyTabExtract)
    Version: 1.0
    
.LINK
    https://github.com/yourusername/KeyTabExtract
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$KeytabFile
)

function Show-Help {
    Write-Output "KeyTabExtract - Extract encryption keys from KeyTab files"
    Write-Output "Usage: .\KeyTabExtract.ps1 -KeytabFile <keytab_file>"
    Write-Output "   or: .\KeyTabExtract.ps1 <keytab_file>"
    Write-Output "Example: .\KeyTabExtract.ps1 -KeytabFile service.keytab"
}

function Extract-KeytabKeys {
    param([string]$FilePath)
    
    # Resolve to absolute path to handle relative paths correctly
    $resolvedPath = Resolve-Path -Path $FilePath -ErrorAction SilentlyContinue
    if (-not $resolvedPath) {
        Write-Output "[!] Error: File not found: $FilePath"
        return
    }
    
    # Read keytab file and convert to hex
    try {
        $bytes = [System.IO.File]::ReadAllBytes($resolvedPath.Path)
        $hexEncoded = ($bytes | ForEach-Object { $_.ToString("X2") }) -join ''
    }
    catch {
        Write-Output "[!] Error reading file: $_"
        return
    }
    
    # Detect encryption types
    $rc4hmac = $false
    $aes128 = $false
    $aes256 = $false
    
    if ($hexEncoded -match '00170010') {
        Write-Output "[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash."
        $rc4hmac = $true
    }
    else {
        Write-Output "[!] No RC4-HMAC located. Unable to extract NTLM hashes."
    }
    
    if ($hexEncoded -match '00120020') {
        Write-Output "[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction."
        $aes256 = $true
    }
    else {
        Write-Output "[!] Unable to identify any AES256-CTS-HMAC-SHA1 hashes."
    }
    
    if ($hexEncoded -match '00110010') {
        Write-Output "[*] AES128-CTS-HMAC-SHA1 hash discovered. Will attempt hash extraction."
        $aes128 = $true
    }
    else {
        Write-Output "[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes."
    }
    
    # Check if any useful hashes found
    if (-not ($rc4hmac -or $aes256 -or $aes128)) {
        Write-Output "[!] Unable to find any useful hashes. Exiting..."
        return
    }
    
    # Check keytab version (first 16 bits)
    $ktVersion = $hexEncoded.Substring(0, 4)
    if ($ktVersion -eq '0502') {
        Write-Output "[+] Keytab File successfully imported."
    }
    else {
        Write-Output "[!] Only Keytab versions 0502 are supported. Found: $ktVersion. Exiting..."
        return
    }
    
    try {
        # Parse keytab structure
        # Array length (32 bits)
        $arrLen = [Convert]::ToInt32($hexEncoded.Substring(4, 8), 16)
        
        # Number of components (16 bits)
        $numComponents = $hexEncoded.Substring(12, 4)
        
        # Realm length (16 bits)
        $numRealm = [Convert]::ToInt32($hexEncoded.Substring(16, 4), 16)
        
        # Calculate realm offset
        $realmJump = 20 + ($numRealm * 2)
        
        # Extract realm
        $realmHex = $hexEncoded.Substring(20, $numRealm * 2)
        $realmBytes = for ($i = 0; $i -lt $realmHex.Length; $i += 2) {
            [Convert]::ToByte($realmHex.Substring($i, 2), 16)
        }
        $realm = [System.Text.Encoding]::UTF8.GetString($realmBytes)
        Write-Output "`tREALM : $realm"
        
        # Component array calculation
        $compArrayCalc = $realmJump + 4
        $compArray = [Convert]::ToInt32($hexEncoded.Substring($realmJump, 4), 16)
        
        # Extract component (e.g., HTTP, HOST, etc.)
        $compArrayOffset = $compArrayCalc + ($compArray * 2)
        
        # Safety check for component extraction
        if ($compArray -gt 0 -and $compArrayCalc + ($compArray * 2) -le $hexEncoded.Length) {
            $compArray2Hex = $hexEncoded.Substring($compArrayCalc, $compArray * 2)
            $compArray2Bytes = for ($i = 0; $i -lt $compArray2Hex.Length; $i += 2) {
                [Convert]::ToByte($compArray2Hex.Substring($i, 2), 16)
            }
            $componentType = [System.Text.Encoding]::UTF8.GetString($compArray2Bytes)
        }
        else {
            $componentType = ""
        }
        
        # Principal array
        $principalArrayOffset = $compArrayOffset + 4
        
        # Safety check before extracting principal
        if ($principalArrayOffset + 4 -le $hexEncoded.Length) {
            $principalArray = $hexEncoded.Substring($compArrayOffset, 4)
            $principalArrayInt = [Convert]::ToInt32($principalArray, 16) * 2
            $prinArrayStart = $principalArrayOffset
            $prinArrayFinish = $prinArrayStart + $principalArrayInt
            
            # Additional safety check
            if ($prinArrayFinish -le $hexEncoded.Length -and $principalArrayInt -gt 0) {
                $principalArrayValueHex = $hexEncoded.Substring($prinArrayStart, $principalArrayInt)
                $principalArrayValueBytes = for ($i = 0; $i -lt $principalArrayValueHex.Length; $i += 2) {
                    [Convert]::ToByte($principalArrayValueHex.Substring($i, 2), 16)
                }
                $principalValue = [System.Text.Encoding]::UTF8.GetString($principalArrayValueBytes)
            }
            else {
                $principalValue = ""
            }
        }
        else {
            $principalValue = ""
        }
        
        if ($componentType -and $principalValue) {
            Write-Output "`tSERVICE PRINCIPAL : $componentType/$principalValue"
        }
        elseif ($componentType) {
            Write-Output "`tSERVICE PRINCIPAL : $componentType"
        }
        else {
            Write-Output "`tSERVICE PRINCIPAL : (unable to parse)"
        }
    }
    catch {
        Write-Output "`tWarning: Error parsing principal information: $_"
    }
    
    # Extract keys based on detected encryption types
    if ($rc4hmac) {
        $split = $hexEncoded -split '00170010'
        if ($split.Count -gt 1 -and $split[1].Length -ge 32) {
            $ntlmHash = $split[1].Substring(0, 32)
            Write-Output "`tNTLM HASH : $ntlmHash"
        }
    }
    
    if ($aes256) {
        $split = $hexEncoded -split '00120020'
        if ($split.Count -gt 1 -and $split[1].Length -ge 64) {
            $aes256Hash = $split[1].Substring(0, 64)
            Write-Output "`tAES-256 HASH : $aes256Hash"
        }
    }
    
    if ($aes128) {
        $split = $hexEncoded -split '00110010'
        if ($split.Count -gt 1 -and $split[1].Length -ge 32) {
            $aes128Hash = $split[1].Substring(0, 32)
            Write-Output "`tAES-128 HASH : $aes128Hash"
        }
    }
}

# Main execution
if (-not (Test-Path $KeytabFile)) {
    Write-Output "[!] File not found: $KeytabFile"
    Show-Help
    exit 1
}

Extract-KeytabKeys -FilePath $KeytabFile
