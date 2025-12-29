# KeyTabExtract

A PowerShell tool to extract encryption keys from Kerberos keytab files. Supports extraction of NTLM hashes (RC4-HMAC), AES256-CTS-HMAC-SHA1-96, and AES128-CTS-HMAC-SHA1-96 keys.

## Credits

This PowerShell implementation is based on the original Python script by **sosdave**:
- Original Python version: https://github.com/sosdave/KeyTabExtract

## Description

For when you want to get the AES Key or NTLM Hash from a Keytab and you can't run Kali or Python.

### Basic Usage
```powershell
# Using relative path
.\KeyTabExtract.ps1 -KeytabFile .\service.keytab

# Using absolute path
.\KeyTabExtract.ps1 -KeytabFile C:\temp\service.keytab

# Positional parameter (no parameter name needed)
.\KeyTabExtract.ps1 .\service.keytab
```

### Example Output
```
[*] AES256-CTS-HMAC-SHA1 key found. Will attempt hash extraction.
[!] Unable to identify any AES128-CTS-HMAC-SHA1 hashes.
[!] No RC4-HMAC located. Unable to extract NTLM hashes.
[+] Keytab File successfully imported.
        REALM : LAB.LOCAL
        SERVICE PRINCIPAL : winrmtestuser
        AES-256 HASH : 117E0A2E6AA4E3F54F48576CD65AB9664534D5BBD1A7BBD7B0CB4808FB7D3E6F
```

## Generating Keytab Files

Keytab files can be generated using Microsoft's `ktpass` utility:

### RC4-HMAC (NTLM Hash)
```cmd
ktpass /princ user@DOMAIN.COM /mapuser DOMAIN\user /crypto RC4-HMAC-NT /ptype KRB5_NT_PRINCIPAL /out user.keytab
```

### AES256-SHA1
```cmd
ktpass /princ user@DOMAIN.COM /mapuser DOMAIN\user /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /out user.keytab
```

### AES128-SHA1
```cmd
ktpass /princ user@DOMAIN.COM /mapuser DOMAIN\user /crypto AES128-SHA1 /ptype KRB5_NT_PRINCIPAL /out user.keytab
```


## Supported Keytab Versions

- **Keytab Version 0502** (standard MIT Kerberos keytab format)

## Encryption Types

The tool identifies and extracts the following encryption types:

| Encryption Type | Key Type Code | Output Length | Description |
|----------------|---------------|---------------|-------------|
| RC4-HMAC | 23 (0x0017) | 32 hex chars | NT hash (NTLM) |
| AES128-CTS-HMAC-SHA1-96 | 17 (0x0011) | 32 hex chars | AES-128 key |
| AES256-CTS-HMAC-SHA1-96 | 18 (0x0012) | 64 hex chars | AES-256 key |

## Limitations

- Only supports keytab version 0502
- Parses first entry in keytab file (if multiple entries exist)
- Requires valid keytab file structure

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is provided for legitimate security testing, troubleshooting, and educational purposes only. Users are responsible for ensuring they have proper authorization before extracting keys from keytab files. Unauthorized access to credentials or cryptographic material may be illegal.
