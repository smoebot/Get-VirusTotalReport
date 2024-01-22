# Get-VirusTotalReport
Powershell.  Pull a VirusTotal report about an IOC, using a range of indicator types.

Supports Domains, URLs, Hashes, and IP addresses
---

**Parameters** 

_Indicator_

The indicator that you wish to pass to VirusTotal
This can be a URL, Domain, IPv4 address, MD5 hash, SHA hash, or SHA256 hash
---

**Examples**
        
```powershell
Get-VirusTotalReport -Indicator example.com
```

```powershell
Get-VirusTotalReport -Indicator 8.8.8.8
```

```powershell
Get-VirusTotalReport -Indicator 938c2cc0dcc05f2b68c4287040cfcf71
```
