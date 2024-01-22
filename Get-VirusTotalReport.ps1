function Get-VirusTotalReport {
    <#
    .SYNOPSIS
        Lookup analysis of an indicator on VirusTotal
    .DESCRIPTION
        Lookup analysis of an indicator on VirusTotal
    .PARAMETER Indicator
        The indicator that you wish to pass to VirusTotal
        This can be a URL, Domain, IPv4 address, MD5 hash, SHA hash, or SHA256 hash
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-16) Initial version
    .EXAMPLE
        Get-VirusTotalReport -Indicator pendantpublishing.com
    #>
    #requires -version 5

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Indicator
    )
    
    # Not a secure way to store this.  Need a better way
    $ApiKey = "<API KEY GOES HERE>"
    # Build the authentication header
    $Header = @{"x-apikey" = $ApiKey}
    # Base URLs for VirusTotal API endpoints
    $HashCheckUrl = "https://www.virustotal.com/api/v3/files/"
    $UrlCheckUrl = "https://www.virustotal.com/api/v3/urls/"
    $DomainCheckUrl = "https://www.virustotal.com/api/v3/domains/"
    $IpCheckUrl = "https://www.virustotal.com/api/v3/ip_addresses/"
    
    # Use regex to determine the type of Indicator, rather than lots of parameters and if/else to manage the resulting combinations
    switch -Regex ($Indicator){
        '^(http[s]?)\://.*$'{
        # Regex taken from here: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_switch?view=powershell-7.4
            Write-Host -ForegroundColor Green "Regex matched a URL"
            $ApiUrl = $UrlCheckUrl + $Indicator
            try{(Invoke-RestMethod -Method Get -Uri $ApiUrl -Headers $Header).data.attributes; Break}
            catch{Write-Warning $Error[0]}
        }
        '^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$'{
        # Regex taken from here: https://stackoverflow.com/questions/5284147/validating-ipv4-addresses-with-regexp
            Write-Host -ForegroundColor Green "Regex matched an IPv4 address"
            $ApiUrl = $IpCheckUrl + $Indicator
            try{(Invoke-RestMethod -Method Get -Uri $ApiUrl -Headers $Header).data.attributes; Break}
            catch{Write-Warning $Error[0]}
        }
        '(^[a-fA-F0-9]{32}$)|(^[a-fA-F0-9]{40}$)|(^[a-fA-F0-9]{64}$)'{
            # Regex adapted from here: https://regex101.com/r/UL39b1/1
            Write-Host -ForegroundColor Green "Regex matched a hash"
            $ApiUrl = $HashCheckUrl + $Indicator
            try{(Invoke-RestMethod -Method Get -Uri $ApiUrl -Headers $Header).data.attributes; Break}
            catch{Write-Warning $Error[0]}
        }
        '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$'{
            # Regex taken from https://regex101.com/r/FLA9Bv/40
            Write-Host -ForegroundColor Green "Regex matched a Domain"
            $ApiUrl = $DomainCheckUrl + $Indicator
            try{(Invoke-RestMethod -Method Get -Uri $ApiUrl -Headers $Header).data.attributes; Break}
            catch{Write-Warning $Error[0]}
        }
        default{
            Write-Host -ForegroundColor Red "Indicator not recognized, exiting"
        }
    }   
}
