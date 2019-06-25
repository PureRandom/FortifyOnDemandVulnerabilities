[CmdletBinding()]
param()

Trace-VstsEnteringInvocation $MyInvocation

try {

    ## Get the inputs.
    [string]$releaseId = Get-VstsInput -Name releaseId
    [string]$apiUrl = Get-VstsInput -Name apiUrl

    [string]$maxCriticalIssues = Get-VstsInput -Name maxCriticalIssues
    [string]$maxHighIssues = Get-VstsInput -Name maxHighIssues
    [string]$maxMediumIssues = Get-VstsInput -Name maxMediumIssues
    [string]$maxLowIssues = Get-VstsInput -Name maxLowIssues

    [string]$apiKey = Get-VstsInput -Name apiKey
    [string]$apiSecret = Get-VstsInput -Name apiSecret

    [string]$alertLevel = Get-VstsInput -Name alertLevel
    [string]$reportingLevel = Get-VstsInput -Name reportingLevel

    ## Import Required's
    [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

    ## Counters
    [int]$global:criticalCount = 0
    [int]$global:highCount = 0
    [int]$global:mediumCount = 0
    [int]$global:lowCount = 0
    [int]$global:bestPracticeCount = 0
    [int]$global:infoCount = 0

    function Get-Auth ([string]$apiKey, [string]$apiSecret, [string]$scope, [string]$apiUrl) {

        ## Create URL
        $url = "$apiUrl/oauth/token"
        Write-Host "Authentication URL: $url"
    
        ## Set Authorisation
        $body = @{
            scope         = "$scope"
            grant_type    = "client_credentials"
            client_id     = "$apiKey"
            client_secret = "$apiSecret"
        }
    
        ## Request
        $response = Invoke-RestMethod -ContentType "application/x-www-form-urlencoded" -Uri $url -Method POST -Body $body -UseBasicParsing
    
        return $response.access_token
    
    }


    function Map-Severity-Level([int]$severityNumber) {

        if ($severityNumber -eq 4) {
            $global:criticalCount = $global:criticalCount + 1
        }
        elseif ($severityNumber -eq 3) {
            $global:highCount = $global:highCount + 1
        }
        elseif ($global:severityNumber -eq 2) {
            $global:mediumCount = $global:mediumCount + 1
        }
        elseif ($severityNumber -eq 1) {
            $global:lowCount = $global:lowCount + 1
        }
        elseif ($severityNumber -eq -1) {
            $global:bestPracticeCount = $global:bestPracticeCount + 1
        }
        elseif ($severityNumber -eq -2) {
            $global:infoCount = $global:infoCount + 1
        }
    }

    function Print-Scan-Details($latestScanDetails) {

        if ($reportingLevel -eq "verbose") {
            Write-Host "`nIssue Count:"
            Write-Host "Critical:" $maxCriticalIssues "/" $global:criticalCount
            Write-Host "High:" $maxHighIssues "/" $global:highCount
            Write-Host "Medium:" $maxMediumIssues "/" $global:mediumCount
            Write-Host "Low:" $maxLowIssues "/" $global:lowCount
            Write-Host "`n"
        }
    }

    function Evaluate-Scan-Results($latestScanVulnerbilities) {

        Write-Host "`nResult:"
        $failed = "false"

        if ($global:criticalCount -gt $maxCriticalIssues) {
            Write-Host "Critical Failed"
            $failed = "true"
        }
        else {
            Write-Host "Critical Succeeded"
        }
        if ($global:highCount -gt $maxHighIssues) {
            Write-Host "High Failed"
            $failed = "true"
        }
        else {
            Write-Host "High Succeeded"
        }
        if ($global:mediumCount -gt $maxMediumIssues) {
            Write-Host "Medium Failed"
            $failed = "true"
        }
        else {
            Write-Host "Medium Succeeded"
        }
        if ($global:lowCount -gt $maxLowIssues) {
            Write-Host "Low Failed"
            $failed = "true"
        }
        else {
            Write-Host "Low Succeeded"
        }

        If ($failed -eq "true") {
            Print-Alert -errorMsg "Security Issues Breached Limits"  
        }

    }

    function Print-Alert([string]$errorMsg) {

        if ($alertLevel -eq "warning") {
            Write-Host "##vso[task.LogIssue type=warning;]$errorMsg"
        }
        else {
            Write-Host "##vso[task.LogIssue type=error;]$errorMsg"
            exit 1
        }
    }

    ## Create URL
    $url = "$apiUrl/api/v3/releases/$releaseId/Vulnerabilities?"
    $url += "orderBy=completedDateTime"
    $url += "&orderByDirection=DESC"

    ## Set Authorisation
    $long_lived_access_token = Get-Auth -apiKey $apiKey -apiSecret $apiSecret -scope "view-issues" -apiUrl $apiUrl
    $headers = @{Authorization = "Bearer $long_lived_access_token" }

    ## Request
    Write-Host "URL: $url `n"
    $response = Invoke-RestMethod -ContentType "application/json"  -Uri $url -Method GET -Headers $headers -UseBasicParsing
    $latestScanVulnerbilities = $response.items

    
    foreach ($item in $latestScanVulnerbilities) {
    
        if ($reportingLevel -eq "verbose") {
            write-Host ""
            write-Host "severity " $item.severity 
            write-Host "severityString  " $item.severityString  
            write-Host "category " $item.category 
        }
        Map-Severity-Level -severityNumber $item.severity
    }

    Print-Scan-Details -latestScanDetails $latestScanVulnerbilities
    Evaluate-Scan-Results -latestScanDetails $latestScanVulnerbilities

}
Catch {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Error "$FailedItem - $ErrorMessage"
}
finally {
    Trace-VstsLeavingInvocation $MyInvocation
}