## Set Proxy
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials


function Get-Auth ([string]$apiKey, [string]$apiSecret, [string]$scope, [string]$apiUrl) {

    ## Create URL
    $url = "$apiUrl/oauth/token"

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
