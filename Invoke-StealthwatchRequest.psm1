Function Invoke-NetflowRequest{
<#

.SYNOPSIS
StealthWatch Netflow query API module

.DESCRIPTION
This module uses the StealthWatch Netflow v2 API to make and receive Netflow data requests

.PARAMETER Username
The StealthWatch username of the account making the request

.PARAMETER Outfile
The file to save search results to. Must be a JSON file

.PARAMETER Records
The number of records to obtain

.PARAMETER Hours
The number of hours to request. E.g., -Hours 24 = flow data in the last day

.PARAMETER Tenant
The tenant ID for the request

.PARAMETER Load
Load a saved JSON request from a configuration file. Any parameters passed during invocation will take precedence over loaded parameters.

.PARAMETER Save
Save the invoked parameters into the configuration file.

.PARAMETER ConfigurationFile
The file used for loading or saving request data.

.PARAMETER HostQuery
Subject parameters passed in request data.

.PARAMETER PeerQuery
Peer parameters passed in request data.

.PARAMETER FlowQuery
Flow parameters passed in request data.

.Example 
    # Request 100 flows observed in the last day
    Invoke-NetflowRequest -Username <user> -Tenant <tenant> -Outfile Results.json -Records 100 -Hours 24

.Example
    # Request 100 flows observed in the last day from a specific host 
    Invoke-NetflowRequest -Username <user> -Tenant <tenant> -Outfile Results.json -Records 100 -Hours 24 -HostQuery @{"ipAddress"=@{"includes"=@("127.0.0.1")}}

.Example 
    # Load a saved request
    Invoke-NetflowRequest -Username <user> -Tenant <tenant> -Outfile Results.json -Records 100 -Hours 24 -Load default.json

#>
    param($Username, $Outfile, $Records, $Hours, $Tenant, [switch]$Load, [switch]$Save, $ConfigurationFile, $HostQuery, $PeerQuery, $FlowQuery)
    # Get secure password and convert into useable string for webrequest
    # This keeps the plaintext password out of command line logging, but it will show in process memory
    $Password = Read-Host -AsSecureString "Password"
    $Password = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $Password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Password)

    # Create the Auth data
    $AuthHeaders =@{
        'username'=$Username
        'password'=$Password
    }

    # BaseURL is the only thing that gets updated
    $BaseURL = "<YourInstanceURLHere>"
    $Authurl = $BaseURL+"/token/v2/authenticate"
    $RequestURI = $BaseURL+"/sw-reporting/v2/tenants/$Tenant/flows/queries"
    
    # Authenticate and create a websession
    $AuthResponse = Invoke-WebRequest -Body $AuthHeaders -Uri $Authurl -SessionVariable apisession -Method POST
    if($AuthResponse.StatusCode -eq 200){
        Write-Host "Login successful"

        # Get the cookies
        $cookies = $apisession.Cookies.GetCookies($Authurl) 
        foreach($x in $cookies){

            # Create a header for the XSRF token
            if($x.name -eq "XSRF-TOKEN"){
                $XSRFTOKEN =@{"X-XSRF-TOKEN"=$x.value}
            }
        }
    }else{
        Write-Host "Logon failed with" $AuthResponse.StatusCode
        exit
    }
    
    # Build Request Headers
    $RequestHeaders =@{
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }

    # Join the headers together
    $RequestHeaders = Merge-Hashtables $RequestHeaders $XSRFTOKEN

    # Build Request Data
    # Must be in wacky time
    $RequestData = RequestConfiguration
    
    # Push the query
    $QueryResponse = Invoke-WebRequest -Headers $RequestHeaders -Body $RequestData -URI $RequestURI -Method POST -WebSession $apisession
    if($QueryResponse.StatusCode -eq 201){
        $Response = $QueryResponse | ConvertFrom-Json
        Write-Host "Generating Results...`nSearchID ="$Response.data.query.id"`nStatus ="$Response.data.query.status
        $SearchURI = $RequestURI+"/"+$Response.data.query.id

        # Test every second until query is done
        while(-Not $Done){
            $Search = Invoke-WebRequest -Method GET -URI $SearchURI -Headers $XSRFTOKEN -WebSession $apisession
            $Response = $Search | ConvertFrom-Json
            if($Response.data.query.percentComplete -eq 100.0){
                $Done = $true
            }else{
                Start-Sleep(1)
            }
        }

        # Get the results
        $ResultsURI = $SearchURI+"/results"
        $NetflowResults = Invoke-WebRequest -URI $ResultsURI -Headers $XSRFTOKEN -Method GET -WebSession $apisession
        if($NetflowResults.StatusCode -eq 200){
            Write-Host "Saving results in $Outfile"
            $NetflowResults.content | Out-File $Outfile
        }else{
            Write-Host "Something went wrong...`nStatus Code:"$NetflowResults.StatusCode
        }

    }else{
        Write-Host "Could not complete request"
    }
}
Function Merge-Hashtables {
    $Output = @{}
    ForEach ($Hashtable in ($Input + $Args)) {
        If ($Hashtable -is [Hashtable]) {
            ForEach ($Key in $Hashtable.Keys) {$Output.$Key = $Hashtable.$Key}
        }
    }
    return $Output
}

function RequestConfiguration{
    $Time = Get-Date
    $Hours = $Hours * -1
    if($Load){
        Write-Host "Using Load parameters"
        <# Import JSON configuration
            Formatting:
            JSON Array = []
            PowerShell Array = @()
            -HostQuery = @{"ipAddresses"=@{"includes"=@("127.0.0.1","192.168.0.1");"excludes"=@()};"hostGroups"=@{"includes"=@();"excludes"=@()}}
            
            Passed values overwrite loaded values. 
        #>
        $RequestData = Get-Content $ConfigurationFile -Raw | ConvertFrom-Json
        $RequestData.startDateTime = $Time.AddHours($Hours).ToString("yyyy-MM-ddT%H:%m:%sZ")
        $RequestData.endDateTime = $Time.ToString("yyyy-MM-ddT%H:%m:%sZ")
        $RequestData.recordLimit = $Records
        if($HostQuery){
            $RequestData.subject = $HostQuery
        }
        if($PeerQuery){
            $RequestData.peer = $PeerQuery
        }
        if($FlowQuery){
            $RequestData.flow = $FlowQuery
        }        
    }else{
        # By default, get all flows
        $RequestData =@{
            'startDateTime'= $Time.AddHours($Hours).ToString("yyyy-MM-ddT%H:%m:%sZ")
            'endDateTime'= $Time.ToString("yyyy-MM-ddT%H:%m:%sZ")
            'recordLimit'=$Records
        }
        if($HostQuery){
            $RequestData.subject = $HostQuery
        }
        if($PeerQuery){
            $RequestData.peer = $PeerQuery
        }
        if($FlowQuery){
            $RequestData.flow = $FlowQuery
        }
    }
    # Depth must be 3 or higher to maintain JSON Array conversions
    $RequestData = $RequestData | ConvertTo-JSON -Depth 3
    if($Save){
        Out-File -FilePath $ConfigurationFile -InputObject $RequestData
        Write-Host "Saved search parameters to"$ConfigurationFile
    }
    return $RequestData
}
 
Export-ModuleMember -Function Invoke-NetflowRequest
