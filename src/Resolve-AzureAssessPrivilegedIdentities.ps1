<#
.SYNOPSIS
    Resolve the list of identities with privileged access to resources, subscriptions and management groups.
    All identities will be saved to a csv with an indication of the source ($null = direct assignemend; guid = group providing this access).
.EXAMPLE
    Resolve-AzureAssessPrivilegedIdentities.ps1
#>

function Resolve-AzureAssessPrivilegedIdentities {
    # load the role assignements 
    $roleassignmentscsv = Join-Path "." -ChildPath "roleassignments.csv"

    # path where to export identities
    $principalscsv = Join-Path -Path "." -ChildPath "principals.csv"
    $membershipscsv = Join-Path -Path "." -ChildPath "memberhips.csv"
    $ownershipscsv = Join-Path -Path "." -ChildPath "owners.csv"
    "principalId,principalType,displayName" | Out-File -FilePath $principalscsv -Force
    "Id,GroupId" | Out-File -FilePath $membershipscsv -Force
    "Id,OwnerId" | Out-File -FilePath $ownershipscsv -Force

    # get PrivilegedRoleAssignements from  csvs    
    $roleAssignements = get-content -Path $roleassignmentscsv | ConvertFrom-Csv

    # gather identities from role assignements
    $privIdentities = @{}
    foreach($roleAssignment in $roleAssignements) {
        $privIdentities[$roleAssignment.principalId] = $roleAssignment | Select-Object principalId,principalType,@{N="displayName";E={""}}
    }


    # get access token for graph
    $graphToken = Get-AzAccessToken -ResourceTypeName MSGraph 

    # expand groups
    # table to retain memberships
    $memberships = @()
    $queries = new-object -TypeName System.Collections.Stack
    $privIdentities.Values | where-object { $_.principalType -ieq "Group"} | Select-Object @{N="id";E={$_.principalId}},@{N="url";E={"/groups/$($_.principalId)/transitiveMembers?`$top=999&`$select=id"}} | ForEach-Object { $queries.Push($_) }
    # get token for ms graph
    $reqtoken = $graphToken.Token | ConvertTo-SecureString -AsPlainText -Force
    $count = 0
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $q = $queries.Pop()
            $requests += "" | select-object @{N="id"; E={$q.id}},@{N="method";E={"GET"}},@{N="url"; E={$q.url}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $failedresps = $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} 
        foreach($failedresp in $failedresps) {
            # get corresponding request
            $req = $requests | Where-Object { $_.id -eq $failedresp.id} | Select-Object id,url
            # requeue request
            $queries.Push($req)
        }
        # parse successfull responses
        $successresps = $resp.responses | Where-Object { [int]($_.status/100) -eq 2 }
        # fill in responses
        foreach($response in $successresps) {
            foreach ($value in $response.body.value) {
                $type = "unknown"
                if ($value."@odata.type" -ieq "#microsoft.graph.user") {
                    $type = "User"
                } elseif ($value."@odata.type" -ieq "#microsoft.graph.group") {
                    $type = "Group"
                } elseif ($value."@odata.type" -ieq "#microsoft.graph.servicePrincipal") {
                    $type = "ServicePrincipal"
                }
                $memberships += "" | Select-Object @{N="Id";E={$value.id}},@{N="GroupId";E={$response.Id}}
                if ($value.id -notin $privIdentities.Keys) {
                    $privIdentities[$value.id] = "" | Select-Object @{N="principalId";E={$value.id}},@{N="principalType";E={$type}},@{N="displayName";E={""}}
                }
            } 
            if ($response."@odata.nextLink") {
                # create request for nextlink
                $req = "" | Select-Object @{N="id";E={$response.id}},@{N="url";E={$response."@odata.nextLink"}}
                # enqueue request
                $queries.Push($req)
            }
            $count += 1
        }
        Write-Progress -Activity "Getting Memberships" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }

    # list of ownerships
    $ownerships = @()
    # check owners of groups (has only users and serviceprincipals)
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | where-object { $_.principalType -ieq "Group"} | ForEach-Object { $queries.Push($_.principalId) }
    # get token for ms graph
    $reqtoken = $graphToken.Token | ConvertTo-SecureString -AsPlainText -Force
    $count = 0
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $requests += $queries.Pop() | select-object @{N="id"; E={$_}},@{N="method";E={"GET"}},@{N="url"; E={"/groups/$($_)/owners?`$top=999&`$select=id"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queues.Push($_.id) }
        # parse successfull responses
        $successresps = $resp.responses | Where-Object { [int]($_.status/100) -eq 2 }
        # fill in responses
        foreach($response in $successresps) {
            foreach ($value in $response.body.value) {
                $type = "unknown"
                if ($value."@odata.type" -ieq "#microsoft.graph.user") {
                    $type = "User"
                } elseif ($value."@odata.type" -ieq "#microsoft.graph.servicePrincipal") {
                    $type = "ServicePrincipal"
                }
                $ownerships += "" | Select-Object @{N="Id";E={$response.id}},@{N="OwnerId";E={$value.Id}}
                if ($value.id -notin $privIdentities.Keys) {
                    $privIdentities[$value.id] = "" | Select-Object @{N="principalId";E={$value.id}},@{N="principalType";E={$type}},@{N="displayName";E={""}}
                }
            } 
            if ($response."@odata.nextLink") {
                # create request for nextlink
                $req = "" | Select-Object @{N="id";E={$response.id}},@{N="url";E={$response."@odata.nextLink"}}
                # enqueue request
                $queries.Push($req)
            }
            $count += 1
        }
        Write-Progress -Activity "Getting Group Owners" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }


    # owner check for serviceprincipals
    # TODO - handle potential of long nesting
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "ServicePrincipal" } | ForEach-Object { $queries.Push($_.principalId)}
    $count = 0
    while ($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $requests += $queries.Pop() | select-object @{N="id"; E={$_}},@{N="method";E={"GET"}},@{N="url"; E={"/servicePrincipals/$($_)/owners?`$top=999&`$select=id"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # add requests havint returned not found to the counter
        $count += ($resp.responses | Where-Object { $_.status -eq 404 }).Count
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queues.Push($_.id) }
        # parse successfull responses
        $successresps = $resp.responses | Where-Object { [int]($_.status/100) -eq 2 }
        # fill in responses
        foreach($response in $successresps) {
            foreach ($value in $response.body.value) {
                $type = "unknown"
                if ($value."@odata.type" -ieq "#microsoft.graph.user") {
                    $type = "User"
                } elseif ($value."@odata.type" -ieq "#microsoft.graph.servicePrincipal") {
                    $type = "ServicePrincipal"
                    if ($value.id -ne $response.id -and $value.id -notin $privIdentities.Keys) {
                        $queries.Push($value.id)
                    }
                }
                $ownerships += "" | Select-Object @{N="Id";E={$response.id}},@{N="OwnerId";E={$value.Id}}
                if ($value.id -notin $privIdentities.Keys) {
                    $privIdentities[$value.id] = "" | Select-Object @{N="principalId";E={$value.id}},@{N="principalType";E={$type}},@{N="displayName";E={""}}
                }
                $count += 1
            } 
            if ($response."@odata.nextLink") {
                # create request for nextlink
                $req = "" | Select-Object @{N="id";E={$response.id}},@{N="url";E={$response."@odata.nextLink"}}
                # enqueue request
                $queries.Push($req)
            }
        }
        Write-Progress -Activity "Getting ServicePrincipals Owners" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }

    # resolve privilegedIdentities displaynames
    $directoryobjects = @{
        ids = @($privIdentities.Keys)
        types = @(
            "user"
            "group"
            "serviceprincipal"
        )
    } | ConvertTo-Json -Depth 2 -Compress
    $res = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body $directoryobjects -Uri "https://graph.microsoft.com/v1.0/directoryObjects/getByIds?`$select=id,displayName"
    Start-Sleep -Seconds 5
    foreach($value in $res.value) {
        $privIdentities[$value.id].displayName = $value.displayName
    }
    foreach($id in $privIdentities.Keys) {
        if ($privIdentities[$id].displayName -eq "") {
            $privIdentities[$id].displayName = $id
        }
    }

    # save extracted information
    $privIdentities.Values | Export-Csv -Path $principalscsv -NoTypeInformation -Append
    $memberships | Export-Csv -Path $membershipscsv -NoTypeInformation -Append
    $ownerships | Export-Csv -Path $ownershipscsv -NoTypeInformation -Append

    # path to export user details
    $userscsv = Join-Path -Path "." -ChildPath "users.csv"
    # path to export group details
    $groupscsv = Join-Path -Path "." -ChildPath "groups.csv"
    # path to export service principal details 
    $serviceprincipalscsv = Join-Path -Path "." -ChildPath "serviceprincipals.csv"

    # check group details
    # create file and headers
    "id,displayName,mailEnabled,securityEnabled,onPremisesSyncEnabled" | Out-File -FilePath $groupscsv -Force
    # get groups informations
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "Group" } | ForEach-Object { $queries.Push($_.principalId) }
    $count = 0
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $groupid = $queries.Pop()
            $requests += "" | select-object @{N="id"; E={$groupid}},@{N="method";E={"GET"}},@{N="url"; E={"/groups/$($groupid)?`$select=id,displayName,mailEnabled,securityEnabled,onPremisesSyncEnabled"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) } 
        # fill in responses
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $count += 1; $_.body } | Select-Object id,displayName,mailEnabled,securityEnabled,onPremisesSyncEnabled | Export-Csv -Path $groupscsv -NoTypeInformation -Append
        Write-Progress -Activity "Getting Groups" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }

    # check service principals details
    $validitydate = get-date
    $appqueries = New-Object -TypeName System.Collections.Stack
    # create file and headers
    "id,appId,displayName,servicePrincipalType,expiredPasswordCredentials,validPasswordCredentials,expiredKeyCredentials,validKeyCredentials,federatedIdentityCredentials,accountEnabled,lastSignIn,lastAzureSignIn" | Out-File -FilePath $serviceprincipalscsv -Force
    $serviceprincipals = @{}
    # get service principals informations
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "ServicePrincipal" } | ForEach-Object { $queries.Push($_.principalId) }
    $count = 0
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $spid = $queries.Pop()
            $requests += "" | select-object @{N="id"; E={$spid}},@{N="method";E={"GET"}},@{N="url"; E={"/servicePrincipals/$($spid)?`$select=id,appId,displayName,servicePrincipalType,passwordCredentials,keyCredentials,federatedIdentityCredentials,accountEnabled"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404 } | ForEach-Object { $queries.Push($_.id) }
        # fill app queries
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $appqueries.Push($_.body.appId) }
        # fill in responses
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $count += 1; $_.body } `
            | Select-Object `
                id, `
                appId, `
                displayName, `
                servicePrincipalType, `
                @{N="expiredPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}}, `
                @{N="validPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -gt $validitydate}).Count}}, `
                @{N="expiredKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}}, `
                @{N="validKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}}, `
                @{N="federatedIdentityCredentials";E={$_.federatedIdentityCredentials.Count}},accountEnabled, `
                @{N="lastAzureSignIn";E={$null}}, `
                @{N="lastSignIn";E={$null}} `
            | ForEach-Object { $serviceprincipals[$_.appId] = $_}
        Write-Progress -Activity "Getting ServicePrincipals" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }

    # get app infromations
    $count = 0
    while($appqueries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $appqueries.Count -gt 0) {
            $appid = $appqueries.Pop()
            $requests += "" | select-object @{N="id"; E={$appid}},@{N="method";E={"GET"}},@{N="url"; E={"/applications?`$filter=appId+eq+'$appid'&`$select=id,appId,displayName,keyCredentials,passwordCredentials,federatedIdentityCredentials"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) }
        # udpate service principals
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $_.body.value } `
            | Select-Object id,appId,displayName,@{N="expiredPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -gt $validitydate}).Count}},@{N="expiredKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="federatedIdentityCredentials";E={$_.federatedIdentityCredentials.Count}} `
            | ForEach-Object {
                $count += 1 
                $serviceprincipals[$_.appId].expiredKeyCredentials += $_.expiredKeyCredentials
                $serviceprincipals[$_.appId].validKeyCredentials += $_.validKeyCredentials
                $serviceprincipals[$_.appId].expiredPasswordCredentials += $_.expiredPasswordCredentials
                $serviceprincipals[$_.appId].validPasswordCredentials += $_.validPasswordCredentials
                $serviceprincipals[$_.appId].federatedIdentityCredentials += $_.federatedIdentityCredentials
            }
        Write-Progress -Activity "Getting Applications" -Status "$count of $($count + $appqueries.Count)" -PercentComplete ($count * 100 / ($count + $appqueries.Count))
    }
    
    # check user details
    # create file and headers
    "id,displayName,userPrincipalName,mail,accountEnabled,department,userType,onPremisesSyncEnabled,lastSignIn,lastAzureSignIn" | Out-File -FilePath $userscsv -Force
    # get user informations
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "User" } | ForEach-Object { $queries.Push($_.principalId) }
    $count = 0
    $users = @()
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $userid = $queries.Pop()
            $requests += "" | select-object @{N="id"; E={$userid}},@{N="method";E={"GET"}},@{N="url"; E={"/users/$($userid)?`$select=id,displayName,userPrincipalName,mail,accountEnabled,department,userType,signInActivity,onPremisesSyncEnabled"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/beta/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        } else {
            Start-Sleep -Seconds 5
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) } 
        # fill in responses
        $users += $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $count += 1; $_.body } | Select-Object `
            id, `
            displayName, `
            userPrincipalName, `
            mail,`
            accountEnabled,`
            department,`
            userType,`
            @{N="onPremisesSyncEnabled";E={$_.onPremisesSyncEnabled -eq $true}}, `
            @{N="lastSignIn";E={$_.signInActivity.lastSuccessfulSignInDateTime}}, `
            @{N="lastAzureSignIn";E={$_.signInActivity.lastSuccessfulSignInDateTime}}
        Write-Progress -Activity "Getting Users" -Status "$count of $($count + $queries.Count)" -PercentComplete ($count * 100 / ($count + $queries.Count))
    }


    # determine if there is a log analytics to get details
    # looking at Azure AD diagnostic settings
    $res = Invoke-AzRestMethod -Method "GET" -path "/providers/microsoft.aadiam/diagnosticSettings/?api-version=2017-04-01"
    $aaddiagsettings = @()
    if ($res.StatusCode -eq 200) {
        $aaddiagsettings += ($res.Content | convertfrom-json).value | Select-Object -ExpandProperty properties `
            | Where-Object { 
                ![string]::IsNullorEmpty($_.workspaceId) -and
                ($_.logs | Where-Object { $_.category -eq "SignInLogs" -and $_.enabled }).count -gt 0 -and # User SignIn logs
                ($_.logs | Where-Object { $_.category -eq "NonInteractiveUserSignInLogs" -and $_.enabled }).count -gt 0 # User Non Interactive SignIn logs
            } `
            | Select-Object workspaceId,@{N="kind";E={"user"}},@{N="retention";E={($_.logs | Where-Object { $_.category -eq "SignInLogs" -and $_.enabled }).retentionPolicy.days}}
        $aaddiagsettings += ($res.Content | convertfrom-json).value | Select-Object -ExpandProperty properties `
            | Where-Object { 
                ![string]::IsNullorEmpty($_.workspaceId) -and
                ($_.logs | Where-Object { $_.category -eq "ServicePrincipalSignInLogs" -and $_.enabled }).count -gt 0 -and # SPN SignIn logs
                ($_.logs | Where-Object { $_.category -eq "ManagedIdentitySignInLogs" -and $_.enabled }).count -gt 0 # MI SignIn logs
            } `
            | Select-Object workspaceId,@{N="kind";E={"spn"}},@{N="retention";E={($_.logs | Where-Object { $_.category -eq "ServicePrincipalSignInLogs" -and $_.enabled }).retentionPolicy.days}}
    }
    $userworkspaceId = $aaddiagsettings | Where-Object { $_.kind -eq "user" } | Sort-Object -Property retention -Descending | Select-Object -First 1 -ExpandProperty workspaceId
    $spnworkspaceId = $aaddiagsettings | Where-Object { $_.kind -eq "spn" } | Sort-Object -Property retention -Descending | Select-Object -First 1 -ExpandProperty workspaceId

    # get user last signin to Azure with a maxspan of last six months
    if (![string]::IsNullorEmpty($userworkspaceId)) {
        $sub = ($userworkspaceId -split "/")[2]
        $rg = ($userworkspaceId -split "/")[4]
        $name = ($userworkspaceId -split "/")[-1]
        $kql = "
        SigninLogs
        | where ResourceDisplayName == 'Windows Azure Service Management API' and TimeGenerated > ago(6*30d) and ResultType == 0
        | project TimeGenerated,UserId
        | summarize TimeGenerated=max(TimeGenerated) by UserId
        | union (
            AADNonInteractiveUserSignInLogs
            | where ResourceDisplayName == 'Windows Azure Service Management API' and TimeGenerated > ago(6*30d) and ResultType == 0
            | project TimeGenerated,UserId
            | summarize TimeGenerated=max(TimeGenerated) by UserId
        )
        | summarize TimeGenerated=max(TimeGenerated) by UserId
        "
        $count = 0
        Write-Progress -Activity "Check Users last signing to Azure" -Status "$count of $($users.Count)" -PercentComplete ($count * 100 / $users.Count)
        Set-AzContext -Subscription $sub | Out-Null
        $ws = Get-AzOperationalInsightsWorkspace -Name $name -ResourceGroupName $rg
        $query = Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $kql
        foreach($user in $users) {
            $timegenerated = ($query.Results | Where-Object { $_.UserId -eq $user.id }).TimeGenerated
            if (![string]::IsNullorEmpty($timegenerated)) {
                $user.lastAzureSignIn = get-date -date $timegenerated
            }
            $count += 1
            Write-Progress -Activity "Check Users last signing to Azure" -Status "$count of $($users.Count)" -PercentComplete ($count * 100 / $users.Count)
        }
    }

    # get serviceprincipal last signin to Azure with a maxspan of last six months
    if (![string]::IsNullorEmpty($userworkspaceId)) {
        $sub = ($spnworkspaceId -split "/")[2]
        $rg = ($spnworkspaceId -split "/")[4]
        $name = ($spnworkspaceId -split "/")[-1]
        $kql = "
        AADServicePrincipalSignInLogs 
        | where TimeGenerated > ago(6*30d) and ResultType == 0
        | project TimeGenerated,ResourceDisplayName,AppId
        | summarize LastAzureSignIn=maxif(TimeGenerated,ResourceDisplayName == 'Windows Azure Service Management API'),LastSignIn=max(TimeGenerated) by AppId
        | union (
            AADManagedIdentitySignInLogs
            | where TimeGenerated > ago(6*30d) and ResultType == 0
            | project TimeGenerated,ResourceDisplayName,AppId
        | summarize LastAzureSignIn=maxif(TimeGenerated,ResourceDisplayName == 'Windows Azure Service Management API'),LastSignIn=max(TimeGenerated) by AppId
        )
        | summarize LastAzureSignIn=max(LastAzureSignIn),LastSignIn=max(LastSignIn) by AppId
        "
        $count = 0
        Write-Progress -Activity "Check ServicePrincipal last signing to Azure" -Status "$count of $($serviceprincipals.Keys.Count)" -PercentComplete ($count * 100 / $serviceprincipals.Keys.Count)
        Set-AzContext -Subscription $sub | Out-Null
        $ws = Get-AzOperationalInsightsWorkspace -Name $name -ResourceGroupName $rg
        $query = Invoke-AzOperationalInsightsQuery -WorkspaceId $ws.CustomerId -Query $kql
        foreach($appid in $serviceprincipals.Keys) {
            $spninfo = $query.Results | Where-Object { $_.AppId -eq $appid }
            $lastsignin = $spninfo.LastSignIn
            $lastazuresignin = $spninfo.LastAzureSignIn
            if (![string]::IsNullorEmpty($lastazuresignin)) {
                $serviceprincipals[$appid].lastAzureSignIn = get-date -date $lastazuresignin
            }
            $lastazuresignin = $spninfo.LastSignIn
            if (![string]::IsNullorEmpty($lastsignin)) {
                $serviceprincipals[$appid].lastSignIn = get-date -date $lastsignin
            }
            $count += 1
            Write-Progress -Activity "Check ServicePrincipal last signing to Azure" -Status "$count of $($serviceprincipals.Keys.Count)" -PercentComplete ($count * 100 / $serviceprincipals.Keys.Count)
        }
    }

    # export users to csv
    $users |  Export-Csv -Path $userscsv -NoTypeInformation -Append
    # save service principals
    $serviceprincipals.Values | Export-Csv -Path $serviceprincipalscsv -NoTypeInformation -Append

    # do not extend if memberships are already found
    if (($roleAssignements | Where-Object { $_.source -eq "Group"}).Count -eq 0) {
        # extend roleassignments with memberships
        $count = 0
        foreach($membership in $memberships) {
            $roleAssignements += @($roleAssignements | Where-Object {$_.principalId -eq $membership.GroupId}) `
                | Select-Object `
                    "roleId", `
                    "role", `
                    @{N="principalId";E={$membership.Id}}, `
                    @{N="principalType";E={$privIdentities[$membership.Id].principalType}}, `
                    "scope", `
                    @{N="source";E={"Group"}},`
                    "resourceType", `
                    "resourceName", `
                    "link"
            $count += 1
            Write-Progress -Activity "Expand Role Assignment with Memberships" -Status "$count of $($memberships.Count)" -PercentComplete ($count * 100 / $memberships.Count)
        }
    }

    # do not extend if ownerhips are already found
    if (($roleAssignements | Where-Object { $_.source -eq "Owner"}).Count -eq 0) {
        $count = 0
        # extend roleassignments with ownerships
        foreach($ownership in $ownerships) {            
            $roleAssignements += @($roleAssignements | Where-Object {$_.principalId -eq $ownership.Id}) `
                | Select-Object `
                    "roleId", `
                    "role", `
                    @{N="principalId";E={$ownership.OwnerId}}, `
                    @{N="principalType";E={$privIdentities[$ownership.OwnerId].principalType}}, `
                    "scope", `
                    @{N="source";E={"Owner"}},`
                    "resourceType", `
                    "resourceName", `
                    "link"
            $count += 1
            Write-Progress -Activity "Expand Role Assignment with Ownerships" -Status "$count of $($ownerships.Count)" -PercentComplete ($count * 100 / $ownerships.Count)
        }
    }

    $roleAssignements | export-csv -Path $roleassignmentscsv -NoTypeInformation -Force
}