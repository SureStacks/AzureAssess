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

    # expand groups
    # table to retain memberships
    $memberships = @()
    $queries = new-object -TypeName System.Collections.Stack
    $privIdentities.Values | where-object { $_.principalType -ieq "Group"} | Select-Object @{N="id";E={$_.principalId}},@{N="url";E={"/groups/$($_.principalId)/transitiveMembers?`$top=999&`$select=id"}} | ForEach-Object { $queries.Push($_) }
    # get token for ms graph
    $graphToken = Get-AzAccessToken -ResourceTypeName MSGraph 
    $reqtoken = $graphToken.Token | ConvertTo-SecureString -AsPlainText -Force
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
        }
    }

    # list of ownerships
    $ownerships = @()
    # check owners of groups (has only users and serviceprincipals)
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | where-object { $_.principalType -ieq "Group"} | ForEach-Object { $queries.Push($_.principalId) }
    # get token for ms graph
    $graphToken = Get-AzAccessToken -ResourceTypeName MSGraph 
    $reqtoken = $graphToken.Token | ConvertTo-SecureString -AsPlainText -Force
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
        }
    }


    # owner check for serviceprincipals
    # TODO - handle potential of long nesting
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "ServicePrincipal" } | ForEach-Object { $queries.Push($_.principalId)}
    while ($queries.Count -gt 0) {$requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $requests += $queries.Pop() | select-object @{N="id"; E={$_}},@{N="method";E={"GET"}},@{N="url"; E={"/servicePrincipals/$($_)/owners?`$top=999&`$select=id"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
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
                    if ($value.id -ne $response.id -and $value.id -notin $privIdentities.Keys) {
                        $queries.Push($value.id)
                    }
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
        }

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
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) } 
        # fill in responses
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $_.body } | Select-Object id,displayName,mailEnabled,securityEnabled,onPremisesSyncEnabled | Export-Csv -Path $groupscsv -NoTypeInformation -Append
    }

    # check service principals details
    $validitydate = get-date
    $appqueries = New-Object -TypeName System.Collections.Stack
    # create file and headers
    "id,appId,displayName,servicePrincipalType,expiredPasswordCredentials,validPasswordCredentials,expiredKeyCredentials,validKeyCredentials,federatedIdentityCredentials,accountEnabled" | Out-File -FilePath $serviceprincipalscsv -Force
    $serviceprincipals = @{}
    # get service principals informations
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "ServicePrincipal" } | ForEach-Object { $queries.Push($_.principalId) }
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
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404 } | ForEach-Object { $queries.Push($_.id) }
        # fill app queries
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $appqueries.Push($_.body.appId) }
        # fill in responses
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $_.body } `
            | Select-Object id,appId,displayName,servicePrincipalType,@{N="expiredPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -gt $validitydate}).Count}},@{N="expiredKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="federatedIdentityCredentials";E={$_.federatedIdentityCredentials.Count}},accountEnabled `
            | ForEach-Object { $serviceprincipals[$_.appId] = $_}
    }

    # get app infromations
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
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) }
        # udpate service principals
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $_.body.value } `
            | Select-Object id,appId,displayName,@{N="expiredPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validPasswordCredentials";E={@($_.passwordCredentials | Where-Object {$_.endDateTime -gt $validitydate}).Count}},@{N="expiredKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="validKeyCredentials";E={@($_.keyCredentials | Where-Object {$_.endDateTime -le $validitydate}).Count}},@{N="federatedIdentityCredentials";E={$_.federatedIdentityCredentials.Count}} `
            | ForEach-Object { 
                $serviceprincipals[$_.appId].expiredKeyCredentials += $_.expiredKeyCredentials
                $serviceprincipals[$_.appId].validKeyCredentials += $_.validKeyCredentials
                $serviceprincipals[$_.appId].expiredPasswordCredentials += $_.expiredPasswordCredentials
                $serviceprincipals[$_.appId].validPasswordCredentials += $_.validPasswordCredentials
                $serviceprincipals[$_.appId].federatedIdentityCredentials += $_.federatedIdentityCredentials
            }
    }

    # save service principals
    $serviceprincipals.Values | Export-Csv -Path $serviceprincipalscsv -NoTypeInformation -Append

    # check user details
    # create file and headers
    "id,displayName,userPrincipalName,mail,accountEnabled,department,userType,onPremisesSyncEnabled" | Out-File -FilePath $userscsv -Force
    # get user informations
    $queries = New-Object -TypeName System.Collections.Stack
    $privIdentities.Values | Where-Object { $_.principalType -eq "User" } | ForEach-Object { $queries.Push($_.principalId) }
    while($queries.Count -gt 0) {
        $requests = @()
        while($requests.Count -lt 20 -and $queries.Count -gt 0) {
            $userid = $queries.Pop()
            $requests += "" | select-object @{N="id"; E={$userid}},@{N="method";E={"GET"}},@{N="url"; E={"/users/$($userid)?`$select=id,displayName,userPrincipalName,mail,accountEnabled,department,userType,onPremisesSyncEnabled"}}
        }
        $batchreq = "" | select-object @{N="requests";E={@(,$requests)}}
        $resp = Invoke-RestMethod -ContentType "application/json" -Authentication Bearer -Token $reqtoken -Method Post -Body ($batchreq | ConvertTo-Json -Compress -Depth 2) -Uri "https://graph.microsoft.com/v1.0/`$batch"
        # check for throttling
        if (($resp.responses | Where-Object {$_.status -eq 429}).Count -gt 0) {
            Start-Sleep -Seconds 60
        }
        # requeue get failed requests
        $resp.responses | Where-Object { [int]($_.status/100) -ne 2 -and $_.status -ne 404} | ForEach-Object { $queries.Push($_.id) } 
        # fill in responses
        $resp.responses | Where-Object { [int]($_.status/100) -eq 2 } | ForEach-Object{ $_.body } | Select-Object id,displayName,userPrincipalName,mail,accountEnabled,department,userType,@{N="onPremisesSyncEnabled";E={$_.onPremisesSyncEnabled -eq $true}} | Export-Csv -Path $userscsv -NoTypeInformation -Append
    }

    # do not extend if memberships are already found
    if (($roleAssignements | Where-Object { $_.source -eq "Group"}).Count -eq 0) {
        # extend roleassignments with memberships
        foreach($membership in $memberships) {
            $toadd = @($roleAssignements | Where-Object {$_.principalId -eq $membership.GroupId}) 
            foreach($assignment in $toadd) {
                $newassignment = $assignment.PsObject.Copy()
                $newassignment.principalId = $membership.Id
                $newassignment.principalType = $privIdentities[$membership.Id].principalType
                $newassignment.source = "Group"
                $roleAssignements += $newassignment
            }
        }
    }

    # do not extend if ownerhips are already found
    if (($roleAssignements | Where-Object { $_.source -eq "Owner"}).Count -eq 0) {
        # extend roleassignments with ownerships
        foreach($ownership in $ownerships) {
            $toadd = @($roleAssignements | Where-Object {$_.principalId -eq $ownership.Id})
            foreach($assignment in $toadd) {
                $newassignment = $assignment.PsObject.Copy()
                $newassignment.principalId = $ownership.OwnerId
                $newassignment.principalType = $privIdentities[$ownership.OwnerId].principalType
                $newassignment.source = "Owner"
                $roleAssignements += $newassignment
            }
        }
    }

    $roleAssignements | export-csv -Path $roleassignmentscsv -NoTypeInformation -Force
}