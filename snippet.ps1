Function Get-VcsaDiskStorage {
    <#
    .PARAMETER vcenter
        vCenter Server Hostname or IP Address
    .PARAMETER ssouser
        VC Username
    .PARAMETER ssopass
        VC Password
    .EXAMPLE
        Get-VcsaDiskStorage -vcenter vcsa-lab00.domain.local -vc_user administrator@vsphere.local
    #> 

    param(
        [Parameter(Mandatory = $true)][string]$vcenter,
        [Parameter(Mandatory = $true)][string]$vc_user,
        [Parameter(Mandatory = $true)][secureString]$vc_pass
    )

    $ErrorActionPreference = "Ignore"
    
    if (!$vcenter) { $vcenter = Read-Host  "Please Enter vCenter for health checks" }
    if (!$vc_user) { $vc_user = Read-Host  "Please enter SSO administrator username (administrator@vsphere.local)" }
    if (!$vc_pass) { $vc_pass = Read-Host  | ConvertFrom-SecureString -AsPlainText -Force "Please Enter SSO Password" }
    
    $BaseUrl = "https://" + $vcenter + "/"
    $AuthUrl = $BaseUrl + "api/session"
    $storageBaseUrl = $BaseUrl + "api/appliance/system/storage"

    # Create API Auth Session
    $auth = $vc_user + ':' + ($vc_pass | ConvertFrom-SecureString -AsPlainText)
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $authorizationInfo = [System.Convert]::ToBase64String($Encoded)
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Basic $($authorizationInfo)")
 
    # Get API Session ID
    $apiSessionId = Invoke-WebRequest $AuthUrl -Method 'POST' -Headers $headers -SkipCertificateCheck
    $sessionId = $apiSessionId.Content | ConvertFrom-Json

    Function Get-vamiDisks {
        <#
            .SYNOPSIS
                This function retrieves VMDK disk number to partition mapping VAMI interface (5480)
                for a VCSA node which can be an Embedded VCSA, External PSC or External VCSA.
            .DESCRIPTION
                Function to return VMDK disk number to OS partition mapping
        #>
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId)    

        $storageAPI = Invoke-WebRequest $storageBaseUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $storageDisks = ($storageAPI.Content | ConvertFrom-Json) | Select-Object Disk, Partition
        $storageDisks
    }
    
    Function Get-vamiStorageUsed {
        <#
                .SYNOPSIS
                    This function retrieves the individual OS partition storage utilization
                    for a VCSA node which can be an Embedded VCSA, External PSC or External VCSA.
                .DESCRIPTION
                    Function to return individual OS partition storage utilization
            #>

        $monitorBaseUrl = $BaseUrl + "api/appliance/monitoring"

        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("vmware-api-session-id", $sessionId) 

        # List of IDs from Get-vamiStatsList to query
        $monitoringAPI = Invoke-WebRequest $monitorBaseUrl -Method 'GET' -Headers $headers -SkipCertificateCheck
        $queryNames = (($monitoringAPI.Content | ConvertFrom-Json) | Where-Object { ($_.name -like "*storage.used.filesystem*") -or ($_.name -like "*storage.totalsize.filesystem*") } | Select-Object id | Sort-Object -Property id)
        $queryName = $queryNames.id

        # Tuple (Filesystem Name, Used, Total) to store results
        $storageStats = @{
            "archive"      = @{"name" = "/storage/archive"; "used" = 0; "total" = 0 };
            "autodeploy"   = @{"name" = "/storage/autodeploy"; "used" = 0; "total" = 0 };
            "boot"         = @{"name" = "/boot"; "used" = 0; "total" = 0 };
            "core"         = @{"name" = "/storage/core"; "used" = 0; "total" = 0 };
            "db"           = @{"name" = "/storage/db"; "used" = 0; "total" = 0 };
            "dblog"        = @{"name" = "/storage/dblog"; "used" = 0; "total" = 0 };
            "imagebuilder" = @{"name" = "/storage/imagebuilder"; "used" = 0; "total" = 0 };
            "lifecycle"    = @{"name" = "/storage/lifecycle"; "used" = 0; "total" = 0 };
            "log"          = @{"name" = "/storage/log"; "used" = 0; "total" = 0 };
            "netdump"      = @{"name" = "/storage/netdump"; "used" = 0; "total" = 0 };
            "root"         = @{"name" = "/root"; "used" = 0; "total" = 0 };
            "updatemgr"    = @{"name" = "/storage/updatemgr"; "used" = 0; "total" = 0 };
            "seat"         = @{"name" = "/storage/seat"; "used" = 0; "total" = 0 };
            "swap"         = @{"name" = "/swap"; "used" = 0; "total" = 0 };
            "vtsdb"        = @{"name" = "/storage/vtsdb"; "used" = 0; "total" = 0 };
            "vtsdblog"     = @{"name" = "/storage/vtsdblog"; "used" = 0; "total" = 0 }
        }
                
        $queryInterval = "DAY1"
        $queryFunction = "MAX"
        $queryStart_time = ((Get-Date).AddDays(-1)).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + ".000Z"
        $queryEnd_time = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + ".000Z"
                
        $querySpecs = "&interval=" + $queryInterval + "&function=" + $queryfunction + "&start_time=" + $queryStart_time + "&end_time=" + $queryEnd_time
                
        $queryResults = foreach ($item in $queryName) {
            $queryUrl = $monitorBaseUrl + "/query?names=" + $item + $querySpecs
            Invoke-WebRequest $queryUrl -Method 'GET' -Headers $headers -SkipCertificateCheck | Select-Object * -ExcludeProperty Help
        }
        $results = $queryResults.Content | ConvertFrom-Json
            
        foreach ($result in $results) {
            # Update hash if its used storage results
            $key = ((($Result.name).toString()).split(".")[-1]) -replace "coredump", "core" -replace "vcdb_", "" -replace "core_inventory", "db" -replace "transaction_log", "dblog"
            $value = [Math]::Round([int]($result.data[1]).toString() / 1MB, 2)
            if ($result.name -match "used") {
                $storageStats[$key]["used"] = $value
                # Update hash if its total storage results
            }
            else {
                $storageStats[$key]["total"] = $value
            }
        }
            
        $storageResults = @()
        foreach ($key in $storageStats.keys | Sort-Object -Property name) {
            $statResult = [pscustomobject] @{
                Filesystem = $storageStats[$key].name;
                Used       = $storageStats[$key].used;
                Total      = $storageStats[$key].total
            }
            $storageResults += $statResult
        }
        $storageResults
    }

    $vamiDisks = Get-vamiDisks
    $vamiDiskStorage = Get-vamiStorageUsed

    $hashRes = @{}
    foreach ($vamiDisk in $vamiDisks) {
        $hashRes[$vamiDisk.partition] = $vamiDisk
    }

    $storageResults = $vamiDiskStorage | ForEach-Object {
        $pctUsed = ($_.used / $_.total) * 100
        $other = $hashRes[$_.filesystem.Split('/')[-1]]
        [pscustomobject]@{
            Filesystem = $_.filesystem
            UsedGB     = $_.used
            TotalGB    = $_.total
            UsedPct    = [math]::Round($pctUsed, 2)
            HardDisk   = $other.disk
            Partition  = $other.partition
        }
    }

    $storageResults | Sort-Object -Property Partition | Format-Table Filesystem, UsedPct, UsedGB, TotalGB, HardDisk, Partition
    $thresholdPercentage = 80

    foreach ($result in $storageResults) {
        if ($result.usedpct -gt $thresholdPercentage) {
            Write-Host The $result.Partition partition on Hard Disk $result.harddisk is low on disk space. 
            Please extend Hard Disk $result.harddisk or cleanup old log files. -ForegroundColor Red
            Write-Host SSH to the OS of the VCSA and run "'du -a /storage/log | sort -n -r | head -n 20'" to determine the directories to be cleaned up. -ForegroundColor Red
            Write-Host These are the commands to run to clean up the commonly filled directories. -ForegroundColor Red
            Write-Host For VCSA 6.5+ : -ForegroundColor Cyan
            Write-Host "rm /storage/log/vmware/lookupsvc/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/sso/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host For VCSA 7.0+ : -ForegroundColor Cyan
            Write-Host "rm /storage/log/vmware/lookupsvc/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/sso/tomcat/localhost_access*log" -ForegroundColor Yellow
            Write-Host "rm /storage/log/vmware/eam/web/localhost_access*log" -ForegroundColor Yellow
        }
    }

}