<#
.SYNOPSIS
    Brilliant collection of powershell scripts that I often use, combined into a single module for me to run through as needed
.DESCRIPTION
    
.PARAMETER LogFile
    
.NOTES
    Author:  Ryan Coates

#>




Function Get-MPSActiveDirectory{
<# 
            " Satnaam WaheGuru Ji"     
             
            Author  :  Aman Dhally 
            E-Mail  :  amandhally@gmail.com 
            website :  www.amandhally.net 
            twitter : https://twitter.com/#!/AmanDhally 
            facebook: http://www.facebook.com/groups/254997707860848/ 
            Linkedin: http://www.linkedin.com/profile/view?id=23651495 
 
            Date    : 05-Spet-2012 
            File    : Active_Directory_Information 
            Purpose : Getting Information about Active Directory 
             
            Version : 1 
 
             
 
 
#> 
 
 
# Html  
#### HTML Output Formatting ####### 
 
    $a = "<!--mce:0-->" 
 
#### path to Output Html File 
 
# Setting Variables 
# 
    $date = (Get-Date -Format d_MMMM_yyyy).toString() 
    $filePATH = "$env:userprofile\Desktop\" 
    $fileNAME = "AD_Info_" + $date + ".html" 
    $file = $filePATH + $fileNAME 
# 
# Active Directory Variables 
    $adFOREST = Get-ADForest 
    $adDOMAIN = Get-ADDomain 
 
    # Forest Variables 
    $adFORESTNAME = $adFOREST.Name 
    $adFORESTMODE = $adFOREST.ForestMode 
    $adFORESTDOMAIN = $adFOREST | select -ExpandProperty Domains 
    $adFORESTROOTDOMAIN = $adFOREST.RootDomain 
    $adFORESTSchemaMaster = $adFOREST.SchemaMaster 
    $adFORESTNamingMaster = $adFOREST.DomainNamingMaster 
    $adFORESTUPNSUFFIX = $adFOREST | select -ExpandProperty UPNSuffixes  
    $adFORESTSPNSUffix = $adFOREST | select -ExpandProperty SPNSuffixes 
    $adFORESTGlobalCatalog = $adFOREST | select -ExpandProperty GlobalCatalogs 
    $adFORESTSites = $adFOREST  |  select -ExpandProperty Sites 
     
 
    #Domain Vaiables 
    $adDomainName = $adDOMAIN.Name 
    $adDOMAINNetBiosName = $adDOMAIN.NetBIOSName 
    $adDOMAINDomainMode = $adDOMAIN.DomainMode 
    $adDOMAINParentDomain = $adDOMAIN.ParentDomain 
    $adDOMAINPDCEMu = $adDOMAIN.PDCEmulator 
    $adDOMAINRIDMaster = $adDOMAIN.RIDMaster 
    $adDOMAINInfra = $adDOMAIN.InfrastructureMaster 
    $adDOMAINChildDomain = $adDOMAIN | select -ExpandProperty ChildDomains 
    $adDOMAINReplica = $adDOMAIN | select -ExpandProperty ReplicaDirectoryServers 
    $adDOMAINReadOnlyReplica = $adDOMAIN | select -ExpandProperty ReadOnlyReplicaDirectoryServers 
     
     
 
# If file exists 
# Test if file exists.If exist we are delting the file and then creating a new one 
# and if there are no file exists then we are going to create a new one  
 
    if (Test-Path "$env:userprofile\Desktop\$filename" ) {  
        "`n" 
        Write-Warning "file already exists, i am deleting it." 
        Remove-Item "$env:userprofile\Desktop\$filename" -Verbose -Force 
        "`n" 
        Write-Host "Creating a New file Named as $fileNAME" -ForegroundColor 'Green' 
        New-Item -Path $filePATH -Name $fileNAME -Type file | Out-Null 
        }  
    else { 
        "`n" 
        Write-Host "Creating a New file Named as $fileNAME" -ForegroundColor 'Green' 
        New-Item -Path $filePATH -Name $fileNAME -Type file | Out-Null 
        "`n" 
        } 
### 
 
# set Title of the HTML Output 
 
    ConvertTo-Html  -Head $a  -Title "ACtive Directory Information" -Body "<h1> Active Directory Information for :  $adFORESTNAME </h1>" > $file 
 
    ConvertTo-Html  -Head $a -Body "<h2> Active Directory Forest Information. </h2>"  >> $file  
 
    ConvertTo-Html -Body "<table><tr><td> Forest Name: </td><td><b> $adFORESTNAME </b></td></tr> ` 
                      <tr><td> Forest Mode: </td><td><b> $adFORESTMODE </b></td></tr> ` 
                      <tr><td> Forest Domains: </td><td><b> $adFORESTDOMAIN </b></td></tr> ` 
                      <tr><td> Root Domain : </td><td><b> $adFORESTROOTDOMAIN </b></td></tr> `     
                      <tr><td> Domain Naming Master: </td><td><b> $adFORESTNamingMaster </b></td></tr> `     
                      <tr><td> Schema Master: </td><td><b> $adFORESTSchemaMaster </b></td></tr> `     
                       <tr><td> Domain SPNSuffixes : </td><td><b> $adFORESTSPNSUffix </b></td></tr> ` 
                      <tr><td> Domain UPNSuffixes : </td><td><b> $adFORESTUPNSUFFI </b></td></tr> `     
                      <tr><td> Global Catalog Servers : </td><td><b> $adFORESTGlobalCatalog </b></td></tr> ` 
                      <tr><td> Forest Domain Sites : </td><td><b> $adFORESTSites </b></td></tr></table>" >> $file  
 
    ConvertTo-Html  -Head $a -Body "<h2> Active Directory Domain Information. </h2>"  >> $file                          
         
    ConvertTo-Html -Body "<table><tr><td> Domain Name: </td><td><b> $adDomainName </b></td></tr> ` 
                      <tr><td> Domain NetBios Name: </td><td><b> $adDOMAINNetBiosName </b></td></tr> ` 
                      <tr><td> Domain Mode: </td><td><b> $adDOMAINDomainMode </b></td></tr> ` 
                      <tr><td> Parent Domain : </td><td><b> $adDOMAINParentDomain </b></td></tr> `     
                      <tr><td> Domain PDC Emulator : </td><td><b> $adDOMAINPDCEMu </b></td></tr> `     
                      <tr><td> Domain RID Master: </td><td><b> $adDOMAINRIDMaster </b></td></tr> `     
                       <tr><td> Domain InfraStructure Master : </td><td><b> $adDOMAINInfra </b></td></tr> ` 
                      <tr><td> Child Domains : </td><td><b> $adDOMAINChildDomain </b></td></tr> `     
                      <tr><td> Replicated Servers : </td><td><b> $adDOMAINReplica</b></td></tr> ` 
                      <tr><td> Read Only Replicated Server : </td><td><b> $adDOMAINReadOnlyReplica </b></td></tr></table>" >> $file  
 
    $Report = "The Report is generated On  $(get-date) by $((Get-Item env:\username).Value) on computer $((Get-Item env:\Computername).Value)" 
    $Report  >> $file  
 
     
    Invoke-Expression $file 
 
#### end of the script ###
}
Function Get-MPSActiveDirectorySchema{
Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion
}
Function Get-MPSActiveDirectoryReplication {
#Variable 
$report_path = "\\server\share" 
$date = Get-Date -Format "yyyy-MM-dd" 
$array = @() 
 
#Powershell Function to delete files older than a certain age 
$intFileAge = 8  #age of files in days 
$strFilePath = $report_path #path to clean up 
  
#create filter to exclude folders and files newer than specified age 
Filter Select-FileAge { 
      param($days) 
      If ($_.PSisContainer) {} 
              # Exclude folders from result set 
      ElseIf ($_.LastWriteTime -lt (Get-Date).AddDays($days * -1)) 
            {$_} 
} 
get-Childitem -recurse $strFilePath | Select-FileAge $intFileAge 'CreationTime' |Remove-Item 
 
Function send_mail([string]$message,[string]$subject) { 
    $emailFrom = "sender@mail.com" 
    $emailTo = "to@mail.com" 
    $emailCC = "cc@mail.com" 
    $smtpServer = "smtp.mail.com" 
    Send-MailMessage -SmtpServer $smtpServer -To $emailTo -Cc $emailCC -From $emailFrom -Subject $subject -Body $message -BodyAsHtml 
} 
 
$myForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest() 
$dclist = $myforest.Sites | % { $_.Servers } 
 
$html_head = "<style type='text/css'> 
table {font-family:verdana,arial,sans-serif;font-size:12px;color:#333333;border-width: 1px;border-color: #729ea5;border-collapse: collapse;} 
th {font-family:verdana,arial,sans-serif;font-size:12px;background-color:#acc8cc;border-width: 1px;padding: 8px;border-style: solid;border-color: #729ea5;text-align:left;} 
tr {font-family:verdana,arial,sans-serif;background-color:#d4e3e5;} 
td {font-family:verdana,arial,sans-serif;font-size:12px;border-width: 1px;padding: 8px;border-style: solid;border-color: #729ea5;} 
</style>" 
 
foreach ($dcname in $dclist){ 
    $source_dc_fqdn = ($dcname.Name).tolower() 
    $ad_partition_list = repadmin /showrepl $source_dc_fqdn | select-string "dc=" 
    foreach ($ad_partition in $ad_partition_list) { 
        [Array]$NewArray=$NULL 
        $result = repadmin /showrepl $source_dc_fqdn $ad_partition 
        $result = $result | where { ([string]::IsNullOrEmpty(($result[$_]))) } 
        $index_array_dst = 0..($result.Count - 1) | Where { $result[$_] -like "*via RPC" } 
        foreach ($index in $index_array_dst){ 
            $dst_dc = ($result[$index]).trim() 
            $next_index = [array]::IndexOf($index_array_dst,$index) + 1 
            $next_index_msg = $index_array_dst[$next_index] 
            $msg = "" 
            if ($index -lt $index_array_dst[-1]){ 
                $last_index = $index_array_dst[$next_index] 
            } 
            else { 
                $last_index = $result.Count 
            } 
            
            for ($i=$index+1;$i -lt $last_index; $i++){ 
                if (($msg -eq "") -and ($result[$i])) { 
                    $msg += ($result[$i]).trim() 
                } 
                else { 
                    $msg += " / " + ($result[$i]).trim() 
                } 
            } 
            $Properties = @{source_dc=$source_dc_fqdn;NC=$ad_partition;destination_dc=$dst_dc;repl_status=$msg} 
            $Newobject = New-Object PSObject -Property $Properties 
            $array +=$newobject 
        } 
    } 
} 
 
$status_repl_ko = "<br><br><font face='Calibri' color='black'><i><b>Active Directory Replication Problem :</b></i><br>" 
$status_repl_ok = "<br><br><font face='Calibri' color='black'><i><b>Active Directory Replication OK :</b></i><br>" 
$subject = "Active Directory Replication status : "+$date 
$message = "<br><br><font face='Calibri' color='black'><i>The full Active Directory Replication report is available <a href=" + $report_path + "\ad_repl_status_$date.html>here</a></i><br>" 
$message += $status_repl_ko 
 
if ($array | where {$_.repl_status -notlike "*successful*"}){ 
    $message += $array | where {$_.repl_status -notlike "*successful*"} | select source_dc,nc,destination_dc,repl_status |ConvertTo-Html -Head $html_head -Property source_dc,nc,destination_dc,repl_status 
    send_mail $message $subject 
} 
else { 
    $message += "<table style='color:gray;font-family:verdana,arial,sans-serif;font-size:11px;'>No problem detected</table>" 
} 
 
$message += $status_repl_ok 
$message += $array | where {$_.repl_status -like "*successful*"} | select source_dc,nc,destination_dc,repl_status |ConvertTo-Html -Head $html_head -Property source_dc,nc,destination_dc,repl_status 
$message | Out-File "$report_path\ad_repl_status_$date.html"
}
Function Get-MPSOutlookConn2007 {
    Get-MailboxServer | Get-LogonStatistics | Select UserName,ClientVersion,LastAccessTime,ServerName
}
Function Get-MPSOutlookConn2010 {
<#
.SYNOPSIS
    Identifies and reports which Outlook client versions are being used to access Exchange.
.DESCRIPTION
    Get-MrRCAProtocolLog is an advanced PowerShell function that parses Exchange Server RPC
    logs to determine what Outlook client versions are being used to access the Exchange Server.
.PARAMETER LogFile
    The path to the Exchange RPC log files.
.EXAMPLE
     Get-MrRCAProtocolLog -LogFile 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\RPC Client Access\RCA_20140831-1.LOG'
.EXAMPLE
     Get-ChildItem -Path '\\servername\c$\Program Files\Microsoft\Exchange Server\V15\Logging\RPC Client Access\*.log' |
     Get-MrRCAProtocolLog |
     Out-GridView -Title 'Outlook Client Versions'
.INPUTS
    String
.OUTPUTS
    PSCustomObject
.NOTES
    Author:  Mike F Robbins
    Website: http://mikefrobbins.com
    Twitter: @mikefrobbins
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
                   ValueFromPipeline)]
        [ValidateScript({
            Test-Path -Path $_ -PathType Leaf -Include '*.log'
        })]
        [string[]]$LogFile
    )
    PROCESS {
        foreach ($file in $LogFile) {
            $Headers = (Get-Content -Path $file -TotalCount 5 | Where-Object {$_ -like '#Fields*'}) -replace '#Fields: ' -split ','
            Import-Csv -Header $Headers -Path $file |
            Where-Object operation -eq 'Connect' |
            Select-Object -Unique -Property @{label='User';expression={$_.'client-name' -replace '^.*cn='}},
                                            @{label='DN';expression={$_.'client-name'}},
                                            client-software,
                                            @{label='Version';expression={$_.'client-software-version'}},
                                            client-mode,
                                            client-ip,
                                            protocol
        }
    }
}
Function Get-MPSExchangeEnvironmentReport {
<# 
    .SYNOPSIS 
    Creates a HTML Report describing the Exchange environment  
    
       Steve Goodman 
     
    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 
     
    Version 1.6.1 September 2015 
     
    .DESCRIPTION 
     
    This script creates a HTML report showing the following information about an Exchange  
    2016, 2013, 2010 and to a lesser extent, 2007 and 2003, environment.  
     
    The following is shown: 
     
    * Report Generation Time 
    * Total Servers per Exchange Version (2003 > 2010 or 2007 > 2016) 
    * Total Mailboxes per Exchange Version, Office 365 and Organisation 
    * Total Roles in the environment 
         
    Then, per site: 
    * Total Mailboxes per site 
    * Internal, External and CAS Array Hostnames 
    * Exchange Servers with: 
        o Exchange Server Version 
        o Service Pack 
        o Update Rollup and rollup version 
        o Roles installed on server and mailbox counts 
        o OS Version and Service Pack 
         
    Then, per Database availability group (Exchange 2010/2013/2016): 
    * Total members per DAG 
    * Member list 
    * Databases, detailing: 
        o Mailbox Count and Average Size 
        o Archive Mailbox Count and Average Size (Only shown if DAG includes Archive Mailboxes) 
        o Database Size and whitespace 
        o Database and log disk free 
        o Last Full Backup (Only shown if one or more DAG database has been backed up) 
        o Circular Logging Enabled (Only shown if one or more DAG database has Circular Logging enabled) 
        o Mailbox server hosting active copy 
        o List of mailbox servers hosting copies and number of copies 
         
    Finally, per Database (Non DAG DBs/Exchange 2007/Exchange 2003) 
    * Databases, detailing: 
        o Storage Group (if applicable) and DB name 
        o Server hosting database 
        o Mailbox Count and Average Size 
        o Archive Mailbox Count and Average Size (Only shown if DAG includes Archive Mailboxes) 
        o Database Size and whitespace 
        o Database and log disk free 
        o Last Full Backup (Only shown if one or more DAG database has been backed up) 
        o Circular Logging Enabled (Only shown if one or more DAG database has Circular Logging enabled) 
         
    This does not detail public folder infrastructure, or examine Exchange 2007/2003 CCR/SCC clusters 
    (although it attempts to detect Clustered Exchange 2007/2003 servers, signified by ClusMBX). 
     
    IMPORTANT NOTE: The script requires WMI and Remote Registry access to Exchange servers from the server  
    it is run from to determine OS version, Update Rollup, Exchange 2007/2003 cluster and DB size information. 
     
    .PARAMETER HTMLReport 
    Filename to write HTML Report to 
     
    .PARAMETER SendMail 
    Send Mail after completion. Set to $True to enable. If enabled, -MailFrom, -MailTo, -MailServer are mandatory 
     
    .PARAMETER MailFrom 
    Email address to send from. Passed directly to Send-MailMessage as -From 
     
    .PARAMETER MailTo 
    Email address to send to. Passed directly to Send-MailMessage as -To 
     
    .PARAMETER MailServer 
    SMTP Mail server to attempt to send through. Passed directly to Send-MailMessage as -SmtpServer 
     
    .PARAMETER ScheduleAs 
    Attempt to schedule the command just executed for 10PM nightly. Specify the username here, schtasks (under the hood) will ask for a password later. 
     
    .PARAMETER ViewEntireForest 
    By default, true. Set the option in Exchange 2007 or 2010 to view all Exchange servers and recipients in the forest. 
    
    .PARAMETER ServerFilter 
    Use a text based string to filter Exchange Servers by, e.g. NL-* -  Note the use of the wildcard (*) character to allow for multiple matches. 
     
    .EXAMPLE 
    Generate the HTML report  
    .\Get-ExchangeEnvironmentReport.ps1 -HTMLReport .\report.html 
     
    #> 
param( 
    [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$false,HelpMessage='Filename to write HTML report to')][string]$HTMLReport, 
    [parameter(Position=1,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Send Mail ($True/$False)')][bool]$SendMail=$false, 
    [parameter(Position=2,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Mail From')][string]$MailFrom, 
    [parameter(Position=3,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Mail To')]$MailTo, 
    [parameter(Position=4,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Mail Server')][string]$MailServer, 
    [parameter(Position=4,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Schedule as user')][string]$ScheduleAs, 
    [parameter(Position=5,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Change view to entire forest')][bool]$ViewEntireForest=$true, 
    [parameter(Position=5,Mandatory=$false,ValueFromPipeline=$false,HelpMessage='Server Name Filter (eg NL-*)')][string]$ServerFilter="*" 
    ) 
 
# Sub-Function to Get Database Information. Shorter than expected.. 
function _GetDAG 
{ 
    param($DAG) 
    @{Name            = $DAG.Name.ToUpper() 
      MemberCount    = $DAG.Servers.Count 
      Members        = [array]($DAG.Servers | % { $_.Name }) 
      Databases        = @() 
      } 
} 
 
 
# Sub-Function to Get Database Information 
function _GetDB 
{ 
    param($Database,$ExchangeEnvironment,$Mailboxes,$ArchiveMailboxes,$E2010) 
     
    # Circular Logging, Last Full Backup 
    if ($Database.CircularLoggingEnabled) { $CircularLoggingEnabled="Yes" } else { $CircularLoggingEnabled = "No" } 
    if ($Database.LastFullBackup) { $LastFullBackup=$Database.LastFullBackup.ToString() } else { $LastFullBackup = "Not Available" } 
     
    # Mailbox Average Sizes 
    $MailboxStatistics = [array]($ExchangeEnvironment.Servers[$Database.Server.Name].MailboxStatistics | Where {$_.Database -eq $Database.Identity}) 
    if ($MailboxStatistics) 
    { 
        [long]$MailboxItemSizeB = 0 
        $MailboxStatistics | %{ $MailboxItemSizeB+=$_.TotalItemSizeB } 
        [long]$MailboxAverageSize = $MailboxItemSizeB / $MailboxStatistics.Count 
    } else { 
        $MailboxAverageSize = 0 
    } 
     
    # Free Disk Space Percentage 
    if ($ExchangeEnvironment.Servers[$Database.Server.Name].Disks) 
    { 
        foreach ($Disk in $ExchangeEnvironment.Servers[$Database.Server.Name].Disks) 
        { 
            if ($Database.EdbFilePath.PathName -like "$($Disk.Name)*") 
            { 
                $FreeDatabaseDiskSpace = $Disk.FreeSpace / $Disk.Capacity * 100 
            } 
            if ($Database.ExchangeVersion.ExchangeBuild.Major -ge 14) 
            { 
                if ($Database.LogFolderPath.PathName -like "$($Disk.Name)*") 
                { 
                    $FreeLogDiskSpace = $Disk.FreeSpace / $Disk.Capacity * 100 
                } 
            } else { 
                $StorageGroupDN = $Database.DistinguishedName.Replace("CN=$($Database.Name),","") 
                $Adsi=[adsi]"LDAP://$($Database.OriginatingServer)/$($StorageGroupDN)" 
                if ($Adsi.msExchESEParamLogFilePath -like "$($Disk.Name)*") 
                { 
                    $FreeLogDiskSpace = $Disk.FreeSpace / $Disk.Capacity * 100 
                } 
            } 
        } 
    } else { 
        $FreeLogDiskSpace=$null 
        $FreeDatabaseDiskSpace=$null 
    } 
     
    if ($Database.ExchangeVersion.ExchangeBuild.Major -ge 14 -and $E2010) 
    { 
        # Exchange 2010 Database Only 
        $CopyCount = [int]$Database.Servers.Count 
        if ($Database.MasterServerOrAvailabilityGroup.Name -ne $Database.Server.Name) 
        { 
            $Copies = [array]($Database.Servers | % { $_.Name }) 
        } else { 
            $Copies = @() 
        } 
        # Archive Info 
        $ArchiveMailboxCount = [int]([array]($ArchiveMailboxes | Where {$_.ArchiveDatabase -eq $Database.Name})).Count 
        $ArchiveStatistics = [array]($ArchiveMailboxes | Where {$_.ArchiveDatabase -eq $Database.Name} | Get-MailboxStatistics -Archive ) 
        if ($ArchiveStatistics) 
        { 
            [long]$ArchiveItemSizeB = 0 
            $ArchiveStatistics | %{ $ArchiveItemSizeB+=$_.TotalItemSize.Value.ToBytes() } 
            [long]$ArchiveAverageSize = $ArchiveItemSizeB / $ArchiveStatistics.Count 
        } else { 
            $ArchiveAverageSize = 0 
        } 
        # DB Size / Whitespace Info 
        [long]$Size = $Database.DatabaseSize.ToBytes() 
        [long]$Whitespace = $Database.AvailableNewMailboxSpace.ToBytes() 
        $StorageGroup = $null 
         
    } else { 
        $ArchiveMailboxCount = 0 
        $CopyCount = 0 
        $Copies = @() 
        # 2003 & 2007, Use WMI (Based on code by Gary Siepser, http://bit.ly/kWWMb3) 
        $Size = [long](get-wmiobject cim_datafile -computername $Database.Server.Name -filter ('name=''' + $Database.edbfilepath.pathname.replace("\","\\") + '''')).filesize 
        if (!$Size) 
        { 
            Write-Warning "Cannot detect database size via WMI for $($Database.Server.Name)" 
            [long]$Size = 0 
            [long]$Whitespace = 0 
        } else { 
            [long]$MailboxDeletedItemSizeB = 0 
            if ($MailboxStatistics) 
            { 
                $MailboxStatistics | %{ $MailboxDeletedItemSizeB+=$_.TotalDeletedItemSizeB } 
            } 
            $Whitespace = $Size - $MailboxItemSizeB - $MailboxDeletedItemSizeB 
            if ($Whitespace -lt 0) { $Whitespace = 0 } 
        } 
        $StorageGroup =$Database.DistinguishedName.Split(",")[1].Replace("CN=","") 
    } 
     
    @{Name                        = $Database.Name 
      StorageGroup                = $StorageGroup 
      ActiveOwner                = $Database.Server.Name.ToUpper() 
      MailboxCount                = [long]([array]($Mailboxes | Where {$_.Database -eq $Database.Identity})).Count 
      MailboxAverageSize        = $MailboxAverageSize 
      ArchiveMailboxCount        = $ArchiveMailboxCount 
      ArchiveAverageSize        = $ArchiveAverageSize 
      CircularLoggingEnabled     = $CircularLoggingEnabled 
      LastFullBackup            = $LastFullBackup 
      Size                        = $Size 
      Whitespace                = $Whitespace 
      Copies                    = $Copies 
      CopyCount                    = $CopyCount 
      FreeLogDiskSpace            = $FreeLogDiskSpace 
      FreeDatabaseDiskSpace        = $FreeDatabaseDiskSpace 
      } 
} 
 
 
# Sub-Function to get mailbox count per server. 
# New in 1.5.2 
function _GetExSvrMailboxCount 
{ 
    param($Mailboxes,$ExchangeServer,$Databases) 
    # The following *should* work, but it doesn't. Apparently, ServerName is not always returned correctly which may be the cause of 
    # reports of counts being incorrect 
    #([array]($Mailboxes | Where {$_.ServerName -eq $ExchangeServer.Name})).Count 
     
    # ..So as a workaround, I'm going to check what databases are assigned to each server and then get the mailbox counts on a per- 
    # database basis and return the resulting total. As we already have this information resident in memory it should be cheap, just 
    # not as quick. 
    $MailboxCount = 0 
    foreach ($Database in [array]($Databases | Where {$_.Server -eq $ExchangeServer.Name})) 
    { 
        $MailboxCount+=([array]($Mailboxes | Where {$_.Database -eq $Database.Identity})).Count 
    } 
    $MailboxCount 
     
} 
 
# Sub-Function to Get Exchange Server information 
function _GetExSvr 
{ 
    param($E2010,$ExchangeServer,$Mailboxes,$Databases,$Hybrids) 
     
    # Set Basic Variables 
    $MailboxCount = 0 
    $RollupLevel = 0 
    $RollupVersion = "" 
    $ExtNames = @() 
    $IntNames = @() 
    $CASArrayName = "" 
     
    # Get WMI Information 
    $tWMI = Get-WmiObject Win32_OperatingSystem -ComputerName $ExchangeServer.Name -ErrorAction SilentlyContinue 
    if ($tWMI) 
    { 
        $OSVersion = $tWMI.Caption.Replace("(R)","").Replace("Microsoft ","").Replace("Enterprise","Ent").Replace("Standard","Std").Replace(" Edition","") 
        $OSServicePack = $tWMI.CSDVersion 
        $RealName = $tWMI.CSName.ToUpper() 
    } else { 
        Write-Warning "Cannot detect OS information via WMI for $($ExchangeServer.Name)" 
        $OSVersion = "N/A" 
        $OSServicePack = "N/A" 
        $RealName = $ExchangeServer.Name.ToUpper() 
    } 
    $tWMI=Get-WmiObject -query "Select * from Win32_Volume" -ComputerName $ExchangeServer.Name -ErrorAction SilentlyContinue 
    if ($tWMI) 
    { 
        $Disks=$tWMI | Select Name,Capacity,FreeSpace | Sort-Object -Property Name 
    } else { 
        Write-Warning "Cannot detect OS information via WMI for $($ExchangeServer.Name)" 
        $Disks=$null 
    } 
     
    # Get Exchange Version 
    if ($ExchangeServer.AdminDisplayVersion.Major -eq 6) 
    { 
        $ExchangeMajorVersion = "$($ExchangeServer.AdminDisplayVersion.Major).$($ExchangeServer.AdminDisplayVersion.Minor)" 
        $ExchangeSPLevel = $ExchangeServer.AdminDisplayVersion.FilePatchLevelDescription.Replace("Service Pack ","") 
    } elseif ($ExchangeServer.AdminDisplayVersion.Major -eq 15 -and $ExchangeServer.AdminDisplayVersion.Minor -eq 1) { 
        $ExchangeMajorVersion = [double]"$($ExchangeServer.AdminDisplayVersion.Major).$($ExchangeServer.AdminDisplayVersion.Minor)" 
        $ExchangeSPLevel = 0 
    } else { 
        $ExchangeMajorVersion = $ExchangeServer.AdminDisplayVersion.Major 
        $ExchangeSPLevel = $ExchangeServer.AdminDisplayVersion.Minor 
    } 
    # Exchange 2007+ 
    if ($ExchangeMajorVersion -ge 8) 
    { 
        # Get Roles 
        $MailboxStatistics=$null 
        [array]$Roles = $ExchangeServer.ServerRole.ToString().Replace(" ","").Split(","); 
        # Add Hybrid "Role" for report 
        if ($Hybrids -contains $ExchangeServer.Name) 
        { 
            $Roles+="Hybrid" 
        } 
        if ($Roles -contains "Mailbox") 
        { 
            $MailboxCount = _GetExSvrMailboxCount -Mailboxes $Mailboxes -ExchangeServer $ExchangeServer -Databases $Databases 
            if ($ExchangeServer.Name.ToUpper() -ne $RealName) 
            { 
                $Roles = [array]($Roles | Where {$_ -ne "Mailbox"}) 
                $Roles += "ClusteredMailbox" 
            } 
            # Get Mailbox Statistics the normal way, return in a consitent format 
            $MailboxStatistics = Get-MailboxStatistics -Server $ExchangeServer | Select DisplayName,@{Name="TotalItemSizeB";Expression={$_.TotalItemSize.Value.ToBytes()}},@{Name="TotalDeletedItemSizeB";Expression={$_.TotalDeletedItemSize.Value.ToBytes()}},Database 
        } 
        # Get HTTPS Names (Exchange 2010 only due to time taken to retrieve data) 
        if ($Roles -contains "ClientAccess" -and $E2010) 
        { 
             
            Get-OWAVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            Get-WebServicesVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            Get-OABVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            Get-ActiveSyncVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            if (Get-Command Get-MAPIVirtualDirectory -ErrorAction SilentlyContinue) 
            { 
                Get-MAPIVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            } 
            if (Get-Command Get-ClientAccessService -ErrorAction SilentlyContinue) 
            { 
                $IntNames+=(Get-ClientAccessService -Identity $ExchangeServer.Name).AutoDiscoverServiceInternalURI.Host 
            } else { 
                $IntNames+=(Get-ClientAccessServer -Identity $ExchangeServer.Name).AutoDiscoverServiceInternalURI.Host 
            } 
             
            if ($ExchangeMajorVersion -ge 14) 
            { 
                Get-ECPVirtualDirectory -Server $ExchangeServer -ADPropertiesOnly | %{ $ExtNames+=$_.ExternalURL.Host; $IntNames+=$_.InternalURL.Host; } 
            } 
            $IntNames = $IntNames|Sort-Object -Unique 
            $ExtNames = $ExtNames|Sort-Object -Unique 
            $CASArray = Get-ClientAccessArray -Site $ExchangeServer.Site.Name 
            if ($CASArray) 
            { 
                $CASArrayName = $CASArray.Fqdn 
            } 
        } 
 
        # Rollup Level / Versions (Thanks to Bhargav Shukla http://bit.ly/msxGIJ) 
        if ($ExchangeMajorVersion -ge 14) { 
            $RegKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\AE1D439464EB1B8488741FFA028E291C\\Patches" 
        } else { 
            $RegKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\461C2B4266EDEF444B864AD6D9E5B613\\Patches" 
        } 
        $RemoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeServer.Name); 
        if ($RemoteRegistry) 
        { 
            $RUKeys = $RemoteRegistry.OpenSubKey($RegKey).GetSubKeyNames() | ForEach {"$RegKey\\$_"} 
            if ($RUKeys) 
            { 
                [array]($RUKeys | %{$RemoteRegistry.OpenSubKey($_).getvalue("DisplayName")}) | %{ 
                    if ($_ -like "Update Rollup *") 
                    { 
                        $tRU = $_.Split(" ")[2] 
                        if ($tRU -like "*-*") { $tRUV=$tRU.Split("-")[1]; $tRU=$tRU.Split("-")[0] } else { $tRUV="" } 
                        if ([int]$tRU -ge [int]$RollupLevel) { $RollupLevel=$tRU; $RollupVersion=$tRUV } 
                    } 
                } 
            } 
        } else { 
            Write-Warning "Cannot detect Rollup Version via Remote Registry for $($ExchangeServer.Name)" 
        } 
        # Exchange 2013 CU or SP Level 
        if ($ExchangeMajorVersion -ge 15) 
        { 
            $RegKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Exchange v15" 
            $RemoteRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ExchangeServer.Name); 
            if ($RemoteRegistry) 
            { 
                $ExchangeSPLevel = $RemoteRegistry.OpenSubKey($RegKey).getvalue("DisplayName") 
                if ($ExchangeSPLevel -like "*Service Pack*" -or $ExchangeSPLevel -like "*Cumulative Update*") 
                { 
                    $ExchangeSPLevel = $ExchangeSPLevel.Replace("Microsoft Exchange Server 2013 ",""); 
                    $ExchangeSPLevel = $ExchangeSPLevel.Replace("Microsoft Exchange Server 2016 ",""); 
                    $ExchangeSPLevel = $ExchangeSPLevel.Replace("Service Pack ","SP"); 
                    $ExchangeSPLevel = $ExchangeSPLevel.Replace("Cumulative Update ","CU");  
                } else { 
                    $ExchangeSPLevel = 0; 
                } 
            } else { 
                Write-Warning "Cannot detect CU/SP via Remote Registry for $($ExchangeServer.Name)" 
            } 
        } 
         
    } 
    # Exchange 2003 
    if ($ExchangeMajorVersion -eq 6.5) 
    { 
        # Mailbox Count 
        $MailboxCount = _GetExSvrMailboxCount -Mailboxes $Mailboxes -ExchangeServer $ExchangeServer -Databases $Databases 
        # Get Role via WMI 
        $tWMI = Get-WMIObject Exchange_Server -Namespace "root\microsoftexchangev2" -Computername $ExchangeServer.Name -Filter "Name='$($ExchangeServer.Name)'" 
        if ($tWMI) 
        { 
            if ($tWMI.IsFrontEndServer) { $Roles=@("FE") } else { $Roles=@("BE") } 
        } else { 
            Write-Warning "Cannot detect Front End/Back End Server information via WMI for $($ExchangeServer.Name)" 
            $Roles+="Unknown" 
        } 
        # Get Mailbox Statistics using WMI, return in a consistent format 
        $tWMI = Get-WMIObject -class Exchange_Mailbox -Namespace ROOT\MicrosoftExchangev2 -ComputerName $ExchangeServer.Name -Filter ("ServerName='$($ExchangeServer.Name)'") 
        if ($tWMI) 
        { 
            $MailboxStatistics = $tWMI | Select @{Name="DisplayName";Expression={$_.MailboxDisplayName}},@{Name="TotalItemSizeB";Expression={$_.Size}},@{Name="TotalDeletedItemSizeB";Expression={$_.DeletedMessageSizeExtended }},@{Name="Database";Expression={((get-mailboxdatabase -Identity "$($_.ServerName)\$($_.StorageGroupName)\$($_.StoreName)").identity)}} 
        } else { 
            Write-Warning "Cannot retrieve Mailbox Statistics via WMI for $($ExchangeServer.Name)" 
            $MailboxStatistics = $null 
        } 
    }     
    # Exchange 2000 
    if ($ExchangeMajorVersion -eq "6.0") 
    { 
        # Mailbox Count 
        $MailboxCount = _GetExSvrMailboxCount -Mailboxes $Mailboxes -ExchangeServer $ExchangeServer -Databases $Databases 
        # Get Role via ADSI 
        $tADSI=[ADSI]"LDAP://$($ExchangeServer.OriginatingServer)/$($ExchangeServer.DistinguishedName)" 
        if ($tADSI) 
        { 
            if ($tADSI.ServerRole -eq 1) { $Roles=@("FE") } else { $Roles=@("BE") } 
        } else { 
            Write-Warning "Cannot detect Front End/Back End Server information via ADSI for $($ExchangeServer.Name)" 
            $Roles+="Unknown" 
        } 
        $MailboxStatistics = $null 
    } 
     
    # Return Hashtable 
    @{Name                    = $ExchangeServer.Name.ToUpper() 
     RealName                = $RealName 
     ExchangeMajorVersion     = $ExchangeMajorVersion 
     ExchangeSPLevel        = $ExchangeSPLevel 
     Edition                = $ExchangeServer.Edition 
     Mailboxes                = $MailboxCount 
     OSVersion                = $OSVersion; 
     OSServicePack            = $OSServicePack 
     Roles                    = $Roles 
     RollupLevel            = $RollupLevel 
     RollupVersion            = $RollupVersion 
     Site                    = $ExchangeServer.Site.Name 
     MailboxStatistics        = $MailboxStatistics 
     Disks                    = $Disks 
     IntNames                = $IntNames 
     ExtNames                = $ExtNames 
     CASArrayName            = $CASArrayName 
    }     
} 
 
# Sub Function to Get Totals by Version 
function _TotalsByVersion 
{ 
    param($ExchangeEnvironment) 
    $TotalMailboxesByVersion=@{} 
    if ($ExchangeEnvironment.Sites) 
    { 
        foreach ($Site in $ExchangeEnvironment.Sites.GetEnumerator()) 
        { 
            foreach ($Server in $Site.Value) 
            { 
                if (!$TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"]) 
                { 
                    $TotalMailboxesByVersion.Add("$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)",@{ServerCount=1;MailboxCount=$Server.Mailboxes}) 
                } else { 
                    $TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"].ServerCount++ 
                    $TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"].MailboxCount+=$Server.Mailboxes 
                } 
            } 
        } 
    } 
    if ($ExchangeEnvironment.Pre2007) 
    { 
        foreach ($FakeSite in $ExchangeEnvironment.Pre2007.GetEnumerator()) 
        { 
            foreach ($Server in $FakeSite.Value) 
            { 
                if (!$TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"]) 
                { 
                    $TotalMailboxesByVersion.Add("$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)",@{ServerCount=1;MailboxCount=$Server.Mailboxes}) 
                } else { 
                    $TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"].ServerCount++ 
                    $TotalMailboxesByVersion["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"].MailboxCount+=$Server.Mailboxes 
                } 
            } 
        } 
    } 
    $TotalMailboxesByVersion 
} 
 
# Sub Function to Get Totals by Role 
function _TotalsByRole 
{ 
    param($ExchangeEnvironment) 
    # Add Roles We Always Show 
    $TotalServersByRole=@{"ClientAccess"      = 0 
                          "HubTransport"      = 0 
                          "UnifiedMessaging" = 0 
                          "Mailbox"             = 0 
                          "Edge"              = 0 
                          } 
    if ($ExchangeEnvironment.Sites) 
    { 
        foreach ($Site in $ExchangeEnvironment.Sites.GetEnumerator()) 
        { 
            foreach ($Server in $Site.Value) 
            { 
                foreach ($Role in $Server.Roles) 
                { 
                    if ($TotalServersByRole[$Role] -eq $null) 
                    { 
                        $TotalServersByRole.Add($Role,1) 
                    } else { 
                        $TotalServersByRole[$Role]++ 
                    } 
                } 
            } 
        } 
    } 
    if ($ExchangeEnvironment.Pre2007["Pre 2007 Servers"]) 
    { 
         
        foreach ($Server in $ExchangeEnvironment.Pre2007["Pre 2007 Servers"]) 
        { 
             
            foreach ($Role in $Server.Roles) 
            { 
                if ($TotalServersByRole[$Role] -eq $null) 
                { 
                    $TotalServersByRole.Add($Role,1) 
                } else { 
                    $TotalServersByRole[$Role]++ 
                } 
            } 
        } 
    } 
    $TotalServersByRole 
} 
 
# Sub Function to return HTML Table for Sites/Pre 2007 
function _GetOverview 
{ 
    param($Servers,$ExchangeEnvironment,$ExRoleStrings,$Pre2007=$False) 
    if ($Pre2007) 
    { 
        $BGColHeader="#880099" 
        $BGColSubHeader="#8800CC" 
        $Prefix="" 
        $IntNamesText="" 
        $ExtNamesText="" 
        $CASArrayText="" 
    } else { 
        $BGColHeader="#000099" 
        $BGColSubHeader="#0000FF" 
        $Prefix="Site:" 
        $IntNamesText="" 
        $ExtNamesText="" 
        $CASArrayText="" 
        $IntNames=@() 
        $ExtNames=@() 
        $CASArrayName="" 
        foreach ($Server in $Servers.Value) 
        { 
            $IntNames+=$Server.IntNames 
            $ExtNames+=$Server.ExtNames 
            $CASArrayName=$Server.CASArrayName 
             
        } 
        $IntNames = $IntNames|Sort -Unique 
        $ExtNames = $ExtNames|Sort -Unique 
        $IntNames = [system.String]::Join(",",$IntNames) 
        $ExtNames = [system.String]::Join(",",$ExtNames) 
        if ($IntNames) 
        { 
            $IntNamesText="Internal Names: $($IntNames)" 
            $ExtNamesText="External Names: $($ExtNames)<br >" 
        } 
        if ($CASArrayName) 
        { 
            $CASArrayText="CAS Array: $($CASArrayName)" 
        } 
    } 
    $Output="<table border=""0"" cellpadding=""3"" width=""100%"" style=""font-size:8pt;font-family:Segoe UI,Arial,sans-serif""> 
    <col width=""20%""><col width=""20%""> 
    <colgroup width=""25%"">"; 
     
    $ExchangeEnvironment.TotalServersByRole.GetEnumerator()|Sort Name| %{$Output+="<col width=""3%"">"} 
    $Output+="</colgroup><col width=""20%""><col  width=""20%""> 
    <tr bgcolor=""$($BGColHeader)""><th><font color=""#ffffff"">$($Prefix) $($Servers.Key)</font></th> 
    <th colspan=""$(($ExchangeEnvironment.TotalServersByRole.Count)+2)"" align=""left""><font color=""#ffffff"">$($ExtNamesText)$($IntNamesText)</font></th> 
    <th align=""center""><font color=""#ffffff"">$($CASArrayText)</font></th></tr>" 
    $TotalMailboxes=0 
    $Servers.Value | %{$TotalMailboxes += $_.Mailboxes} 
    $Output+="<tr bgcolor=""$($BGColSubHeader)""><th><font color=""#ffffff"">Mailboxes: $($TotalMailboxes)</font></th><th>" 
    $Output+="<font color=""#ffffff"">Exchange Version</font></th>" 
    $ExchangeEnvironment.TotalServersByRole.GetEnumerator()|Sort Name| %{$Output+="<th><font color=""#ffffff"">$($ExRoleStrings[$_.Key].Short)</font></th>"} 
    $Output+="<th><font color=""#ffffff"">OS Version</font></th><th><font color=""#ffffff"">OS Service Pack</font></th></tr>" 
    $AlternateRow=0 
     
    foreach ($Server in $Servers.Value) 
    { 
        $Output+="<tr " 
        if ($AlternateRow) 
        { 
            $Output+=" style=""background-color:#dddddd""" 
            $AlternateRow=0 
        } else 
        { 
            $AlternateRow=1 
        } 
        $Output+="><td>$($Server.Name)" 
        if ($Server.RealName -ne $Server.Name) 
        { 
            $Output+=" ($($Server.RealName))" 
        } 
        $Output+="</td><td>$($ExVersionStrings["$($Server.ExchangeMajorVersion).$($Server.ExchangeSPLevel)"].Long)" 
        if ($Server.RollupLevel -gt 0) 
        { 
            $Output+=" UR$($Server.RollupLevel)" 
            if ($Server.RollupVersion) 
            { 
                $Output+=" $($Server.RollupVersion)" 
            } 
        } 
        $Output+="</td>" 
        $ExchangeEnvironment.TotalServersByRole.GetEnumerator()|Sort Name| %{  
            $Output+="<td" 
            if ($Server.Roles -contains $_.Key) 
            { 
                $Output+=" align=""center"" style=""background-color:#00FF00""" 
            } 
            $Output+=">" 
            if (($_.Key -eq "ClusteredMailbox" -or $_.Key -eq "Mailbox" -or $_.Key -eq "BE") -and $Server.Roles -contains $_.Key)  
            { 
                $Output+=$Server.Mailboxes 
            }  
        } 
                 
        $Output+="<td>$($Server.OSVersion)</td><td>$($Server.OSServicePack)</td></tr>";     
    } 
    $Output+="<tr></tr> 
    </table><br />" 
    $Output 
} 
 
# Sub Function to return HTML Table for Databases 
function _GetDBTable 
{ 
    param($Databases) 
    # Only Show Archive Mailbox Columns, Backup Columns and Circ Logging if at least one DB has an Archive mailbox, backed up or Cir Log enabled. 
    $ShowArchiveDBs=$False 
    $ShowLastFullBackup=$False 
    $ShowCircularLogging=$False 
    $ShowStorageGroups=$False 
    $ShowCopies=$False 
    $ShowFreeDatabaseSpace=$False 
    $ShowFreeLogDiskSpace=$False 
    foreach ($Database in $Databases) 
    { 
        if ($Database.ArchiveMailboxCount -gt 0)  
        { 
            $ShowArchiveDBs=$True 
        } 
        if ($Database.LastFullBackup -ne "Not Available")  
        { 
            $ShowLastFullBackup=$True 
        } 
        if ($Database.CircularLoggingEnabled -eq "Yes")  
        { 
            $ShowCircularLogging=$True 
        } 
        if ($Database.StorageGroup)  
        { 
            $ShowStorageGroups=$True 
        } 
        if ($Database.CopyCount -gt 0)  
        { 
            $ShowCopies=$True 
        } 
        if ($Database.FreeDatabaseDiskSpace -ne $null) 
        { 
            $ShowFreeDatabaseSpace=$true 
        } 
        if ($Database.FreeLogDiskSpace -ne $null) 
        { 
            $ShowFreeLogDiskSpace=$true 
        } 
    } 
     
     
    $Output="<table border=""0"" cellpadding=""3"" width=""100%"" style=""font-size:8pt;font-family:Segoe UI,Arial,sans-serif""> 
     
    <tr align=""center"" bgcolor=""#FFD700""> 
    <th>Server</th>" 
    if ($ShowStorageGroups) 
    { 
        $Output+="<th>Storage Group</th>" 
    } 
    $Output+="<th>Database Name</th> 
    <th>Mailboxes</th> 
    <th>Av. Mailbox Size</th>" 
    if ($ShowArchiveDBs) 
    { 
        $Output+="<th>Archive MBs</th><th>Av. Archive Size</th>" 
    } 
    $Output+="<th>DB Size</th><th>DB Whitespace</th>" 
    if ($ShowFreeDatabaseSpace) 
    { 
        $Output+="<th>Database Disk Free</th>" 
    } 
    if ($ShowFreeLogDiskSpace) 
    { 
        $Output+="<th>Log Disk Free</th>" 
    } 
    if ($ShowLastFullBackup) 
    { 
        $Output+="<th>Last Full Backup</th>" 
    } 
    if ($ShowCircularLogging) 
    { 
        $Output+="<th>Circular Logging</th>" 
    } 
    if ($ShowCopies) 
    { 
        $Output+="<th>Copies (n)</th>" 
    } 
     
    $Output+="</tr>" 
    $AlternateRow=0; 
    foreach ($Database in $Databases) 
    { 
        $Output+="<tr" 
        if ($AlternateRow) 
        { 
            $Output+=" style=""background-color:#dddddd""" 
            $AlternateRow=0 
        } else 
        { 
            $AlternateRow=1 
        } 
         
        $Output+="><td>$($Database.ActiveOwner)</td>" 
        if ($ShowStorageGroups) 
        { 
            $Output+="<td>$($Database.StorageGroup)</td>" 
        } 
        $Output+="<td>$($Database.Name)</td> 
        <td align=""center"">$($Database.MailboxCount)</td> 
        <td align=""center"">$("{0:N2}" -f ($Database.MailboxAverageSize/1MB)) MB</td>" 
        if ($ShowArchiveDBs) 
        { 
            $Output+="<td align=""center"">$($Database.ArchiveMailboxCount)</td>  
            <td align=""center"">$("{0:N2}" -f ($Database.ArchiveAverageSize/1MB)) MB</td>"; 
        } 
        $Output+="<td align=""center"">$("{0:N2}" -f ($Database.Size/1GB)) GB </td> 
        <td align=""center"">$("{0:N2}" -f ($Database.Whitespace/1GB)) GB</td>"; 
        if ($ShowFreeDatabaseSpace) 
        { 
            $Output+="<td align=""center"">$("{0:N1}" -f $Database.FreeDatabaseDiskSpace)%</td>" 
        } 
        if ($ShowFreeLogDiskSpace) 
        { 
            $Output+="<td align=""center"">$("{0:N1}" -f $Database.FreeLogDiskSpace)%</td>" 
        } 
        if ($ShowLastFullBackup) 
        { 
            $Output+="<td align=""center"">$($Database.LastFullBackup)</td>"; 
        } 
        if ($ShowCircularLogging) 
        { 
            $Output+="<td align=""center"">$($Database.CircularLoggingEnabled)</td>"; 
        } 
        if ($ShowCopies) 
        { 
            $Output+="<td>$($Database.Copies|%{$_}) ($($Database.CopyCount))</td>" 
        } 
        $Output+="</tr>"; 
    } 
    $Output+="</table><br />" 
     
    $Output 
} 
 
 
# Sub Function to neatly update progress 
function _UpProg1 
{ 
    param($PercentComplete,$Status,$Stage) 
    $TotalStages=5 
    Write-Progress -id 1 -activity "Get-ExchangeEnvironmentReport" -status $Status -percentComplete (($PercentComplete/$TotalStages)+(1/$TotalStages*$Stage*100)) 
} 
 
# 1. Initial Startup 
 
# 1.0 Check Powershell Version 
if ((Get-Host).Version.Major -eq 1) 
{ 
    throw "Powershell Version 1 not supported"; 
} 
 
# 1.1 Check Exchange Management Shell, attempt to load 
if (!(Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) 
{ 
    if (Test-Path "C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1") 
    { 
        . 'C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1' 
        Connect-ExchangeServer -auto 
    } elseif (Test-Path "C:\Program Files\Microsoft\Exchange Server\bin\Exchange.ps1") { 
        Add-PSSnapIn Microsoft.Exchange.Management.PowerShell.Admin 
        .'C:\Program Files\Microsoft\Exchange Server\bin\Exchange.ps1' 
    } else { 
        throw "Exchange Management Shell cannot be loaded" 
    } 
} 
 
# 1.2 Check if -SendMail parameter set and if so check -MailFrom, -MailTo and -MailServer are set 
if ($SendMail) 
{ 
    if (!$MailFrom -or !$MailTo -or !$MailServer) 
    { 
        throw "If -SendMail specified, you must also specify -MailFrom, -MailTo and -MailServer" 
    } 
} 
 
# 1.3 Check Exchange Management Shell Version 
if ((Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue)) 
{ 
    $E2010 = $false; 
    if (Get-ExchangeServer | Where {$_.AdminDisplayVersion.Major -gt 14}) 
    { 
        Write-Warning "Exchange 2010 or higher detected. You'll get better results if you run this script from the latest management shell" 
    } 
}else{ 
     
    $E2010 = $true 
    $localserver = get-exchangeserver $Env:computername 
    $localversion = $localserver.admindisplayversion.major 
    if ($localversion -eq 15) { $E2013 = $true } 
 
} 
 
# 1.4 Check view entire forest if set (by default, true) 
if ($E2010) 
{ 
    Set-ADServerSettings -ViewEntireForest:$ViewEntireForest 
} else { 
    $global:AdminSessionADSettings.ViewEntireForest = $ViewEntireForest 
} 
 
# 1.5 Initial Variables 
 
# 1.5.1 Hashtable to update with environment data 
$ExchangeEnvironment = @{Sites                    = @{} 
                         Pre2007                = @{} 
                         Servers                = @{} 
                         DAGs                    = @() 
                         NonDAGDatabases        = @() 
                        } 
# 1.5.7 Exchange Major Version String Mapping 
$ExMajorVersionStrings = @{"6.0" = @{Long="Exchange 2000";Short="E2000"} 
                              "6.5" = @{Long="Exchange 2003";Short="E2003"} 
                              "8"   = @{Long="Exchange 2007";Short="E2007"} 
                           "14"  = @{Long="Exchange 2010";Short="E2010"} 
                           "15"  = @{Long="Exchange 2013";Short="E2013"} 
                           "15.1"  = @{Long="Exchange 2016";Short="E2016"}} 
# 1.5.8 Exchange Service Pack String Mapping 
$ExSPLevelStrings = @{"0" = "RTM" 
                      "1" = "SP1" 
                      "2" = "SP2" 
                      "3" = "SP3" 
                      "4" = "SP4" 
                      "SP1" = "SP1" 
                      "SP2" = "SP2"} 
    # Add many CUs                
    for ($i = 1; $i -le 20; $i++) 
    { 
        $ExSPLevelStrings.Add("CU$($i)","CU$($i)"); 
    } 
# 1.5.9 Populate Full Mapping using above info 
$ExVersionStrings = @{} 
foreach ($Major in $ExMajorVersionStrings.GetEnumerator()) 
{ 
    foreach ($Minor in $ExSPLevelStrings.GetEnumerator()) 
    { 
        $ExVersionStrings.Add("$($Major.Key).$($Minor.Key)",@{Long="$($Major.Value.Long) $($Minor.Value)";Short="$($Major.Value.Short)$($Minor.Value)"}) 
    } 
} 
# 1.5.10 Exchange Role String Mapping 
$ExRoleStrings = @{"ClusteredMailbox" = @{Short="ClusMBX";Long="CCR/SCC Clustered Mailbox"} 
                   "Mailbox"          = @{Short="MBX";Long="Mailbox"} 
                   "ClientAccess"      = @{Short="CAS";Long="Client Access"} 
                   "HubTransport"      = @{Short="HUB";Long="Hub Transport"} 
                   "UnifiedMessaging" = @{Short="UM";Long="Unified Messaging"} 
                   "Edge"              = @{Short="EDGE";Long="Edge Transport"} 
                   "FE"              = @{Short="FE";Long="Front End"} 
                   "BE"              = @{Short="BE";Long="Back End"} 
                   "Hybrid"       = @{Short="HYB"; Long="Hybrid"} 
                   "Unknown"      = @{Short="Unknown";Long="Unknown"}} 
 
# 2 Get Relevant Exchange Information Up-Front 
 
# 2.1 Get Server, Exchange and Mailbox Information 
_UpProg1 1 "Getting Exchange Server List" 1 
$ExchangeServers = [array](Get-ExchangeServer $ServerFilter) 
if (!$ExchangeServers) 
{ 
    throw "No Exchange Servers matched by -ServerFilter ""$($ServerFilter)""" 
} 
$HybridServers=@() 
if (Get-Command Get-HybridConfiguration -ErrorAction SilentlyContinue) 
{ 
    $HybridConfig = Get-HybridConfiguration 
    $HybridConfig.ReceivingTransportServers|%{ $HybridServers+=$_.Name  } 
    $HybridConfig.SendingTransportServers|%{ $HybridServers+=$_.Name  } 
    $HybridServers =  $HybridServers | Sort-Object -Unique 
} 
 
_UpProg1 10 "Getting Mailboxes" 1 
$Mailboxes = [array](Get-Mailbox -ResultSize Unlimited) | Where {$_.Server -like $ServerFilter} 
if ($E2010) 
{  
    _UpProg1 60 "Getting Archive Mailboxes" 1 
    $ArchiveMailboxes = [array](Get-Mailbox -Archive -ResultSize Unlimited) | Where {$_.Server -like $ServerFilter} 
    _UpProg1 70 "Getting Remote Mailboxes" 1 
    $RemoteMailboxes = [array](Get-RemoteMailbox  -ResultSize Unlimited) 
    $ExchangeEnvironment.Add("RemoteMailboxes",$RemoteMailboxes.Count) 
    _UpProg1 90 "Getting Databases" 1 
    if ($E2013)  
    {     
        $Databases = [array](Get-MailboxDatabase -IncludePreExchange2013 -Status)  | Where {$_.Server -like $ServerFilter}  
    } 
    elseif ($E2010) 
    {     
        $Databases = [array](Get-MailboxDatabase -IncludePreExchange2010 -Status)  | Where {$_.Server -like $ServerFilter}  
    } 
    $DAGs = [array](Get-DatabaseAvailabilityGroup) | Where {$_.Servers -like $ServerFilter} 
} else { 
    $ArchiveMailboxes = $null 
    $ArchiveMailboxStats = $null     
    $DAGs = $null 
    _UpProg1 90 "Getting Databases" 1 
    $Databases = [array](Get-MailboxDatabase -IncludePreExchange2007 -Status) | Where {$_.Server -like $ServerFilter} 
    $ExchangeEnvironment.Add("RemoteMailboxes",0) 
} 
 
# 2.3 Populate Information we know 
$ExchangeEnvironment.Add("TotalMailboxes",$Mailboxes.Count + $ExchangeEnvironment.RemoteMailboxes); 
 
# 3 Process High-Level Exchange Information 
 
# 3.1 Collect Exchange Server Information 
for ($i=0; $i -lt $ExchangeServers.Count; $i++) 
{ 
    _UpProg1 ($i/$ExchangeServers.Count*100) "Getting Exchange Server Information" 2 
    # Get Exchange Info 
    $ExSvr = _GetExSvr -E2010 $E2010 -ExchangeServer $ExchangeServers[$i] -Mailboxes $Mailboxes -Databases $Databases -Hybrids $HybridServers 
    # Add to site or pre-Exchange 2007 list 
    if ($ExSvr.Site) 
    { 
        # Exchange 2007 or higher 
        if (!$ExchangeEnvironment.Sites[$ExSvr.Site]) 
        { 
            $ExchangeEnvironment.Sites.Add($ExSvr.Site,@($ExSvr)) 
        } else { 
            $ExchangeEnvironment.Sites[$ExSvr.Site]+=$ExSvr 
        } 
    } else { 
        # Exchange 2003 or lower 
        if (!$ExchangeEnvironment.Pre2007["Pre 2007 Servers"]) 
        { 
            $ExchangeEnvironment.Pre2007.Add("Pre 2007 Servers",@($ExSvr)) 
        } else { 
            $ExchangeEnvironment.Pre2007["Pre 2007 Servers"]+=$ExSvr 
        } 
    } 
    # Add to Servers List 
    $ExchangeEnvironment.Servers.Add($ExSvr.Name,$ExSvr) 
} 
 
# 3.2 Calculate Environment Totals for Version/Role using collected data 
_UpProg1 1 "Getting Totals" 3 
$ExchangeEnvironment.Add("TotalMailboxesByVersion",(_TotalsByVersion -ExchangeEnvironment $ExchangeEnvironment)) 
$ExchangeEnvironment.Add("TotalServersByRole",(_TotalsByRole -ExchangeEnvironment $ExchangeEnvironment)) 
 
# 3.4 Populate Environment DAGs 
_UpProg1 5 "Getting DAG Info" 3 
if ($DAGs) 
{ 
    foreach($DAG in $DAGs) 
    { 
        $ExchangeEnvironment.DAGs+=(_GetDAG -DAG $DAG) 
    } 
} 
 
# 3.5 Get Database information 
_UpProg1 60 "Getting Database Info" 3 
for ($i=0; $i -lt $Databases.Count; $i++) 
{ 
    $Database = _GetDB -Database $Databases[$i] -ExchangeEnvironment $ExchangeEnvironment -Mailboxes $Mailboxes -ArchiveMailboxes $ArchiveMailboxes -E2010 $E2010 
    $DAGDB = $false 
    for ($j=0; $j -lt $ExchangeEnvironment.DAGs.Count; $j++) 
    { 
        if ($ExchangeEnvironment.DAGs[$j].Members -contains $Database.ActiveOwner) 
        { 
            $DAGDB=$true 
            $ExchangeEnvironment.DAGs[$j].Databases += $Database 
        } 
    } 
    if (!$DAGDB) 
    { 
        $ExchangeEnvironment.NonDAGDatabases += $Database 
    } 
     
     
} 
 
# 4 Write Information 
_UpProg1 5 "Writing HTML Report Header" 4 
# Header 
$Output="<html> 
<body> 
<font size=""1"" face=""Segoe UI,Arial,sans-serif""> 
<h2 align=""center"">Exchange Environment Report</h3> 
<h4 align=""center"">Generated $((Get-Date).ToString())</h5> 
</font> 
<table border=""0"" cellpadding=""3"" style=""font-size:8pt;font-family:Segoe UI,Arial,sans-serif""> 
<tr bgcolor=""#009900""> 
<th colspan=""$($ExchangeEnvironment.TotalMailboxesByVersion.Count)""><font color=""#ffffff"">Total Servers:</font></th>" 
if ($ExchangeEnvironment.RemoteMailboxes) 
    { 
    $Output+="<th colspan=""$($ExchangeEnvironment.TotalMailboxesByVersion.Count+2)""><font color=""#ffffff"">Total Mailboxes:</font></th>" 
    } else { 
    $Output+="<th colspan=""$($ExchangeEnvironment.TotalMailboxesByVersion.Count+1)""><font color=""#ffffff"">Total Mailboxes:</font></th>" 
    } 
$Output+="<th colspan=""$($ExchangeEnvironment.TotalServersByRole.Count)""><font color=""#ffffff"">Total Roles:</font></th></tr> 
<tr bgcolor=""#00CC00"">" 
# Show Column Headings based on the Exchange versions we have 
$ExchangeEnvironment.TotalMailboxesByVersion.GetEnumerator()|Sort Name| %{$Output+="<th>$($ExVersionStrings[$_.Key].Short)</th>"} 
$ExchangeEnvironment.TotalMailboxesByVersion.GetEnumerator()|Sort Name| %{$Output+="<th>$($ExVersionStrings[$_.Key].Short)</th>"} 
if ($ExchangeEnvironment.RemoteMailboxes) 
{ 
    $Output+="<th>Office 365</th>" 
} 
$Output+="<th>Org</th>" 
$ExchangeEnvironment.TotalServersByRole.GetEnumerator()|Sort Name| %{$Output+="<th>$($ExRoleStrings[$_.Key].Short)</th>"} 
$Output+="<tr>" 
$Output+="<tr align=""center"" bgcolor=""#dddddd"">" 
$ExchangeEnvironment.TotalMailboxesByVersion.GetEnumerator()|Sort Name| %{$Output+="<td>$($_.Value.ServerCount)</td>" } 
$ExchangeEnvironment.TotalMailboxesByVersion.GetEnumerator()|Sort Name| %{$Output+="<td>$($_.Value.MailboxCount)</td>" } 
if ($RemoteMailboxes) 
{ 
    $Output+="<th>$($ExchangeEnvironment.RemoteMailboxes)</th>" 
} 
$Output+="<td>$($ExchangeEnvironment.TotalMailboxes)</td>" 
$ExchangeEnvironment.TotalServersByRole.GetEnumerator()|Sort Name| %{$Output+="<td>$($_.Value)</td>"} 
$Output+="</tr><tr><tr></table><br>" 
 
# Sites and Servers 
_UpProg1 20 "Writing HTML Site Information" 4 
foreach ($Site in $ExchangeEnvironment.Sites.GetEnumerator()) 
{ 
    $Output+=_GetOverview -Servers $Site -ExchangeEnvironment $ExchangeEnvironment -ExRoleStrings $ExRoleStrings 
} 
_UpProg1 40 "Writing HTML Pre-2007 Information" 4 
foreach ($FakeSite in $ExchangeEnvironment.Pre2007.GetEnumerator()) 
{ 
    $Output+=_GetOverview -Servers $FakeSite -ExchangeEnvironment $ExchangeEnvironment -ExRoleStrings $ExRoleStrings -Pre2007:$true 
} 
 
_UpProg1 60 "Writing HTML DAG Information" 4 
foreach ($DAG in $ExchangeEnvironment.DAGs) 
{ 
    if ($DAG.MemberCount -gt 0) 
    { 
        # Database Availability Group Header 
        $Output+="<table border=""0"" cellpadding=""3"" width=""100%"" style=""font-size:8pt;font-family:Segoe UI,Arial,sans-serif""> 
        <col width=""20%""><col width=""10%""><col width=""70%""> 
        <tr align=""center"" bgcolor=""#FF8000 ""><th>Database Availability Group Name</th><th>Member Count</th> 
        <th>Database Availability Group Members</th></tr> 
        <tr><td>$($DAG.Name)</td><td align=""center""> 
        $($DAG.MemberCount)</td><td>" 
        $DAG.Members | % { $Output+="$($_) " } 
        $Output+="</td></tr></table>" 
         
        # Get Table HTML 
        $Output+=_GetDBTable -Databases $DAG.Databases 
    } 
     
} 
 
if ($ExchangeEnvironment.NonDAGDatabases.Count) 
{ 
    _UpProg1 80 "Writing HTML Non-DAG Database Information" 4 
    $Output+="<table border=""0"" cellpadding=""3"" width=""100%"" style=""font-size:8pt;font-family:Segoe UI,Arial,sans-serif""> 
          <tr bgcolor=""#FF8000""><th>Mailbox Databases (Non-DAG)</th></table>" 
    $Output+=_GetDBTable -Databases $ExchangeEnvironment.NonDAGDatabases 
} 
 
 
# End 
_UpProg1 90 "Finishing off.." 4 
$Output+="</body></html>"; 
$Output | Out-File $HTMLReport 
 
 
if ($SendMail) 
{ 
    _UpProg1 95 "Sending mail message.." 4 
    Send-MailMessage -Attachments $HTMLReport -To $MailTo -From $MailFrom -Subject "Exchange Environment Report" -BodyAsHtml $Output -SmtpServer $MailServer 
}
}
Function Get-MPSEASDeviceReport {
<#
.SYNOPSIS
Get-EASDeviceReport.ps1 - Exchange Server ActiveSync device report

.DESCRIPTION 
Produces a report of ActiveSync device associations in the organization.

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.PARAMETER SendEmail
Sends the HTML report via email using the SMTP configuration within the script.

.EXAMPLE
.\Get-EASDeviceReport.ps1
Produces a CSV file containing stats for all ActiveSync devices.

.EXAMPLE
.\Get-EASDeviceReport.ps1 -SendEmail -MailFrom:exchangeserver@exchangeserverpro.net -MailTo:paul@exchangeserverpro.com -MailServer:smtp.exchangeserverpro.net
Sends an email report with CSV file attached for all ActiveSync devices.

.EXAMPLE
.\Get-EASDeviceReport.ps1 -Age 30
Limits the report to devices that have not attempted synced in more than 30 days.

.NOTES
Written by: Paul Cunningham

Find me on:

* My Blog:	http://paulcunningham.me
* Twitter:	https://twitter.com/paulcunningham
* LinkedIn:	http://au.linkedin.com/in/cunninghamp/
* Github:	https://github.com/cunninghamp

For more Exchange Server tips, tricks and news
check out Exchange Server Pro.

* Website:	http://exchangeserverpro.com
* Twitter:	http://twitter.com/exchservpro

Change Log
V1.00, 25/11/2013 - Initial version
V1.01, 11/02/2014 - Added parameters for emailing the report and specifying an "age" to report on
V1.02, 17/02/2014 - Fixed missing $mydir variable and added UTF8 encoding to Export-CSV and Send-MailMessage
#>

#requires -version 2

[CmdletBinding()]
param (
	
	[Parameter( Mandatory=$false)]
	[switch]$SendEmail,

	[Parameter( Mandatory=$false)]
	[string]$MailFrom,

	[Parameter( Mandatory=$false)]
	[string]$MailTo,

	[Parameter( Mandatory=$false)]
	[string]$MailServer,

    [Parameter( Mandatory=$false)]
    [int]$Age = 0

	)


#...................................
# Variables
#...................................

$now = Get-Date											#Used for timestamps
$date = $now.ToShortDateString()						#Short date format for email message subject

$report = @()

$stats = @("DeviceID",
            "DeviceAccessState",
            "DeviceAccessStateReason",
            "DeviceModel"
            "DeviceType",
            "DeviceFriendlyName",
            "DeviceOS",
            "LastSyncAttemptTime",
            "LastSuccessSync"
          )

$reportemailsubject = "Exchange ActiveSync Device Report - $date"
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$reportfile = "$myDir\ExchangeActiveSyncDeviceReport.csv"


#...................................
# Email Settings
#...................................

$smtpsettings = @{
	To =  $MailTo
	From = $MailFrom
    Subject = $reportemailsubject
	SmtpServer = $MailServer
	}


#...................................
# Initialize
#...................................

#Add Exchange 2010/2013 snapin if not already loaded in the PowerShell session
if (!(Get-PSSnapin | where {$_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010"}))
{
	try
	{
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction STOP
	}
	catch
	{
		#Snapin was not loaded
		Write-Warning $_.Exception.Message
		EXIT
	}
	. $env:ExchangeInstallPath\bin\RemoteExchange.ps1
	Connect-ExchangeServer -auto -AllowClobber
}


#...................................
# Script
#...................................

Write-Host "Fetching list of mailboxes with EAS device partnerships"

$MailboxesWithEASDevices = @(Get-CASMailbox -Resultsize Unlimited | Where {$_.HasActiveSyncDevicePartnership})

Write-Host "$($MailboxesWithEASDevices.count) mailboxes with EAS device partnerships"

Foreach ($Mailbox in $MailboxesWithEASDevices)
{
    
    $EASDeviceStats = @(Get-ActiveSyncDeviceStatistics -Mailbox $Mailbox.Identity)
    
    Write-Host "$($Mailbox.Identity) has $($EASDeviceStats.Count) device(s)"

    $MailboxInfo = Get-Mailbox $Mailbox.Identity | Select DisplayName,PrimarySMTPAddress
    
    Foreach ($EASDevice in $EASDeviceStats)
    {
        Write-Host -ForegroundColor Green "Processing $($EASDevice.DeviceID)"
        
        $lastsyncattempt = ($EASDevice.LastSyncAttemptTime)

        if ($lastsyncattempt -eq $null)
        {
            $syncAge = "Never"
        }
        else
        {
            $syncAge = ($now - $lastsyncattempt).Days
        }

        #Add to report if last sync attempt greater than Age specified
        if ($syncAge -ge $Age -or $syncAge -eq "Never")
        {
            Write-Host -ForegroundColor Yellow "$($EASDevice.DeviceID) sync age of $syncAge days is greater than $age, adding to report"

            $reportObj = New-Object PSObject
            $reportObj | Add-Member NoteProperty -Name "Display Name" -Value $MailboxInfo.DisplayName
            $reportObj | Add-Member NoteProperty -Name "Email Address" -Value $MailboxInfo.PrimarySMTPAddress
            $reportObj | Add-Member NoteProperty -Name "Sync Age (Days)" -Value $syncAge
                
            Foreach ($stat in $stats)
            {
                $reportObj | Add-Member NoteProperty -Name $stat -Value $EASDevice.$stat
            }

            $report += $reportObj
        }
    }
}

Write-Host -ForegroundColor White "Saving report to $reportfile"
$report | Export-Csv -NoTypeInformation $reportfile -Encoding UTF8


if ($SendEmail)
{

    $reporthtml = $report | ConvertTo-Html -Fragment

	$htmlhead="<html>
				<style>
				BODY{font-family: Arial; font-size: 8pt;}
				H1{font-size: 22px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H2{font-size: 18px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H3{font-size: 16px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				TH{border: 1px solid #969595; background: #dddddd; padding: 5px; color: #000000;}
				TD{border: 1px solid #969595; padding: 5px; }
				td.pass{background: #B7EB83;}
				td.warn{background: #FFF275;}
				td.fail{background: #FF2626; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
                <p>Report of Exchange ActiveSync device associations with greater than $age days since last sync attempt as of $date. CSV version of report attached to this email.</p>"
		
	$htmltail = "</body></html>"	

	$htmlreport = $htmlhead + $reporthtml + $htmltail

	Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Attachments $reportfile
}
}
Function Get-MPSMailboxReport {
<#
.SYNOPSIS
Get-MailboxReport.ps1 - Mailbox report generation script.

.DESCRIPTION 
Generates a report of useful information for
the specified server, database, mailbox or list of mailboxes.
Use only one parameter at a time depending on the scope of
your mailbox report.

.OUTPUTS
Single mailbox reports are output to the console, while all other
reports are output to a CSV file.

.PARAMETER All
Generates a report for all mailboxes in the organization.

.PARAMETER Server
Generates a report for all mailboxes on the specified server.

.PARAMETER Database
Generates a report for all mailboxes on the specified database.

.PARAMETER File
Generates a report for mailbox names listed in the specified text file.

.PARAMETER Mailbox
Generates a report only for the specified mailbox.

.PARAMETER Filename
(Optional) Specifies the CSV file name to be used for the report.
If no file name specificed then a unique file name is generated by the script.

.PARAMETER SendEmail
Specifies that an email report with the CSV file attached should be sent.

.PARAMETER MailFrom
The SMTP address to send the email from.

.PARAMETER MailTo
The SMTP address to send the email to.

-MailServer The SMTP server to send the email through.

.EXAMPLE
.\Get-MailboxReport.ps1 -Database DB01
Returns a report with the mailbox statistics for all mailbox users in
database HO-MB-01

.EXAMPLE
.\Get-MailboxReport.ps1 -All -SendEmail -MailFrom exchangereports@exchangeserverpro.net -MailTo alan.reid@exchangeserverpro.net -MailServer smtp.exchangeserverpro.net
Returns a report with the mailbox statistics for all mailbox users and
sends an email report to the specified recipient.

.LINK
http://exchangeserverpro.com/powershell-script-create-mailbox-size-report-exchange-server-2010

.NOTES
Written by: Paul Cunningham

Find me on:

* My Blog:	http://paulcunningham.me
* Twitter:	https://twitter.com/paulcunningham
* LinkedIn:	http://au.linkedin.com/in/cunninghamp/
* Github:	https://github.com/cunninghamp

For more Exchange Server tips, tricks and news
check out Exchange Server Pro.

* Website:	http://exchangeserverpro.com
* Twitter:	http://twitter.com/exchservpro

Additional Credits:
Chris Brown, http://www.flamingkeys.com
Boe Prox, http://learn-powershell.net/

Change Log
V1.00, 2/2/2012 - Initial version
V1.01, 27/2/2012 - Improved recipient scope settings, exception handling, and custom file name parameter.
V1.02, 16/10/2012 - Reordered report fields, added OU, primary SMTP, some specific folder stats,
                    archive mailbox info, and updated to show DAG name for databases when applicable.
V1.03, 27/05/2015 - Modified behavior of Server parameter
                - Added UseDatabaseQuotaDefaults, AuditEnabled, HiddenFromAddressListsEnabled, IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota
                - Added email functionality
                - Added auto-loading of snapin for simpler command lines in Task Scheduler
V1.04, 31/05/2015 - Fixed bug reported by some Exchange 2010 users
V1.05, 10/06/2015 - Fixed bug with date in email subject line

#>

#requires -version 2

param(
	[Parameter(ParameterSetName='database')]
    [string]$Database,

	[Parameter(ParameterSetName='file')]
    [string]$File,

	[Parameter(ParameterSetName='server')]
    [string]$Server,

	[Parameter(ParameterSetName='mailbox')]
    [string]$Mailbox,

	[Parameter(ParameterSetName='all')]
    [switch]$All,

    [Parameter( Mandatory=$false)]	
    [string]$Filename,

    [Parameter( Mandatory=$false)]
	[switch]$SendEmail,

	[Parameter( Mandatory=$false)]
	[string]$MailFrom,

	[Parameter( Mandatory=$false)]
	[string]$MailTo,

	[Parameter( Mandatory=$false)]
	[string]$MailServer,

    [Parameter( Mandatory=$false)]
    [int]$Top = 10

)

#...................................
# Variables
#...................................

$now = Get-Date

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

$reportemailsubject = "Exchange Mailbox Size Report - $now"
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$report = @()


#...................................
# Email Settings
#...................................

$smtpsettings = @{
	To =  $MailTo
	From = $MailFrom
    Subject = $reportemailsubject
	SmtpServer = $MailServer
	}


#...................................
# Initialize
#...................................

#Try Exchange 2007 snapin first

$2007snapin = Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.Admin -Registered
if ($2007snapin)
{
    if (!(Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue))
    {
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
	}

	$AdminSessionADSettings.ViewEntireForest = 1
}
else
{
    #Add Exchange 2010 snapin if not already loaded in the PowerShell session
    if (Test-Path $env:ExchangeInstallPath\bin\RemoteExchange.ps1)
    {
	    . $env:ExchangeInstallPath\bin\RemoteExchange.ps1
	    Connect-ExchangeServer -auto -AllowClobber
    }
    else
    {
        Write-Warning "Exchange Server management tools are not installed on this computer."
        EXIT
    }

    Set-ADServerSettings -ViewEntireForest $true
}


#If no filename specified, generate report file name with random strings for uniqueness
#Thanks to @proxb and @chrisbrownie for the help with random string generation

if ($filename)
{
	$reportfile = $filename
}
else
{
	$timestamp = Get-Date -UFormat %Y%m%d-%H%M
	$random = -join(48..57+65..90+97..122 | ForEach-Object {[char]$_} | Get-Random -Count 6)
	$reportfile = "$mydir\MailboxReport-$timestamp-$random.csv"
}


#...................................
# Script
#...................................

#Get the mailbox list

Write-Host -ForegroundColor White "Collecting mailbox list"

if($all) { $mailboxes = @(Get-Mailbox -resultsize unlimited -IgnoreDefaultScope) }

if($server)
{
    $databases = @(Get-MailboxDatabase -Server $server)
    $mailboxes = @($databases | Get-Mailbox -resultsize unlimited -IgnoreDefaultScope)
}

if($database){ $mailboxes = @(Get-Mailbox -database $database -resultsize unlimited -IgnoreDefaultScope) }

if($file) {	$mailboxes = @(Get-Content $file | Get-Mailbox -resultsize unlimited) }

if($mailbox) { $mailboxes = @(Get-Mailbox $mailbox) }

#Get the report

Write-Host -ForegroundColor White "Collecting report data"

$mailboxcount = $mailboxes.count
$i = 0

$mailboxdatabases = @(Get-MailboxDatabase)

#Loop through mailbox list and collect the mailbox statistics
foreach ($mb in $mailboxes)
{
	$i = $i + 1
	$pct = $i/$mailboxcount * 100
	Write-Progress -Activity "Collecting mailbox details" -Status "Processing mailbox $i of $mailboxcount - $mb" -PercentComplete $pct

	$stats = $mb | Get-MailboxStatistics | Select-Object TotalItemSize,TotalDeletedItemSize,ItemCount,LastLogonTime,LastLoggedOnUserAccount
    
    if ($mb.ArchiveDatabase)
    {
        $archivestats = $mb | Get-MailboxStatistics -Archive | Select-Object TotalItemSize,TotalDeletedItemSize,ItemCount
    }
    else
    {
        $archivestats = "n/a"
    }

    $inboxstats = Get-MailboxFolderStatistics $mb -FolderScope Inbox | Where {$_.FolderPath -eq "/Inbox"}
    $sentitemsstats = Get-MailboxFolderStatistics $mb -FolderScope SentItems | Where {$_.FolderPath -eq "/Sent Items"}
    $deleteditemsstats = Get-MailboxFolderStatistics $mb -FolderScope DeletedItems | Where {$_.FolderPath -eq "/Deleted Items"}
    #FolderandSubFolderSize.ToMB()

	$lastlogon = $stats.LastLogonTime

	$user = Get-User $mb
	$aduser = Get-ADUser $mb.samaccountname -Properties Enabled,AccountExpirationDate
    
    $primarydb = $mailboxdatabases | where {$_.Name -eq $mb.Database.Name}
    $archivedb = $mailboxdatabases | where {$_.Name -eq $mb.ArchiveDatabase.Name}

	#Create a custom PS object to aggregate the data we're interested in
	
	$userObj = New-Object PSObject
	$userObj | Add-Member NoteProperty -Name "DisplayName" -Value $mb.DisplayName
	$userObj | Add-Member NoteProperty -Name "Mailbox Type" -Value $mb.RecipientTypeDetails
	$userObj | Add-Member NoteProperty -Name "Title" -Value $user.Title
    $userObj | Add-Member NoteProperty -Name "Department" -Value $user.Department
    $userObj | Add-Member NoteProperty -Name "Office" -Value $user.Office

    $userObj | Add-Member NoteProperty -Name "Total Mailbox Size (Mb)" -Value ($stats.TotalItemSize.Value.ToMB() + $stats.TotalDeletedItemSize.Value.ToMB())
	$userObj | Add-Member NoteProperty -Name "Mailbox Size (Mb)" -Value $stats.TotalItemSize.Value.ToMB()
	$userObj | Add-Member NoteProperty -Name "Mailbox Recoverable Item Size (Mb)" -Value $stats.TotalDeletedItemSize.Value.ToMB()
	$userObj | Add-Member NoteProperty -Name "Mailbox Items" -Value $stats.ItemCount

    $userObj | Add-Member NoteProperty -Name "Inbox Folder Size (Mb)" -Value $inboxstats.FolderandSubFolderSize.ToMB()
    $userObj | Add-Member NoteProperty -Name "Sent Items Folder Size (Mb)" -Value $sentitemsstats.FolderandSubFolderSize.ToMB()
    $userObj | Add-Member NoteProperty -Name "Deleted Items Folder Size (Mb)" -Value $deleteditemsstats.FolderandSubFolderSize.ToMB()

    if ($archivestats -eq "n/a")
    {
        $userObj | Add-Member NoteProperty -Name "Total Archive Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Deleted Item Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Items" -Value "n/a"
    }
    else
    {
        $userObj | Add-Member NoteProperty -Name "Total Archive Size (Mb)" -Value ($archivestats.TotalItemSize.Value.ToMB() + $archivestats.TotalDeletedItemSize.Value.ToMB())
	    $userObj | Add-Member NoteProperty -Name "Archive Size (Mb)" -Value $archivestats.TotalItemSize.Value.ToMB()
	    $userObj | Add-Member NoteProperty -Name "Archive Deleted Item Size (Mb)" -Value $archivestats.TotalDeletedItemSize.Value.ToMB()
	    $userObj | Add-Member NoteProperty -Name "Archive Items" -Value $archivestats.ItemCount
    }

    $userObj | Add-Member NoteProperty -Name "Audit Enabled" -Value $mb.AuditEnabled
    $userObj | Add-Member NoteProperty -Name "Email Address Policy Enabled" -Value $mb.EmailAddressPolicyEnabled
    $userObj | Add-Member NoteProperty -Name "Hidden From Address Lists" -Value $mb.HiddenFromAddressListsEnabled
    $userObj | Add-Member NoteProperty -Name "Use Database Quota Defaults" -Value $mb.UseDatabaseQuotaDefaults
    
    if ($mb.UseDatabaseQuotaDefaults -eq $true)
    {
        $userObj | Add-Member NoteProperty -Name "Issue Warning Quota" -Value $primarydb.IssueWarningQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Quota" -Value $primarydb.ProhibitSendQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Receive Quota" -Value $primarydb.ProhibitSendReceiveQuota
    }
    elseif ($mb.UseDatabaseQuotaDefaults -eq $false)
    {
        $userObj | Add-Member NoteProperty -Name "Issue Warning Quota" -Value $mb.IssueWarningQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Quota" -Value $mb.ProhibitSendQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Receive Quota" -Value $mb.ProhibitSendReceiveQuota
    }

	$userObj | Add-Member NoteProperty -Name "Account Enabled" -Value $aduser.Enabled
	$userObj | Add-Member NoteProperty -Name "Account Expires" -Value $aduser.AccountExpirationDate
	$userObj | Add-Member NoteProperty -Name "Last Mailbox Logon" -Value $lastlogon
	$userObj | Add-Member NoteProperty -Name "Last Logon By" -Value $stats.LastLoggedOnUserAccount
    

	$userObj | Add-Member NoteProperty -Name "Primary Mailbox Database" -Value $mb.Database
	$userObj | Add-Member NoteProperty -Name "Primary Server/DAG" -Value $primarydb.MasterServerOrAvailabilityGroup

	$userObj | Add-Member NoteProperty -Name "Archive Mailbox Database" -Value $mb.ArchiveDatabase
	$userObj | Add-Member NoteProperty -Name "Archive Server/DAG" -Value $archivedb.MasterServerOrAvailabilityGroup

    $userObj | Add-Member NoteProperty -Name "Primary Email Address" -Value $mb.PrimarySMTPAddress
    $userObj | Add-Member NoteProperty -Name "Organizational Unit" -Value $user.OrganizationalUnit

	
	#Add the object to the report
	$report = $report += $userObj
}

#Catch zero item results
$reportcount = $report.count

if ($reportcount -eq 0)
{
	Write-Host -ForegroundColor Yellow "No mailboxes were found matching that criteria."
}
else
{
	#Output single mailbox report to console, otherwise output to CSV file
	if ($mailbox) 
	{
		$report | Format-List
	}
	else
	{
		$report | Export-Csv -Path $reportfile -NoTypeInformation -Encoding UTF8
		Write-Host -ForegroundColor White "Report written to $reportfile in current path."
		Get-Item $reportfile
	}
}


if ($SendEmail)
{

    $topmailboxeshtml = $report | Sort "Total Mailbox Size (Mb)" -Desc | Select -First $top | Select DisplayName,Title,Department,Office,"Total Mailbox Size (Mb)" | ConvertTo-Html -Fragment

    $reporthtml = $report | ConvertTo-Html -Fragment

	$htmlhead="<html>
				<style>
				BODY{font-family: Arial; font-size: 8pt;}
				H1{font-size: 22px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H2{font-size: 18px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H3{font-size: 16px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				TH{border: 1px solid #969595; background: #dddddd; padding: 5px; color: #000000;}
				TD{border: 1px solid #969595; padding: 5px; }
				td.pass{background: #B7EB83;}
				td.warn{background: #FFF275;}
				td.fail{background: #FF2626; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
                <h1 align=""center"">Exchange Server Mailbox Report</h1>
                <h3 align=""center"">Generated: $now</h3>
                <p>Report of Exchange mailboxes. Top $top mailboxes are listed below. Full list of mailboxes is in the CSV file attached to this email.</p>"
    
    $spacer = "<br />"

	$htmltail = "</body></html>"

	$htmlreport = $htmlhead + $topmailboxeshtml + $htmltail

	try
    {
        Write-Host "Sending email report..."
        Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Attachments $reportfile -ErrorAction STOP
        Write-Host "Finished."
    }
    catch
    {
        Write-Warning "An SMTP error has occurred, refer to log file for more details."
        $_.Exception.Message | Out-File "$myDir\get-mailboxreport-error.log"
        EXIT
    }
}
}
Function Get-MPSDAGReport {
<#
.SYNOPSIS
Get-DAGHealth.ps1 - Exchange Server 2010/2013 Database Availability Group Health Check Script.

.DESCRIPTION 
Performs a series of health checks on the Database Availability Groups
and outputs the results to screen or HTML email.

.OUTPUTS
Results are output to screen or HTML email

.PARAMETER Detailed
When this parameter is used a more detailed report is shown in the output.

.PARAMETER HTMLFile
When this parameter is used the HTML report is also writte to a file.

.PARAMETER SendEmail
Sends the HTML report via email using the SMTP configuration within the script.

.EXAMPLE
.\Get-DAGHealth.ps1
Checks all DAGs in the organization and outputs a health summary to the PowerShell window.

.EXAMPLE
.\Get-DAGHealth.ps1 -Detailed
Checks all DAGs in the organization and outputs a detailed health report to the PowerShell
window. Due to the amount of detail the full report may get cut off in your window. I recommend
detailed reports be output to HTML file or email instead.

.EXAMPLE
.\Get-DAGHealth.ps1 -Detailed -SendEmail
Checks all DAGs in the organization and outputs a detailed health report via email using
the SMTP settings you configure in the script.

.LINK
http://exchangeserverpro.com/get-daghealth-ps1-database-availability-group-health-check-script/

.NOTES
Written by: Paul Cunningham

Find me on:

* My Blog:	http://paulcunningham.me
* Twitter:	https://twitter.com/paulcunningham
* LinkedIn:	http://au.linkedin.com/in/cunninghamp/
* Github:	https://github.com/cunninghamp

For more Exchange Server tips, tricks and news
check out Exchange Server Pro.

* Website:	http://exchangeserverpro.com
* Twitter:	http://twitter.com/exchservpro

Change Log
V1.00, 14/02/2013 - Initial version
V1.01, 24/04/2013 - Bug fixes, Exchange 2013 testing
V1.02, 15/10/2014 - Updated to include fixes from Test-ExchangeServerHealth.ps1
#>

[CmdletBinding()]
param(
	[Parameter( Mandatory=$false)]
	[switch]$SendEmail,
	
	[Parameter( Mandatory=$false)]
	[switch]$HTMLFile,
	
	[Parameter( Mandatory=$false)]
	[switch]$Detailed,

	[Parameter( Mandatory=$false)]
	[switch]$Log
	)


#...................................
# Variables
#...................................

$now = Get-Date											#Used for timestamps
$date = $now.ToShortDateString()						#Short date format for email message subject
$pass = "Green"
$warn = "Yellow"
$fail = "Red"
$ip = $null
[array]$dagsummary = @()								#Summary of issues found during DAG health checks
[array]$report = @()
[bool]$alerts = $false
[array]$dags = @()										#Array for DAG health check
[array]$dagdatabases = @()								#Array for DAG databases
[int]$replqueuewarning = 8								#Threshold to consider a replication queue unhealthy
$dagreportbody = $null

$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$ignorelistfile = "$myDir\ignorelist.txt"
$logfile = "$myDir\get-daghealth.log"
$reportfile = "$myDir\get-daghealth.html"


#...................................
# SMTP settings are stored in
# Settings.xml file
#...................................

# Import Settings.xml config file
[xml]$ConfigFile = Get-Content "$MyDir\Settings.xml"

# Email settings from Settings.xml
$smtpsettings = @{
    To = $ConfigFile.Settings.EmailSettings.MailTo
    From = $ConfigFile.Settings.EmailSettings.MailFrom
    SmtpServer = $ConfigFile.Settings.EmailSettings.SMTPServer
    Subject = "$($ConfigFile.Settings.EmailSettings.Subject) - $now"
    }


#...................................
# Logfile Strings
#...................................

$logstring0 = "====================================="
$logstring1 = " Exchange Server DAG Health Check"

#...................................
# Initialization Strings
#...................................

$initstring0 = "Initializing..."
$initstring1 = "Loading the Exchange Server PowerShell snapin"
$initstring2 = "The Exchange Server PowerShell snapin did not load."
$initstring3 = "Setting scope to entire forest"

#...................................
# Error/Warning Strings
#...................................

$string3 = "------ Checking"
$string14 = "Sending email. "
$string15 = "Done."
$string16 = "------ Finishing"
$string19 = "No alerts found, and AlertsOnly switch was used. No email sent. "
$string22 = "The file $ignorelistfile could not be found. No servers, DAGs or databases will be ignored."
$string28 = "Servers, DAGs and databases to ignore:"
$string51 = "Skipped"
$string60 = "Beginning the DAG health checks"
$string61 = "Could not determine server with active database copy"
$string62 = "mounted on server that is activation preference"
$string63 = "unhealthy database copy count is"
$string64 = "healthy copy/replay queue count is"
$string65 = "(of"
$string66 = ")"
$string67 = "unhealthy content index count is"
$string68 = "DAGs to check:"
$string69 = "DAG databases to check"



#...................................
# Functions
#...................................

#This function is used to generate HTML for the DAG member health report
Function New-DAGMemberHTMLTableCell()
{
	param( $lineitem )
	
	$htmltablecell = $null

	switch ($($line."$lineitem"))
	{
		$null { $htmltablecell = "<td>n/a</td>" }
		"Passed" { $htmltablecell = "<td class=""pass"">$($line."$lineitem")</td>" }
		default { $htmltablecell = "<td class=""warn"">$($line."$lineitem")</td>" }
	}
	
	return $htmltablecell
}


#This function is used to write the log file if -Log is used
Function Write-Logfile()
{
	param( $logentry )
	$timestamp = Get-Date -DisplayHint Time
	"$timestamp $logentry" | Out-File $logfile -Append
}


#This function is used to test replication health for Exchange 2010 DAG members in mixed 2010/2013 organizations
Function Test-E14ReplicationHealth()
{
	param ( $e14mailboxserver )

	$e14replicationhealth = $null
	
    #Find an E14 CAS in the same site
    $ADSite = (Get-ExchangeServer $e14mailboxserver).Site
    $e14cas = (Get-ExchangeServer | where {$_.IsClientAccessServer -and $_.AdminDisplayVersion -match "Version 14" -and $_.Site -eq $ADSite} | select -first 1).FQDN

	Write-Verbose "Creating PSSession for $e14cas"
    $url = (Get-PowerShellVirtualDirectory -Server $e14cas -AdPropertiesOnly | Where {$_.Name -eq "Powershell (Default Web Site)"}).InternalURL.AbsoluteUri
    if ($url -eq $null)
    {
        $url = "http://$e14cas/powershell"
    }

    Write-Verbose "Using URL $url"

	try
	{
	    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url -ErrorAction STOP
	}
	catch
	{
	    Write-Verbose "Something went wrong"
		if ($Log) {Write-Log $_.Exception.Message}
    	Write-Warning $_.Exception.Message
		#$e14replicationhealth = "Fail"
	}

	try
	{
	    Write-Verbose "Running replication health test on $e14mailboxserver"
	    #$e14replicationhealth = Invoke-Command -Session $session {Test-ReplicationHealth} -ErrorAction STOP
        $e14replicationhealth = Invoke-Command -Session $session -Args $e14mailboxserver.Name {Test-ReplicationHealth $args[0]} -ErrorAction STOP
	}
	catch
	{
	    Write-Verbose "An error occurred"
		if ($Log) {Write-Log $_.Exception.Message}
	    Write-Warning $_.Exception.Message
	    #$e14replicationhealth = "Fail"
	}

	#Write-Verbose "Replication health test: $e14replicationhealth"
	Write-Verbose "Removing PSSession"
	Remove-PSSession $session.Id

	return $e14replicationhealth
}


#...................................
# Initialize
#...................................

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
	$timestamp = Get-Date -DisplayHint Time
	"$timestamp $logstring0" | Out-File $logfile
	Write-Logfile $logstring1
	Write-Logfile "  $now"
	Write-Logfile $logstring0
}

Write-Host $initstring0
if ($Log) {Write-Logfile $initstring0}

#Add Exchange 2010 snapin if not already loaded in the PowerShell session
if (!(Get-PSSnapin | where {$_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010"}))
{
	Write-Verbose $initstring1
	if ($Log) {Write-Logfile $initstring1}
	try
	{
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction STOP
	}
	catch
	{
		#Snapin was not loaded
		Write-Verbose $initstring2
		if ($Log) {Write-Logfile $initstring2}
		Write-Warning $_.Exception.Message
		EXIT
	}
	. $env:ExchangeInstallPath\bin\RemoteExchange.ps1
	Connect-ExchangeServer -auto -AllowClobber
}


#Set scope to include entire forest
Write-Verbose $initstring3
if ($Log) {Write-Logfile $initstring3}
if (!(Get-ADServerSettings).ViewEntireForest)
{
	Set-ADServerSettings -ViewEntireForest $true -WarningAction SilentlyContinue
}


#...................................
# Script
#...................................

#This is the list of servers, DAGs, and databases to never alert for
try
{
    $ignorelist = @(Get-Content $ignorelistfile -ErrorAction STOP)
	if ($Log) {Write-Logfile $string28}
	if ($Log) {
		if ($($ignorelist.count) -gt 0)
		{
			foreach ($line in $ignorelist)
			{
				Write-Logfile "- $line"
			}
		}
		else
		{
			Write-Logfile $string38
		}
	}
}
catch
{
	Write-Warning $string22
	if ($Log) {Write-Logfile $string22}
}
    

### Check if any Exchange 2013 servers exist
if (Get-ExchangeServer | Where {$_.AdminDisplayVersion -like "Version 15.*"})
{
	[bool]$HasE15 = $true
}


### Begin DAG Health Report


if ($Log) {Write-Logfile $string60}
Write-Verbose "Retrieving Database Availability Groups"

#Get all DAGs
$tmpdags = @(Get-DatabaseAvailabilityGroup)
$tmpstring = "$($tmpdags.count) DAGs found"
Write-Verbose $tmpstring
if ($Log) {Write-Logfile $tmpstring}

#Remove DAGs in ignorelist
foreach ($tmpdag in $tmpdags)
{
	if (!($ignorelist -icontains $tmpdag.name))
	{
		$dags += $tmpdag
	}
}

$tmpstring = "$($dags.count) DAGs will be checked"
Write-Verbose $tmpstring
if ($Log) {Write-Logfile $tmpstring}

if ($Log) {Write-Logfile $string68}
if ($Log) {
	foreach ($dag in $dags)
	{
		Write-Logfile "- $dag"
	}
}


if ($($dags.count) -gt 0)
{
	foreach ($dag in $dags)
	{
		
		#Strings for use in the HTML report/email
		$dagsummaryintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Summary:</p>"
		$dagdetailintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Details:</p>"
		$dagmemberintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Member Health:</p>"

		$dagdbcopyReport = @()		#Database copy health report
		$dagciReport = @()			#Content Index health report
		$dagmemberReport = @()		#DAG member server health report
		$dagdatabaseSummary = @()	#Database health summary report
		$dagdatabases = @()			#Array of databases in the DAG
		
		$tmpstring = "---- Processing DAG $($dag.Name)"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}
		
		$dagmembers = @($dag | Select-Object -ExpandProperty Servers | Sort-Object Name)
		$tmpstring = "$($dagmembers.count) DAG members found"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}
		
		#Get all databases in the DAG
        if ($HasE15)
        {
		    $tmpdatabases = @(Get-MailboxDatabase -Status -IncludePreExchange2013 | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $dag.Name} | Sort-Object Name)
        }
        else
        {
		    $tmpdatabases = @(Get-MailboxDatabase -Status | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $dag.Name} | Sort-Object Name)
        }

		foreach ($tmpdatabase in $tmpdatabases)
		{
			if (!($ignorelist -icontains $tmpdatabase.name))
			{
				$dagdatabases += $tmpdatabase
			}
		}
				
		$tmpstring = "$($dagdatabases.count) DAG databases will be checked"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}

		if ($Log) {Write-Logfile $string69}
		if ($Log) {
			foreach ($database in $dagdatabases)
			{
				Write-Logfile "- $database"
			}
		}
		
		foreach ($database in $dagdatabases)
		{
			$tmpstring = "---- Processing database $database"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}

			#Custom object for Database
			$objectHash = @{
				"Database" = $database.Identity
				"Mounted on" = "Unknown"
				"Preference" = $null
				"Total Copies" = $null
				"Healthy Copies" = $null
				"Unhealthy Copies" = $null
				"Healthy Queues" = $null
				"Unhealthy Queues" = $null
				"Lagged Queues" = $null
				"Healthy Indexes" = $null
				"Unhealthy Indexes" = $null
				}
			$databaseObj = New-Object PSObject -Property $objectHash

			$dbcopystatus = @($database | Get-MailboxDatabaseCopyStatus)
			$tmpstring = "$database has $($dbcopystatus.Count) copies"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}
			
			foreach ($dbcopy in $dbcopystatus)
			{
				#Custom object for DB copy
				$objectHash = @{
					"Database Copy" = $dbcopy.Identity
					"Database Name" = $dbcopy.DatabaseName
					"Mailbox Server" = $null
					"Activation Preference" = $null
					"Status" = $null
					"Copy Queue" = $null
					"Replay Queue" = $null
					"Replay Lagged" = $null
					"Truncation Lagged" = $null
					"Content Index" = $null
					}
				$dbcopyObj = New-Object PSObject -Property $objectHash
				
				$tmpstring = "Database Copy: $($dbcopy.Identity)"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				$mailboxserver = $dbcopy.MailboxServer
				$tmpstring = "Server: $mailboxserver"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
                
                if ($database.AdminDisplayVersion -like "Version 14.*")
                {
				    $pref = ($database | Select-Object -ExpandProperty ActivationPreference | Where-Object {$_.Key -eq $mailboxserver}).Value
                }
                else
                {
                    $pref = $dbcopy.ActivationPreference
                }

				$tmpstring = "Activation Preference: $pref"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}

				$copystatus = $dbcopy.Status
				$tmpstring = "Status: $copystatus"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				[int]$copyqueuelength = $dbcopy.CopyQueueLength
				$tmpstring = "Copy Queue: $copyqueuelength"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				[int]$replayqueuelength = $dbcopy.ReplayQueueLength
				$tmpstring = "Replay Queue: $replayqueuelength"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				if ($($dbcopy.ContentIndexErrorMessage -match "is disabled in Active Directory"))
                {
                    $contentindexstate = "Disabled"
                }
                else
                {
                    $contentindexstate = $dbcopy.ContentIndexState
                }
				$tmpstring = "Content Index: $contentindexstate"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}				

				#Checking whether this is a replay lagged copy
				$replaylagcopies = @($database | Select -ExpandProperty ReplayLagTimes | Where-Object {$_.Value -gt 0})
				if ($($replaylagcopies.count) -gt 0)
	            {
	                [bool]$replaylag = $false
	                foreach ($replaylagcopy in $replaylagcopies)
				    {
					    if ($replaylagcopy.Key -eq $mailboxserver)
					    {
						    $tmpstring = "$database is replay lagged on $mailboxserver"
							Write-Verbose $tmpstring
							if ($Log) {Write-Logfile $tmpstring}
						    [bool]$replaylag = $true
					    }
				    }
	            }
	            else
				{
				   [bool]$replaylag = $false
				}
	            $tmpstring = "Replay lag is $replaylag"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}				
						
				#Checking for truncation lagged copies
				$truncationlagcopies = @($database | Select -ExpandProperty TruncationLagTimes | Where-Object {$_.Value -gt 0})
				if ($($truncationlagcopies.count) -gt 0)
	            {
	                [bool]$truncatelag = $false
	                foreach ($truncationlagcopy in $truncationlagcopies)
				    {
					    if ($truncationlagcopy.Key -eq $mailboxserver)
					    {
						    $tmpstring = "$database is truncate lagged on $mailboxserver"
							Write-Verbose $tmpstring
							if ($Log) {Write-Logfile $tmpstring}							
							[bool]$truncatelag = $true
					    }
				    }
	            }
	            else
				{
				   [bool]$truncatelag = $false
				}
	            $tmpstring = "Truncation lag is $truncatelag"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				$dbcopyObj | Add-Member NoteProperty -Name "Mailbox Server" -Value $mailboxserver -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Activation Preference" -Value $pref -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Status" -Value $copystatus -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Copy Queue" -Value $copyqueuelength -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Replay Queue" -Value $replayqueuelength -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Replay Lagged" -Value $replaylag -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Truncation Lagged" -Value $truncatelag -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Content Index" -Value $contentindexstate -Force
				
				$dagdbcopyReport += $dbcopyObj
			}
		
			$copies = @($dagdbcopyReport | Where-Object { ($_."Database Name" -eq $database) })
		
			$mountedOn = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Mailbox Server"
			if ($mountedOn)
			{
				$databaseObj | Add-Member NoteProperty -Name "Mounted on" -Value $mountedOn -Force
			}
		
			$activationPref = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Activation Preference"
			$databaseObj | Add-Member NoteProperty -Name "Preference" -Value $activationPref -Force

			$totalcopies = $copies.count
			$databaseObj | Add-Member NoteProperty -Name "Total Copies" -Value $totalcopies -Force
		
			$healthycopies = @($copies | Where-Object { (($_.Status -eq "Mounted") -or ($_.Status -eq "Healthy")) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Healthy Copies" -Value $healthycopies -Force
			
			$unhealthycopies = @($copies | Where-Object { (($_.Status -ne "Mounted") -and ($_.Status -ne "Healthy")) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Copies" -Value $unhealthycopies -Force

			$healthyqueues  = @($copies | Where-Object { (($_."Copy Queue" -lt $replqueuewarning) -and (($_."Replay Queue" -lt $replqueuewarning)) -and ($_."Replay Lagged" -eq $false)) }).Count
	        $databaseObj | Add-Member NoteProperty -Name "Healthy Queues" -Value $healthyqueues -Force

			$unhealthyqueues = @($copies | Where-Object { (($_."Copy Queue" -ge $replqueuewarning) -or (($_."Replay Queue" -ge $replqueuewarning) -and ($_."Replay Lagged" -eq $false))) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Queues" -Value $unhealthyqueues -Force

			$laggedqueues = @($copies | Where-Object { ($_."Replay Lagged" -eq $true) -or ($_."Truncation Lagged" -eq $true) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Lagged Queues" -Value $laggedqueues -Force

			$healthyindexes = @($copies | Where-Object { ($_."Content Index" -eq "Healthy" -or $_."Content Index" -eq "Disabled") }).Count
			$databaseObj | Add-Member NoteProperty -Name "Healthy Indexes" -Value $healthyindexes -Force
			
			$unhealthyindexes = @($copies | Where-Object { ($_."Content Index" -ne "Healthy" -and $_."Content Index" -ne "Disabled") }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Indexes" -Value $unhealthyindexes -Force
			
			$dagdatabaseSummary += $databaseObj
		
		}
		
		#Get Test-Replication Health results for each DAG member
		foreach ($dagmember in $dagmembers)
		{
            $replicationhealth = $null

            $replicationhealthitems = @{ClusterService = $null
                                        ReplayService = $null
                                        ActiveManager = $null
                                        TasksRpcListener = $null
                                        TcpListener = $null
                                        ServerLocatorService = $null
                                        DagMembersUp = $null
                                        ClusterNetwork = $null
                                        QuorumGroup = $null
                                        FileShareQuorum = $null
                                        DatabaseRedundancy = $null
                                        DatabaseAvailability = $null
                                        DBCopySuspended = $null
                                        DBCopyFailed = $null
                                        DBInitializing = $null
                                        DBDisconnected = $null
                                        DBLogCopyKeepingUp = $null
                                        DBLogReplayKeepingUp = $null
                                        }

			$memberObj = New-Object PSObject -Property $replicationhealthitems
			$memberObj | Add-Member NoteProperty -Name "Server" -Value $dagmember
		
			$tmpstring = "---- Checking replication health for $dagmember"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}
			
			try
            {
                $replicationhealth = $dagmember | Invoke-Command {Test-ReplicationHealth -ErrorAction STOP} 
            }
            catch
            {
		        if ($Log) {Write-Logfile "Using E14 replication health test workaround"}
                $replicationhealth = Test-E14ReplicationHealth $dagmember
            }
			
	        foreach ($healthitem in $replicationhealth)
	        {
                if ($($healthitem.Result) -eq $null)
                {
                    $healthitemresult = "n/a"
                }
                else
                {
                    $healthitemresult = $($healthitem.Result)
                }
                $tmpstring = "$($healthitem.Check) $healthitemresult"
		        Write-Verbose $tmpstring
		        if ($Log) {Write-Logfile $tmpstring}
		        $memberObj | Add-Member NoteProperty -Name $($healthitem.Check) -Value $healthitemresult -Force
	        }
			$dagmemberReport += $memberObj
		}

		
		#Generate the HTML from the DAG health checks
		if ($SendEmail -or $HTMLFile)
		{
		
			####Begin Summary Table HTML
			$dagdatabaseSummaryHtml = $null
			#Begin Summary table HTML header
			$htmltableheader = "<p>
							<table>
							<tr>
							<th>Database</th>
							<th>Mounted on</th>
							<th>Preference</th>
							<th>Total Copies</th>
							<th>Healthy Copies</th>
							<th>Unhealthy Copies</th>
							<th>Healthy Queues</th>
							<th>Unhealthy Queues</th>
							<th>Lagged Queues</th>
							<th>Healthy Indexes</th>
							<th>Unhealthy Indexes</th>
							</tr>"

			$dagdatabaseSummaryHtml += $htmltableheader
			#End Summary table HTML header
			
			#Begin Summary table HTML rows
			foreach ($line in $dagdatabaseSummary)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line.Database)</strong></td>"
				
				#Warn if mounted server is still unknown
				switch ($($line."Mounted on"))
				{
					"Unknown" {
						$htmltablerow += "<td class=""warn"">$($line."Mounted on")</td>"
						$dagsummary += "$($line.Database) - $string61"
						}
					default { $htmltablerow += "<td>$($line."Mounted on")</td>" }
				}
				
				#Warn if DB is mounted on a server that is not Activation Preference 1
				if ($($line.Preference) -gt 1)
				{
					$htmltablerow += "<td class=""warn"">$($line.Preference)</td>"
					$dagsummary += "$($line.Database) - $string62 $($line.Preference)"
				}
				else
				{
					$htmltablerow += "<td class=""pass"">$($line.Preference)</td>"
				}
				
				$htmltablerow += "<td>$($line."Total Copies")</td>"
				
				#Show as info if health copies is 1 but total copies also 1,
	            #Warn if healthy copies is 1, Fail if 0
				switch ($($line."Healthy Copies"))
				{	
					0 {$htmltablerow += "<td class=""fail"">$($line."Healthy Copies")</td>"}
					1 {
						if ($($line."Total Copies") -eq $($line."Healthy Copies"))
						{
							$htmltablerow += "<td class=""info"">$($line."Healthy Copies")</td>"
						}
						else
						{
							$htmltablerow += "<td class=""warn"">$($line."Healthy Copies")</td>"
						}
					  }
					default {$htmltablerow += "<td class=""pass"">$($line."Healthy Copies")</td>"}
				}

				#Warn if unhealthy copies is 1, fail if more than 1
				switch ($($line."Unhealthy Copies"))
				{
					0 {	$htmltablerow += "<td class=""pass"">$($line."Unhealthy Copies")</td>" }
					1 {
						$htmltablerow += "<td class=""warn"">$($line."Unhealthy Copies")</td>"
						$dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
						}
					default {
						$htmltablerow += "<td class=""fail"">$($line."Unhealthy Copies")</td>"
						$dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
						}
				}

				#Warn if healthy queues + lagged queues is less than total copies
				#Fail if no healthy queues
				if ($($line."Total Copies") -eq ($($line."Healthy Queues") + $($line."Lagged Queues")))
				{
					$htmltablerow += "<td class=""pass"">$($line."Healthy Queues")</td>"
				}
				else
				{
					$dagsummary += "$($line.Database) - $string64 $($line."Healthy Queues") $string65 $($line."Total Copies") $string66"
					switch ($($line."Healthy Queues"))
					{
						0 {	$htmltablerow += "<td class=""fail"">$($line."Healthy Queues")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Healthy Queues")</td>" }
					}
				}
				
				#Fail if unhealthy queues = total queues
				#Warn if more than one unhealthy queue
				if ($($line."Total Queues") -eq $($line."Unhealthy Queues"))
				{
					$htmltablerow += "<td class=""fail"">$($line."Unhealthy Queues")</td>"
				}
				else
				{
					switch ($($line."Unhealthy Queues"))
					{
						0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Queues")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Queues")</td>" }
					}
				}
				
				#Info for lagged queues
				switch ($($line."Lagged Queues"))
				{
					0 { $htmltablerow += "<td>$($line."Lagged Queues")</td>" }
					default { $htmltablerow += "<td class=""info"">$($line."Lagged Queues")</td>" }
				}
				
				#Pass if healthy indexes = total copies
				#Warn if healthy indexes less than total copies
				#Fail if healthy indexes = 0
				if ($($line."Total Copies") -eq $($line."Healthy Indexes"))
				{
					$htmltablerow += "<td class=""pass"">$($line."Healthy Indexes")</td>"
				}
				else
				{
					$dagsummary += "$($line.Database) - $string67 $($line."Unhealthy Indexes") $string65 $($line."Total Copies") $string66"
					switch ($($line."Healthy Indexes"))
					{
						0 { $htmltablerow += "<td class=""fail"">$($line."Healthy Indexes")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Healthy Indexes")</td>" }
					}
				}
				
				#Fail if unhealthy indexes = total copies
				#Warn if unhealthy indexes 1 or more
				#Pass if unhealthy indexes = 0
				if ($($line."Total Copies") -eq $($line."Unhealthy Indexes"))
				{
					$htmltablerow += "<td class=""fail"">$($line."Unhealthy Indexes")</td>"
				}
				else
				{
					switch ($($line."Unhealthy Indexes"))
					{
						0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Indexes")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Indexes")</td>" }
					}
				}
				
				$htmltablerow += "</tr>"
				$dagdatabaseSummaryHtml += $htmltablerow
			}
			$dagdatabaseSummaryHtml += "</table>
									</p>"
			#End Summary table HTML rows
			####End Summary Table HTML

			####Begin Detail Table HTML
			$databasedetailsHtml = $null
			#Begin Detail table HTML header
			$htmltableheader = "<p>
							<table>
							<tr>
							<th>Database Copy</th>
							<th>Database Name</th>
							<th>Mailbox Server</th>
							<th>Activation Preference</th>
							<th>Status</th>
							<th>Copy Queue</th>
							<th>Replay Queue</th>
							<th>Replay Lagged</th>
							<th>Truncation Lagged</th>
							<th>Content Index</th>
							</tr>"

			$databasedetailsHtml += $htmltableheader
			#End Detail table HTML header
			
			#Begin Detail table HTML rows
			foreach ($line in $dagdbcopyReport)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line."Database Copy")</strong></td>"
				$htmltablerow += "<td>$($line."Database Name")</td>"
				$htmltablerow += "<td>$($line."Mailbox Server")</td>"
				$htmltablerow += "<td>$($line."Activation Preference")</td>"
				
				Switch ($($line."Status"))
				{
					"Healthy" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
					"Mounted" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
					"Failed" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"FailedAndSuspended" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"ServiceDown" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"Dismounted" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					default { $htmltablerow += "<td class=""warn"">$($line."Status")</td>" }
				}
				
				if ($($line."Copy Queue") -lt $replqueuewarning)
				{
					$htmltablerow += "<td class=""pass"">$($line."Copy Queue")</td>"
				}
				else
				{
					$htmltablerow += "<td class=""warn"">$($line."Copy Queue")</td>"
				}
				
				if (($($line."Replay Queue") -lt $replqueuewarning) -or ($($line."Replay Lagged") -eq $true))
				{
					$htmltablerow += "<td class=""pass"">$($line."Replay Queue")</td>"
				}
				else
				{
					$htmltablerow += "<td class=""warn"">$($line."Replay Queue")</td>"
				}
				

				Switch ($($line."Replay Lagged"))
				{
					$true { $htmltablerow += "<td class=""info"">$($line."Replay Lagged")</td>" }
					default { $htmltablerow += "<td>$($line."Replay Lagged")</td>" }
				}

				Switch ($($line."Truncation Lagged"))
				{
					$true { $htmltablerow += "<td class=""info"">$($line."Truncation Lagged")</td>" }
					default { $htmltablerow += "<td>$($line."Truncation Lagged")</td>" }
				}
				
				Switch ($($line."Content Index"))
				{
					"Healthy" { $htmltablerow += "<td class=""pass"">$($line."Content Index")</td>" }
                    "Disabled" { $htmltablerow += "<td class=""info"">$($line."Content Index")</td>" }
					default { $htmltablerow += "<td class=""warn"">$($line."Content Index")</td>" }
				}
				
				$htmltablerow += "</tr>"
				$databasedetailsHtml += $htmltablerow
			}
			$databasedetailsHtml += "</table>
									</p>"
			#End Detail table HTML rows
			####End Detail Table HTML
			
			
			####Begin Member Table HTML
			$dagmemberHtml = $null
			#Begin Member table HTML header
			$htmltableheader = "<p>
								<table>
								<tr>
								<th>Server</th>
								<th>Cluster Service</th>
								<th>Replay Service</th>
								<th>Active Manager</th>
								<th>Tasks RPC Listener</th>
								<th>TCP Listener</th>
								<th>Server Locator Service</th>
								<th>DAG Members Up</th>
								<th>Cluster Network</th>
								<th>Quorum Group</th>
								<th>File Share Quorum</th>
								<th>Database Redundancy</th>
								<th>Database Availability</th>
								<th>DB Copy Suspended</th>
								<th>DB Copy Failed</th>
								<th>DB Initializing</th>
								<th>DB Disconnected</th>
								<th>DB Log Copy Keeping Up</th>
								<th>DB Log Replay Keeping Up</th>
								</tr>"
			
			$dagmemberHtml += $htmltableheader
			#End Member table HTML header
			
			#Begin Member table HTML rows
			foreach ($line in $dagmemberReport)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line."Server")</strong></td>"
				$htmltablerow += (New-DAGMemberHTMLTableCell "ClusterService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ReplayService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ActiveManager")
				$htmltablerow += (New-DAGMemberHTMLTableCell "TasksRPCListener")
				$htmltablerow += (New-DAGMemberHTMLTableCell "TCPListener")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ServerLocatorService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DAGMembersUp")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ClusterNetwork")
				$htmltablerow += (New-DAGMemberHTMLTableCell "QuorumGroup")
				$htmltablerow += (New-DAGMemberHTMLTableCell "FileShareQuorum")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseRedundancy")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseAvailability")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBCopySuspended")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBCopyFailed")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBInitializing")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBDisconnected")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBLogCopyKeepingUp")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBLogReplayKeepingUp")
				$htmltablerow += "</tr>"
				$dagmemberHtml += $htmltablerow
			}
			$dagmemberHtml += "</table>
			</p>"
		}
		
		#Output the report objects to console, and optionally to email and HTML file
		#Forcing table format for console output due to issue with multiple output
		#objects that have different layouts

		#Write-Host "---- Database Copy Health Summary ----"
		#$dagdatabaseSummary | ft
				
		#Write-Host "---- Database Copy Health Details ----"
		#$dagdbcopyReport | ft
		
		#Write-Host "`r`n---- Server Test-Replication Report ----`r`n"
		#$dagmemberReport | ft
		
		if ($SendEmail -or $HTMLFile)
		{
			$dagreporthtml = $dagsummaryintro + $dagdatabaseSummaryHtml + $dagdetailintro + $databasedetailsHtml + $dagmemberintro + $dagmemberHtml
			$dagreportbody += $dagreporthtml
		}
		
	}
}
else
{
	$tmpstring = "No DAGs found"
	if ($Log) {Write-LogFile $tmpstring}
	Write-Verbose $tmpstring
	$dagreporthtml = "<p>No database availability groups found.</p>"
}
### End DAG Health Report

Write-Host $string16
### Begin report generation
if ($HTMLFile -or $SendEmail)
{
	#Get report generation timestamp
	$reportime = Get-Date

	#Create HTML Report
	#Common HTML head and styles
	$htmlhead="<html>
				<style>
				BODY{font-family: Arial; font-size: 8pt;}
				H1{font-size: 16px;}
				H2{font-size: 14px;}
				H3{font-size: 12px;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				TD{border: 1px solid black; padding: 5px; }
				td.pass{background: #7FFF00;}
				td.warn{background: #FFE600;}
				td.fail{background: #FF0000; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
				<h1 align=""center"">Exchange Server Health Check Report</h1>
				<h3 align=""center"">Generated: $reportime</h3>"

	#Check if the DAG summary has 1 or more entries
	if ($($dagsummary.count) -gt 0)
	{
		#Set alert flag to true
		$alerts = $true
	
		#Generate the HTML
		$dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
						<p>The following DAG errors and warnings were detected.</p>
						<p>
						<ul>"
		foreach ($reportline in $dagsummary)
		{
			$dagsummaryhtml +="<li>$reportline</li>"
		}
		$dagsummaryhtml += "</ul></p>"
		$alerts = $true
	}
	else
	{
		#Generate the HTML to show no alerts
		$dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
						<p>No Exchange DAG errors or warnings.</p>"
	}


	$htmltail = "</body>
				</html>"

	$htmlreport = $htmlhead +  $dagsummaryhtml + $dagreportbody + $htmltail
	
	if ($HTMLFile)
	{
        Write-Verbose "Writing HTML report file"
		$htmlreport | Out-File $ReportFile -Encoding UTF8
	}

	if ($SendEmail)
	{
		if ($alerts -eq $false -and $AlertsOnly -eq $true)
		{
			#Do not send email message
			Write-Host $string19
			if ($Log) {Write-Logfile $string19}
		}
		else
		{
			#Send email message
			Write-Host $string14
			Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
		}
	}
}
### End report generation


Write-Host $string15


#...................................
# End
#...................................

if ($Log) {
	$timestamp = Get-Date -DisplayHint Time
	"$timestamp $logstring0" | Out-File $logfile
	Write-Logfile $logstring1
	Write-Logfile "  $now"
	Write-Logfile $logstring0
}

}
Function Get-MPSMessageStats {
<#
.NOTES
Updated by Justin Beeden
V1.0 11.25.2013
    I have updated the original script by parameterizing it and adding support for Exchange 2013, including the option to include 2013 Health mailboxes. 
    Original script written by Rob Campbell
        http://blogs.technet.com/b/heyscriptingguy/archive/2011/03/02/use-powershell-to-track-email-messages-in-exchange-server.aspx
.SYNOPSIS
Checks Message Tracking Logs and pulls message statistics for an Exchange Organization.  Works on Exchange 2007 and later.
By default does not include messages for the Exchange 2013 Health Mailboxes, use the Include2013HealthMailboxes to include them in report.
.DESCRIPTION
Checks Message Tracking Logs and pulls message statistics for an Exchange Organization.  Works on Exchange 2007 and later.
By default does not include messages for the Exchange 2013 Health Mailboxes, use the Include2013HealthMailboxes to include them in report.
.PARAMETER DaysToGoBack
Specifies the amount of days to go back and search through the Message Tracking Logs.
.PARAMETER IncludeDistListStats
Optional parameter that will add an additional exported csv containing statistcics for Distribution List usage.
.PARAMETER Include2013HealthMailboxes
Optional parameter that will include the Exchange 2013 Health Mailboxes used by Managed Availabilty in the exported csv report.
.EXAMPLE
PS> .\GetMessageStatsToFile.ps1 -DaysToGoBack 30
Searches the past 30 days of Message Tracking Logs. Message Trackign logs are kept for 30 days by default on all transport servers.
.EXAMPLE
PS> .\GetMessageStatsToFile.ps1 -DaysToGoBack 15 -IncludeDistListStats
Searches the past 15 days of Message Tracking Logs. Also exports optional DistListStats csv.
#>

#Requires -version 2.0

Param(
    [Parameter(Position=0, Mandatory = $true,
    HelpMessage="Enter the number of days to go back and search message tracking log files.")]
    [int]$DaysToGoBack,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDistListStats,

    [Parameter(Mandatory = $false)]
    [switch]$Include2013HealthMailboxes
)
$rundate = $(Get-Date).toshortdatestring()
$startdate = $((Get-Date).adddays(-$DaysToGoBack)).toshortdatestring()

$outfile_date = ([datetime]$rundate).tostring("yyyy_MM_dd") 
$outfile = "$DaysToGoBack" + "DaysMessageStats_" + $outfile_date + ".csv"
 
$dloutfile = "DistListStats_" + $outfile_date +".csv"
 
$accepted_domains = Get-AcceptedDomain |Foreach {$_.domainname.domain} 
[regex]$dom_rgx = "`(?i)(?:" + (($accepted_domains |% {"@" + [regex]::escape($_)}) -join "|") + ")$" 
 
$mbx_servers = Get-ExchangeServer |Where {$_.serverrole -match "Mailbox"}|Foreach {$_.fqdn} 
[regex]$mbx_rgx = "`(?i)(?:" + (($mbx_servers |Foreach {"@" + [regex]::escape($_)}) -join "|") + ")\>$" 
 
$msgid_rgx = "^\<.+@.+\..+\>$" 
 
$hts = Get-TransportServer -WarningAction SilentlyContinue | Foreach {$_.name} 
 
$exch_addrs = @{} 
$msgrec = @{} 
$bytesrec = @{} 
$msgrec_exch = @{} 
$bytesrec_exch = @{} 
$msgrec_smtpext = @{} 
$bytesrec_smtpext = @{} 
$total_msgsent = @{} 
$total_bytessent = @{} 
$unique_msgsent = @{} 
$unique_bytessent = @{} 
$total_msgsent_exch = @{} 
$total_bytessent_exch = @{} 
$unique_msgsent_exch = @{} 
$unique_bytessent_exch = @{} 
$total_msgsent_smtpext = @{} 
$total_bytessent_smtpext = @{} 
$unique_msgsent_smtpext=@{} 
$unique_bytessent_smtpext = @{} 
$dl = @{} 
 
$obj_table = { 
@" 
        Date = $rundate 
        User = $($address.split("@")[0]) 
        Domain = $($address.split("@")[1]) 
        Sent Total = $(0 + $total_msgsent[$address]) 
        Sent MB Total = $("{0:F2}" -f $($total_bytessent[$address]/1mb)) 
        Received Total = $(0 + $msgrec[$address]) 
        Received MB Total = $("{0:F2}" -f $($bytesrec[$address]/1mb)) 
        Sent Internal = $(0 + $total_msgsent_exch[$address]) 
        Sent Internal MB = $("{0:F2}" -f $($total_bytessent_exch[$address]/1mb)) 
        Sent External = $(0 + $total_msgsent_smtpext[$address]) 
        Sent External MB = $("{0:F2}" -f $($total_bytessent_smtpext[$address]/1mb)) 
        Received Internal = $(0 + $msgrec_exch[$address]) 
        Received Internal MB = $("{0:F2}" -f $($bytesrec_exch[$address]/1mb)) 
        Received External = $(0 + $msgrec_smtpext[$address]) 
        Received External MB = $("{0:F2}" -f $($bytesrec_smtpext[$address]/1mb)) 
        Sent Unique Total = $(0 + $unique_msgsent[$address]) 
        Sent Unique MB Total = $("{0:F2}" -f $($unique_bytessent[$address]/1mb)) 
        Sent Internal Unique  = $(0 + $unique_msgsent_exch[$address])  
        Sent Internal Unique MB = $("{0:F2}" -f $($unique_bytessent_exch[$address]/1mb)) 
        Sent External  Unique = $(0 + $unique_msgsent_smtpext[$address]) 
        Sent External Unique MB = $("{0:F2}" -f $($unique_bytessent_smtpext[$address]/1mb)) 
"@ 
} 
 
$props = $obj_table.ToString().Split("`n")|% {if ($_ -match "(.+)="){$matches[1].trim()}} 
 
$stat_recs = @() 
 
function time_pipeline { 
    param ($increment  = 1000) 
        begin{$i=0;$timer = [diagnostics.stopwatch]::startnew()} 
        process { 
            $i++ 
            if (!($i % $increment)){Write-host �`rProcessed $i in $($timer.elapsed.totalseconds) seconds� -nonewline} 
            $_ 
            } 
        end { 
            write-host �`rProcessed $i log records in $($timer.elapsed.totalseconds) seconds� 
            Write-Host "   Average rate: $([int]($i/$timer.elapsed.totalseconds)) log recs/sec." 
            } 
} 
 
foreach ($ht in $hts){ 
 
    Write-Host "`nStarted processing $ht" 
 
    get-messagetrackinglog -Server $ht -Start "$startdate" -End "$rundate 11:59:59 PM" -resultsize unlimited | 
    time_pipeline |%{ 
     
    If ($Include2013HealthMailboxes){ 
        if ($_.eventid -eq "DELIVER" -and $_.source -eq "STOREDRIVER"){ 
     
            if ($_.messageid -match $mbx_rgx -and $_.sender -match $dom_rgx) { 
             
                $total_msgsent[$_.sender] += $_.recipientcount 
                $total_bytessent[$_.sender] += ($_.recipientcount * $_.totalbytes) 
                $total_msgsent_exch[$_.sender] += $_.recipientcount 
                $total_bytessent_exch[$_.sender] += ($_.totalbytes * $_.recipientcount) 
         
                foreach ($rcpt in $_.recipients){ 
                $exch_addrs[$rcpt] ++ 
                $msgrec[$rcpt] ++ 
                $bytesrec[$rcpt] += $_.totalbytes 
                $msgrec_exch[$rcpt] ++ 
                $bytesrec_exch[$rcpt] += $_.totalbytes 
                } 
             
            }  
            else { 
                if ($_.messageid -match $msgid_rgx){ 
                        foreach ($rcpt in $_.recipients){ 
                            $msgrec[$rcpt] ++ 
                            $bytesrec[$rcpt] += $_.totalbytes 
                            $msgrec_smtpext[$rcpt] ++ 
                            $bytesrec_smtpext[$rcpt] += $_.totalbytes 
                        } 
                    } 
         
                } 
                 
        }
    }
    Else {
          if ($_.eventid -eq "DELIVER" -and $_.source -eq "STOREDRIVER" -and $_.Recipients -notmatch "HealthMailbox"){ 
     
            if ($_.messageid -match $mbx_rgx -and $_.sender -match $dom_rgx) { 
             
                $total_msgsent[$_.sender] += $_.recipientcount 
                $total_bytessent[$_.sender] += ($_.recipientcount * $_.totalbytes) 
                $total_msgsent_exch[$_.sender] += $_.recipientcount 
                $total_bytessent_exch[$_.sender] += ($_.totalbytes * $_.recipientcount) 
         
                foreach ($rcpt in $_.recipients){ 
                $exch_addrs[$rcpt] ++ 
                $msgrec[$rcpt] ++ 
                $bytesrec[$rcpt] += $_.totalbytes 
                $msgrec_exch[$rcpt] ++ 
                $bytesrec_exch[$rcpt] += $_.totalbytes 
                } 
             
            }  
            else { 
                if ($_.messageid -match $msgid_rgx){ 
                        foreach ($rcpt in $_.recipients){ 
                            $msgrec[$rcpt] ++ 
                            $bytesrec[$rcpt] += $_.totalbytes 
                            $msgrec_smtpext[$rcpt] ++ 
                            $bytesrec_smtpext[$rcpt] += $_.totalbytes 
                        } 
                    } 
         
                } 
                 
        }
    } 
     
   If ($Include2013HealthMailboxes){  
    if ($_.eventid -eq "RECEIVE" -and $_.source -eq "STOREDRIVER"){ 
        $exch_addrs[$_.sender] ++ 
        $unique_msgsent[$_.sender] ++ 
        $unique_bytessent[$_.sender] += $_.totalbytes 
         
            if ($_.recipients -match $dom_rgx){ 
                $unique_msgsent_exch[$_.sender] ++ 
                $unique_bytessent_exch[$_.sender] += $_.totalbytes 
                } 
 
            if ($_.recipients -notmatch $dom_rgx){ 
                $ext_count = ($_.recipients -notmatch $dom_rgx).count 
                $unique_msgsent_smtpext[$_.sender] ++ 
                $unique_bytessent_smtpext[$_.sender] += $_.totalbytes 
                $total_msgsent[$_.sender] += $ext_count 
                $total_bytessent[$_.sender] += ($ext_count * $_.totalbytes) 
                $total_msgsent_smtpext[$_.sender] += $ext_count 
                $total_bytessent_smtpext[$_.sender] += ($ext_count * $_.totalbytes) 
                } 
                                
             
        }
        }
     Else{
            if ($_.eventid -eq "RECEIVE" -and $_.source -eq "STOREDRIVER" -and $_.Recipients -notmatch "HealthMailbox"){ 
        $exch_addrs[$_.sender] ++ 
        $unique_msgsent[$_.sender] ++ 
        $unique_bytessent[$_.sender] += $_.totalbytes 
         
            if ($_.recipients -match $dom_rgx){ 
                $unique_msgsent_exch[$_.sender] ++ 
                $unique_bytessent_exch[$_.sender] += $_.totalbytes 
                } 
 
            if ($_.recipients -notmatch $dom_rgx){ 
                $ext_count = ($_.recipients -notmatch $dom_rgx).count 
                $unique_msgsent_smtpext[$_.sender] ++ 
                $unique_bytessent_smtpext[$_.sender] += $_.totalbytes 
                $total_msgsent[$_.sender] += $ext_count 
                $total_bytessent[$_.sender] += ($ext_count * $_.totalbytes) 
                $total_msgsent_smtpext[$_.sender] += $ext_count 
                $total_bytessent_smtpext[$_.sender] += ($ext_count * $_.totalbytes) 
                }                                
            }        
        } 
         
    if ($_.eventid -eq "expand"){ 
        $dl[$_.relatedrecipientaddress] ++ 
        } 
    }      
     
} 
 
foreach ($address in $exch_addrs.keys){ 
 
    $stat_rec = (new-object psobject -property (ConvertFrom-StringData (&$obj_table))) 
    $stat_recs += $stat_rec | select $props 
} 
 
$stat_recs | export-csv $outfile -notype

Write-Host "Email stats file is $outfile" -ForegroundColor Green  
 
If ($IncludeDistListStats) { 
        If (Test-Path $dloutfile){ 
            $DL_stats = Import-Csv $dloutfile 
            $dl_list = $dl_stats | Foreach {$_.address} 
            } 
     
        else { 
            $dl_list = @() 
            $DL_stats = @() 
            } 
 
 
        $DL_stats | Foreach { 
            if ($dl[$_.address]){ 
                if ([datetime]$_.lastused -le [datetime]$rundate){  
                    $_.used = [int]$_.used + [int]$dl[$_.address] 
                    $_.lastused = $rundate 
                    } 
                } 
        } 
     
        $dl.keys | Foreach { 
            if ($dl_list -notcontains $_){ 
                $new_rec = "" | select Address,Used,Since,LastUsed 
                $new_rec.address = $_ 
                $new_rec.used = $dl[$_] 
                $new_rec.Since = $rundate 
                $new_rec.lastused = $rundate 
                $dl_stats += @($new_rec) 
            } 
        } 
 
        $dl_stats | Export-Csv $dloutfile -NoTypeInformation 

        Write-Host "DL usage stats file is $dloutfile" -ForegroundColor Green
}
}
Function Get-MPSDGInfo {
<# 
.SYNOPSIS 
    Gather exchange distribution group info and membership and feed back to parent script
        
                
.DESCRIPTION 
    No really. It's really really cool" 
.NOTES 
    Author     : Ryan Coates - ryan.coates@inquisitivegeek.com
    Attrib     : Based on code from Alan Byrne @ https://gallery.technet.microsoft.com/office/List-all-Users-Distribution-7f2013b2
.LINK 
    Homepage   : http://inquisitivegeek.com
    ScriptPage : https://github.com/ryandcoates/pds-powershell-pvt/blob/master/Get-DGInfo.ps1
#> 

Function Get-DGInfo {
    
    [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$OutputDir,
    
            [switch]$IncludeMembers
             )

    #Constant Variables
    $arrDLMembers = @{}
    $arrDGInfo = @()
    $arrDGMemberInfo = @()  

    
    #Get all Distribution Groups
    $objDistributionGroups = Get-DistributionGroup -ResultSize Unlimited
    ForEach ($objDistributionGroup in $objDistributionGroups){

                $objDistributionGroup = Get-DistributionGroup $objDistributionGroup.identity
                $objDGInfo = New-Object -TypeName PSObject
                $objDGInfo | Add-Member -MemberType NoteProperty -Name DGDisplayName -Value $objDistributionGroup.DisplayName
                $objDGInfo | Add-Member -MemberType NoteProperty -Name DGPrimarySMTP -Value $objDistributionGroup.PrimarySMTPAddress

                $arrDGInfo += $objDGInfo
    }
  
    If ($IncludeMembers -eq $true)
        {
            #Iterate through all groups, one at a time      
            Foreach ($objDistributionGroup in $objDistributionGroups) {      
     
                #Get members of this group  
                $objDGMembers = Get-DistributionGroupMember -Identity $($objDistributionGroup.PrimarySmtpAddress)  
      
                #Iterate through each member  
                Foreach ($objMember in $objDGMembers){
                  
                    $objDGMemberInfo = New-Object -TypeName PSObject
                    $objDGMemberInfo | Add-Member -MemberType NoteProperty -Name DGDisplayName -Value $objDistributionGroup.DisplayName
                    $objDGMemberInfo | Add-Member -MemberType NoteProperty -Name DGPrimarySMTP -Value $objDistributionGroup.PrimarySMTPAddress
                    $objDGMemberInfo | Add-Member -MemberType NoteProperty -Name DGMemberDisplayName -Value $objMember.DisplayName
                    $objDGMemberInfo | Add-Member -MemberType NoteProperty -Name DGMemberPrimarySMTP -Value $objMember.PrimarySMTPAddress
                    $objDGMemberInfo | Add-Member -MemberType NoteProperty -Name DGMemberType -Value $objMember.RecipientType

                    $arrDGMemberInfo += $objDGMemberInfo 
                }

                }


        }  

    $global:arrDGMemberInfo = $arrDGMemberInfo
    $global:arrDGInfo = $arrDGInfo
        
}
}
Function Get-MPSVirDirInfo {
#========================================================================================================
# Created on:   12/16/2012 09:30 PM
# Last Update:	06/06/2014 3:30 PM
# Created by:   Michael Van Horenbeeck
# Website:      http://www.vanhybrid.com
# Filename:     get-virdirinfo.ps1
# Version:      1.6
# Credits:      Thomas Torggler for some great ideas and remarks (@Torggler)
#               http://social.technet.microsoft.com/wiki/contents/articles/240.exchange-server-and-update-rollups-build-numbers.aspx
#
# Version History:  1.6     Will only discover MAPI virtual directory if servers are Exchange 2013 SP1+
#                           Added OWA and ECP authentication information, Autodiscover Site Scope, General Server info
#                           Script now also translates build number into version name
#                   1.5     Added check for the new MAPI virtual directory, added in Exchange 2013 SP1 (CU4),
#                           re-added WebServices Virtual Directory to script.
#                   1.4     Added "Last modified on"
#                   1.3     Added -Filter parameter, improved error handling in general, added warnings
#                           
#                	1.2     Added -ADPropertiesOnly parameter to speed up the script
#                   1.1		Fixed count error when only a single server exists
#					1.0		Initial Version
#========================================================================================================

<#
.Synopsis
   This script will create an HTML-report which will gather the URL-information from different virtual directories over different Exchange Servers (currently only Exchange 2010/Exchange 2013)
.DESCRIPTION
   This script will create an HTML-report which will gather the URL-information from different virtual directories over different Exchange Servers (currently only Exchange 2010/Exchange 2013)
.EXAMPLE
   . .\get-virdirinfo.ps1
   Get-VirDirInfo -filepath c:\reports

   This command will create the report in the following directory: C:\Reports
#>

function Get-VirDirInfo
{
    [CmdletBinding()]
    [OutputType([int])]
    Param
    (
        #Specify the report file path
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
                   [Alias("ReportPath")]
                   [ValidateNotNullOrEmpty()]
                   $Filepath,
        
        #query AD instead of the IIS metabase
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$false,
                   Position=1)]
                   [Alias("ADPropertiesOnly")]
                   [Switch]
                   $ADProperties,
        
        #specify the computername to connect to. Defaults to the local host.
        [Parameter(Mandatory=$false,
                   Position=1)]
                   [ValidateNotNull()]
                   [ValidateNotNullOrEmpty()]
                   [string]
                   $ComputerName = $env:COMPUTERNAME,

        #optional filter to only query certain CAS servers. Default filter is wildcard.
        [Parameter(Mandatory=$false,
                   Position=2)]
                   [ValidateNotNull()]
                   [ValidateNotNullOrEmpty()]
                   [string]
                   $Filter="*"

    )

    Begin
    {
        #Open a Remote PS session if none already exists.
	    if (!(Get-PSSession).ConfigurationName -eq "Microsoft.Exchange") {
            try {
                $sExch = New-PSSession -ConfigurationName Microsoft.Exchange -Name ExchMgmt -ConnectionUri http://$ComputerName/PowerShell/ -Authentication Kerberos 
	            $null = Import-PSSession $sExch
            } catch {
                Write-Warning "Could not connect to Exchange."
                Break
            }
        }

    }
    Process
    {
    	try{
            $servers = @(Get-ExchangeServer | ?{$_.ServerRole -like "*ClientAccess*" -and (($_.AdminDisplayVersion -like "*15*") -or ($_.AdminDisplayVersion -like "*14*") -and ($_.Name -like $Filter))} | Select-Object Name,AdminDisplayVersion,ServerRole,Edition)
        }
        catch{
            Write-Warning "An error occured: could not connect to one or more Exchange servers".
            Break
        }
        #Define Version Array

        $versionArray = @("Microsoft Exchange Server 2010 RTM","14.0.639.21"),
            ("Update Rollup 1 for Exchange Server 2010","14.0.682.1"),   
            ("Update Rollup 2 for Exchange Server 2010","14.0.689.0"),  
            ("Update Rollup 3 for Exchange Server 2010","14.0.694.0"),  
            ("Update Rollup 4 for Exchange Server 2010","14.0.702.1"),
            #Exchange 2010 SP1
            ("Microsoft Exchange Server 2010 SP1","14.1.218.15"),   
            ("Update Rollup 1 for Exchange Server 2010 SP1","14.1.255.2"),
            ("Update Rollup 2 for Exchange Server 2010 SP1","14.1.270.1"),   
            ("Update Rollup 3 for Exchange Server 2010 SP1","14.1.289.3"),
            ("Update Rollup 3-v3 for Exchange Server 2010 SP1","14.1.289.7"),
            ("Update Rollup 4 for Exchange Server 2010 SP1","14.1.323.1"),
            ("Update Rollup 4-v2 for  Exchange Server 2010 SP1","14.1.323.6"),
            ("Update Rollup 5 for  Exchange Server 2010 SP1","14.1.339.1"),
            ("Update Rollup 6 for  Exchange Server 2010 SP1","14.1.355.2"),
            ("Update Rollup 7 for  Exchange Server 2010 SP1","14.1.421.0"),
            ("Update Rollup 7-v2 for  Exchange Server 2010 SP1","14.1.421.2"),
            ("Update Rollup 7-v3 for Exchange Server 2010 SP1","14.1.421.3"),
            ("Update Rollup 8 for Exchange Server 2010 SP1","14.1.438.0"),
            #Exchange 2010 SP2
            ("Microsoft Exchange Server 2010 SP2","14.2.247.5"),
            ("Update Rollup 1 for Exchange Server 2010 SP2","14.2.283.3"),
            ("Update Rollup 2 for Exchange Server 2010 SP2","14.2.298.4"),
            ("Update Rollup 3 for Exchange Server 2010 SP2","14.2.309.2"),
            ("Update Rollup 4 for Exchange Server 2010 SP2","14.2.318.2"),
            ("Update Rollup 4-v2 for Exchange Server 2010 SP2","14.2.318.4"),
            ("Update Rollup 5 for Exchange Server 2010 SP2","14.2.328.5"),
            ("Update Rollup 5-v2 for Exchange Server 2010 SP2","14.2.328.10"),
            ("Update Rollup 6 for Exchange Server 2010 SP2","14.2.342.3"),
            ("Update Rollup 7 for Exchange Server 2010 SP2","14.2.375.0"),
            ("Update Rollup 8 for Exchange Server 2010 SP2","14.2.390.3"),
            #Exchange 2010 SP3
            ("Microsoft Exchange Server 2010 SP3","14.3.123.4"),
            ("Update Rollup 1 for Exchange Server 2010 SP3","14.3.146.0"),
            ("Update Rollup 2 for Exchange Server 2010 SP3","14.3.158.1"),
            ("Update Rollup 3 for Exchange Server 2010 SP3","14.3.169.1"),
            ("Update Rollup 4 for Exchange Server 2010 SP3","14.3.174.1"),
            ("Update Rollup 5 for Exchange Server 2010 SP3","14.3.181.6"),
            ("Update Rollup 6 for Exchange Server 2010 SP3","14.3.195.1"),
            #Exchange Exchange 2013
            ("Exchange Server 2013 Cumulative Update 1 (CU1)","15.0.620.29"),
            ("Exchange Server 2013 Cumulative Update 2 (CU2)","15.0.712.22"),
            ("Exchange Server 2013 Cumulative Update 2 (CU2-v2)","15.0.712.24"),
            ("Exchange Server 2013 Cumulative Update 3 (CU3)","15.0.775.38"),
            ("Exchange Server 2013 Service Pack 1 (SP1) (CU4)","15.0.847.32"),
            ("Exchange Server 2013 Service Pack 1 (SP1) (CU5)","15.0.913.22")

        #HTML headers
        $html += "<html>"
            $html += "<head>"
                $html += "<style type='text/css'>"
		    $html += "body {font-family:verdana;font-size:10pt}"
		    $html += "H1 {font-family:verdana;font-size:12pt}"
                    $html += "table {border:1px solid #000000;font-family:verdana; font-size:10pt;cellspacing:1;cellpadding:0}"
		    $html += "tr.color {background-color:#00A2E8;color:#FFFFFF;font-weight:bold}"
                $html += "</style>"
            $html += "</head>"
        $html += "<body>"

        #Report Legend
        $html += "Get-VirDirInfo.ps1<br/>"
        $html += "<b>Report generated on: </b>"+(get-date).DateTime
        
        #Add warning that the script pulled only the ADProperties
        if($ADProperties){
            $html += "<br/><b><font color='red'>Warning: The script was run using the -ADPropertiesOnly switch and might not show all information</font></b>"
        }
        $html += "<br/><br/>"

        #General Server Info

        $html += "<h1>General Client Access Server Information</h1>"
        $html += "<table border='1'>"
        $html += "<tr class='color'>"
        $html += "<td>Server</td><td>Exchange Version</td><td>Roles</td><td>Edition</td>"
        $html += "</tr>"
        
        $i=0
        foreach($server in $servers){
        $build = [string]$server.AdminDisplayVersion.Major+"."+$server.AdminDisplayVersion.Minor+"."+$server.AdminDisplayVersion.Build+"."+$server.AdminDisplayVersion.Revision
            for($n=0;$n -lt $versionArray.count; $n++){
                if($build -eq $versionArray[$n][1]){
                    $version = $versionArray[$n][0]
                }
            }
            
            $html += "<tr>"
             $html += "<td>"+$server.name+"</td>"
             $html += "<td>"+$version+"</td>"
             $html += "<td>"+$server.ServerRole+"</td>"
             $html += "<td>"+$server.Edition+"</td>"
            $html += "</tr>"
        }

        
        $html += "</table>"
        
        #Autodiscover
        $html += "<br/><br/>"
		$html += "<h1>Autodiscover</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Internal Uri</td><td>InternalURL</td><td>ExternalUrl</td><td>Auth. (Int.)</td><td>Auth. (Ext.)</td><td>Site Scope</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting Autodiscover URL information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
			$autodresult = Get-ClientAccessServer -Identity $server.name | Select Name,AutodiscoverServiceInternalUri,AutoDiscoverSiteScope
            if($ADProperties){
                $autodvirdirresult = Get-AutodiscoverVirtualDirectory -Server $server.name -ADPropertiesOnly | Select InternalUrl,ExternalUrl,InternalAuthenticationMethods,ExternalAuthenticationMethods,WhenChanged
            }
            else{
                $autodvirdirresult = Get-AutodiscoverVirtualDirectory -Server $server.name | Select InternalUrl,ExternalUrl,InternalAuthenticationMethods,ExternalAuthenticationMethods,WhenChanged
            }
            
			$autodhtml += "<tr>"
			$autodhtml += "<td>"+$autodresult.Name+"</td>"
            $autodhtml += "<td>"+$autodresult.AutodiscoverServiceInternalUri+"</td>"
			$autodhtml += "<td>"+$autodvirdirresult.InternalURL.absoluteURI+"</td>"
			$autodhtml += "<td>"+$autodvirdirresult.ExternalURL.absoluteURI+"</td>"
            $autodhtml += "<td>"+$autodvirdirresult.InternalAuthenticationMethods+"</td>"
			$autodhtml += "<td>"+$autodvirdirresult.ExternalAuthenticationMethods+"</td>"
            $autodhtml += "<td>"+$autodresult.AutoDiscoverSiteScope+"</td>"
            $autodhtml += "<td>"+$autodvirdirresult.WhenChanged+"</td>"
			$autodhtml += "</tr>"
			
			Clear-Variable -Name autodresult,autodvirdirresult
			
		}
		$html += $autodhtml
		$html += "</table>"

        #Outlook Web App (OWA)
        $html += "<br/><br/>"
		$html += "<h1>Outlook Web App (OWA):</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Name</td><td>InternalURL</td><td>ExternalUrl</td><td>Int. Auth.</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting OWA virtual directory information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
                $owaresult = Get-OWAVirtualDirectory -server $server.name -AdPropertiesOnly | Select Name,Server,InternalUrl,ExternalUrl,WhenChanged,InternalAuthenticationMethods
            }
            else{
                $owaresult = Get-OWAVirtualDirectory -server $server.name | Select Name,Server,InternalUrl,ExternalUrl,WhenChanged,InternalAuthenticationMethods
            }
			
			$owahtml += "<tr>"
			$owahtml += "<td>"+$owaresult.Server+"</td>"
			$owahtml += "<td>"+$owaresult.Name+"</td>"
			$owahtml += "<td>"+$owaresult.InternalURL.absoluteURI+"</td>"
			$owahtml += "<td>"+$owaresult.ExternalURL.absoluteURI+"</td>"
            $owahtml += "<td>"+$owaresult.InternalAuthenticationMethods+"</td>"
            $owahtml += "<td>"+$owaresult.WhenChanged+"</td>"
			$owahtml += "</tr>"
			
			Clear-Variable -Name owaresult
			
		}
		$html += $owahtml
		$html += "</table>"

        #Exchange Control Panel (ECP)
        $html += "<br/><br/>"
        $html += "<h1>Exchange Control Panel (ECP):</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Name</td><td>InternalURL</td><td>ExternalUrl</td><td>Int. Auth.</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting ECP virtual directory information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
			    $ecpresult = Get-ECPVirtualDirectory -server $server.name -ADPropertiesOnly | Select Name,Server,InternalUrl,ExternalUrl,WhenChanged,InternalAuthenticationMethods
            }
            else{
                $ecpresult = Get-ECPVirtualDirectory -server $server.name | Select Name,Server,InternalUrl,ExternalUrl,WhenChanged,InternalAuthenticationMethods
            }

			$ecphtml += "<tr.color>"
			$ecphtml += "<td>"+$ecpresult.Server+"</td>"
			$ecphtml += "<td>"+$ecpresult.Name+"</td>"
			$ecphtml += "<td>"+$ecpresult.InternalURL.absoluteURI+"</td>"
			$ecphtml += "<td>"+$ecpresult.ExternalURL.absoluteURI+"</td>"
            $ecphtml += "<td>"+$ecpresult.InternalAuthenticationMethods+"</td>"
            $ecphtml += "<td>"+$ecpresult.WhenChanged+"</td>"
			$ecphtml += "</tr>"

            Clear-Variable -Name ecpresult
		}
		$html += $ecphtml
		$html += "</table>"
   		
        #Outlook Anywhere
        $html += "<br/><br/>"
        $html += "<h1>Outlook Anywhere:</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Internal Hostname</td><td>External Hostname</td><td>Auth.(Int.)</td><td>Auth. (Ext.)</td><td>Auth. IIS</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting Outlook Anywhere Information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
			    $oaresult = Get-OutlookAnywhere -server $server.name -ADPropertiesOnly | Select Name,Server,InternalHostname,ExternalHostname,ExternalClientAuthenticationMethod,InternalClientAuthenticationMethod,IISAuthenticationMethods,WhenChanged
            }
            else{
                $oaresult = Get-OutlookAnywhere -server $server.name | Select Name,Server,InternalHostname,ExternalHostname,ExternalClientAuthenticationMethod,InternalClientAuthenticationMethod,IISAuthenticationMethods,WhenChanged
            }

            if($oaresult -eq $null){
            
                $oahtml += "<tr.color>"
                $oahtml += "<td>"+$server.name+"</td>"
                $oahtml += "<td colspan='6'>"
                $oahtml += "Outlook Anywhere isn't enabled."
                $oahtml += "</td>"
                $oahtml += "</tr>"
			    
            }
            else{
                $oahtml += "<tr.color>"
                $oahtml += "<td>"+$oaresult.Server+"</td>"
                $oahtml += "<td>"+$oaresult.InternalHostname+"</td>"
                $oahtml += "<td>"+$oaresult.ExternalHostname+"</td>"
                $oahtml += "<td>"+$oaresult.InternalClientAuthenticationMethod+"</td>"
                $oahtml += "<td>"+$oaresult.ExternalClientAuthenticationMethod+"</td>"
                $oahtml += "<td>"+$oaresult.IISAuthenticationMethods+"</td>"
                $oahtml += "<td>"+$oaresult.WhenChanged+"</td>"
                $oahtml += "</tr>"
            }


            Clear-Variable oaresult
		}
		$html += $oahtml
		$html += "</table>"

        #MAPI/HTTP
        $html += "<br/><br/>"
        $html += "<h1>MAPI/HTTP:</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Internal URL</td><td>External URL</td><td>Auth.(Int.)</td><td>Auth. (Ext.)</td><td>Auth. IIS</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            if($server.AdminDisplayVersion.Major -eq "15" -and $server.AdminDisplayVersion.Build -ge "847")
            {
               Write-Progress -Activity "Getting MAPI/HTTP Information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
               if($ADProperties){
			       $mapiresult = Get-MapiVirtualDirectory -server $server.name -ADPropertiesOnly | Select Name,Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,IISAuthenticationMethods,WhenChanged
               }
               else{
                   $mapiresult = Get-MapiVirtualDirectory -server $server.name | Select Name,Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,IISAuthenticationMethods,WhenChanged
               }

               $mapihtml += "<tr.color>"
			   $mapihtml += "<td>"+$mapiresult.Server+"</td>"
			   $mapihtml += "<td>"+$mapiresult.InternalUrl+"</td>"
			   $mapihtml += "<td>"+$mapiresult.ExternalUrl+"</td>"
               $mapihtml += "<td>"+$mapiresult.InternalAuthenticationMethods+"</td>"
			   $mapihtml += "<td>"+$mapiresult.ExternalAuthenticationMethods+"</td>"
               $mapihtml += "<td>"+$mapiresult.IISAuthenticationMethods+"</td>"
               $mapihtml += "<td>"+$mapiresult.WhenChanged+"</td>"
			   $mapihtml += "</tr>"
            }
            else{

			   $mapihtml += "<tr.color>"
               $mapihtml += "<td>"+$server.name+"</td>"
			   $mapihtml += "<td colspan='6'>"
               $mapihtml += "Server isn't running Exchange 2013 SP1 or later."
               $mapihtml += "</td>"
			   $mapihtml += "</tr>"
            }

            Clear-Variable oaresult
		}
		$html += $mapihtml
		$html += "</table>"    


        #Offline Address Book (OAB)
        $html += "<br/><br/>"
        $html += "<h1>Offline Address Book (OAB):</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>OABs</td><td>Internal URL</td><td>External Url</td><td>Auth.(Int.)</td><td>Auth. (Ext.)</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting OAB Information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
                $oabresult = Get-OABVirtualDirectory -server $server.name -ADPropertiesOnly | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,OfflineAddressBooks,WhenChanged
            }
            else{
                $oabresult = Get-OABVirtualDirectory -server $server.name | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,OfflineAddressBooks,WhenChanged
            }
			

			$oabhtml += "<tr.color>"
			$oabhtml += "<td>"+$oabresult.Server+"</td>"
            $oabhtml += "<td>"+$oabresult.OfflineAddressBooks+"</td>"
			$oabhtml += "<td>"+$oabresult.InternalURL.absoluteURI+"</td>"
			$oabhtml += "<td>"+$oabresult.ExternalURL.absoluteURI+"</td>"
            $oabhtml += "<td>"+$oabresult.InternalAuthenticationMethods+"</td>"
			$oabhtml += "<td>"+$oabresult.ExternalAuthenticationMethods+"</td>"
            $oabhtml += "<td>"+$oabresult.WhenChanged+"</td>"
			$oabhtml += "</tr>"

            Clear-Variable oabresult
		}
		$html += $oabhtml
		$html += "</table>"

        #ActiveSync (EAS)
        $html += "<br/><br/>"
        $html += "<h1>ActiveSync (EAS):</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Internal URL</td><td>External Url</td><td>Auth. (Ext.)</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting ActiveSync Information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
                $easresult = Get-ActiveSyncVirtualDirectory -server $server.name -ADPropertiesOnly | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,WhenChanged
            }
            else{
                $easresult = Get-ActiveSyncVirtualDirectory -server $server.name | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,WhenChanged
            }
			

			$eashtml += "<tr.color>"
			$eashtml += "<td>"+$easresult.Server+"</td>"
			$eashtml += "<td>"+$easresult.InternalURL.absoluteUri+"</td>"
			$eashtml += "<td>"+$easresult.ExternalURL.absoluteUri+"</td>"
			$eashtml += "<td>"+$easresult.ExternalAuthenticationMethods+"</td>"
            $eashtml += "<td>"+$easresult.WhenChanged+"</td>"
			$eashtml += "</tr>"

            Clear-Variable easresult
		}
		$html += $eashtml
		$html += "</table>"

        #Exchange Web Services (EWS)
        $html += "<br/><br/>"
        $html += "<h1>Exchange Web Services(EWS):</h1>"
		$html += "<table border='1'>"
		$html += "<tr class='color'>"
		$html += "<td>Server</td><td>Internal URL</td><td>External Url</td><td>Auth. (Int.)</td><td>Auth. (Ext.)</td><td>MRS Proxy Enabled</td><td>Last modified on:</td>"
		$html += "</tr>"
		$i=0
		foreach($server in $servers){
            $i++
            Write-Progress -Activity "Getting Web Services Information" -Status "Progress:"-PercentComplete (($i / $servers.count)*100)
            if($ADProperties){
                $ewsresult = Get-WebServicesVirtualDirectory -server $server.name -ADPropertiesOnly | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,MRSProxyEnabled,WhenChanged
            }
            else{
                $ewsresult = Get-WebServicesVirtualDirectory -server $server.name | Select Server,InternalUrl,ExternalUrl,ExternalAuthenticationMethods,InternalAuthenticationMethods,MRSProxyEnabled,WhenChanged
            }
			

			$ewshtml += "<tr.color>"
			$ewshtml += "<td>"+$ewsresult.Server+"</td>"
			$ewshtml += "<td>"+$ewsresult.InternalURL.absoluteUri+"</td>"
			$ewshtml += "<td>"+$ewsresult.ExternalURL.absoluteUri+"</td>"
            $ewshtml += "<td>"+$ewsresult.InternalAuthenticationMethods+"</td>"
			$ewshtml += "<td>"+$ewsresult.ExternalAuthenticationMethods+"</td>"
            $ewshtml += "<td>"+$ewsresult.MRSProxyEnabled+"</td>"
            $ewshtml += "<td>"+$ewsresult.WhenChanged+"</td>"
			$ewshtml += "</tr>"

            Clear-Variable easresult
		}
		$html += $ewshtml
		$html += "</table>"



		$html | Out-File $filepath"\virdirinfo_"$(get-date -Format d-MM-yyyy_HH\hmm\mss\s)".html"
    }
    End
    {
		Get-PSSession | ?{$_.ComputerName -like "$server"} | Remove-PSSession
		Clear-Variable Owahtml
		Clear-Variable Owaresult
		Clear-Variable html
    }
}
}
Function Get-MPSEAPReport {
Get-Mailbox -ResultSize Unlimited -Filter {EmailAddressPolicyEnabled -eq $false} |ft name, alias, emailaddresspolicyenabled, PrimarySmtpAddress  >> Report.txt
}
Function Get-MPSPublicFolderReplicationReport {
<#
.SYNOPSIS
Generates a report for Exchange 2010 Public Folder Replication.
.DESCRIPTION
This script will generate a report for Exchange 2010 Public Folder Replication. It returns general information, such as total number of public folders, total items in all public folders, total size of all items, the top 10 largest folders, and more. Additionally, it lists each Public Folder and the replication status on each server. By default, this script will scan the entire Exchange environment in the current domain and all public folders. This can be limited by using the -ComputerName and -FolderPath parameters.
.PARAMETER ComputerName
This parameter specifies the Exchange 2010 server(s) to scan. If this is omitted, all Exchange servers with the Mailbox role in the current domain are scanned.
.PARAMETER FolderPath
This parameter specifies the Public Folder(s) to scan. If this is omitted, all public folders are scanned.
.PARAMETER Recurse
When used in conjunction with the FolderPath parameter, this will include all child Public Folders of the Folders listed in Folder Path.
.PARAMETER AsHTML
Specifying this switch will have this script output HTML, rather than the result objects. This is independent of the Filename or SendEmail parameters and only controls the console output of the script.
.PARAMETER Filename
Providing a Filename will save the HTML report to a file.
.PARAMETER SendEmail
This switch will set the script to send an HTML email report. If this switch is specified, then the To, From and SmtpServers are required.
.PARAMETER To
When SendEmail is used, this sets the recipients of the email report.
.PARAMETER From
When SendEmail is used, this sets the sender of the email report.
.PARAMETER SmtpServer
When SendEmail is used, this is the SMTP Server to send the report through.
.PARAMETER Subject
When SendEmail is used, this sets the subject of the email report.
.PARAMETER NoAttachment
When SendEmail is used, specifying this switch will set the email report to not include the HTML Report as an attachment. It will still be sent in the body of the email.
#>
param(
    [string[]]$ComputerName = @(),
    [string[]]$FolderPath = @(),
    [switch]$Recurse,
    [switch]$AsHTML,
    [string]$Filename,
    [switch]$SendEmail,
    [string[]]$To,
    [string]$From,
    [string]$SmtpServer,
    [string]$Subject,
    [switch]$NoAttachment
)

# Validate parameters
if ($SendEmail)
{
    [array]$newTo = @()
    foreach($recipient in $To)
    {
        if ($recipient -imatch "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z0-9.-]+$")
        {
            $newTo += $recipient
        }
    }
    $To = $newTo
    if (-not $To.Count -gt 0)
    {
        Write-Error "The -To parameter is required when using the -SendEmail switch. If this parameter was used, verify that valid email addresses were specified."
        return
    }
    
    if ($From -inotmatch "^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z0-9.-]+$")
    {
        Write-Error "The -From parameter is not valid. This parameter is required when using the -SendEmail switch."
        return
    }

    if ([string]::IsNullOrEmpty($SmtpServer))
    {
        Write-Error "You must specify a SmtpServer. This parameter is required when using the -SendEmail switch."
        return
    }
    if ((Test-Connection $SmtpServer -Quiet -Count 2) -ne $true)
    {
        Write-Error "The SMTP server specified ($SmtpServer) could not be contacted."
        return
    }
}

if (-not $ComputerName.Count -gt 0)
{
    [array]$ComputerName = @()
    Get-ExchangeServer | Where-Object { $_.ServerRole -ilike "*Mailbox*" } | % { $ComputerName += $_.Name }
}

# Build a list of public folders to retrieve
if ($Recurse)
{
    [array]$newFolderPath = @()
    foreach($srv in $ComputerName)
    {
        foreach($f in $FolderPath)
        {
            Get-PublicFolder $f -Recurse | ForEach-Object { if ($newFolderPath -inotcontains $_.Identity) { $newFolderPath += $_.Identity } }
        }
    }
    $FolderPath = $newFolderPath
}

# Get statistics for all public folders on all selected servers
# This is significantly faster than trying to get folders one by one by name
[array]$publicFolderList = @()
[array]$nameList = @()
foreach($server in $ComputerName)
{ 
    $pfOnServer = $null
    $pfOnServer = Get-PublicFolderStatistics -Server $server -ResultSize Unlimited -ErrorAction SilentlyContinue
    $pfOnServer.FolderPath
    if ($FolderPath.Count -gt 0)
    {
        $pfOnServer = $pfOnServer | Where-Object { $FolderPath -icontains "\$($_.FolderPath)" }
    }
    if ($pfOnServer -eq $null) { continue }
    $publicFolderList += New-Object PSObject -Property @{"ComputerName" = $server; "PublicFolderStats" = $pfOnServer}
    $pfOnServer | Foreach-Object { if ($nameList -inotcontains $_.FolderPath) { $nameList += $_.FolderPath } }
}
if ($nameList.Count -eq 0)
{
    Write-Error "There are no public folders in the specified servers."
    return
}
$nameList = [array]$nameList | Sort-Object
[array]$ResultMatrix = @()
foreach($folder in $nameList)
{ 
    $resultItem = @{}
    $maxBytes = 0
    $maxSize = $null
    $maxItems = 0
    foreach($pfServer in $publicFolderList)
    { 
        $pfData = $pfServer.PublicFolderStats | Where-Object { $_.FolderPath -eq $folder }
        if ($pfData -eq $null) { Write-Verbose "Skipping $pfServer.CompuerName for $folder"; continue }
        if (-not $resultItem.ContainsKey("FolderPath"))
        {
            $resultItem.Add("FolderPath", "\$($pfData.FolderPath)")
        }
        if (-not $resultItem.ContainsKey("Name"))
        {
            $resultItem.Add("Name", $pfData.Name)
        }
        if ($resultItem.Data -eq $null)
        {
            $resultItem.Data = @()
        }
        $currentItems = $pfData.ItemCount
        $currentSize = $pfData.TotalItemSize.Value
        
        if ($currentItems -gt $maxItems)
        {
            $maxItems = $currentItems
        }
        if ($currentSize.ToBytes() -gt $maxBytes)
        {
            $maxSize = $currentSize
            $maxBytes = $currentSize.ToBytes()
        }
        $resultItem.Data += New-Object PSObject -Property @{"ComputerName" = $pfServer.ComputerName;"TotalItemSize" = $currentSize; "ItemCount" = $currentItems}
    }
    $resultItem.Add("TotalItemSize", $maxSize)
    $resultItem.Add("TotalBytes", $maxBytes)
    $resultItem.Add("ItemCount", $maxItems)
    $replCheck = $true
    foreach($dataRecord in $resultItem.Data)
    {
        if ($maxItems -eq 0)
        {
            $progress = 100
        } else {
            $progress = ([Math]::Round($dataRecord.ItemCount / $maxItems * 100, 0))
        }
        if ($progress -lt 100)
        {
            $replCheck = $false
        }
        $dataRecord | Add-Member -MemberType NoteProperty -Name "Progress" -Value $progress
    }
    $resultItem.Add("ReplicationComplete", $replCheck)
    $ResultMatrix += New-Object PSObject -Property $resultItem
    if (-not $AsHTML)
    {
        New-Object PSObject -Property $resultItem
        
    }
}

if ($AsHTML -or $SendEmail -or $Filename -ne $null)
{
    $html = @"
<html>
<style>
body
{
font-family:Arial,sans-serif;
font-size:8pt;
}
table
{
border-collapse:collapse;
font-size:8pt;
font-family:Arial,sans-serif;
border-collapse:collapse;
min-width:400px;
}
table,th, td
{
border: 1px solid black;
}
th
{
text-align:center;
font-size:18;
font-weight:bold;
}
</style>
<body>
<font size="1" face="Arial,sans-serif">
<h1 align="center">Exchange Public Folder Replication Report</h1>
<h4 align="center">Generated $([DateTime]::Now)</h3>

</font><h2>Overall Summary</h2>
<table border="0" cellpadding="3">
<tr style="background-color:#B0B0B0"><th colspan="2">Public Folder Environment Summary</th></tr>
<tr><td>Servers Selected for this Report</td><td>$($ComputerName -join ", ")</td></tr>
<tr><td>Servers Selected with Public Folders Present</td><td>$(
$serverList = @()
$publicFolderList | ForEach-Object { $serverList += $_.ComputerName }
$serverList -join ", "
)</td></tr>
<tr><td>Number of Public Folders</td><td>$($TotalCount = $ResultMatrix.Count; $TotalCount)</td></tr>
<tr><td>Total Size of Public Folders</td><td>$(
$totalSize = $null
$ResultMatrix | Foreach-Object { $totalSize += $_.TotalItemSize }
$totalSize
)</td></tr>
<tr><td>Average Folder Size</td><td>$($totalSize / $TotalCount)</td></tr>
<tr><td>Total Number of Items in Public Folders</td><td>$(
$totalItemCount = $null
$ResultMatrix | Foreach-Object { $totalItemCount += $_.ItemCount }
$totalItemCount
)</td></tr>
<tr><td>Average Folder Item Count</td><td>$([Math]::Round($totalItemCount / $TotalCount, 0))</td></tr>
</table>
<br />
<table border="0" cellpadding="3">
<tr style="background-color:#B0B0B0"><th colspan="4">Folders with Incomplete Replication</th></tr>
<tr style="background-color:#E9E9E9;font-weight:bold"><td>Folder Path</td><td>Item Count</td><td>Size</td><td>Servers with Replication Incomplete</td></tr>
$(
[array]$incompleteItems = $ResultMatrix | Where-Object { $_.ReplicationComplete -eq $false }
if (-not $incompleteItems.Count -gt 0)
{
    "<tr><td colspan='4'>There are no public folders with incomplete replication.</td></tr>"
} else {
    foreach($result in $incompleteItems)
    {
        "<tr><td>$($result.FolderPath)</td><td>$($result.ItemCount)</td><td>$($result.TotalItemSize)</td><td>$(($result.Data | Where-Object { $_.Progress -lt 100 }).ComputerName -join ", ")</td></tr>`r`n"
    }
}
)
</table>
<br />
<table border="0" cellpadding="3">
<tr style="background-color:#B0B0B0"><th colspan="3">Largest Public Folders</th></tr>
<tr style="background-color:#E9E9E9;font-weight:bold"><td>Folder Path</td><td>Item Count</td><td>Size</td></tr>
$(
[array]$largestItems = $ResultMatrix | Sort-Object TotalItemSize -Descending | Select-Object -First 10
if (-not $largestItems.Count -gt 0)
{
    "<tr><td colspan='3'>There are no public folders in this report.</td></tr>"
} else {
    foreach($sizeResult in $largestItems)
    {
        "<tr><td>$($sizeResult.FolderPath)</td><td>$($sizeResult.ItemCount)</td><td>$($sizeResult.TotalItemSize)</td></tr>`r`n"
    }
}
)
</table>

</font><h2>Public Folder Replication Results</h2>
<table border="0" cellpadding="3">
<tr style="background-color:#B0B0B0"><th colspan="$($publicFolderList.Count + 1)">Public Folder Replication Information</th></tr>
<tr style="background-color:#E9E9E9;font-weight:bold"><td>Folder Path</td>
$(
foreach($rServer in $publicFolderList)
{
    "<td>$($rServer.ComputerName)</td>"
}
)
</tr>
$(
if (-not $ResultMatrix.Count -gt 0)
{
    "<tr><td colspan='$($publicFolderList.Count + 1)'>There are no public folders in this report.</td></tr>"
}
foreach($rItem in $ResultMatrix)
{
    "<tr><td>$($rItem.FolderPath)</td>"
    foreach($rServer in $publicFolderList)
    {
        $(
        $rDataItem = $rItem.Data | Where-Object { $_.ComputerName -eq $rServer.ComputerName }
        if ($rDataItem -eq $null)
        {
            "<td>N/A</td>"
        } else {
            if ($rDataItem.Progress -ne 100)
            {
                $color = "#FC2222"
            } else {
                $color = "#A9FFB5"
            }
            "<td style='background-color:$($color)'><div title='$($rDataItem.TotalItemSize) of $($rItem.TotalItemSize) and $($rDataItem.ItemCount) of $($rItem.ItemCount) items.'>$($rDataItem.Progress)%</div></td>"
        }
        )
    }
    "</tr>"
}
)
</table>
</body>
</html>
"@
}

if ($AsHTML)
{
    $html
}

if (-not [string]::IsNullOrEmpty($Filename))
{
    $html | Out-File $Filename
}

if ($SendEmail)
{
    if ([string]::IsNullOrEmpty($Subject))
    {
        $Subject = "Public Folder Environment Report"
    }
    if ($NoAttachment)
    {
        Send-MailMessage -SmtpServer $SmtpServer -BodyAsHtml -Body $html -From $From -To $To -Subject $Subject
    } else {
        if (-not [string]::IsNullOrEmpty($Filename))
        {
            $attachment = $Filename
        } else {
            $attachment = "$($Env:TEMP)\Public Folder Report - $([DateTime]::Now.ToString("MM-dd-yy")).html"
            $html | Out-File $attachment
        }
        Send-MailMessage -SmtpServer $SmtpServer -BodyAsHtml -Body $html -From $From -To $To -Subject $Subject -Attachments $attachment
        Remove-Item $attachment -Confirm:$false -Force
    }
}
}

