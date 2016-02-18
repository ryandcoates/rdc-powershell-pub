Function Test-ModuleAvailableToLoad {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]$modname
    )

    $modtest = (Get-Module -ListAvailable $modname)
    If ($modtest -eq $null){
        Return $null}
    Else{
        Return $true}
}

Function Disconnect-O365{
Try{
    Remove-PSSession -Name "o365*"; Disconnect-SPOService
}
    Catch {}
}

Function Get-Connecto365Prereq{
    #[CmdletBinding()]
    #Param(
    #[Parameter(Mandatory=$true)]
    #[string]$value
    #)
    
    $outputpath = "c:\temp\connectto365prereq"
    If (!(Test-Path $outputpath)){
        New-Item -ItemType Directory $outputpath
    }
    Else{Write-Output "Path already exists"}
    
    # .NET Framework 4.5.2 Offline Installer URL
    # https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe
    
    # Microsoft Online Services Sign-In Assistant for IT Professionals RTW URL
    # https://download.microsoft.com/download/5/0/1/5017D39B-8E29-48C8-91A8-8D0E4968E6D4/en/msoidcli_64.msi
    
    # Sharepoint Online Management Shell URL
    # https://download.microsoft.com/download/0/2/E/02E7E5BA-2190-44A8-B407-BC73CA0D6B87/sharepointonlinemanagementshell_4915-1200_x64_en-us.msi
    
    # Skype for Business Online Windows PowerShell Module URL
    # https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowershell.exe
    
    $dlPath = (Join-Path $outputpath -ChildPath "NDP452-KB2901907-x86-x64-AllOS-ENU.exe")
    Invoke-WebRequest -Uri https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe -OutFile $dlPath
    
    $dlPath = (Join-Path $outputpath -ChildPath "msoidcli_64.msi")
    Invoke-WebRequest -Uri https://download.microsoft.com/download/5/0/1/5017D39B-8E29-48C8-91A8-8D0E4968E6D4/en/msoidcli_64.msi -OutFile $dlPath
    
    $dlPath = (Join-Path $outputpath -ChildPath "sharepointonlinemanagementshell_4915-1200_x64_en-us.msi")
    Invoke-WebRequest -Uri https://download.microsoft.com/download/0/2/E/02E7E5BA-2190-44A8-B407-BC73CA0D6B87/sharepointonlinemanagementshell_4915-1200_x64_en-us.msi -OutFile $dlPath
    
    $dlPath = (Join-Path $outputpath -ChildPath "SkypeOnlinePowershell.exe")
    Invoke-WebRequest -Uri https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowershell.exe -OutFile $dlPath
    
    Write-Output "Prerequesites downloaded to $outputpath"
    Invoke-Item $outputpath 
}

Function Connect-O365 {
<# 
.SYNOPSIS 
    Connect to all o365 powershell endpoints in a single command
.DESCRIPTION 
    Connect-o365
    
.NOTES 
    Author     : Ryan Coates - ryan.coates@inquisitivegeek.com
    Attrib     : Steve @ PowerShell Blogger for original codebase
.LINK 
    Homepage   : http://inquisitivegeek.com
    ScriptPage : https://github.com/ryandcoates/rdc-powershell-pub/blob/master/Office365Connectivity.ps1
    ScriptRAW  : https://github.com/ryandcoates/rdc-powershell-pub/raw/master/Office365Connectivity.ps1
#>        
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$false)]
    [string]$client,
    [switch]$getprereq
    )

# Write out starting ErrorActionPreference prior to changing 
$startErrorAction = $erroractionpreference
$ea = "SilentlyContinue"
$clientURLPrefix = "?DelegatedOrg="
$clientURL = $ClientURLPrefix +$Client

# Define module names to test against
$MSOLModname = "MSOnline"
$SPModName = "Microsoft.Online.SharePoint.PowerShell"
$SFBModName = "LyncOnlineConnector"

# Test module for existence 
$SPTrue = Test-ModuleAvailableToLoad $SPModName
$SFBTrue = Test-ModuleAvailableToLoad $SFBModName
$MSOLTrue = Test-ModuleAvailableToLoad $MSOLModName

############################################################################
#           PreReq Operation, Grab all Pre-Reqs and dump to directory      #
############################################################################

If ($getprereq -eq $true){
    Get-ConnectO365PreReq
    Break
} 
 
############################################################################
#              Standard Operation, Connect to available modules            #
############################################################################

# Import Credentiials from user
$o365Creds = Get-Credential # Get your 365 credentials for all connections

If ($MSOLTrue -eq $true){
    Write-Host "Importing $MSOLModname" -ForegroundColor Green
    Import-Module $MSOLModname
    Write-Host "Connecting to MSOL" -ForegroundColor Green
    Connect-MsolService -Credential $o365Creds}
Else {Write-Warning "MSOL module is not present, use ./Connect-o365 -getprereq"}


If ($SPTrue -eq $true){
    Write-Host "Importing $SPModName" -ForegroundColor Green
    Import-Module $SPModName -DisableNameChecking
    Write-Host "Connecting to SPOnline"
    Connect-SPOService -Url https://biib-admin.sharepoint.com -credential $o365Creds}
Else {Write-Warning "SPOnline module is not present, use ./Connect-o365 -getprereq"}
 

If ($SFBTrue -eq $true){
    Write-Host "Importing $SFBModName"
    Import-Module $SFBModName
    $o365sfboSession = New-CsOnlineSession -Credential $o365Creds -OverrideAdminDomain "biib.onmicrosoft.com"
    Write-Host "Connecting to Skype for Business Online" -ForegroundColor Green
    Import-PSSession $o365sfboSession}
Else {Write-Warning "Skype for Business Online module is not present, use ./Connect-o365 -getprereq"}
 

$o365exchangeSession = New-PSSession -Name "o365Exchange" -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $o365Creds -Authentication "Basic" -AllowRedirection
Write-Host "Connecting to Exchange Online" -ForegroundColor Green
Import-PSSession $o365exchangeSession -DisableNameChecking -Prefix eo
 

$o365ccSession = New-PSSession -Name "o365Protect" -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.compliance.protection.outlook.com/powershell-liveid/" -Credential $o365Creds -Authentication "Basic" -AllowRedirection
Write-Host "Connecting to Exchange Online Protection" -ForegroundColor Green
Import-PSSession $o365ccSession -Prefix eop

# Return ErrorActionPreference to start value
$ErrorActionPreference = $startErrorAction
}

