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

Function Connect-O365 {
<# 
.SYNOPSIS 
    Connect to all o365 powershell endpoints in a single command
.DESCRIPTION 
    Connect-o365
    
.NOTES 
    Author     : Ryan Coates - ryan.coates@inquisitivegeek.com
.LINK 
    Homepage   : http://inquisitivegeek.com
    ScriptPage : https://github.com/ryandcoates/rdc-powershell-pub/blob/master/Office365Connectivity.ps1
    ScriptRAW  : https://github.com/ryandcoates/rdc-powershell-pub/raw/master/Office365Connectivity.ps1
#>        

# Write out starting ErrorActionPreference prior to changing 
$startErrorAction = $erroractionpreference
$ea = "SilentlyContinue"
Write-Host "$ea"

$o365Creds = Get-Credential # Get your 365 credentials for all connections
 
$MSOLModname = "MSOnline"
If ((Test-ModuleAvailableToLoad $MSOLModname) -eq $true){
    Write-Host "Importing $MSOLModname" -ForegroundColor Green
    Import-Module $MSOLModname
    Write-Host "Connecting to MSOL" -ForegroundColor Green
    Connect-MsolService -Credential $o365Creds}
Else {Write-Warning "Unable to connect to MSOL"}


$SPModName = "Microsoft.Online.SharePoint.PowerShell"
If ((Test-ModuleAvailableToLoad $SPModName) -eq $true){
    Write-Host "Importing $SPModName" -ForegroundColor Green
    Import-Module $SPModName -DisableNameChecking
    Write-Host "Connecting to SPOnline"
    Connect-SPOService -Url https://biib-admin.sharepoint.com -credential $o365Creds}
Else {Write-Warning "Unable to connect to SPOnline"}
 
$SFBModName = "LyncOnlineConnector"
If ((Test-ModuleAvailableToLoad $SFBModName) -eq $true){
    Write-Host "Importing $SFBModName"
    Import-Module $SFBModName
    $o365sfboSession = New-CsOnlineSession -Credential $o365Creds -OverrideAdminDomain "biib.onmicrosoft.com" .\@edptoastimage.png
    Write-Host "Connecting to Skype for Business Online" -ForegroundColor Green
    Import-PSSession $o365sfboSession}
Else {Write-Warning "Unable to connect to Skype for Business Online"}
 

$o365exchangeSession = New-PSSession -Name "o365Exchange" -ConfigurationName Microsoft.Exchange -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -Credential $o365Creds -Authentication "Basic" -AllowRedirection
Write-Host "Connecting to Exchange Online" -ForegroundColor Green
Import-PSSession $o365exchangeSession -DisableNameChecking -Prefix eo
 

$o365ccSession = New-PSSession -Name "o365Protect" -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.compliance.protection.outlook.com/powershell-liveid/" -Credential $o365Creds -Authentication "Basic" -AllowRedirection
Write-Host "Connecting to Exchange Online Protection" -ForegroundColor Green
Import-PSSession $o365ccSession -Prefix eop

# Return ErrorActionPreference to start value
$ErrorActionPreference = $startErrorAction
}

Function Disconnect-O365{
Try{
    Remove-PSSession -Name "o365*"; Disconnect-SPOService
}
    Catch {}
}
