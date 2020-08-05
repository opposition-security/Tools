##########################################################################################################################################
## PowerShell script to collect Windows Active Directory data for audit testing                                                         ##
## Script Version: 1.0                                                                                                                  ##
## Authors: Opposition Security                                                                                                         ##
## Contact: https://www.oppositionsecurity.com                                                                                          ##
##########################################################################################################################################

# Setup HTML Head tag
$header = @"
<style>
  h1 {
    font-family: Arial, Helvetica, sans-serif;
    color: #e68a00;
    font-size: 28px;
    font-weight: 500;
  }

  h2 {

    font-family: Arial, Helvetica, sans-serif;
    color: #e68a00;
    font-size: 18px;
    font-weight: 500;
}

h3 {

  font-family: Arial, Helvetica, sans-serif;
  color: #e68a00;
  font-size: 16px;
  font-weight: 400;
}

table {
font-size: 14px;
border: 0px; 
font-family: Arial, Helvetica, sans-serif;
} 

td {
padding: 4px;
margin: 0px;
border: 0;
}

hr {
  border: 1px solid #e68a00;
}

body {
  font-size: 14px;
  font-weight: bold;
  background-color: #000;
  color: #FFF;
}

a {
  color: #e68a00;
}

</style>
"@

# Get testing credential
$Cred = Get-Credential -UserName domain\user -Message 'Enter Password'

# Prompt for CSV file of computer names
Function Get-FileName($InitialDirectory)
{
  [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

  $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
  $OpenFileDialog.initialDirectory = $initialDirectory
  $OpenFileDialog.filter = "CSV (*.csv) | *.csv"
  $OpenFileDialog.ShowDialog() | Out-Null
  $OpenFileDialog.FileName
}

$Path = Get-FileName
$computerData = Get-Content $Path

# Retrieve local administrators members from computer
function Get-LocalAdministrators {
  param ($strcomputer)

  $admins = Get-WmiObject win32_groupuser -ComputerName $strcomputer
  $admins = $admins | Where-Object {$_.groupcomponent -like '*"Administrators"'}

  $allAdmins = $admins | ForEach-Object {
    $_.partcomponent -match ".+Domain\=(.+)\,Name\=(.+)$" > $nul
    $matches[1].trim('"') + "\" + $matches[2].trim('"')
  }

  return $allAdmins
}
#Set Report Header
$ReportTitle = ConvertTo-Html -Fragment -PreContent "<h1>Active Directory Audit Report</h1>Audit Date: $(Get-Date)<hr>"

# Check Active Directory Password Policy
$ADPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Current LoggedOnUser -Credential $Cred | ConvertTo-Html -As List -Property ComplexityEnabled,DistinguishedName,LockoutDuration,LockoutObservationWindow,LockoutThreshold,MaxPasswordAge,MinPasswordAge,MinPasswordLength,PasswordHistoryCount,ReversibleEncryptionEnabled -Fragment -PreContent "<h2>Domain Password Policy</h2>"

# Retrieve members from enterprise & domain administrators groups
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive | ForEach-Object{Get-ADUser -Identity $_.distinguishedName} | Select-Object Name, Enabled, PasswordLastSet | ConvertTo-Html -As List -Fragment -PreContent "<h2>Domain Administrators</h2>"
$EnterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive | ForEach-Object{Get-ADUser -Identity $_.distinguishedName} | Select-Object Name, Enabled, PasswordLastSet | ConvertTo-Html -As List -Fragment -PreContent "<h2>Enterprise Administrators</h2>"

# Loop through provided CSV of computer names to collect data
$computerNameHeader = ConvertTo-Html -Fragment -PreContent "<p></p><hr><h1>Computer Testing Results</h1>"

$computerReport = ''
$ErrorReport = ''
foreach ($computer in $computerData) {
    $wmi = Get-WmiObject Win32_Bios -ComputerName $computer -ErrorAction SilentlyContinue
    #Test-Connection $computer -Quiet -Count 1    

    if($wmi) {
      $Workstationheader = ConvertTo-Html -PreContent "<h2>Workstation Details</h2>"    
      #$ComputerName = $computer | ConvertTo-Html -As List -Fragment -PreContent "<h3>Computer Name</h3>"
      $ComputerName = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computer | ConvertTo-Html -As List -Property Name -Fragment

      # Gather operating system version
      $OS = Get-WmiObject -query "SELECT * FROM Win32_OperatingSystem" -ComputerName $computer -Credential $Cred | Select-Object Caption -ExpandProperty Caption
      #$OS = Get-WmiObject -query "SELECT * FROM Win32_OperatingSystem" -ComputerName $computer | Select-Object Caption -ExpandProperty Caption
      $OSVer = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computer | ConvertTo-Html -As List -Property Caption -Fragment
  
      # Get local administrators
      $allAdmins = Get-LocalAdministrators $computer

      $LocalAdmins = ConvertTo-Html -PreContent "<h3>Local Administrators</h3>"
      ConvertTo-Html -InputObject $allAdmins

      # Check for Server or Client OS
      $OSValidate = $OS -Match "Server"
      if ($OSValidate) {
        $OS2019 = $OS -Match "2019"
        $OS2016 = $OS -Match "2016"
        $OS2012 = $OS -Match "2012"

        if ($OS2019) {
          # Get endpoint security information
          $EndPointHeader = ConvertTo-Html -PreContent "<h3>Endpoint Security Status</h3>"
          $AVStatus = Get-MpComputerStatus -CimSession $computer | Select-Object -Property AntivirusEnabled -ExpandProperty AntivirusEnabled
          if ($AVStatus -eq $false) {
            $EndPointState = "Endpoint Security Status Reporting: Disabled or Not Installed"
            ConvertTo-Html -InputObject $EndPointState
          }
          else {
            $EndPointState = "Endpoint Security Status Reporting: Installed"
            ConvertTo-Html -InputObject $EndPointState
          }

          # Get drive encryption status
          $BitLockerStatus = "BitLocker Status not assessed, Windows Server detected"
          ConvertTo-Html -InputObject $BitLockerStatus
        }

        elseif ($OS2016) {
          # Get endpoint security information
          $EndPointHeader = ConvertTo-Html -PreContent "<h3>Endpoint Security Status</h3>"  
          $AVStatus = Get-MpComputerStatus -CimSession $computer | Select-Object -Property AntivirusEnabled -ExpandProperty AntivirusEnabled
          if ($AVStatus -eq $false) {
            $EndPointState = "Endpoint Security Status Reporting: Disabled or Not Installed"
            ConvertTo-Html -InputObject $EndPointState
          }
          else {
            $EndPointState = "Endpoint Security Status Reporting: Installed"
            ConvertTo-Html -InputObject $EndPointState
          }

          # Get drive encryption status
          $BitLockerStatus = "BitLocker Status not assessed, Windows Server detected"
          ConvertTo-Html -InputObject $BitLockerStatus
        }

        elseif ($OS2012) {
          # Get endpoint security information
          $EndPointHeader = ConvertTo-Html -PreContent "<h3>Endpoint Security Status</h3>"
          $EndPointState = "Windows Server 2012 Detected - Check manually or third-party console"
          ConvertTo-Html -InputObject $EndPointState

          # Get drive encryption status
          $BitLockerStatus = "BitLocker Status not assessed, Windows Server detected"
          ConvertTo-Html -InputObject $BitLockerStatus
        }

        else {
          $EndPointState = "Windows Server version is end of life"
          ConvertTo-Html -InputObject $EndPointState

          # Get drive encryption status
          $BitLockerStatus = "Windows Server version is end of life"
          ConvertTo-Html -InputObject $BitLockerStatus
        }
      }

      else {
        # Get endpoint security information
        $EndPointHeader = ConvertTo-Html -PreContent "<h3>Endpoint Security Status</h3>"  
        # Get endpoint security product state
        $AVProductStates = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ComputerName $computer | Select-Object productState -ExpandProperty productState

        foreach ($AVProductState in $AVProductStates) {
          $AVProducts = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ComputerName $computer | Select-Object productState -ExpandProperty displayName | Where-Object productState -eq $AVProductState
          
          # Convert product state to HEX
          $pStateHex = "0x{0:x}" -f $AVProductState
          $productStateVal = $pStateHex.Substring(3, 2)

          if ($productStateVal -eq 10) {
            $EndPointState = $AVProducts + " Endpoint Security Status Reporting: Enabled - Current"
            ConvertTo-Html -InputObject $EndPointState             
          }
          elseif ($productStateVal -eq 11) {
            $EndPointState = $AVProducts + " Endpoint Security Status: Enabled - Out of Date"
            ConvertTo-Html -InputObject $EndPointState          
          }
          else {
            $EndPointState = $AVProducts + " Endpoint Security Status Reporting: Disabled or Not Installed"
            ConvertTo-Html -InputObject $EndPointState
          }
        }
        
        # Get BitLocker Status
        $BitLockerHeader = ConvertTo-Html -PreContent "<h3>BitLocker Drive Encryption Status</h3>"
    
        # Get drive encryption status
        $BitLockerStatus = Manage-BDE -ComputerName $computer -Status C: | Select-String "Conversion Status","Protection Status"
        ConvertTo-Html -InputObject $BitLockerStatus
      }

      $endComputerReport = ConvertTo-Html -PreContent "<p><hr>"

      $computerReport += "$Workstationheader $ComputerName $OSVer $LocalAdmins $allAdmins $EndPointHeader $EndPointState $BitLockerHeader $BitLockerStatus $endComputerReport"
    }

  else {    
    $ErrorReport += $computer + " Not reachable, check WMI settings"
    $ErrorReport += ConvertTo-Html -PreContent "<br>"    
  }
}
# Add errors
$ErrorHeader = ConvertTo-Html -PreContent "<h1>Errors</h1>" 
ConvertTo-Html -InputObject $ErrorReport

$Report = ConvertTo-Html -Body "$ReportTitle $ADPasswordPolicy $DomainAdmins $EnterpriseAdmins $computerNameHeader $computerReport $ErrorHeader $ErrorReport $endComputerReport" `
-Title "SOC2 Active Directory Testing Report" -Head $header -PostContent "<p>$([char]0x00A9)2020 <a href='https://www.oppositionsecurity.com'>Opposition Security</a></p>"

# Write report to HTML file
$Report | Out-File .\SOC2-AD-Testing-Report.html
