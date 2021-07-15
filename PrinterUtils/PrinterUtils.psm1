<#
	.NOTES
		Author: Max Kozlov
#>
Set-StrictMode -Version Latest
Add-Type -IgnoreWarnings -TypeDefinition @"
namespace PrinterUtils {
	[System.FlagsAttribute]
	public enum AccessPermissions
	{
		ManagePrinters = 983052,
		ManageDocuments = 983088,
		Print = 131080,
		TakeOwnership = 524288,
		ReadPermission = 131072,
		ChangePermission = 262144,
		Generic_Read = -2147483648,
		Generic_Write = 0x40000000,
		Generic_Execute = 0x20000000,
		Generic_All = 0x10000000,
		SACL_Access = 0x08000000
	}
	public class PrinterPermission {
		public string Name;
		public string SID;
		public string Domain;
		public int AceFlags;
		public int AccessMask;
		public System.Security.AccessControl.AccessControlType AceType;
		public AccessPermissions Permission;
	}
	public class PrinterInfo {
		public string Name;
		public string ComputerName;
		public bool Shared;
		public string ShareName;
		public string DriverName;
		public string PortName;
		public string Location;
		public string Comment;
		public int PrinterState;
		public int PrinterStatus;
		public string Owner;
		public PrinterPermission[] Permissions;
	}
}
"@
function Get-PrinterInfo {
[CmdletBinding(
	DefaultParameterSetName="Name",
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
[OutputType('PrinterUtils.PrinterInfo')]
param(
	[Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0, ParameterSetName="Info")]
	[PrinterUtils.PrinterInfo]$Printer,
	[Alias('ServerName')]
	[Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0, ParameterSetName="Name")]
	[Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0, ParameterSetName="Port")]
	[String[]]$ComputerName = '.',
	[string][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1, ParameterSetName="Name")]$PrinterName = "",
	[string][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1, ParameterSetName="Port")]$PortName = ""
)
	PROCESS {
		if ($Printer) {
			$ComputerName = $Printer.ComputerName
			$PortName = $Printer.PortName
		}
		$Filter = "local = '$True'"
		if ($PrinterName) { $Filter = ("Name like '{0}'" -f $PrinterName) }
		if ($PortName) { $Filter = ("PortName like '{0}'" -f $PortName) }
		Write-Verbose ('Searching "{0}" with filter "{1}"' -f ($ComputerName -join ', '), $Filter)
		$p = @(Get-WmiObject Win32_Printer -ComputerName $ComputerName -Filter $Filter -ErrorAction Continue) | Where-Object { $_.Local }
		if ($p -eq $null) { return }
		$p | ForEach-Object {
			Write-Verbose ("  found {0} @ {1}" -f $_.Name, $_.PortName)
			$sd = $null
			if ('XPSPort:','nul:' -notcontains $_.PortName) {
				$sd = $_.GetSecurityDescriptor()
			}
			$po = New-Object -TypeName PrinterUtils.PrinterInfo -Property @{
					Name = $_.Name; ComputerName = $_.SystemName
					Shared = $_.Shared; ShareName = $_.ShareName
					DriverName = $_.DriverName;	PortName = $_.PortName
					Location = $_.Location; Comment = $_.Comment
					PrinterState = $_.PrinterState; PrinterStatus = $_.PrinterStatus
					Permissions = New-Object -TypeName PrinterUtils.AccessPermissions[] 0
				}
			if (($sd -ne $null) -and ($sd.Descriptor -ne $null))
			{
				$po.Owner = $sd.Descriptor.Owner.Name
				$th = @{}
				$t = $sd.Descriptor.DACL | ForEach-Object{
					$k = if ($_.Trustee.Name) { $_.Trustee.Name } else {$_.Trustee.SIDString}
					$th[$k] += ,[PrinterUtils.AccessPermissions]$_.AccessMask
					New-Object -TypeName PrinterUtils.PrinterPermission -Property @{
						Name = $_.Trustee.Name; SID = $_.Trustee.SIDString; Domain = $_.Trustee.Domain
						AceFlags = $_.AceFlags; AccessMask = $_.AccessMask; AceType = $_.AceType
						Permission = [PrinterUtils.AccessPermissions]$_.AccessMask
					}
				} | sort Name
				$po.Permissions = $t
			}
			$po
		}
	}
}
function New-PrinterPermission {
[OutputType('PrinterUtils.PrinterPermission')]
param(
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0, ParameterSetName="User")]$UserName,
	[System.Security.AccessControl.AccessControlType][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="User")]$AccessType,
	[PrinterUtils.AccessPermissions[]][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=2, ParameterSetName="User")]$AccessRights
)
	$ud = $UserName -split '\\'
	if ($ud.length -eq 1) {
		$ud += $ud[0]
		$ud[0] = $env:UserDomain
	}
	
	foreach ($ar in $AccessRights)
	{
		$af = 0
		if ($ar -eq 'ManageDocuments') { $af = 9 }
		New-Object -TypeName PrinterUtils.PrinterPermission -Property @{
			Name = $ud[1]; Domain = $ud[0]
			SID = (New-Object Security.Principal.NTAccount $ud[0], $ud[1]).Translate([Security.Principal.SecurityIdentifier])
			AceFlags = $af; AceType = $AccessType
			AccessMask = [int]$ar; Permission = $ar
		}
	}
}
function Add-PrinterPermission {
[OutputType('PrinterUtils.PrinterInfo')]
[CmdletBinding(
	DefaultParametersetName="Perm",
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]$Printer,
	[PrinterUtils.PrinterPermission[]][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Perm")]$Permissions,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="User")]$UserName,
	[System.Security.AccessControl.AccessControlType][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=2, ParameterSetName="User")]$AccessType,
	[PrinterUtils.AccessPermissions[]][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=3, ParameterSetName="User")]$AccessRights
)
	PROCESS
	{
		if ($PSCmdlet.ParameterSetName -ne "Perm") {
			$Permissions = @(New-PrinterPermission $UserName $AccessType $AccessRights)
		}
		if ($Permissions.length -gt 0) {
			$Printer.Permissions += $Permissions
		}
		$Printer
	}
}
function Remove-PrinterPermission {
[OutputType('PrinterUtils.PrinterInfo')]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]$Printer,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1)]$UserName
)
	PROCESS
	{
		$ud = $UserName -split '\\'
		if ($ud.length -eq 1) {
			$ud += $ud[0]
			$ud[0] = $env:UserDomain
		}
		$Printer.Permissions = $Printer.Permissions | ? { $_.Name -ne $ud[1] }
		$Printer
	}
}

function New-SecurityDescriptor {
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0)]$Printer
)
	$SD = ([WMIClass] "Win32_SecurityDescriptor").CreateInstance()
	$SD.ControlFlags = 0x0004
	$ace = ([WMIClass] "Win32_Ace").CreateInstance()
	$Trustee = ([WMIClass] "Win32_Trustee").CreateInstance()
	foreach ($perm in $Printer.Permissions) {
		$SID = New-Object Security.Principal.SecurityIdentifier($perm.SID)
		[byte[]] $SIDArray = ,0 * $SID.BinaryLength
		$SID.GetBinaryForm($SIDArray,0)
		$Trustee.Name = $perm.Name
		$Trustee.Domain = $perm.Domain
		$Trustee.SID = $SIDArray
		$ace.AccessMask = $perm.AccessMask
		$ace.AceType = $perm.AceType
		$ace.AceFlags = $perm.AceFlags
		$ace.Trustee = $Trustee
		$SD.DACL += @($ace.psobject.baseobject)
		# устанавливаем флаг SE_DACL_PRESENT, что будет говорить о том, что мы изменяем
		# только DACL и ничего более
	}
	$SD
}

function Set-PrinterInfo {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]$Printer,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$Location = $false,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$Comment = $false,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$Permissions = $false,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$Sharing = $false,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$PortName = $false,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false)]$All = $false
)
	PROCESS {
		$Prn = Get-WmiObject Win32_Printer -ComputerName $Printer.ComputerName -Filter ("Name = '{0}'" -f $Printer.Name )
		if ($Prn) {
			Write-Verbose ("Processing: {0} on {1} " -f $Printer.Name, $Printer.ComputerName)
			if ($All) {
				$Location = $Comment = $Sharing = $Permissions = $PortName = $true
			}
			if ($PortName) {
				$prn.PortName = $Printer.PortName
				Write-Verbose (" Set PortName to '{0}'" -f $Printer.PortName)
			}
			if ($Location) {
				$prn.Location = $Printer.Location
				Write-Verbose (" Set Location to '{0}'" -f $Printer.Location)
			}
			if ($Comment) {
				$prn.Comment = $Printer.Comment
				Write-Verbose (" Set Comment to '{0}'" -f $Printer.Comment)
			}
			if ($Sharing) {
				$prn.Shared = $Printer.Shared
				$prn.ShareName = $Printer.ShareName
				Write-Verbose (" Set Sharing to {0}/'{1}'" -f $Printer.Shared, $Printer.ShareName)
			}
			if ($Permissions) {
				$perm = $Printer.Permissions | Select-Object -expand Name | Sort-Object -Unique
				Write-Verbose (" Set Permissions for '{0}'" -f ($perm -join ','))
				$SD = New-SecurityDescriptor $Printer
			}
			
			if ($PSCmdlet.ShouldProcess($Printer.ComputerName,"Set PrinterInfo for '{0}'" -f $Printer.Name)) {
				if ($Location -or $Comment -or $Sharing -or $PortName) {
					Write-Verbose ($Prn.Put())
				}
				if ($Permissions) {
					$result = $Prn.SetSecurityDescriptor($SD)
					$errortext = switch ($result.ReturnValue)
						{
							"0" {"Success"}
							"2" {"Access Denied"}
							"8" {"Unknown Error"}
							"9" {"The user does not have adequate privileges to execute the method"}
							"21" {"A parameter specified in the method call is invalid"}
							default {"Unknown error {0}" -f $result.ReturnValue }
						}
					if ($result.ReturnValue -eq 0) {
						Write-Verbose ("{0}: {1}" -f $result.ReturnValue, $errortext)
					}
					else {
						Write-Warning ("{0}: {1}" -f $result.ReturnValue, $errortext)
					}
				}
			}
		} else {
			Write-Warning ("Skipping non-present printer: {0}" -f $Printer.Name)
		}
	}
}

function Set-PrinterPermissions {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]$Printer,
	[string[]][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1)]$Target
)
	PROCESS
	{
		if (-not $Target) {
			Set-PrinterInfo -Printer $Printer -Permissions
		}
		else {
			Get-PrinterInfo -ComputerName $Target -PrinterName $Printer.Name |
			%{ $_.Permissions = $Printer.Permissions; $_ } | Set-PrinterInfo -Permissions
		}
	}
}

function New-PrinterTCPPort {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1)]$PortName,
	[String][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=2)]$IPAddress
)
BEGIN {
	if (-Not $IPAddress) { $IPAddress = $PortName }
}
PROCESS {
	Write-Verbose ("Creating TCP/IP Printer Port '{0}' ({1}) on '{2}'" -f $PortName, $IPAddress, $ComputerName)
	##?? This works for both win7, 2008, w2k3.
	$PortClass = Get-WMIObject -ComputerName $ComputerName -Class Win32_TCPIPPrinterPort -List
	#$PortClass = ([WMICLASS]"\\$ComputerName\ROOT\cimv2:Win32_TCPIPPrinterPort")
	$PortClass.PSBase.Scope.Options.EnablePrivileges = $true
	#$PortClass.PSBase.Scope.Options.Username="domain\user"
	#$PortClass.PSBase.Scope.Options.Password="P@xxxxxx"

	$NewPort = $PortClass.CreateInstance()
	$NewPort.PSBase.Scope.Options.EnablePrivileges = $true
	$NewPort.Name = $PortName
	$NewPort.HostAddress = $IPAddress
	$NewPort.Protocol = 1 #1=RAW (default) 2=LPR
	if ($PSCmdlet.ShouldProcess($ComputerName,"New TCP/IP Printer Port '{0}'" -f $PortName)) {
		$NewPort.Put()
	}
}
}
function Get-PrinterTCPPort {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName='Obj')]
	[System.Management.ManagementBaseObject]$InputObject,
	[Alias('ServerName','Server', 'PSComputerName')]
	[Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipeLineByPropertyName=$true, Position=0, ParameterSetName='Name')]
	[string]$ComputerName = '.',
	[Alias('Name')]
	[Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1, ParameterSetName='Name')]
	[string]$PortName,
	[Alias('HostAddress','HostName')]
	[Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=2, ParameterSetName='Name')]
	[string]$IPAddress
)
BEGIN {
	$Filter = @()
	if ($PortName) {
		$Filter += "(Name like '{0}')" -f $PortName
	}
	if ($IPAddress) {
		$Filter += "(HostName like '{0}')" -f $IPAddress
	}
	$Filter = $Filter -join ' AND '
}
PROCESS {
	if ($InputObject) {
		Write-Verbose ('Get TCP Port from {0} with object name={1}' -f $InputObject.PSComputerName, $InputObject.Name)
		Get-WmiObject -ComputerName $ComputerName -Class Win32_TCPIPPrinterPort -Filter ("(Name like '{0}')" -f $InputObject.Name)
	}
	else {
		Write-Verbose ('Get TCP Ports from {0} with filter {1}' -f $ComputerName, $Filter)
		Get-WmiObject -ComputerName $ComputerName -Class Win32_TCPIPPrinterPort -Filter $Filter
	}
}
}

function Remove-PrinterTCPPort {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="High"
)]
param(
	[Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName='Obj')]
	[System.Management.ManagementBaseObject]$InputObject,
	[Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName='Name')]
	[Alias('Server', 'PSComputerName')]
	[String]$ComputerName,
	[Alias('Name')]
	[Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName='Name')]
	[String]$PortName
)
PROCESS {
	if ($InputObject) {
		$PortName = $InputObject.Name
		$ComputerName = $InputObject.PSComputerName
	}
	else {
		$InputObject = Get-WmiObject -ComputerName $ComputerName -Class Win32_TCPIPPrinterPort -Filter ("(Name like '{0}')" -f $PortName)
	}
	if ($PSCmdlet.ShouldProcess($ComputerName,"Remove TCP/IP Printer Port '{0}'" -f $PortName)) {
			$InputObject | Remove-WmiObject
	}
}
}

function New-PrinterLocalPort {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0)]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1)]$PortName
)
	Write-Verbose ("Open registry on '{0}'" -f $ComputerName)
	if ($ComputerName -eq '.') {
		$reg = [Microsoft.Win32.Registry]::LocalMachine
	}
	else {
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
	}
	if ($reg -ne $null) {
		try {
			$regKey= $reg.OpenSubKey("Software\Microsoft\Windows NT\CurrentVersion\Ports",$true)
			if ($regkey -ne $null) {
				try {
					$portnames = $regKey.GetValueNames()
					if ($portnames -contains $PortName) {
						Write-Verbose ("Local Printer Port '{0}' on '{1}' already exists" -f $PortName, $ComputerName)
						# writeout portname
						return $PortName
					}
					else {
						# add port
						Write-Verbose ("Local Printer Port '{0}' on '{1}' not found, adding..." -f $PortName, $ComputerName)
						if ($PSCmdlet.ShouldProcess($ComputerName,("Creating Local Printer Port '{0}'" -f $PortName))) {
							[void]$regKey.SetValue($PortName, '')
							$spooler = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter 'Name="spooler"'
							if ($spooler) {
								Write-Verbose ("Stopping Spooler service on '{0}'" -f $ComputerName)
								[void]$spooler.StopService()
								Write-Verbose ("Starting Spooler service on '{0}'" -f $ComputerName)
								[void]$spooler.StartService()
							}
							else {
								Write-Warning ("Cannot restart Spooler on '{0}'" -f $PortName, $ComputerName)
							}
						}
						return $PortName
					}
				}
				finally {
					$regKey.Close()
				}
			}
		}
		finally {
			$reg.Close()
		}
	}
}

function Remove-PrinterLocalPort {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0)]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1)]$PortName
)
	Write-Verbose ("Open registry on '{0}'" -f $ComputerName)
	if ($ComputerName -eq '.') {
		$reg = [Microsoft.Win32.Registry]::LocalMachine
	}
	else {
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
	}
	if ($reg -ne $null) {
		try {
			$regKey= $reg.OpenSubKey("Software\Microsoft\Windows NT\CurrentVersion\Ports",$true)
			if ($regkey -ne $null) {
				try {
					$portnames = $regKey.GetValueNames()
					if ($portnames -notcontains $PortName) {
						Write-Verbose ("Local Printer Port '{0}' on '{1}' does not exists" -f $PortName, $ComputerName)
						# writeout portname
						return $PortName
					}
					else {
						# remove port
						Write-Verbose ("Local Printer Port '{0}' on '{1}' found, removing..." -f $PortName, $ComputerName)
						if ($PSCmdlet.ShouldProcess($ComputerName,("Removing Local Printer Port '{0}'" -f $PortName))) {
							[void]$regKey.DeleteValue($PortName, $false)
							$spooler = Get-WmiObject -ComputerName $ComputerName -Class Win32_Service -Filter 'Name="spooler"'
							if ($spooler) {
								Write-Verbose ("Stopping Spooler service on '{0}'" -f $ComputerName)
								[void]$spooler.StopService()
								Write-Verbose ("Starting Spooler service on '{0}'" -f $ComputerName)
								[void]$spooler.StartService()
							}
							else {
								Write-Warning ("Cannot restart Spooler on '{0}'" -f $PortName, $ComputerName)
							}
						}
						return $PortName
					}
				}
				finally {
					$regKey.Close()
				}
			}
		}
		finally {
			$reg.Close()
		}
	}
}

function Rename-Printer {
[CmdletBinding(
	DefaultParametersetName="Prn",
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String[]][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Comp")]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName,
	[String]$NewName
)
	PROCESS {
		if ($PSCmdlet.ParameterSetName -eq "Prn") {
			$ComputerName = $Printer.ComputerName
			$PrinterName = $Printer.Name
		}
		$Prn = Get-WmiObject Win32_Printer -ComputerName $ComputerName -Filter ("Name = '{0}'" -f $PrinterName )
		if ($Prn) {
			$Prn | %{
				Write-Verbose ("  Processing: {0} - " -f $PrinterName)
				if ($PSCmdlet.ShouldProcess($_.__SERVER,("Rename Printer '{0}' to '{1}'" -f $PrinterName, $NewName))) {
					$result = $_.RenamePrinter($NewName)
				}
				$errortext = switch ($result.ReturnValue)
				{
					"0" {"Success"}
					"2" {"Access Denied"}
					"8" {"Unknown Error"}
					"9" {"The user does not have adequate privileges to execute the method"}
					"21" {"A parameter specified in the method call is invalid"}
					default {"Unknown error {0}" -f $result.ReturnValue }
				}
				if ($result.ReturnValue -eq 0) {
					Write-Verbose ("{0}: {1}" -f $result.ReturnValue, $errortext)
				}
				else {
					Write-Warning ("{0}: {1}" -f $result.ReturnValue, $errortext)
				}
				$result.ReturnValue
			}
		} else {
			Write-Warning ("Skipping non-present printer: {0}" -f $Printer.Name)
		}
	}
}

function Remove-Printer {
[CmdletBinding(
	DefaultParametersetName="Prn",
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String[]][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Comp")]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName
)
	PROCESS {
		#Write-Host ("Parameterset: {0}" -f $PSCmdlet.ParameterSetName)
		if ($PSCmdlet.ParameterSetName -eq "Prn") {
			$ComputerName = $Printer.ComputerName
			$PrinterName = $Printer.Name
		}
		Write-Verbose ('Searching printer ''{0}'' on ''{1}''' -f $PrinterName, $ComputerName)
		$Prn = Get-WmiObject Win32_Printer -ComputerName $ComputerName -Filter ("Name = '{0}'" -f $PrinterName )
		if ($Prn) {
			$Prn | %{
				if ($PSCmdlet.ShouldProcess($_.__SERVER,"Remove Printer '{0}'" -f $PrinterName)) {
					$result = $_.CancelAllJobs()
					if ($result.ReturnValue -ne 0) {
						Write-Error ('Cannot clear printer jobs on printer ''{0}'' on ''{1}'' - error {2}' -f $PrinterName, $ComputerName, $result.ReturnValue)
					}
					else {
						$_.Delete()
					}
				}
			}
		} else {
			Write-Warning ("Skipping non-present printer: {0}" -f $PrinterName)
		}
	}
}

function Copy-Printer {
[CmdletBinding(
	DefaultParametersetName="Prn",
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
[OutputType('PrinterUtils.PrinterInfo')]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0, ParameterSetName="Comp")]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName,
	[String[]][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=2)]$TargetComputerName,
	[Alias('DriverPath')]
	[String][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=3)]$InfPath = ''
)
	if ($PSCmdlet.ParameterSetName -ne "Prn") {
		$Printer = Get-PrinterInfo -ComputerName $ComputerName -PrinterName $PrinterName
		if (!($Printer))
		{
			Write-Error ("Can't find source printer {0} on {1}" -f $PrinterName, $ComputerName)
			return
		}
	}
	if ($Printer -and $Printer.Name) {
		$cmd = (Get-Command RunDll32.exe)
		foreach ($TargetComputer in $TargetComputerName) {
			if ($TargetComputer -eq $Printer.ComputerName) {
				Write-Warning ('Printer.ComputerName and TargetComputerName is the same - {0}, skipping...' -f $TargetComputer)
				continue
			}
			Write-Host ('Creating {0} printer on {1}' -f $Printer.Name, $TargetComputer) -ForegroundColor Green
			$PortName = $Printer.PortName
			if ($PortName -match '^LPT\d+$') {
				#standart local port
				Write-Warning ('skipping standart port ({0}) creation on {1}, assume it exists' -f $PortName, $TargetComputer)
			}
			elseif ($PortName -match '^\\\\[\w\.\-]+\\') {
				#local lanman port
				$port = New-PrinterLocalPort -ComputerName $TargetComputer -PortName $PortName
				if ($port -eq $null) {
					Write-Error ("Cannot create new local port {0}, skipping {1}" -f $PortName, $ComputerName)
				}
			}
			else {
				$port = @(Get-WmiObject -Class Win32_TCPIPPrinterPort -ComputerName $TargetComputer -Filter "HostAddress='$($Printer.PortName)'")
				if (($port.Count -eq 1) -and ($port[0].Name -ne $port[0].HostAddress)) {
					Write-Warning ('Non-standart port name - {0} instead of {1}' -f $port[0].Name, $PortName)
					$PortName = $port[0].Name
				}
				elseif ($port.Count -eq 0) {
					Write-Verbose (New-PrinterTCPPort -ComputerName $TargetComputer -PortName $Printer.PortName)
				}
			}
			$Inf = @('/w') # ask for inf path if need
			if ($InfPath) {
				$Inf += '/f',$InfPath # define inf path
			}
			else {
				$driver = @(Get-WmiObject -Class Win32_PrinterDriver -ComputerName $TargetComputer -Filter ("Name like '{0},[1-3],Windows%'" -f $Printer.DriverName))
				$Inf += '/u' # Use existing driver if found
				if ($driver.Count -eq 0) {
					Write-Warning ('no driver ''{0}'' found on ''{1}'', please specify inf driver file' -f $Printer.DriverName, $TargetComputer)
				}
				else {
					Write-Verbose ('found ''{0}'' driver in ''{1}'' driver database' -f $Printer.DriverName, $TargetComputer)
				}
			}

			if ($PSCmdlet.ShouldProcess($TargetComputer,"Creating New Printer '{0}'" -f $Printer.Name)) {
				
				& $cmd 'printui.dll,PrintUIEntry' /c ('\\{0}' -f $TargetComputer) /n $Printer.Name /r $PortName /if /m $Printer.DriverName $Inf /z /Y /b $Printer.Name
				
				do {
					$wait = $false
					Write-Verbose "Wait while printer is creating..."; Start-Sleep -Seconds 5
					$p = @(Get-WmiObject -Class Win32_Process -Filter "Name = 'RunDll32.exe'")
					$p | % {
					  	if ($_.CommandLine -match 'printui.dll,PrintUIEntry') {
							$wait = $true
						}
					}
				} while ($wait -eq $true)
				
				$newp = Get-PrinterInfo -ComputerName $TargetComputer -PrinterName $Printer.Name
				if ($newp) {
					$newp.Comment = $Printer.Comment
					$newp.Location = $Printer.Location
					$newp.Shared = $Printer.Shared
					$newp.ShareName = $Printer.ShareName
					$newp.Permissions = $Printer.Permissions
					Set-PrinterInfo -Printer $newp -Location -Comment -Permissions -Sharing
					$newp
				}
				else {
					Write-Error ("Can't find newly created printer {0} on {1}" -f $Printer.Name, $TargetComputer)
				}
			}
		}
	}
}

function New-NetworkPrinter {
[CmdletBinding(
	SupportsShouldProcess=$true,
	DefaultParametersetName="Prn",
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0, ParameterSetName="Comp")]$ComputerName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName
)
	if ($PSCmdlet.ParameterSetName -eq "Prn") {
		$PrinterName = $Printer.Name
		$ComputerName = $Printer.ComputerName
	}
	Write-Verbose ("Adding Printer \\{0}\{1}" -f $ComputerName, $PrinterName)
	if ($PSCmdlet.ShouldProcess($Env:COMPUTERNAME, "Add Network Printer '\\{0}\{1}'" -f $ComputerName, $PrinterName)) {
		([wmiclass]'Win32_Printer').AddPrinterConnection("\\$ComputerName\$PrinterName")
	}
}

function Remove-NetworkPrinter {
[CmdletBinding(
	SupportsShouldProcess=$true,
	DefaultParametersetName="Prn",
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Prn")]$Printer,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Comp")]$PrinterName
)
	PROCESS {
		if ($PSCmdlet.ParameterSetName -eq "Prn") {
			$PrinterName = $Printer.ShareName
			Write-Warning "Support only removing of network printers on localhost"
		}
		Write-Verbose ("Searching {0} on {1}" -f $PrinterName, $Env:COMPUTERNAME)
		$Prn = @(Get-WmiObject Win32_Printer -Filter "ShareName='$PrinterName'")
		if ($Prn.Count -eq 1) {
			if ($PSCmdlet.ShouldProcess($Prn.ComputerName,"Remove Printer '{0}'" -f $Prn.Name)) {
	    		$Prn.Delete()
			}
	    }
		elseif ($Prn.Count -eq 0) {
			Write-Error ("'{0}' not found" -f $PrinterName)
		}
		else {
			Write-Warning ("Found {0} '{1}' printers" -f $Prn.Count, $PrinterName)
	    }
	}
}
function New-PrinterShare {
[CmdletBinding(
	SupportsShouldProcess=$true,
	DefaultParametersetName="Prn",
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0, ParameterSetName="Comp")]$ComputerName = '.',
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName,
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=2)]$ShareName
)
	PROCESS {
		if ($PSCmdlet.ParameterSetName -eq "Prn") {
			$PrinterName = $Printer.Name
			$ComputerName = $Printer.ComputerName
		}
		Write-Verbose ("Add New Printer Share \\{0}\{1}" -f $ComputerName, $PrinterName)
		$Prn = @(Get-WMIObject Win32_Printer -ComputerName $ComputerName -Filter "Name='$PrinterName'")
		
		if ($Prn.Count -eq 1) {
			$Prn[0].Shared = $true
			$Prn[0].ShareName = $ShareName
			if ($PSCmdlet.ShouldProcess($ComputerName,"New Printer share '{0}' for {1}" -f $ShareName, $PrinterName)) {
				$Prn[0].Put()
				if ($PSCmdlet.ParameterSetName -eq "Prn") {
					$Printer.Shared = $true
					$Printer.ShareName = $ShareName
				}
			}
	    }
		elseif ($Prn.Count -eq 0) {
			Write-Error ("'{0}' not found on {1}" -f $PrinterName, $ComputerName)
		}
		else {
			Write-Warning ("Found {0} '{1}' printers on {2}" -f $Prn.Count, $PrinterName, $ComputerName)
	    }
	}
}

function Remove-PrinterShare {
[CmdletBinding(
	SupportsShouldProcess=$true,
	DefaultParametersetName="Comp",
	ConfirmImpact="Medium"
)]
param(
	[PrinterUtils.PrinterInfo][Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0, ParameterSetName="Prn")]$Printer,
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0, ParameterSetName="Comp")]$ComputerName = '.',
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=1, ParameterSetName="Comp")]$PrinterName
)
	PROCESS {
		if ($PSCmdlet.ParameterSetName -eq "Prn") {
			$PrinterName = $Printer.Name
			$ComputerName = $Printer.ComputerName
		}
		$Prn = Get-WmiObject Win32_Printer -ComputerName $ComputerName -Filter "Name = '$PrinterName'"
		if ($Prn.Count -eq 1) {
			$Prn[0].Shared = $false
			$Prn[0].ShareName = $ShareName
			if ($PSCmdlet.ShouldProcess($ComputerName,"Remove Printer share for {0}" -f $PrinterName)) {
				$Prn[0].Put()
				if ($PSCmdlet.ParameterSetName -eq "Prn") { $Printer.Shared = $false }
			}
	    }
		elseif ($Prn.Count -eq 0) {
			Write-Error ("'{0}' not found on {1}" -f $PrinterName, $ComputerName)
		}
		else {
			Write-Warning ("Found {0} '{1}' printers on {2}" -f $Prn.Count, $PrinterName, $ComputerName)
	    }
	}
}

function Get-DefaultPrinter {
param(
	[Alias('ServerName')]
	[String][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=0)]$ComputerName = '.'
)
	if ($ComputerName -eq '.') {
		$reg = [Microsoft.Win32.Registry]::CurrentUser
	}
	else {
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('CurrentUser', $ComputerName)
	}
	if ($reg -ne $null) {
		try {
			$regKey= $reg.OpenSubKey("Software\Microsoft\Windows NT\CurrentVersion\Windows",$true)
			if ($regkey -ne $null) {
				try {
					$dev = [string]$regKey.GetValue('Device')
					$p = $dev.IndexOf(',')
					$name = if ($p -gt 0) { $dev.Substring(0, $p) } else { '' }
					return $name
				}
				finally {
					$regKey.Close()
				}
			}
		}
		finally {
			$reg.Close()
		}
	}
}

function Set-DefaultPrinter {
[CmdletBinding(
	SupportsShouldProcess=$true,
	ConfirmImpact="Medium"
)]
param(
	[String][Parameter(Mandatory=$true, ValueFromPipeline=$false, Position=0)]$PrinterName,
	[switch][Parameter(Mandatory=$false, ValueFromPipeline=$false, Position=1)]$UseWMI = $true
)
	if (!$PrinterName) {
		Write-Error "You must to specify printer name. Operation aborted!"
    } else {
		if ($UseWMI) {
		    $Printer = Get-WmiObject Win32_Printer -Filter "name='$PrinterName'"
	        if ($Printer) {
				if ($PSCmdlet.ShouldProcess($ComputerName,"Set default Printer to {0}" -f $PrinterName)) {
		            $result = $Printer.SetDefaultPrinter()
		            $errortext = switch ($result.ReturnValue) {
		                "0" { "Now your default printer is $PrinterName"}
						"1794" { "The redirector is in use and cannot be unloaded."}
						"1795" { "The specified printer driver is already installed."}
						"1796" { "The specified port is unknown."}
						"1797" { "The printer driver is unknown."}
						"1798" { "The print processor is unknown."}
						"1799" { "The specified separator file is invalid."}
						"1800" { "The specified priority is invalid."}
						"1801" { "The printer name is invalid."}
						"1802" { "The printer already exists."}
						"1803" { "The printer command is invalid."}
						"1904" { "The specified printer handle is already being waited on"}
						"1905" { "The specified printer has been deleted."}
						"1906" { "The state of the printer is invalid."}
						"3001" { "The specified printer driver is currently in use."}
						"3009" { "The requested operation is not allowed when there are jobs queued to the printer."}
						"3010" { "The requested operation is successful. Changes will not be effective until the system is rebooted."}
						"3011" { "The requested operation is successful. Changes will not be effective until the service is restarted."}
						"3012" { "No printers were found."}
						"3013" { "The printer driver is known to be unreliable."}
						"3014" { "The printer driver is known to harm the system."}
		                default { "Unknown error" }
		            }
					if ($result.ReturnValue -eq 0) {
						Write-Verbose ("{0}: {1}" -f $result.ReturnValue, $errortext)
					}
					else {
						Write-Warning ("{0}: {1}" -f $result.ReturnValue, $errortext)
					}
					$result.ReturnValue
				}
	        }
			else {
	            Write-Error "Specified printer not exist!"
				1801
			}
		}
		else {
			#$t = [Type]::GetTypeFromProgID("WScript.Network")
			#$o = [Activator]::CreateInstance($t)
			#$t.InvokeMember('SetDefaultPrinter', [System.Reflection.BindingFlags]::InvokeMethod, $null, $o, @($PrinterName))
			$t = New-Object -ComObject WScript.Network
			if ($PSCmdlet.ShouldProcess($ComputerName,"Set default Printer to {0}" -f $PrinterName)) {
				$t.SetDefaultPrinter($PrinterName)
			}
			[System.Runtime.InteropServices.Marshal]::FinalReleaseComObject([System.__ComObject]$t); Remove-Variable t
			[System.GC]::Collect()
			[System.GC]::WaitForPendingFinalizers()
			[System.GC]::Collect()
		}
    }
}

Export-ModuleMember -Function Get-PrinterInfo, Set-PrinterInfo,
		New-PrinterPermission, Add-PrinterPermission,
		Remove-PrinterPermission, Set-PrinterPermissions,
		Rename-Printer, Remove-Printer,
		Get-PrinterTCPPort, New-PrinterTCPPort, Remove-PrinterTCPPort,
		New-PrinterLocalPort,
		Remove-PrinterLocalPort,
		Copy-Printer,
		New-NetworkPrinter, Remove-NetworkPrinter,
		New-PrinterShare, Remove-PrinterShare,
		Get-DefaultPrinter, Set-DefaultPrinter
