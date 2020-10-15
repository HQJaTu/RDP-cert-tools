#Requires -RunAsAdministrator

<#
Copyright (c) 2020 Jari Turkia (jatu@hqcodeshop.fi)
 
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
#>

# Powershell execution policy:
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-5.1

# Set-ExecutionPolicy Unrestricted -Scope CurrentUser


# For PSPKI-module, see:
# https://github.com/Crypt32/PSPKI/blob/master/PSPKI/Client/Convert-PemToPfx.ps1

# Debug output:
# $DebugPreference = "Continue"

<#
.SYNOPSIS
Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate
 
.DESCRIPTION
Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate
 
.PARAMETER certPath
PEM X.509 certificate path
 
.PARAMETER certPath
PEM X.509 private key path
#>
param(
    [Parameter()]	# [Parameter(Mandatory=$True)]
    [string]
    $certPath,

    [Parameter()]
    [string]
    $keyPath,

    [Parameter()]
    [string]
    $existingCertHash
)

Import-Module -Name PSPKI


<#
.SYNOPSIS
	Helper to convert bytes into ASCII hexadcimal

.DESCRIPTION
	A longer description.
#>
Function Convert-ByteArrayToHex([Byte[]] $Bytes) {
    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)

    ForEach($byte in $Bytes) {
        $HexString.AppendFormat("{0:x2}", $byte) | Out-Null
    }

    return $HexString.ToString()
}


<#
.SYNOPSIS
	Helper to convert ASCII hexadcimal into bytes

.DESCRIPTION
	A longer description.
#>
Function Convert-HexToByteArray([String] $HexString) {
    $Bytes = [byte[]]::new($HexString.Length / 2)

    For ($i=0; $i -lt $HexString.Length; $i+=2) {
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }

    return $Bytes
}


<#
.SYNOPSIS
	Convert PEM-formatted X.509 certificate into a PKCS#12 (or PFX)

.DESCRIPTION
	This code from:
	https://github.com/Crypt32/PSPKI/blob/master/PSPKI/Client/Convert-PemToPfx.ps1

.INPUTS
	$InputPath: path to certificate file to install/confirm
	$KeyPath: path to certificate private key file to install
	$ExistingThumbprint: Hex thumbprint of expected certificate

.OUTPUTS
	If input certificate matches expected certificate thumbprint, will return:
	$None, $True;
	
	Otherwise:
	Tuple of (Private key, Certificate) returned

.LINK
	Docs:
	https://www.pkisolutions.com/tools/pspki/

.NOTES
	On execution, unlike original code, this won't install private key of input certificate into certificate store.
	See: https://github.com/PKISolutions/PSPKI/issues/64
	
	
#>
function Convert-PemToPfx-2 {
[OutputType('[System.Security.Cryptography.X509Certificates.X509Certificate2]')]
[CmdletBinding()]
	param(
		[Parameter(Mandatory = $true, Position = 0)]
		[string]$InputPath,
		[string]$KeyPath,
		[string]$OutputPath,
		[Security.Cryptography.X509Certificates.X509KeySpecFlags]$KeySpec = "AT_KEYEXCHANGE",
		[string]$ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider",
		[string]$ExistingThumbprint = $None
	)
	if ($PSBoundParameters.Verbose) {
		$VerbosePreference = "continue"
	}
	if ($PSBoundParameters.Debug) {
		$Host.PrivateData.DebugForegroundColor = "Cyan"
		$DebugPreference = "continue"
	}
	
	#region helper functions
	function __normalizeAsnInteger ($array) {
        $padding = $array.Length % 8
        if ($padding) {
            $array = $array[$padding..($array.Length - 1)]
        }
        [array]::Reverse($array)
        [Byte[]]$array
    }
	function __extractCert([string]$Text) {
		if ($Text -match "(?msx).*-{5}BEGIN\sCERTIFICATE-{5}(.+)-{5}END\sCERTIFICATE-{5}") {
			$keyFlags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
			#$keyFlags += [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
			$RawData = [Convert]::FromBase64String($matches[1])
			try {
				New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $RawData, "", $keyFlags
			} catch {
				throw "The data is not valid security certificate."
			}
			Write-Debug "X.509 certificate is correct."
		} else {
			throw "Missing certificate file."
		}
	}
	# returns [byte[]]
	function __composePRIVATEKEYBLOB($modulus, $PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1, $Exponent2, $Coefficient) {
		Write-Debug "Calculating key length."
		$bitLen = "{0:X4}" -f $($modulus.Length * 8)
		Write-Debug "Key length is $($modulus.Length * 8) bits."
		[byte[]]$bitLen1 = Invoke-Expression 0x$([int]$bitLen.Substring(0,2))
		[byte[]]$bitLen2 = Invoke-Expression 0x$([int]$bitLen.Substring(2,2))
		[Byte[]]$PrivateKey = 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00
		[Byte[]]$PrivateKey = $PrivateKey + $bitLen1 + $bitLen2 + $PublicExponent + ,0x00 + `
			$modulus + $Prime1 + $Prime2 + $Exponent1 + $Exponent2 + $Coefficient + $PrivateExponent
		$PrivateKey
	}
	# returns RSACryptoServiceProvider for dispose purposes
	function __attachPrivateKey($Cert, [Byte[]]$PrivateKey) {
		$cspParams = New-Object Security.Cryptography.CspParameters -Property @{
			ProviderName = $ProviderName
			KeyContainerName = "pspki-" + [Guid]::NewGuid().ToString()
			KeyNumber = [int]$KeySpec
		}
		$cspParams.Flags += [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
		# Create new private-key file in filesystem:
		$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider -ArgumentList $cspParams
		$rsa.ImportCspBlob($PrivateKey)
		Write-Debug "__attachPrivateKey() set private key to a X509Certificate2"
		# XXX old working!
		#$Cert.PrivateKey = $rsa
		if ($PSVersionTable.PSEdition -eq "Core") {
            Add-Type -AssemblyName "System.Security.Cryptography.X509Certificates"
            $script:Cert = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($_Cert.RawData, $rsa)
        } else {
            $script:Cert.PrivateKey = $rsa
        }

		return $rsa, $Cert
	}
	# returns Asn1Reader
	function __decodePkcs1($base64) {
		Write-Debug "Processing PKCS#1 RSA KEY module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		$asn
	}
	# returns Asn1Reader
	function __decodePkcs8($base64) {
		Write-Debug "Processing PKCS#8 Private Key module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		# version
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# algorithm identifier
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# octet string
		if (!$asn.MoveNextCurrentLevel()) {throw "The data is invalid."}
		if ($asn.Tag -ne 4) {throw "The data is invalid."}
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		$asn
	}
	#endregion
	$ErrorActionPreference = "Stop"
	
	$File = Get-Item $InputPath -Force -ErrorAction Stop
	if ($KeyPath) {
		$Key = Get-Item $KeyPath -Force -ErrorAction Stop
	}
	
	# parse content
	$Text = Get-Content -Path $InputPath -Raw -ErrorAction Stop
	Write-Debug "Extracting certificate information..."
	$Cert = __extractCert $Text
	
	# Early abort here on existing X.509 cert thumbprint.
	if ($ExistingThumbprint -and $Cert.Thumbprint -eq $ExistingThumbprint) {
		return $None, $True;
	}

	# parse private key
	if ($Key) {$Text = Get-Content -Path $KeyPath -Raw -ErrorAction Stop}
	$asn = if ($Text -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
		__decodePkcs8 $matches[1]
	} elseif ($Text -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
		__decodePkcs1 $matches[1]
	}  else {throw "The data is invalid."}
	# private key version
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	# modulus n
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$modulus = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Modulus length: $($modulus.Length)"
	# public exponent e
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	# public exponent must be 4 bytes exactly.
	$PublicExponent = if ($asn.GetPayload().Length -eq 3) {
		,0 + $asn.GetPayload()
	} else {
		$asn.GetPayload()
	}
	Write-Debug "PublicExponent length: $($PublicExponent.Length)"
	# private exponent d
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$PrivateExponent = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "PrivateExponent length: $($PrivateExponent.Length)"
	# prime1 p
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Prime1 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Prime1 length: $($Prime1.Length)"
	# prime2 q
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Prime2 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Prime2 length: $($Prime2.Length)"
	# exponent1 d mod (p-1)
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Exponent1 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Exponent1 length: $($Exponent1.Length)"
	# exponent2 d mod (q-1)
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Exponent2 = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Exponent2 length: $($Exponent2.Length)"
	# coefficient (inverse of q) mod p
	if (!$asn.MoveNext()) {throw "The data is invalid."}
	$Coefficient = __normalizeAsnInteger $asn.GetPayload()
	Write-Debug "Coefficient length: $($Coefficient.Length)"
	# creating Private Key BLOB structure
	$PrivateKey = __composePRIVATEKEYBLOB $modulus $PublicExponent $PrivateExponent $Prime1 $Prime2 $Exponent1 $Exponent2 $Coefficient
	
	#region key attachment and export
	try {
		$rsaKey = __attachPrivateKey $Cert $PrivateKey
	} finally {
		if ($rsaKey) {
			$rsaKey[0].Dispose()
		}
	}
	if (!$rsaKey) {
		Write-Host "Failed to create new cert!"
		Exit 1
	}

	return $rsaKey
}


<#
.SYNOPSIS
	(obsoleted) Get currently installed RDP-certificate from registry.

.DESCRIPTION
	A longer description.
#>
function GetCurrentValidRDPcertHash_Registry()
{
	$key = 'HKLM:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
	$value = 'SSLCertificateSHA1Hash'
	$regVal = Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue;
	Write-Debug "Reg ${key}\\${value}: $($regVal.SSLCertificateSHA1Hash)"
	if (!$regVal) {
		return $None;
	}

	$regHex = Convert-ByteArrayToHex $regVal.SSLCertificateSHA1Hash;
	$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object -Property Thumbprint -EQ -Value $regHex;
	if ($existingCert) {
		return $regHex;
	}

	return $None;
}


<#
.SYNOPSIS
	Get currently installed RDP-certificate via CIM-call.

.DESCRIPTION
	This effectively does:
	PS C:\> wmic /namespace:"\\root\cimv2\TerminalServices" PATH "Win32_TSGeneralSetting" get "SSLCertificateSHA1Hash"
#>
function GetCurrentValidRDPcertHash()
{
	$tsSetting = Get-CimInstance -Class "Win32_TSGeneralSetting" `
		-Namespace "root\cimv2\terminalservices" `
		-Filter "TerminalName='RDP-tcp'";
	Write-Debug "WMIC SSLCertificateSHA1Hash: $($tsSetting.SSLCertificateSHA1Hash)"
	if (!$tsSetting) {
		return $None;
	}

	$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object -Property "Thumbprint" -EQ -Value $tsSetting.SSLCertificateSHA1Hash;
	if ($existingCert) {
		Write-Debug "Found RDP certificate with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";
		
		return $tsSetting.SSLCertificateSHA1Hash;
	}

	Write-Warning "No RDP certificate found with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";

	return $None;
}


<#
.SYNOPSIS
	(obsoleted) Update RDP-certificate into certificate store if missing.

.DESCRIPTION
	A longer description.
#>
function ConfirmRDPRegistry([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)
{
	$key = 'HKLM:\\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
	$value = 'SSLCertificateSHA1Hash'
	$regVal = Get-ItemProperty -Path $key -Name $value -ErrorAction SilentlyContinue
	Write-Debug "Reg ${key}\\${value}: $($regVal.SSLCertificateSHA1Hash)"
	if (!$regVal) {
		Write-Host "Adding certificate thumbprint to registry";
		$regVal = New-ItemProperty -Path $key -Name $value -PropertyType Binary -Value (Convert-HexToByteArray $cert.Thumbprint);
		return $True;
	}
	elseif ((Convert-ByteArrayToHex $regVal.SSLCertificateSHA1Hash) -ne $cert.Thumbprint) {
		Write-Host "Updating certificate thumbprint in registry"
		$regVal = Set-ItemProperty -Path $key -Name $value -Value (Convert-HexToByteArray $cert.Thumbprint)
		return $True;
	}

	Write-Host "Registry has all good."
	return $False;
}


<#
.SYNOPSIS
	(obsoleted) Update RDP-certificate if cert needs updating.

.DESCRIPTION
	A longer description.
#>
Function UpdateRDPCert_manual([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)
{
	# Confirm registry key for RDP cert
	Write-Debug "Set RDP certificate hash to $($cert.Thumbprint)";
	ConfirmRDPRegistry $cert | Out-Null;

	# Confirm private key access permissions
	Write-Debug "Confirm private key"
	$rsaFile = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName;
	if (!$rsaFile) {

		Write-Host "Error: No private key name in X.509 cert. Failed!"
		Exit 1
	}
	$keyPath = "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\$rsaFile";
	Write-Debug "Private key path is: $keyPath";
	$acl = Get-Acl -Path $keyPath;

	# Make sure Administrators-group has owner
	$Group = New-Object System.Security.Principal.NTAccount -ArgumentList 'BUILTIN\Administrators';
	$acl.SetOwner($Group);
	Set-Acl -Path $keyPath -AclObject $acl;

	# Add permission for NETWORK SERVICE to read the file
	# NetworkServiceSid == "NT AUTHORITY\NETWORK SERVICE"
	$sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::NetworkServiceSid, $null);
	$permission = $sid, "Read", "Allow";
	$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission;
	$acl.AddAccessRule($accessRule);
	#$acl | Format-List
	Try
	{
		Set-Acl -Path $keyPath -AclObject $acl | Out-Null;
		Write-Debug "Set ACL ok for private key file $keyPath"
	}
	Catch
	{
		Write-Error "Failed to set permission for NETWORK SERVICE"
		Exit 1
	}

	# Restart RDP:
	Write-Debug "Restarting RDP service to make sure all is good."
	Restart-Service -DisplayName "Remote Desktop Services" -Force
	Start-Sleep -Seconds 3
	
	
	# Confirm registry key again (for debug purposes).
	# Restarting "Remote Desktop Services" will delete the registry entry for custom certificate
	# on any minor failure and fall back to a self-generated one.
	if (ConfirmRDPRegistry $cert) {
		Write-Host "Custom certificate setting to RDP failed!"
		Exit 1
	}
}


<#
.SYNOPSIS
	Update RDP-certificate if cert needs updating.

.LINK
	Wmic docs:
	https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic

.DESCRIPTION
	This effectively does:
	PS C:\> Write-Debug "Doing wmic with cert thumbprint: $certThumbprint"
	PS C:\> wmic /namespace:"\\root\cimv2\TerminalServices" PATH "Win32_TSGeneralSetting" Set "SSLCertificateSHA1Hash=$certThumbprint"
#>
Function UpdateRDPCert($certThumbprint)
{
	# Replace Certificate for RDS using direct command. This works!

	# Replace Certificate for RDS using Powershell cmdlet.
	$tsSetting = Get-CimInstance -Class "Win32_TSGeneralSetting" `
		-Namespace "root\cimv2\terminalservices" `
		-Filter "TerminalName='RDP-tcp'";

	Write-Debug "Doing Set-WmiInstance with cert thumbprint: $certThumbprint"
	# Docs: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-wmiinstance
	$updatedTsSetting = Set-CimInstance -InputObject $tsSetting `
		-Argument @{SSLCertificateSHA1Hash=$certThumbprint};
}



# Begin script execution
if ($PSVersionTable.PSVersion.Major -gt 6) {
	Write-Host "This script will NOT work on Powershell version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)!"

	Exit 2
}
Write-Debug "Begin script execution"

$currentRDPcertThumbprint = GetCurrentValidRDPcertHash;
Write-Debug "Current RDP certificate thumbprint is: $currentRDPcertThumbprint"

if ($certPath -And $keyPath) {
	# If filenames were given ...
	# Go confirm/install the input certificate
	if ((Test-Path $certPath -PathType Leaf) -eq $false) {
		Write-Host "Argument $certPath is not a file!"
		Exit 2
	}
	if ((Test-Path $keyPath -PathType Leaf) -eq $false) {
		Write-Host "Argument $keyPath is not a file!"
		Exit 2
	}

	#Write-Debug "Going to Convert-PemToPfx-2"
	$privateKey, $cert = Convert-PemToPfx-2 -InputPath $certPath `
		-KeyPath $keyPath `
		-OutputPath $null `
		-ExistingThumbprint $currentRDPcertThumbprint;
	#Write-Debug "Did Convert-PemToPfx-2"

	if (!$cert) {
		throw "Failed to load certificate"
	}
	if ($cert -eq $True) {
		Write-Host "All ok. Certificate '$($cert.Subject)' with thumbprint $($cert.Thumbprint) already exists in cert store."
		Exit 0
	}
	if (!$cert.HasPrivateKey) {
		throw "Failed to load valid certificate"
	}
	#Write-Debug $cert
	#Write-Debug $cert.Thumbprint
	Write-Host "Loaded certificate with thumbprint $($cert.Thumbprint)";
	
	
	# See:
	# https://superuser.com/questions/1093159/how-to-provide-a-verified-server-certificate-for-remote-desktop-rdp-connection

	# Check to see if the certificate is already installed
	$storeName = "My";
	$store = New-Object Security.Cryptography.X509Certificates.X509Store $storeName, "Local";
	$certInstalled = $False;
	$store.Open("OpenExistingOnly");
	foreach ($existingCert in $store.Certificates) {
		if ($existingCert.Thumbprint -eq $cert.Thumbprint) {
			$certInstalled = $True;
			$cert = $existingCert;
			Write-Debug "Existing certificate '$($cert.Subject)' found in Local\My store with thumbprint $($cert.Thumbprint)";
			break;
		}
	}
	$store.Close()
}
elseif ($existingCertHash) {
	# As filenames were not given, simply get the current one and confirm it is already installed.
	# Find already installed certificate with given hash.
	$storeName = "My";
	$store = New-Object Security.Cryptography.X509Certificates.X509Store $storeName, "Local";
	$cert = $None;
	$certInstalled = $False;
	$store.Open("OpenExistingOnly");
	foreach ($existingCert in $store.Certificates) {
		if ($existingCert.Thumbprint -eq $existingCertHash) {
			$cert = $existingCert;
			Write-Debug "Existing certificate '$($cert.Subject)' found in Local\My store with thumbprint $($cert.Thumbprint)";
			break;
		}
	}
	$store.Close();
	
	#
	if (!$cert) {
		Write-Host "Installed certificate with hash '$existingCertHash' cannot be found!";
		Exit 1;
	}
	if ($currentRDPcertThumbprint -Eq $cert.Thumbprint) {
		$certInstalled = $True;
		Write-Host "RDP certificate is '$existingCertHash'. No need to install."
	}
}
else {
	Write-Host "Neither certificate files or already installed hash were given. Nothing to do.";
	Write-Host "All ok. Done.";
	Exit 0;
}

if (!$certInstalled) {
	Write-Host "Installing certificate '$($cert.Subject)' to RDP";
	$store.Open("ReadWrite");
	$store.Add($cert);
	$store.Close();
	
	UpdateRDPCert $cert.Thumbprint;
}

# At end.
Write-Host "All ok. RDP setup done.";
