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
	$True, X509Certificate2;
	
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

		return [Byte[]]$array
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
			throw "X.509 certificate data doesn't look like a PEM-certificate."
		}
	}
	# returns [byte[]]
	function __composeRsaPrivateKeyBlob($modulus, $PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1, $Exponent2, $Coefficient) {
		Write-Debug "Calculating key length."
		$bitLen = "{0:X4}" -f $($modulus.Length * 8)
		$keyLen = $modulus.Length * 8
		Write-Debug "RSA Key length is $keyLen bits."
		[byte[]]$bitLen1 = Invoke-Expression 0x$([int]$bitLen.Substring(0,2))
		[byte[]]$bitLen2 = Invoke-Expression 0x$([int]$bitLen.Substring(2,2))
		[Byte[]]$PrivateKey = 0x07,0x02,0x00,0x00,0x00,0x24,0x00,0x00,0x52,0x53,0x41,0x32,0x00
		[Byte[]]$PrivateKey = $PrivateKey + $bitLen1 + $bitLen2 + $PublicExponent + ,0x00 + `
			$modulus + $Prime1 + $Prime2 + $Exponent1 + $Exponent2 + $Coefficient + $PrivateExponent

		return $keyLen, $PrivateKey
	}
	# returns RSACryptoServiceProvider/RSACng for dispose purposes
	function __attachRSAPrivateKey([System.Security.Cryptography.X509Certificates.X509Certificate2]$_Cert, $PrivateKeyLength, [Byte[]]$PrivateKey) {
		Write-Debug "__attachRSAPrivateKey() set private key to a X509Certificate2"
		if ($PSVersionTable.PSEdition -eq "Core") {
			# .Net Core way of importing a RSA key is a complex one:

			# $script:Cert.PrivateKey = $rsa will result in error:
			# The property 'PrivateKey' cannot be found on this object. Verify that the property exists and can be set.

			# Key locations are documented in: https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
			# CNG Machine store:
			# %ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys
			# Legacy Machine store:
			# %PROGRAMDATA%\Microsoft\Crypto\RSA\MachineKeys
			# Legacy User store:
			# %APPDATA%\Microsoft\Crypto\RSA\S-1-5-21-...

			# Step 1)
			# Import the RSA key bytes using Cryptography Next Generation (CNG).

			# Create Cng Key Parameter and set its properties to allow export.
			# Make sure to store the key in Machine Store.
			$cngKeyParameter = [System.Security.Cryptography.CngKeyCreationParameters]::new()
			$cngKeyParameter.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
			$cngKeyParameter.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
			$cngKeyParameter.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
			$cngKeyParameter.UIPolicy = [System.Security.Cryptography.CngUIPolicy]::new([System.Security.Cryptography.CngUIProtectionLevels]::None)
			$cngKeyParameter.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey

			# Create Cng Property for Length, set its value and add it to Cng Key Parameter
			$cngKeyLenProperty = [System.Security.Cryptography.CngProperty]::new( `
				"Length", `
				[System.BitConverter]::GetBytes($PrivateKeyLength), `
				[System.Security.Cryptography.CngPropertyOptions]::None)
			$cngKeyParameter.Parameters.Add($cngKeyLenProperty)

			# Create Cng Property for blob, set its value and add it to Cng Key Parameter
			$keyBlobProperty = [System.Security.Cryptography.CngProperty]::new( `
				[System.Security.Cryptography.CngKeyBlobFormat]::GenericPrivateBlob, `
				$PrivateKey, `
				[System.Security.Cryptography.CngPropertyOptions]::None)
			$cngKeyParameter.Parameters.Add($keyBlobProperty)

			# Create Cng Key for given $keyName using Rsa Algorithm
			# Use X.509 thumbprint as unique name for this key
			$rsaKey = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $_Cert.Thumbprint, $cngKeyParameter)
			$rsa = New-Object Security.Cryptography.RSACng -ArgumentList $rsaKey

			# To get the Unique container name in CNG:
			# https://www.sysadmins.lv/blog-en/retrieve-cng-key-container-name-and-unique-name.aspx

			# Step 2)
			# Using CopyWithPrivateKey() glue the public and private keys together into a X.509 certificate.

            Add-Type -AssemblyName "System.Security.Cryptography.X509Certificates"
            $script:Cert = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($_Cert, $rsa)
        } else {
			# Trivial .Net way of importing an RSA key:

			$cspParams = New-Object Security.Cryptography.CspParameters -Property @{
				ProviderName = $ProviderName
				KeyContainerName = "pspki-" + [Guid]::NewGuid().ToString()
				KeyNumber = [int]$KeySpec
			}
			$cspParams.Flags += [Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
			# Create new private-key file in filesystem
			# Note: Constructing a new RSACryptoServiceProvider-object will create a new private key file into filesystem.
			# Note 2: RSACryptoServiceProvider is derived from System.Security.Cryptography.RSA
			$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider -ArgumentList $cspParams
			$rsa.ImportCspBlob($PrivateKey)

			$script:Cert = $_Cert
            $script:Cert.PrivateKey = $rsa
        }
		if (!$script:cert.HasPrivateKey) {
			throw "__attachRSAPrivateKey() Failed to attach private key into cert $($_Cert.Thumbprint). Cannot continue."
		}
		return $rsa, $script:Cert
	}
	# returns [byte[]]
	function __composeEcDsaPrivateKeyBlob([UInt32]$PrivateKeyLen, [Byte[]]$PrivateKey, [Byte[]]$PublicKey) {
		Write-Debug "ECDSA key length: $PrivateKeyLen bytes"

		# Magic bytes. See: https://github.com/dotnet/corefx/blob/master/src/Common/src/Interop/Windows/BCrypt/Interop.Blobs.cs
		Switch ($PrivateKeyLen) {
			256 {
				[Byte[]]$magic = 0x45,0x43,0x53,0x32
				$PrivateKeyBytes = 256 / 8 # 32
			}
			384 {
				[Byte[]]$magic = 0x45,0x43,0x53,0x34
				$PrivateKeyBytes = 384 / 8 # 48
			}
			521 {
				[Byte[]]$magic = 0x45,0x43,0x53,0x36
				$PrivateKeyBytes = 66 # ceil(521 / 8)
			}
			default {
				throw "Don't know how to handle ECC private key of size $PrivateKeyLen."
			}
		}

		if ($PrivateKey.Length -Ne $PrivateKeyBytes) {
			throw "ECDSA private key size mismatch! Expected to be $PrivateKeyBytes."
		}
		if ($PublicKey.Length -Ne $PrivateKeyBytes + $PrivateKeyBytes + 2) {
			throw "ECDSA public key size mismatch! Expected to be $($PrivateKeyBytes + $PrivateKeyBytes + 2)."
		}

		[Byte[]]$keyLenBytes = [System.BitConverter]::GetBytes($PrivateKeyBytes)
		[Byte[]]$PrivateKeyBytes = $magic + $keyLenBytes + `
 			($PublicKey | Select-Object -Skip 2) + `
 			$PrivateKey

		return $PrivateKeyLen, $PrivateKeyBytes
	}
	# returns ECDsaCng for dispose purposes
	function __attachECPrivateKey([System.Security.Cryptography.X509Certificates.X509Certificate2]$_Cert, `
 		[UInt32]$PrivateKeyLen, [Byte[]]$PrivateKey) {
		Write-Debug "__attachECPrivateKey() set private key to a X509Certificate2"
		if ($PSVersionTable.PSEdition -eq "Core") {
			# .Net Core way of importing an EC key is a complex one:

			# Step 1)
			# Import the ECC key bytes using Cryptography Next Generation (CNG).

			if ($False) {
				$cngKeyParameter2 = [System.Security.Cryptography.CngKeyCreationParameters]::new()
				$cngKeyParameter2.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
				$cngKeyParameter2.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
				$cngKeyParameter2.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
				$cngKeyParameter2.UIPolicy = [System.Security.Cryptography.CngUIPolicy]::new([System.Security.Cryptography.CngUIProtectionLevels]::None)
				#$cngKeyParameter2.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
				$cngKeyParameter2.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
				$keyAlgo = [System.Security.Cryptography.CngAlgorithm]::ECDsaP384
				$keyAlgo = [System.Security.Cryptography.CngAlgorithm]::ECDsaP521
				$key = [System.Security.Cryptography.CngKey]::Create($keyAlgo, "anEccKey", $cngKeyParameter2);
				Write-Debug "CngKey::Export(Pkcs8PrivateBlob)"
				$exportedBytes = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
				$dataHex = ($exportedBytes | ForEach-Object ToString X2) -join ''
				Write-Debug "Export: $dataHex"
				Write-Debug "CngKey::Export(EccPrivateBlob)"
				$exportedBytes = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob)
				$PrivateKey = $exportedBytes
				$dataHex = ($exportedBytes | ForEach-Object ToString X2) -join ''
				Write-Debug "Export: $dataHex"
			}
			# Create Cng Key Parameter and set its properties to allow export.
			# Make sure to store the key in Machine Store.
			$cngKeyParameter = [System.Security.Cryptography.CngKeyCreationParameters]::new()
			$cngKeyParameter.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
			$cngKeyParameter.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
			$cngKeyParameter.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
			$cngKeyParameter.UIPolicy = [System.Security.Cryptography.CngUIPolicy]::new([System.Security.Cryptography.CngUIProtectionLevels]::None)
			$cngKeyParameter.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey -Bor [System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey

			# Create Cng Property for blob, set its value and add it to Cng Key Parameter
			$keyBlobProperty = [System.Security.Cryptography.CngProperty]::new( `
					[System.Security.Cryptography.CngKeyBlobFormat]::EccPrivateBlob, `
					$PrivateKey, `
					[System.Security.Cryptography.CngPropertyOptions]::None)
			$cngKeyParameter.Parameters.Add($keyBlobProperty)

			if ($False) {
				Write-Debug "CngKey::Import(Pkcs8PrivateBlob)"
				$key = [System.Security.Cryptography.CngKey]::Import(
						$PrivateKey,
						[System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob);
				Write-Debug $key.ExportPolicy
				Write-Debug $key.IsEphemeral
				Write-Debug $key.IsMachineKey
			}
			# Create Cng Key for given $keyName using ECDsa Algorithm
			Write-Debug "CngKey::Create(ECDsa)"
			Switch ($PrivateKeyLen) {
				256 {
					$algo = [System.Security.Cryptography.CngAlgorithm]::ECDsaP256
				}
				384 {
					$algo = [System.Security.Cryptography.CngAlgorithm]::ECDsaP384
				}
				521 {
					$algo = [System.Security.Cryptography.CngAlgorithm]::ECDsaP521
				}
				default {
					throw "Don't know how to handle ECC private key of size $PrivateKeyLen."
				}
			}
			# Use X.509 thumbprint as unique name for this key
			$eccKey = [System.Security.Cryptography.CngKey]::Create($algo, $_Cert.Thumbprint, $cngKeyParameter)
			Write-Debug "ECDsaCng::new(eccKey)"
			$ecc = New-Object Security.Cryptography.ECDsaCng -ArgumentList $eccKey

			# To get the Unique container name in CNG:
			# https://www.sysadmins.lv/blog-en/retrieve-cng-key-container-name-and-unique-name.aspx

			# Step 2)
			# Using CopyWithPrivateKey() glue the public and private keys together into a X.509 certificate.

			Add-Type -AssemblyName "System.Security.Cryptography.X509Certificates"
			Write-Debug "ECDsaCertificateExtensions::CopyWithPrivateKey()"
			$script:Cert = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($_Cert, $ecc)
		} else {
			throw "Reading EC-keys not implemented!"
		}
		if (!$script:cert.HasPrivateKey) {
			Write-Error -ErrorAction Continue -Message "An error occurred!"
			throw "__attachECPrivateKey() Failed to attach private key into cert $($_Cert.Thumbprint). Cannot continue."
		}
		return $ecc, $script:Cert
	}
	# returns Asn1Reader
	function __decodePkcs1($base64) {
		# See: https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
		Write-Debug "Processing PKCS#1 KEY module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}

		return $asn
	}
	# returns Asn1Reader
	function __decodePkcs8($base64) {
		# See: https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
		Write-Debug "Processing PKCS#8 Private Key module."
		$asn = New-Object SysadminsLV.Asn1Parser.Asn1Reader @(,[Convert]::FromBase64String($base64))
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		# version
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# algorithm identifier, sequence
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		if ($asn.Tag -ne 48) {throw "The data is invalid."}
		# algorithm identifier, field 1
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		$oidAlgo = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeObjectIdentifier($asn.GetTagRawData())
		Write-Debug "Algorithm OID: $($oidAlgo.FriendlyName) = $($oidAlgo.Value)"
		# algorithm identifier, field 2, ignored
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		if ($asn.Tag -Eq 6)
		{
			$oidAlgoParam = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeObjectIdentifier($asn.GetTagRawData())
			Write-Debug "Parameter OID: $( $oidAlgoParam.FriendlyName ) = $( $oidAlgoParam.Value )"
		} else {
			$oidAlgoParam = $None
			Write-Debug "Parameter OID: -none-"
		}
		# octet string
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		if ($asn.Tag -ne 4) {throw "The data is invalid."}
		if (!$asn.MoveNext()) {throw "The data is invalid."}

		return $asn, $oidAlgo, $oidAlgoParam
	}
	function __rsaKeyFromAsn($asn) {
		Write-Debug "Processing RSA private key"
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
		$PrivateKeyLength, $PrivateKey = __composeRsaPrivateKeyBlob $modulus $PublicExponent $PrivateExponent $Prime1 $Prime2 $Exponent1 $Exponent2 $Coefficient

		return $PrivateKeyLength, $PrivateKey
	}
	function __eccKeyFromAsn($asn, $oid) {
		Write-Debug "Processing EC private key"
		Switch ($oid.FriendlyName) {
			"ECDSA_P256" {
				$PrivateKeyLength = 256
			}
			"ECDSA_P384" {
				$PrivateKeyLength = 384
			}
			"ECDSA_P521" {
				$PrivateKeyLength = 521
			}
			default {
				throw "Don't know how to handle ECDSA key $($oid.FriendlyName)."
			}
		}

		# all of the ASN.1 encoded data
		# See: https://www.ietf.org/rfc/rfc5915.txt
		if (!$asn.MoveNext()) {throw "The data is invalid."}

		# version INTEGER { ecPrivkeyVer1(1) }
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# privateKey OCTET STRING
		$PrivateKey = $asn.GetPayload()
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		# parameters [0] ECParameters {{ NamedCurve }}
		if (!$oid) {
			if (!$asn.MoveNext()) {throw "The data is invalid."}
			$oid = [SysadminsLV.Asn1Parser.Asn1Utils]::DecodeObjectIdentifier($asn.GetTagRawData())
			Write-Debug "OID (PKCS#1): $($oid.FriendlyName) = $($oid.Value)"
			if (!$asn.MoveNext()) {throw "The data is invalid."}
		}
		else {
			Write-Debug "OID (PKCS#8): $($oid.FriendlyName) = $($oid.Value)"
		}
		# publicKey [1] BIT STRING
		if (!$asn.MoveNext()) {throw "The data is invalid."}
		if ($asn.Tag -ne 3) {throw "The data is invalid."}
		$PublicKey = $asn.GetPayload()

		$PrivateKeyBytes = __composeEcDsaPrivateKeyBlob $PrivateKeyLength $PrivateKey $PublicKey

		return $PrivateKeyBytes
	}
#endregion

	$ErrorActionPreference = "Stop"

	if (-Not (Test-Path $InputPath -PathType Leaf)) {
		throw "Certificate file $InputPath doesn't exist!"
	}
	if (-Not (Test-Path $KeyPath -PathType Leaf)) {
		throw "Private key file $KeyPath doesn't exist!"
	}

	$FileContents = Get-Content -Path $InputPath -Raw -ErrorAction Stop

	# parse content
	Write-Debug "Extracting certificate information..."
	$Cert = __extractCert $FileContents

	# Early abort here on existing X.509 cert thumbprint.
	if ($ExistingThumbprint -and $Cert.Thumbprint -eq $ExistingThumbprint) {
		return $True, $Cert;
	}

	# Parse private key
	if ($KeyPath) {
		$FileContents = Get-Content -Path $KeyPath -Raw -ErrorAction Stop
	}
	$oidAlgorithm = $None
	$oidAlgoParam = $None
	if ($FileContents -match "(?msx).*-{5}BEGIN\sPRIVATE\sKEY-{5}(.+)-{5}END\sPRIVATE\sKEY-{5}") {
		$pkcs8Key = $matches[1]
		$asn, $oidAlgorithm, $oidAlgoParam = __decodePkcs8 $pkcs8Key
		if ($oidAlgorithm.FriendlyName -Eq 'RSA') {
			$rsaAsn = $asn
		} elseif ($oidAlgorithm.FriendlyName -Eq 'ECC') {
			$eccAsn = $asn
		} else {
			throw "PKCS#8 private key is of type $($oidAlgorithm.FriendlyName), which cannot be handled by this app."
		}
	} elseif ($FileContents -match "(?msx).*-{5}BEGIN\sRSA\sPRIVATE\sKEY-{5}(.+)-{5}END\sRSA\sPRIVATE\sKEY-{5}") {
		$rsaAsn = __decodePkcs1 $matches[1]
	} elseif ($FileContents -match "(?msx).*-{5}BEGIN\sEC\sPRIVATE\sKEY-{5}(.+)-{5}END\sEC\sPRIVATE\sKEY-{5}") {
		$eccAsn = __decodePkcs1 $matches[1]
	} else {
		throw "The private key data is invalid."
	}

	if ($rsaAsn) {
		$PrivateKeyLength, $PrivateKey = __rsaKeyFromAsn $rsaAsn

#region RSA key attachment and export
		try {
			$rsaKey, $CertOut = __attachRSAPrivateKey $Cert $PrivateKeyLength $PrivateKey
		} finally {
		}
		if (!$rsaKey) {
			Write-Host "Failed to create new cert!"
			Exit 1
		}
#endregion

		return $rsaKey, $CertOut
	}
	elseif ($eccAsn)
	{
		$PrivateKeyLength, $PrivateKey = __eccKeyFromAsn $eccAsn $oidAlgoParam

#region ECC key attachment and export
		try {
			$ecdsaKey, $CertOut = __attachECPrivateKey $Cert $PrivateKeyLength $PrivateKey
		} catch {
			Write-Error -ErrorAction Continue -Message "An error occurred:`nException: $_`nStack trace: $($_.ScriptStackTrace)"
		}
		if (!$ecdsaKey) {
			Write-Host "Failed to create new cert!"
			Exit 1
		}

		return $ecdsaKey, $CertOut
#endregion
	}
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
		return $None, $None;
	}

	# Attempt 1:
	# Look for Local Machine's personal certificates. That's where newly installed custom certs go.
	$existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object -Property "Thumbprint" -EQ -Value $tsSetting.SSLCertificateSHA1Hash;
	if ($existingCert) {
		Write-Debug "Found custom RDP certificate with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";
		
		return "My", $tsSetting.SSLCertificateSHA1Hash;
	}

	# Attempt 2:
	# Look for Local Machine's Remote Desktop certificates. That's where machine generated self-signed certs go.
	$existingCert = Get-ChildItem "Cert:\LocalMachine\Remote Desktop" | Where-Object -Property "Thumbprint" -EQ -Value $tsSetting.SSLCertificateSHA1Hash;
	if ($existingCert) {
		Write-Debug "Found Windows-generated self-signed RDP certificate with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";

		return "Remote Desktop", $tsSetting.SSLCertificateSHA1Hash;
	}


	Write-Warning "No RDP certificate found with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";

	return $None, $None;
}


<#
.SYNOPSIS
	Update RDP-certificate if cert needs updating.

.LINK
	Wmic docs:
	https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic

	Win32_TSGeneralSetting class docs:
	https://docs.microsoft.com/en-us/windows/win32/termserv/win32-tsgeneralsetting

.DESCRIPTION
	This effectively does:
	PS C:\> Write-Debug "Doing wmic with cert thumbprint: $certThumbprint"
	PS C:\> wmic /namespace:"\\root\cimv2\TerminalServices" PATH "Win32_TSGeneralSetting" Set "SSLCertificateSHA1Hash=$certThumbprint"
#>
Function UpdateRDPCert([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert)
{
	$certThumbprint = $cert.Thumbprint;

	# Replace Certificate for RDS using Powershell cmdlet.
	$tsSetting = Get-CimInstance -ClassName 'Win32_TSGeneralSetting' `
		-Namespace 'root\cimv2\terminalservices';

	# Note:
	# FullyQualifiedErrorId : HRESULT 0x80041008
	# will be emitted, if certificate won't have a valid private key.
	Write-Debug "Doing Set-WmiInstance with cert thumbprint: $certThumbprint"
	# Docs: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-wmiinstance
	$updatedTsSetting = Set-CimInstance -CimInstance $tsSetting `
		-Property @{SSLCertificateSHA1Hash=$certThumbprint} `
		-PassThru;
	if (!$updatedTsSetting) {
		Write-Host "Won't continue script execution.";
		Exit 1;
	}
}


# Begin script execution
if ($PSVersionTable.PSVersion.Major -gt 6) {
	# XXX ToDo: Test on PowerShell Core 7
	Write-Host "This script will NOT work on Powershell version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)!"

	Exit 2
}
Write-Debug "Begin script execution"

$currentRDPcertStore, $currentRDPcertThumbprint = GetCurrentValidRDPcertHash;
if (!$currentRDPcertThumbprint) {
	Write-Warning "Weird. No RDP certificate found at all."
}
else {
	Write-Host "Currently installed RDP certificate thumbprint in store '$currentRDPcertStore' is: $currentRDPcertThumbprint"
}

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

	$privateKey, $cert = Convert-PemToPfx-2 -InputPath $certPath `
		-KeyPath $keyPath `
		-OutputPath $null `
		-ExistingThumbprint $currentRDPcertThumbprint;

	if (!$cert) {
		throw "Failed to load certificate"
	}
	if ($privateKey -eq $True) {
		Write-Host "All ok. Certificate '$($cert.Subject)' with thumbprint $($cert.Thumbprint) already exists in cert store."
		Exit 0
	}
	if (!$cert.HasPrivateKey) {
		throw "Failed to load valid certificate. No private key in cert $($cert.Thumbprint). Cannot continue."
	}
	#Write-Debug $cert
	#Write-Debug $cert.Thumbprint
	Write-Host "Loaded certificate with thumbprint $($cert.Thumbprint)";


	# See:
	# https://superuser.com/questions/1093159/how-to-provide-a-verified-server-certificate-for-remote-desktop-rdp-connection

	# Check to see if the certificate is already installed
	$store = New-Object Security.Cryptography.X509Certificates.X509Store "My", "Local";
	$certInstalled = $False;
	$openFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -Bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
	$store.Open($openFlags);
	foreach ($existingCert in $store.Certificates) {
		if ($existingCert.Thumbprint -eq $cert.Thumbprint) {
			$certInstalled = $True;
			$cert = $existingCert;
			Write-Debug "Existing certificate '$($cert.Subject)' found in Local\My store with thumbprint $($cert.Thumbprint)";
			break;
		}
	}
	$store.Close()

	if (!$certInstalled) {
		Write-Host "Installing certificate '$($cert.Subject)' to Windows Certificate Store";
		$openFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite
		$store.Open($openFlags);
		$store.Add($cert);
		$store.Close();
	}
	else {
		if ($currentRDPcertThumbprint -Ne $cert.Thumbprint) {
			$certInstalled = $False;
			Write-Host "Existing certificate '$($cert.Subject)' not used as RDP-certificate.";
		}
	}
}
elseif ($existingCertHash) {
	# As filenames were not given, simply get the current one and confirm it is already installed.
	# Find already installed certificate with given hash.
	$store = New-Object Security.Cryptography.X509Certificates.X509Store "My", "Local";
	$cert = $None;
	$certInstalled = $False;
	$openFlags = [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -Bor [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly
	$store.Open("OpenExistingOnly");
	foreach ($existingCert in $store.Certificates) {
		if ($existingCert.Thumbprint -eq $existingCertHash) {
			$cert = $existingCert;
			Write-Debug "Existing certificate '$($cert.Subject)' found in Local\My store with thumbprint $($cert.Thumbprint)";
			break;
		}
	}
	$store.Close();

	# Confirm there is a certificate.
	# If yes, confirm it is different than the current one.
	if (!$cert) {
		Write-Host "Installed certificate with hash '$existingCertHash' cannot be found!";
		Exit 1;
	}
	if ($currentRDPcertThumbprint -Eq $cert.Thumbprint) {
		$certInstalled = $True;
		Write-Host "RDP certificate is '$existingCertHash'. No need to install."
	}
	if (!$cert.HasPrivateKey) {
		throw "Failed to locate valid certificate. No private key in cert $($cert.Thumbprint). Cannot continue."
	}
}
else {
	Write-Host "Neither certificate files or already installed hash were given. Nothing to do.";
	Write-Host "All ok. Done.";
	Exit 0;
}

if (!$certInstalled) {
	UpdateRDPCert $cert;
}

# At end.
Write-Host "All ok. RDP setup done.";
