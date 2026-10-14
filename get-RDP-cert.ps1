#Requires -RunAsAdministrator

<#
Copyright (c) 2020-2026 Jari Turkia (jatu@hqcodeshop.fi)

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

# Debug output:
# $DebugPreference = "Continue"

<#
.SYNOPSIS
Script to download PEM-formatted X.509 certificate and private key via SFTP and set them as RDP service certificate
 
.DESCRIPTION
Wrapper for update-RDP-cert.ps1.

Transfers a PEM-formatted X.509 certificate and its private key from a remote host using
Windows OpenSSH sftp.exe into temporary files. Then update-RDP-cert.ps1 is executed to install
the certificate as RDP service certificate. Finally, SHA-1 and SHA-256 thumbprints of the
installed RDP certificate are displayed and the transferred temporary files are deleted.

SSH authentication is done with the private key given in -serverAuthPrivateKeyPath or
with any key loaded into OpenSSH Authentication Agent.

If using passphrase protected private key:
PS C:\> Start-Service ssh-agent
PS C:\> ssh-add "key.file"

Note: Fix for "unable to start ssh-agent service, error :1058" error:
(as admin) Set-Service ssh-agent -StartupType Manual
 
.PARAMETER serverHost
SSH server hostname to transfer the files from

.PARAMETER serverUser
SSH username

.PARAMETER serverAuthPrivateKeyPath
Optional SSH private key file for authentication. If omitted, ssh-agent and default keys are used.

.PARAMETER remotePrivateKeyPath
Path of PEM X.509 private key file at the server

.PARAMETER remoteCertificatePath
Path of PEM X.509 certificate file at the server

.PARAMETER rdpFilePath
Optional path to an .rdp definition file to sign with rdpsign.exe using the RDP certificate
#>
Param(
    [Parameter(Mandatory=$True)]
    [string]
    $serverHost,

    [Parameter(Mandatory=$True)]
    [string]
    $serverUser,

    [Parameter()]
    [string]
    $serverAuthPrivateKeyPath,

    [Parameter(Mandatory=$True)]
    [string]
    $remotePrivateKeyPath,

    [Parameter(Mandatory=$True)]
    [string]
    $remoteCertificatePath,

    [Parameter()]
    [string]
    $rdpFilePath
)


<#
.SYNOPSIS
Helper function to secure copy (SFTP) files from a server.

Note: Using scp it is not possible to specify destination filename.
      If *nix filename is not a valid filename in Windows, copy will fail.
#>
Function Get-SFTPFile-OpenSSH([String]$hostname, [String]$username, [String]$privateKeyFile,
	[String]$remoteFile, [String]$localFile) {

	$sftpCommand = "${env:systemroot}\System32\OpenSSH\sftp.exe"

	# Create temporary batch file for non-interactive execution
    $batchFile = [System.IO.Path]::GetTempFileName()
    "get `"$remoteFile`" `"$localFile`"" | Set-Content -Path $batchFile -Encoding ascii

    try {
        # Build argument array cleanly WITHOUT manual single-quote wrapping
        $argList = @("-b", $batchFile)
        
        if ($privateKeyFile) {
            $argList += "-i"
            $argList += $privateKeyFile
        }
        
        $argList += "${username}@${hostname}"

        Write-Debug "EXEC CMD : $sftpCommand $($argList -join ' ')"

        $process = Start-Process -NoNewWindow -FilePath $sftpCommand `
            -ArgumentList $argList `
            -PassThru `
            -Wait

        Write-Debug "SFTP exit code is: $($process.ExitCode)"
        
        if ($process.ExitCode -ne 0) {
            throw "SFTP for file '$remoteFile' failed with exit code $($process.ExitCode)." 
        }
    }
    finally {
        if (Test-Path $batchFile) {
            Remove-Item -Path $batchFile -Force -ErrorAction SilentlyContinue
        }
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
	if ((Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -ne 0) {
		Write-Warning "RDP server is not enabled. Suggest running two commands:";
		Write-Warning "1) Set-ItemProperty -Path `"HKLM:\System\CurrentControlSet\Control\Terminal Server`" -Name fDenyTSConnections -Value 0";
		Write-Warning "2) Enable-NetFirewallRule -DisplayGroup `"Remote Desktop`""
		return $None, $None;
	}
	
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
	# XXX: "Cert:\LocalMachine\Remote Desktop" may not exist if RDP never run
	$existingCert = Get-ChildItem "Cert:\LocalMachine\Remote Desktop" | Where-Object -Property "Thumbprint" -EQ -Value $tsSetting.SSLCertificateSHA1Hash;
	if ($existingCert) {
		Write-Debug "Found Windows-generated self-signed RDP certificate with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";

		return "Remote Desktop", $tsSetting.SSLCertificateSHA1Hash;
	}

	Write-Warning "No RDP certificate found with thumbprint: $($tsSetting.SSLCertificateSHA1Hash)";

	return $None, $None;
}


# Begin script execution
#$DebugPreference = "continue";

# Change to script directory
$scriptpath = $MyInvocation.MyCommand.Path;
$dir = Split-Path $scriptpath;

# Create two temp-files for incoming data.
$privateKeyFile = New-TemporaryFile;
$certificateFile = New-TemporaryFile;

# Try doing some transfers:
try {
	Get-SFTPFile-OpenSSH $serverHost $serverUser `
		$serverAuthPrivateKeyPath `
		$remotePrivateKeyPath `
		$privateKeyFile;
	Get-SFTPFile-OpenSSH $serverHost $serverUser `
		$serverAuthPrivateKeyPath `
		$remoteCertificatePath `
		$certificateFile;
}
catch {
	Pop-Location
	Remove-Item -LiteralPath $privateKeyFile -Force;
	Remove-Item -LiteralPath $certificateFile -Force;
	
	Write-Host "SFTP failure. Stopped."
	Write-Host "For passphrase of the private key, use: ssh-add.exe <keyfile>"
	
	exit 1
}

# So far, looking good.
# Go execute the other script.
Push-Location -Path $dir;
try {
	$updateArgs = @{
		certPath = $certificateFile
		keyPath  = $privateKeyFile
	}
	if ($rdpFilePath) {
		$updateArgs.rdpFilePath = $rdpFilePath
	}
	& .\update-RDP-cert.ps1 @updateArgs
}
catch {
	Remove-Item -LiteralPath $privateKeyFile -Force;
	Remove-Item -LiteralPath $certificateFile -Force;

	Write-Host $_;
	Write-Host "Certificate set failure. Stopped get-RDP-cert.ps1."
	
	exit 1
}
finally {
	Pop-Location
}

#
$currentRDPcertStore, $currentRDPcertThumbprint = GetCurrentValidRDPcertHash;
if ($currentRDPcertThumbprint) {
	$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $currentRDPcertThumbprint }
	if ($cert) {	
		# Compute SHA256 (hex, no dashes)
		$sha256Bytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData)
		$sha256Hex = ([System.BitConverter]::ToString($sha256Bytes)).Replace("-", "").ToUpper()
		Write-Host "Cert SHA-1 160bit: $currentRDPcertThumbprint"
		Write-Host "Cert SHA-2 256bit: $sha256Hex"
	}
} else {
	Write-Warning "Weird. No RDP certificate found at all."
}

# Delete transferred material at the end.
Remove-Item -LiteralPath $privateKeyFile -Force;
Remove-Item -LiteralPath $certificateFile -Force;
