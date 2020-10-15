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

# Debug output:
# $DebugPreference = "Continue"

<#
.SYNOPSIS
Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate
 
.DESCRIPTION
Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate

If using passphrase protected private key:
PS C:\> ssh-agent
PS C:\> ssh-add "key.file"

Note: Fix for "unable to start ssh-agent service, error :1058" error:
(as admin) Set-Service ssh-agent -StartupType Manual
 
.PARAMETER certPath
PEM X.509 certificate path
 
.PARAMETER certPath
PEM X.509 private key path
#>
Param(
    [Parameter(Mandatory=$True)]
    [string]
    $serverHost,

    [Parameter(Mandatory=$True)]
    [string]
    $serverUser,

    [Parameter(Mandatory=$True)]
    [string]
    $serverAuthPrivateKeyPath,

    [Parameter(Mandatory=$True)]
    [string]
    $remotePrivateKeyPath,

    [Parameter(Mandatory=$True)]
    [string]
    $remoteCertificatePath
)


<#
.SYNOPSIS
Helper function to secure copy (SFTP) files from a server.

Note: Using scp it is not possible to specify destination filename.
      If *nix filename is not a valid filename in Windows, copy will fail.
#>
Function Get-SFTPFile-OpenSSH([String]$hostname, [String]$username, [String]$privateKeyFile,
	[String]$remoteFile, [String]$localFile) {

	$sftpCommand = "${env:systemroot}\System32\OpenSSH\sftp.exe";
	# Properly escape argument filename.
	$userServerPath = "`"${username}@${hostname}:'$remoteFile'" + '"'; # to keep text editor happy: '

	Write-Debug "Got: $userServerPath to $localFile"

	$process = Start-Process -NoNewWindow -FilePath $sftpCommand `
		-ArgumentList @("-i", $privateKeyFile, $userServerPath, $localFile) `
		-PassThru `
		-Wait
	Write-Debug "SFTP exit code is: ${$process.ExitCode}"
	
	if ($process.ExitCode -gt 0) {
		throw "SFTP for file '$remoteFile' failed." 
	}
}


<#
.SYNOPSIS
Helper function to secure copy (SFTP) files from a server.

Note: Using scp it is not possible to specify destination filename.
      If *nix filename is not a valid filename in Windows, copy will fail.
#>
Function Get-SFTPFile-POSH([String]$hostname, [String]$username, [String]$privateKeyFile,
	[String]$remoteFile, [String]$localFile) {

	Write-Debug "Going to $hostname as $username"
	Write-Debug "Using keyfile $privateKeyFile"
	# Docs: https://github.com/darkoperator/Posh-SSH/blob/master/docs/Get-SCPFile.md
	#$creds = ConvertTo-SecureString -String $username;
	$keyPassphrase = 'ncLQ7s5I';
	$creds = New-Object System.Management.Automation.PSCredential($username, $keyPassphrase)
	#$creds = ConvertTo-SecureString -AsPlainText $username -Force
	#$creds = Get-Credential -Message "Private key passphrase" -User $username;
	$creds
	Get-SCPFile -ComputerName $hostname `
		-Credential $creds `
		-KeyFile $privateKeyFile `
		-RemoteFile $remoteFile `
		-LocalFile $localFile;
}


<#
.SYNOPSIS
Helper function to confirm SSH module existence
#>
Function Confirm-SSH() {
	$mod = Import-Module -Name "Posh-SSH" -ErrorAction:SilentlyContinue;
	if (!$mod) {
		Install-Module -Name -Name "Posh-SSH";
	}
}

# Begin script execution
$DebugPreference = "continue";

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
	& .\update-RDP-cert.ps1 -certPath $certificateFile -keyPath $privateKeyFile
}
catch {
	Remove-Item -LiteralPath $privateKeyFile -Force;
	Remove-Item -LiteralPath $certificateFile -Force;

	Write-Host $_;
	Write-Host "Certificate set failure. Stopped."
	
	exit 1
}
finally {
	Pop-Location
}

# Delete transferred material at the end.
Remove-Item -LiteralPath $privateKeyFile -Force;
Remove-Item -LiteralPath $certificateFile -Force;
