#Requires -RunAsAdministrator

<#
The MIT License (MIT)
 
Copyright (c) 2020 Jari Turkia (jatu@hqcodeshop.fi)
 
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
 
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
 
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
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
	& .\update-RDP-cert.ps1 -certPath $certificateFile -keyPath $privateKeyFile
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

# Delete transferred material at the end.
Remove-Item -LiteralPath $privateKeyFile -Force;
Remove-Item -LiteralPath $certificateFile -Force;
