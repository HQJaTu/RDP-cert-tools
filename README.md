# RDP cert tools
PowerShell scripts to maintain custom X.509 certificate in
Windows Remote Desktop Services.

## Problem
On installation, all Windows versions will use a self-signed certificate
to encrypt RDP-connections. When a RDP-client cannot verify the certificate
to a trusted root, a warning is issued before connecting.

As the warning is being displayed every single time a connection is made,
very soon any user will be annoyed.

# Solution
To suppress the warning, a properly trusted certificate can be used instead of the default self-signed one.

These tools in this repository are intended to install and maintain a custom certificate in Remote Desktop Services.

As an example, a free-of-charge X.509 certificate issued by [Let's Encrypt](https://letsencrypt.org/) can be used
in RDP service. The only requirement is the certificate subject needs to match the target hostname.
Thus, a wildcard certificate is well suited for use in your LAN. 

## update-RDP-cert.ps1

Tool to import a PEM-formatted certificate file into Windows Certificate Store.
The store used by RDP services is Local Computer. Any access to that store requires _Administrator_ access.

### Syntax:
```
NAME
    update-RDP-cert.ps1

SYNOPSIS
    Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate


SYNTAX
    update-RDP-cert.ps1 [[-certPath] <String>] [[-keyPath] <String>]
    [[-existingCertHash] <String>] [<CommonParameters>]


DESCRIPTION
    Script to set given PEM-formatted X.509 certificate and private key as RDP service certificate
```

### Importing and installing PEM-formatted certificate

Example:
```
PS C:\> .\update-RDP-cert.ps1 `
  -certPath '*.example.com.cer' `
  -keyPath '*.example.com.key'
Installing certificate 'CN=*.example.com' to RDP
All ok. RDP setup done.
```


### Using existing certificate from Windows certificate store
Argument `-existingCertHash` can be used to update RDP

Example, a known certificate is already installed into Local Computer's Personal store:
```
PS C:\> .\update-RDP-cert.ps1 -existingCertHash f53500ed2f833251dccf992acbd4e6392978e391
Installing certificate 'CN=*.example.com' to RDP
All ok. RDP setup done.
```

### Administrator permissions
Lacking the required permissions:
```
.\update-RDP-cert.ps1 : The script 'update-RDP-cert.ps1' cannot be run because it contains a "#requires" statement for running as Administrator. The current PowerShell session is not running as Administrator. Start PowerShell by using the Run as Administrator option, and then try running the script again.
At line:1 char:1
+ .\update-RDP-cert.ps1
+ ~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : PermissionDenied: (update-RDP-cert.ps1:String) [], ScriptRequiresException
+ FullyQualifiedErrorId : ScriptRequiresElevation
```

### Idempotence
Updating the certificate with same information is a no-op.

Example, an attempt to re-install an existing certificate:
```
PS C:\> .\update-RDP-cert.ps1 -existingCertHash f53500ed2f833251dccf992acbd4e6392978e391
RDP certificate is 'f53500ed2f833251dccf992acbd4e6392978e391'. No need to install.
All ok. RDP setup done.
```

## get-RDP-cert.ps1
Wrapper to transfer PEM-certificate via SSH and call `update-RDP-cert.ps1`
to do the update on-the-fly.

Both the X.509 certificate and private key are transferred via SSH from a host into a temporary file.
Then `update-RDP-cert.ps1` is executed with appropriate paths to update the certificate used by RDP services.

### Example:
Server _server.example.com_ is running SSH and allows
user _joetheuser_ to login with SSH private key `id_ecdsa-sha2-nistp521`.

Let's Encrypt retrieved wildcard certificate and private key are stored in
directory `certs/*.example.com/`. 

```
PS C:\> .\get-RDP-cert.ps1 `
  -serverHost server.example.com `
  -serverUser joetheuser `
  -serverAuthPrivateKeyPath id_ecdsa-sha2-nistp521 `
  -remotePrivateKeyPath 'certs/*.example.com/*.example.com.key' `
  -remoteCertificatePath 'certs/*.example.com/*.example.com.cer'
```

### Using private keys with SSH-agent
To suppress a passphrase request, private key can be imported before transfer.
A requirement is to have _OpenSSH Authentication Agent_ -service running, then add the
private key into agent.

Example: 

```
PS C:\> Start-Service ssh-agent
PS C:\> ssh-add.exe id_ecdsa-sha2-nistp521
Enter passphrase for id_ecdsa-sha2-nistp521:
Identity added: id_ecdsa-sha2-nistp521 (id_ecdsa-sha2-nistp521)
```

## SSH in Windows

[Microsoft documentation of OpenSSH](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)

**Note:**

Microsoft introduced OpenSSH into Windowsverse with release of version 1709 (Fall Creators Update) in September 26 2017.
At the time, OpenSSH client was an optional feature.

Any Windows 10 version since Windows 10 1803 (April 2018 Update) has SSH and SSH-agent installed by default.
This feature can obviouly be uninstalled, but any reasonable modern Windows 10 will have `ssh.exe` already installed.

## PowerShell versions
Scripts have been tested with PowerShell 5.x and PowerShell Core 6.x.