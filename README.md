# RDP cert tools
PowerShell scripts to maintain custom X.509 certificate in
Windows Remote Desktop Services.

## Problem
On installation, all Windows versions will use a self-signed certificate
to encrypt RDP-connections. When a RDP-client cannot verify the certificate
to a trusted root, a warning is issued before connecting.

As the warning is being displayed every single time a connection is made,
very soon any user will be annoyed.

## Requirements
* PowerShell Core 7
  * Core 6 isn't supported. Code is likely to work, but supporting obsoleted versions is impossible.
  * Non-Core -versions are not support and won't work.
* PSPKI
  * https://github.com/PKISolutions/PSPKI
  * With _Administrator_ permissions, run `Install-Module -Name PSPKI`
* For RDP-client, verifiable and trusted certificate chain for the installed server certificate

### PKI Requirements
* For a trusted certificate chain to verify, a trusted root and optionally required intermediate certificates
  need to be installed into Windows Certificate Store.
* In RDP-server end, the is no requirement to have entire chain up to CA-root.
  * RDP running as a Service Account (of type Remote Desktop Services) won't verify the chain
  * Obviously, installing any possible root/interemediate certificates into the server will help in debugging possible problems.
    The installation of such chain need to be done for the entire machine or for user doing the debugging.
* In RDP-client end, any missing root/intermediate certificate will collapse the entire chain of trust.
  * When a RDP-server presents its certificate during handshake, it's the job of the client to verify the chain and
    evaluate if the certificate presented should be trusted or not.

**Note:** This is exactly how most other services with certificates operate. As an example a web server with HTTPS works with a similar fashion.
RDP is no different from that.

## Solution
To suppress the warning, a properly trusted certificate can be used instead of the default self-signed one.

These tools in this repository are intended to install and maintain a custom certificate in Remote Desktop Services.

**Note:** In RDP, for Windows Certificate Store, you can install only a single certificate.
If you require any additional certificates to complete the chain, you need to do that separately.
The PEM-file being imported cannot contain a chain of certificates, only the single one intended for RDP.

As an example, a free-of-charge X.509 certificate issued by [Let's Encrypt](https://letsencrypt.org/) can be used
in RDP service. The only requirement is the certificate subject needs to match the target hostname.
Thus, a wildcard certificate is well suited for use in your LAN. 

**Note:** Let's Encrypt CA root certificate _DST Root CA X3_ should be installed in your Windows machine-wide
certificate store in Microsoft certificate bundle. However, the intermediate _R3_ is not.
Missing this breaks your chain-of-trust for RDP-client.

# Tools

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
    [[-existingCertHash] <String>] [[-rdpFilePath] <String>] [<CommonParameters>]


DESCRIPTION
    Installs a custom X.509 certificate for Windows Remote Desktop Services.

    The certificate is either imported from PEM-formatted certificate and private key files
    (-certPath and -keyPath) into the Local Computer's Personal (LocalMachine\My) store, or an
    already installed certificate is selected by its SHA-1 thumbprint (-existingCertHash).
    The certificate is then set as the RDP-Tcp listener certificate.

    Running the script with the currently used certificate is a no-op.
    Running it without arguments displays the thumbprint of the currently installed RDP certificate.

    Optionally, an .rdp connection file can be signed with rdpsign.exe using the same certificate (-rdpFilePath).
    The file is signed even when the certificate itself did not need to be updated.

    Requires Administrator permissions, PowerShell 7 and the PSPKI module.
```

### Display currently installed certificate SHA1-thumbprint
Example:
```powershell
PS C:\> .\update-RDP-cert.ps1
Currently installed RDP certificate thumbprint in store 'My' is: -the-thubnail-in-hex-here-
Neither certificate files or already installed hash were given. Nothing to do.
All ok. Done.
```

### Importing and installing PEM-formatted certificate

Example:
```powershell
PS C:\> .\update-RDP-cert.ps1 `
  -certPath 'wildcard.example.com.cer' `
  -keyPath 'wildcard.example.com.key'
Installing certificate 'CN=*.example.com' to RDP
All ok. RDP setup done.
```


### Using existing certificate from Windows certificate store
Argument `-existingCertHash` can be used to update RDP

Example, a known certificate is already installed into Local Computer's Personal store:
```powershell
PS C:\> .\update-RDP-cert.ps1 -existingCertHash f53500ed2f833251dccf992acbd4e6392978e391
Installing certificate 'CN=*.example.com' to RDP
All ok. RDP setup done.
```

### Administrator permissions
Lacking the required permissions:
```powershell
.\update-RDP-cert.ps1 : The script 'update-RDP-cert.ps1' cannot be run because it contains a "#requires" statement for running as Administrator. The current PowerShell session is not running as Administrator. Start PowerShell by using the Run as Administrator option, and then try running the script again.
At line:1 char:1
+ .\update-RDP-cert.ps1
+ ~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : PermissionDenied: (update-RDP-cert.ps1:String) [], ScriptRequiresException
+ FullyQualifiedErrorId : ScriptRequiresElevation
```

### Signing an .rdp connection file
Argument `-rdpFilePath` signs a Remote Desktop connection file with the installed RDP certificate.
Internally function `SignRDPFile` runs Windows built-in `rdpsign.exe`:
```
rdpsign.exe /sha256 <SHA-1 thumbprint> <rdpFile>
```
**Note:** Despite the argument name `/sha256`, `rdpsign.exe` expects the SHA-1 thumbprint of the certificate.

A signed .rdp-file lets the RDP-client verify who published the connection settings.
Instead of the yellow _unknown publisher_ warning, the client displays the verified publisher name.
For this to work, the client needs to trust the certificate chain, see [PKI Requirements](#pki-requirements).

The .rdp-file is modified in place. Signing is done even if the certificate was already installed,
thus the argument can be used together with `-certPath`/`-keyPath` or `-existingCertHash`.

Example:
```powershell
PS C:\> .\update-RDP-cert.ps1 `
  -existingCertHash f53500ed2f833251dccf992acbd4e6392978e391 `
  -rdpFilePath 'C:\Users\Public\Desktop\server.example.com.rdp'
RDP certificate is 'f53500ed2f833251dccf992acbd4e6392978e391'. No need to install.
Signing RDP file 'C:\Users\Public\Desktop\server.example.com.rdp' using certificate f53500ed2f833251dccf992acbd4e6392978e391
All ok. RDP setup done.
```

Signing fails if the file doesn't exist, the certificate lacks its private key,
or `%SystemRoot%\System32\rdpsign.exe` is missing.

### Idempotence
Updating the certificate with same information is a no-op.

Example, an attempt to re-install an existing certificate:
```powershell
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

```powershell
PS C:\> .\get-RDP-cert.ps1 `
  -serverHost server.example.com `
  -serverUser joetheuser `
  -serverAuthPrivateKeyPath id_ecdsa-sha2-nistp521 `
  -remotePrivateKeyPath 'certs/*.example.com/*.example.com.key' `
  -remoteCertificatePath 'certs/*.example.com/*.example.com.cer'
```

After installation, SHA-1 and SHA-256 thumbprints of the RDP certificate are displayed.
Transferred temporary files are always deleted.

Argument `-rdpFilePath` is passed through to `update-RDP-cert.ps1`, see
[Signing an .rdp connection file](#signing-an-rdp-connection-file).

### Using private keys with SSH-agent
To suppress a passphrase request, private key can be imported before transfer.
A requirement is to have _OpenSSH Authentication Agent_ -service running, then add the
private key into agent.

Example: 

```powershell
PS C:\> Start-Service ssh-agent
PS C:\> ssh-add.exe id_ecdsa-sha2-nistp521
Enter passphrase for id_ecdsa-sha2-nistp521:
Identity added: id_ecdsa-sha2-nistp521 (id_ecdsa-sha2-nistp521)
```

# General information

## SSH in Windows

[Microsoft documentation of OpenSSH](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)

Microsoft introduced OpenSSH into Windowsverse with release of version 1709 (Fall Creators Update) in September 26 2017.
At the time, OpenSSH client was an optional feature.

Any Windows 10 version since Windows 10 1803 (April 2018 Update) has SSH and SSH-agent installed by default.
This feature can obviouly be uninstalled, but any reasonable modern Windows 10 will have `ssh.exe` already installed.

## PowerShell versions
Running `update-RDP-cert.ps1` requires PowerShell Core 7.x.

Historically, these scripts have been developed and tested with PowerShell 5.x and
PowerShell Core 6.x. However, PowerShell Core is platform-independent and lost direct access to Windows CrytoAPI.
Also cryptography system is constantly evolving. Windows is shifting into _Cryptography API: Next Generation_ (aka. CNG)
with a different, completely improved and future-proofed API adding support for Elliptic Curve algorithms.

Personally I have no interest in supporting obsoleted versions of Windows and their Cryto API.
Thus, run this stuff with something reasonable and supported.

## Certificate types
Remote Desktop Cervices can only operate with RSA-certificate.
This requirement is not documented, but can be observed via testing.

However, this tool is capable of importing also ECDSA-certificate.
Future versions may support other certificate types too.

## PowerShell Script Execution Policy
**For PowerShell newbies:**

In PowerShell, out-of-the-box you cannot run an arbitrary un-signed script. In real world most scripts you see are unsigned.
The list of disallowed scripts include both `update-RDP-cert.ps1` and `get-RDP-cert.ps1`.
Read all about this built-in security mechanism from [Microsoft's documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.1).

To get the scripts running, what you can do is either one of these:
1. With your pre-existing PKI, sign the scripts with a code-signing certificate.
   The procedure is documented in Microsoft's [PowerShell Code Signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.1) article.
1. Allow executiong of non-signed scripts in your computer. This is what most users do.
   Running a command like this will do the trick:
```powershell
Set-ExecutionPolicy Unrestricted -Scope CurrentUser
```

Now the scripts can be executed in your Windows without being blocked by system script execution policy.