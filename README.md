# ssl_mitm

A PowerShell-based tool for detecting potential SSL/TLS man-in-the-middle (MITM) attacks by monitoring certificate changes across various websites.

All credit to https://github.com/clr2of8/Detect-SSLmitm as this is a fork of that repo

## Usage

1. Download the ssl_mitm.ps1 script to your local machine
2. Set the appropriate PowerShell execution policy:
`Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
3. Dot source the script and initialize golden hashes:
```
> . .\ssl_mitm.ps1
> Update-GoldenHashes -UpdateScript
```

Run: 
```
> Test-SSLMitm
```
The Output looks like this:

![image](https://github.com/user-attachments/assets/2c00fbfe-0708-4acd-b159-885638a43e1d)

