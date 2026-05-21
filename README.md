# SharpPXE

A simple tool for extracting information from SCCM PXE boot media. 

It will connect to a provided SCCM PXE server, download the boot media configuration, and try to decrypt it or output the hash for cracking.

**No admin privileges required**
## What It Does

When SCCM is configured for PXE boot, it stores encrypted configuration files on the PXE server. 

The tool will:

1. Sends a PXE boot request to the target server on port 4011.

2. The server responds with information about where to find the boot files, including:
   - The variables file (encrypted configuration)
   - The BCD file (boot configuration)
   - Sometimes an encrypted key for decryption

3. Downloads the variables file using TFTP .

4. If the server provided an encryption key, the tool decrypts the variables file. If not, it extracts a hash that can be used with tools like Hashcat to crack the password.

5. Once decrypted, the tool parses the XML configuration and extracts:
   - Management Point URL
   - Site Code
   - Media GUIDs
   - Other SCCM identifiers

6. It outputs a ready-to-use SharpSCCM command with all the necessary parameters filled in.

## Output

When successful, you'll see output like:

```
Variables File: SMSBoot\x64\pxe\variables.dat
BCD File: SMSBoot\x64\pxe\boot.bcd
Decryption Key: AB-CD-EF-...
Downloading variables file via TFTP...
File 'SMSBoot\x64\pxe\variables.dat' downloaded successfully. Size: 1234 bytes
Decrypted (Unicode): <XML content>
Management Point: http://sccm-mp.company.local
Site Code: PS1
Use SharpSCCM to get goodies!!!!
  SharpSCCM.exe get secrets -i "{GUID}" -m "{MediaGUID}" -c "{PFX}" -sc PS1 -mp sccm-mp.company.local
```

If the media is password-protected (no encryption key provided), you'll see:

```
PXE boot media is encrypted with custom password
Got the hash: $sccm$aes128$<hash>
```

You can then use this hash with Hashcat to crack the password.

## Credits - Original Work from 

* https://github.com/MWR-CyberSec/PXEThief - Christopher Panayi (@Raiona_ZA)
* https://github.com/SpecterOps/cred1py - Adam Chester (@_xpn_) 
* https://github.com/Mayyhem/SharpSCCM - Chris Thompson (@_Mayyhem)
* https://github.com/SpecterOps/ConfigManBearPig - Chris Thompson (@_Mayyhem)


## Author
Lefty @ 2025