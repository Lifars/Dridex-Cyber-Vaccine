# Dridex-Vaccine

This is a custom program written by <a href="https://lifars.com" target="_blank" rel="noopener noreferrer">LIFARS</a> Incident Reponse Team to remove Dridex infection. 

To read more about this check these LIFARS blogs:
* <a href="https://lifars.com/2019/11/the-emergence-of-dridex/" target="_blank" rel="noopener noreferrer">The Emergence of Dridex</a>
* <a href="https://lifars.com/2019/11/from-dridex-to-bitpaymer-ransomware-to-doppelpaymerthe-evolution/" target="_blank" rel="noopener noreferrer">From Dridex to BitPaymer Ransomware to DoppelPaymer……The Evolution</a>
* <a href="https://lifars.com/2019/11/analysis-of-dridex-bitpaymer-and-doppelpaymer-campaign/" target="_blank" rel="noopener noreferrer">Analysis of Dridex, BitPaymer and DoppelPaymer campaign</a>

## Usage

* Create list of hostnames to be cleaned and save as `hostnames.txt`
* Download [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) and save it to the same directory
* Put Base64-encoded executables of [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) and [Process Hacker](https://processhacker.sourceforge.io/) to the `dedri.ps1`:
	```
$prochack_base64str = "<PUT BASE64-ENCODED PROCESSHACKER.EXE HERE>"
$procmon_base64str = "<PUT BASE64-ENCODED PROCMON.EXE HERE>"
	```
* Run `.\dedri-automatization.ps1` from PowerShell console (or, in case of execution of scripts is blocked, you can select all lines in PowerShell ISE and click on "Run Selection")

## DEDRI Vaccine algorithm:

* Find malicious injected thread in Explorer.exe via Process Monitor – if such thread exists, then DEDRI will suspend it
* Find directories with Dridex artifacts – these directories could be found  in `%APPDATA%` of any user and in `%WinDir%\System32`. They have random-looking name and contain one legitimate Windows executable (same as its original in `%WinDir%\System32`), also could contain one .DLL library with legitimate name (but not legitimate content) which will be hijacked, and these directories could contain encrypted file with random-looking filename and extension beginning with char ‘x’
  * Check every:
    * scheduled tasks
    * autoruns via HKLM (Local Machine) and HKCU (Current User) registry entry with path `“\SOFTWARE\Microsoft\Windows\CurrentVersion\Run”` for any user,
    * Windows Start Menu `.lnk` startup file for any user

Find items pointing to some of the malicious directories with Dridex artifacts found in previous step.

* Remove all malicious artifacts found in previous steps
* Terminate malicious injected thread if this thread exists (1st step)
* (Optionally) – prevent future successful Dridex execution by creating read-only file `“C:\Windows “` (including trailing space) – Dridex will not be able to use fake directory with same name for one of its stage
* (Optionally) – prevent future successful BitPaymer ransomware infection by creating file `“C:\aaa_TouchMeNot_.txt”`
 
## Notes
* If PsExec is blocked in your environment, you can use `Invoke-Command -ComputerName ...` or Group Policy
* Three Base64-encoded blobs in `dedri.ps` are embedded binary files of:
  * Process Monitor executable for finding malicious thread
  * Configuration for Process Monitor for findind malicious thread
  * Process Hacker as a 2nd method for suspending and terminating malicious thread. It will be used only after the native method via Win32-API will fail
* The Base64 encoded blob of Process Monitor and Process Hacker could be obtained by command:
```
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileName))
```

For more information contact us at:

* https://lifars.com/contact-us/
* https://lifars.com/ransomware-response-and-cyber-extortion-bitcoin-decryption/

@mwlac @LIFARS
