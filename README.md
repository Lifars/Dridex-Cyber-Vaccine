# Dridex-Vaccine

This is a custom program written by <a href="https://lifars.com" target="_blank" rel="noopener noreferrer">LIFARS</a> Incident Reponse Team to remove Dridex infection for DoppelPaymer and BitPaymer Ransomware. 

To read more about this check these LIFARS blogs:
* <a href="https://lifars.com/2019/11/the-emergence-of-dridex/" target="_blank" rel="noopener noreferrer">The Emergence of Dridex</a>
* <a href="https://lifars.com/2019/11/from-dridex-to-bitpaymer-ransomware-to-doppelpaymerthe-evolution/" target="_blank" rel="noopener noreferrer">From Dridex to BitPaymer Ransomware to DoppelPaymer……The Evolution</a>
* <a href="https://lifars.com/2019/11/analysis-of-dridex-bitpaymer-and-doppelpaymer-campaign/" target="_blank" rel="noopener noreferrer">Analysis of Dridex, BitPaymer and DoppelPaymer campaign</a>

## DEDRI Vaccine perform:

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
 
For more information contact us at:

* https://lifars.com/contact-us/
* https://lifars.com/ransomware-response-and-cyber-extortion-bitcoin-decryption/

@mwlac @LIFARS
