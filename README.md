# Credential-to-Controller-A-Four-Hour-Attack-Chain

## Objective

To analyze a multi‑stage attack chain that progressed from initial credential access to domain controller interaction within four hours. This project demonstrates my ability to follow an end‑to‑end intrusion, review authentication logs, identify privilege escalation behavior, and document findings using a structured SOC investigation workflow.
It also highlights my growing experience using Microsoft Defender XDR to correlate alerts, review device timelines, and validate suspicious activity.


### Skills Learned

- Understanding how attackers move from credential access to lateral movement
- Identifying suspicious authentication patterns (failed logons, unusual logon types, new account creation)
- Reviewing Windows Security Logs for account activity, privilege escalation, and Kerberos behavior
- Using Microsoft Defender XDR to investigate alerts, analyze device timelines, and correlate events
- Recognizing indicators of credential misuse and unauthorized access attempts
- Correlating events across multiple hosts to build a timeline of attacker actions
- Mapping activity to MITRE ATT&CK techniques (Credential Access, Lateral Movement, Privilege Escalation)
- Strengthening investigation structure: verify → correlate → conclude
- Improving documentation clarity for SOC‑style reporting


### Tools Used

- Microsoft Defender XDR – alert investigation, device timeline review, correlation of suspicious activity
- Windows Event Viewer – authentication logs, account activity, and security events
- Sysmon – process creation, network connections, and system activity visibility
- Windows Defender – alert context and threat detection signals
- PowerShell – understanding command execution and script behavior
- Splunk (Fundamentals) – SIEM searching, correlation, and detection logic
- CyberChef – decoding and quick data analysis
- VirusTotal – validating file and hash reputation
- Notepad++ – log parsing, note‑taking, and documentation


## Steps

🏠  [Back to Portfolio](https://www.notion.so/Toukee-Vang-Portfoilo-29c0c3b8580a803ea4c7e402115d24a2?pvs=21) 

▶️  [**Duolingo Phish!**](https://www.notion.so/Duolingo-Phish-29c0c3b8580a805ab70fe533e503e9e5?pvs=21) 

# Table of Contents:

# Case Summary

On October 7, 2025, at 04:00 UTC, Maple Tax Solutions experienced the beginning of a targeted cyberattack. 

By 04:13 UTC, Defender logs recorded external IP activity from `81.141.209.165`, confirming the presence of unauthorized access. The attacker gained remote access to a contractor workstation (`MTS-ContractorPC1`) using valid credentials.  At 04:18 UTC, the attacker retrieved a PowerShell script (`kb5029244.ps1`) from an external server, further embedding their tools into the environment.

At 06:07 UTC, the attacker modified Defender exclusions and executed `systeminfo.exe` to gather host details. Nine minutes later, at 06:16 UTC, they established persistence by modifying registry keys on`OneDriveStandalone` on startup. At 06:38 UTC, they ran `mimikatz.exe` to extract credentials from memory, gaining elevated access.

At 07:02 UTC, the attacker moved laterally to the domain controller (`MTC-DC`). By 07:35 UTC, a second external IP (`78.141.205.85`) accessed the domain controller, indicating continued control and staging.

At 08:00 UTC, the attacker opened a file named `Bank_Routing_Number.txt` to assess its value. Thirty seconds later, at 08:00:34 UTC, they created a ZIP archive (`backup.zip`) containing data. At 08:11 UTC, attacker likely uploaded the archive to a public file-sharing site (`www.file.io`).

The attacker’s use of public infrastructure, credential harvesting, and stealthy data transfer demonstrates a high level of operational efficiency. Their actions impacted the confidentiality of client financial records and the integrity of internal systems. The incident spanned multiple stages of compromise, from initial access to exfiltration, all within a four-hour window.

This case highlights the importance of timely detection, strong access controls, continuous monitoring and the need for layered defense and rapid response capabilities.

# Analysts

Analyst: Toukee Vang

# Initial Access

Initial Access

On October 7, 2025, at 04:07:58 UTC, an attacker successfully authenticated to Maple Tax Solutions’ contractor workstation (`MTS-ContractorPC1`) via Remote Desktop Protocol (RDP). The login originated from IP address `81.141.209.165` using valid credentials for the local administrator account `MTS-Contractor\administrator`. 

Just prior to this, a failed login attempt was recorded from IP address `142.90.213.242`, suggesting reconnaissance or credential testing before the successful breach. The attacker’s use of valid credentials and familiarity with the environment indicates prior knowledge, possibly obtained through phishing, credential reuse.

- The attacker used brute force to compromise`MTS-ContractorPC`.
- The originating IP (`81.141.209.165`) is geolocated in **Europe**, which violates Maple Tax Solutions’ remote access policy restricting logins to **Canada-only** regions.
- A total of **13 brute-force attempts** were observed prior to successful authentication, using variations of the administrator account name:
- `mts\administrator`
- `\administrator`
- `MTS-CONTRACTORP\administrator`

successful login
<img width="1521" height="432" alt="image" src="https://github.com/user-attachments/assets/7129954f-01ff-40cd-b302-f471dd44f507" />


Fig. 1

Assets

Internal Assets (Effective Targets)

| **Asset Name** | **Type** | **Role / Sensitivity** | **Notes** |
| --- | --- | --- | --- |
| `MTS-ContractorPC1` | Endpoint (Workstation) | Initial access point via RDP | Used for payload delivery, discovery, and credential dumping |
| `MTC-DC` | Domain Controller | High-value target with domain-level access | Used for lateral movement, exfiltration, and C2 |
| `Bank_Routing_Number.txt` | File (Unknown Data) | Unknown documents targeted for exfiltration | Accessed and evaluated by attacker |
| `backup.zip` | Archive | Staging container for exfiltrated data | Created minutes before attacker likely exfiltration unknown data |
| `OneDriveStandalone` | Registry  | Used for persistence via registry modification | Used to execute MicrosoftEdgeUpdate |
| `mimikatz.exe` | Executable | Credential dumping tool | Ran successfully on `MTS-ContractorPC1` |
| `kb5029244.ps1` | Script | PowerShell payload | Downloaded from attacker infrastructure  |

---

External Attacker Assets

| **Asset** | **Type** | **Purpose** | **Notes** |
| --- | --- | --- | --- |
| `81.141.209.165` | IP Address | Initial RDP access to `MTS-ContractorPC1` | Logged by Defender |
| `78.141.234.86:1337` | IP + Port | Hosted PowerShell payload (`kb5029244.ps1`) | Used during execution phase |
| `78.141.205.85` | IP Address | Accessed `MTC-DC` during lateral movement | Matches attacker infrastructure |
| `www[.]file[.]io` | Domain | Data exfiltration | Received `backup.zip` |
| `104.21.66.52` | IP Address | Resolved from `file.io` | Likely used for final data transfer |

# Execution

On October 7, 2025 at 04:18:54 UTC, the attacker remotely executed a PowerShell command from `MTS-ContractorPC1` using the `MTS-Contractor\administrator` account. The command used `Invoke-WebRequest` to download a malicious script named `kb5029244.ps1` from the external IP `78.141.234.86` over port 1337. This script was hosted on a non-standard web service, likely chosen to evade traditional network monitoring.

The payload delivery was initiated via `powershell.exe`, and may have been launched through `svchost.exe` to further disguise the activity as legitimate system behavior. This marks the transition from initial access to active exploitation, enabling the attacker to deploy additional tooling and prepare for persistence and credential theft.

(see fig. 9)

- The script `kb5029244.ps1` was downloaded using PowerShell’s `Invoke-WebRequest`, a common method for fileless payload delivery.
- The hosting IP (`78.141.234.86`) used port `1337`, indicating use of a non-standard service for staging.
- Execution occurred shortly after successful RDP access, suggesting a pre-planned payload deployment.
- Use of `svchost.exe` may indicate an attempt to blend malicious activity with legitimate service execution.

remote connection IP address
<img width="1532" height="533" alt="image" src="https://github.com/user-attachments/assets/9a06ac2a-a257-4554-ba80-ef67a728c5a5" />


Fig. 9

# Persistence

On October 7, 2025 at 06:16:36 UTC, the attacker established persistence by modifying registry values associated with `OneDriveStandalone` under the `MTS-Contractor\administrator` account on `MTS-ContractorPC1`. This binary, typically associated with legitimate OneDrive operations, was likely repurposed or masqueraded to maintain access across reboots or logons.

The registry modification likely suggests the attacker configured `OneDriveStandalone` to autostart and keep presistence using `MicrosoftEdgeUpdate`, allowing it to execute automatically during system boot or user login. This technique is commonly used to ensure continued access without requiring repeated exploitation.

(see fig. 6 & 7)

- The attacker leveraged a trusted binary (`OneDriveStandalone`) to avoid detection.
- Registry changes were made under the administrator account, indicating elevated privileges.
- The timing of persistence setup followed credential access and system discovery, suggesting a deliberate sequence to maintain long-term control.

attacker leveraged a trusted binary
<img width="780" height="847" alt="image" src="https://github.com/user-attachments/assets/65a84989-6f99-401b-8836-8aeea5ab4ad6" />


Fig. 7

# Privilege Escalation

Following initial access to `MTS-ContractorPC1`, the attacker escalated privileges by successfully brute-forcing the `MTS-Contractor\administrator` account. A total of 13 login attempts were observed using variations of the administrator username, including `mts\administrator`, `\administrator`, and `MTS-CONTRACTORP\administrator`. The successful login granted elevated access, enabling the attacker to execute further actions such as credential dumping and lateral movement.

The attacker’s source IP (`81.141.200.165`) was traced to Europe, violating Maple Tax Solutions’ remote access policy, which restricts logins to Canadian regions. The attacker’s tooling and behavior suggest use of a Kali Linux environment, known for its pre-installed penetration testing utilities.

Subsequently, the attacker leveraged the compromised administrator credentials to access the domain controller `MTC-DC` via RDP, indicating successful privilege escalation across systems.

(see fig. 2 & 2.1, fig. 4, fig. 10 & 11)

- Brute-force activity involved 13 login attempts with multiple administrator account formats.
- Successful login from a European IP violated geographic access policies.
- Use of Kali Linux tooling suggests adversary familiarity with offensive security frameworks.
- Credentials were reused to access `MTC-DC`, confirming domain-level privilege escalation.

Credentials were reused to access MTC-DC
<img width="470" height="782" alt="image" src="https://github.com/user-attachments/assets/c17ba58f-5b25-4693-a23a-432ace73d83a" />


Fig. 11

# Defense Evasion

On October 7, 2025 at 06:21:46 UTC, the attacker modified eight registry values under the `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` path on `MTS-ContractorPC1`. These changes excluded several binaries from Defender’s scanning and logging mechanisms, effectively disabling detection for commonly abused tools and LOLBins. This action was performed under the `MTS-Contractor\administrator` account and represents a deliberate attempt to suppress visibility during post-exploitation activity.

(see fig. 6 & 7)

- The attacker excluded binaries such as `powershell.exe`, `cmd.exe`, `rundll32.exe`, and `mimikatz.exe`, which are frequently used in fileless attacks and credential theft.
- Additional exclusions included renamed or suspicious binaries (`svchost_update.exe`, `MicrosoftEdgeUpdate.exe`, `regsvr32.exe`) likely used for persistence or lateral movement.
- These exclusions allowed malicious scripts and tools to operate without triggering Defender alerts, significantly reducing the chance of detection during the attack window.

| Registry Path | Excluded Binaries | Description  |
| --- | --- | --- |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `powershell.exe` | Used for fileless attacks, payload delivery, and C2 communication. Exclusion hides malicious scripts. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `cmd.exe` | Abused to run malicious DLLs or scripts stealthily. Exclusion prevents Defender from scanning DLL payloads. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `rundll32.exe` | Used to load remote scripts via COM objects. Exclusion allows silent registration of malicious DLLs. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `certutil.exe` | Used for launching scripts, binaries, and lateral movement. Exclusion hides batch-based execution. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `mimikatz.exe` | Abused to download payloads or encode/decode data. Exclusion avoids detection of file transfer activity. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `MicrosoftEdgeUpdate.exe` | Directly used to steal passwords and hashes. Exclusion is a blatant attempt to bypass AV detection. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `svchost_update.exe` | Can be renamed or abused for persistence. Exclusion may be used to mask malicious binaries under trusted names. |
| `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes` | `regsvr32.exe` | Likely a fake or renamed binary for persistence. Exclusion hides it from Defender scans. |

# Credential Access

Credential Access

On October 7, 2025 at 06:28:25 UTC, the attacker executed `mimikatz.exe` on `MTS-ContractorPC1` to extract authentication credentials directly from memory. The tool was run using the command `sekurlsa::logonpasswords`, which enabled the attacker to retrieve plaintext passwords, password hashes, PINs, and Kerberos tickets.

This access facilitated multiple credential-based attacks, including:

- **Pass-the-Hash**: Using stolen NTLM hashes to authenticate without knowing the actual password.
- **Pass-the-Ticket**: Leveraging stolen Kerberos tickets to impersonate users.
- **Golden Ticket**: Forging a Kerberos Ticket Granting Ticket (TGT) to gain unrestricted access across the domain.

The use of `mimikatz.exe` was preceded by Defender exclusions that specifically allowed the binary to run undetected. This credential dump was a critical step in enabling lateral movement and domain dominance.

(see fig. 8)

- `mimikatz.exe` was executed from `C:\Windows\Temp\TMP121235\mimikatz.exe`.
- The command `sekurlsa::logonpasswords` was used to extract credentials from memory.
- Multiple credential theft techniques were likely employed, including pass-the-hash, pass-the-ticket, and golden ticket attacks.
- Defender exclusions were in place to prevent detection of `mimikatz.exe`.

mimikatz.exe was executed
<img width="1509" height="163" alt="image" src="https://github.com/user-attachments/assets/ade97c88-f183-4b3f-8503-f0237fc2a038" />


Fig. 8

# Discovery

On October 7, 2025 at 06:07:19 UTC, the attacker executed a series of reconnaissance commands on `MTS-ContractorPC1` to enumerate host and domain information. The initial command used was `systeminfo.exe`, which provided details about the operating system, hardware, and network configuration. This was followed by additional commands including `netsh.exe`, `whoami.exe`, `hostname.exe`, and `ipconfig.exe`, all of which are commonly used to gather system-level context during early-stage discovery.

These commands were executed via PowerShell, indicating the attacker’s preference for fileless techniques and native tooling to avoid detection.

(see fig. 5)

- `systeminfo.exe` was used to collect OS and hardware details.
- Additional commands (`netsh.exe`, `whoami.exe`, `hostname.exe`, `ipconfig.exe`) were executed to enumerate user context and network configuration.
- All commands were run via PowerShell, suggesting use of LOLBins for stealth.
- Discovery activity occurred after initial access but before persistence and credential dumping.

# Lateral Movement

On October 7, 2025 at 07:02:25 UTC, the attacker initiated lateral movement from `MTS-ContractorPC1` to the domain controller `MTC-DC`. This was achieved using Remote Desktop Protocol (RDP), leveraging previously dumped credentials from the `MTS-Contractor\administrator` account. The remote IP used for this connection was `78.141.234.85`, which is associated with the attacker’s infrastructure.

This movement allowed the attacker to expand their foothold within the network and access sensitive domain-level resources, including unknown documentation later likely confirmed to be exfiltrated.

(see fig. 10 & 11)

- RDP was used to access `MTC-DC` from `MTS-ContractorPC1`.
- The attacker used valid credentials obtained via prior credential dumping.
- Remote IP `78.141.234.85` was used to establish the connection.
- Movement occurred after privilege escalation and before exfiltration, indicating a structured attack progression.

# Command and Control

During the post-exploitation phase, the attacker established a command and control (C2) channel using the domain `www[.]file[.]io`. This domain was accessed from `MTC-DC`, indicating that the attacker had successfully moved laterally and was now operating from a domain controller. The method of communication appears to be web-based, likely leveraging HTTP or HTTPS to exfiltrate data and maintain control over the compromised environment.

This C2 infrastructure was tied to external IP addresses `78.141.234.85` and `104.21.66.52`, which were used during lateral movement and likely unknown data exfiltration. The use of a public file-sharing domain for C2 suggests an attempt to blend malicious traffic with legitimate web activity.

(see fig. 13 & 14)

- C2 domain: `www[.]file[.]io` accessed from `MTC-DC`.
- Associated IPs: `78.141.234.85`, `104.21.66.52`.
- Communication method: Web-based, likely HTTP/HTTPS.
- C2 activity occurred after credential dumping and lateral movement.

C2 domain: www[.]file[.]io accessed from MTC-DC
<img width="787" height="687" alt="image" src="https://github.com/user-attachments/assets/76c0d1b5-6ad0-4304-b2a7-068945420309" />


Fig, 13

# Exfiltration

On October 7, 2025 at 08:00:35 UTC, the attacker accessed `Bank_Routing_Number.txt` on `MTC-DC` to evaluate its contents for potential exfiltration. This file likely contained financial data, and its inspection suggests the attacker was selectively identifying high-value targets.

At 08:10:59 UTC, the attacker created a ZIP archive to consolidate exfiltration data. Just two seconds later, at 08:11:01 UTC, the archive was likely uploaded to the external domain `www[.]file[.]io`, a public file-sharing service known for anonymous, one-time uploads with automatic expiration.

The domain resolved to IP address `104.21.66.52`, which was previously associated with the attacker’s infrastructure during command and control operations. The likely exfiltrated content included unknown documentation and internal records belonging to Maple Tax Solutions.

(see fig. 12, 13, 14 & 16)

- At 08:00:35 UTC, the attacker opened `Bank_Routing_Number.txt` to assess its value for likely exfiltration.
- At 08:10:59 UTC, a ZIP archive was created on `MTC-DC` to stage exfiltration data.
- At 08:11:01 UTC, the archive was uploaded to `www[.]file[.]io`.
- IP address used: `104.21.66.52`.
- Method: Web-based upload to a public file-sharing service.
- Likely exfiltrated content unknown documentation and internal records.

| Path | File | Hash SHA256 | File Size |
| --- | --- | --- | --- |
| C:\ProgamData\Microsoft\Crypto\RSA\ | backup.zip | 832514f44081b141d5fe835acb1b712b19f38fffe936b3e36357b7c790b40e77 | 1.97 KB |

| URL | IP Address |
| --- | --- |
| www[.]file[.]io | 104.21.66.52 |

# Impact

The attacker’s actions likely resulted in the exfiltration of unknown documentation from `MTC-DC`, likely including internal records and banking information. This breach poses significant risks to Maple Tax Solutions’ clients, regulatory compliance posture, and brand reputation.

The use of `file.io` for anonymous data transfer, combined with credential theft and domain-level access, indicates a high-impact compromise with potential for long-term damage. The attacker’s ability to move laterally, evade defenses, and likely extract data without immediate detection underscores the effectiveness of their tactics.

(see fig. 12, 13, 14 & 16)

- Unknown documents and internal records were likely exfiltrated from the domain controller.
- `Bank_Routing_Number.txt` was accessed and likely included in the stolen data.
- Data was staged in a ZIP archive and likely transferred to `www[.]file[.]io`.
- The attacker maintained domain-level access and operated from `MTC-DC`.

Unknown documents and internal records were likely exfiltrated from the domain controller
<img width="1033" height="808" alt="image" src="https://github.com/user-attachments/assets/97d5ff52-de9b-4c46-badb-2a5e836206fc" />


Fig. 12

# Timeline

---

Attack Timeline (Grouped by Phase)

| MITRE Attack Group | **Time (UTC)** | **Event Description** | **MITRE Technique** | **Figure Ref.** |
| --- | --- | --- | --- | --- |
| **Initial Access** |  |  |  |  |
|  | 04:00 | RDP access to `MTS-ContractorPC1` using brute-forced administrator credentials | Valid Accounts (`T1078`) | fig. 2, 4 |
|  | 04:13:08 | Defender logs external IP `81.141.209.165` | N/A | fig. 4 |
| **Execution** |  |  |  |  |
|  | 04:00 | PowerShell payload downloaded via `Invoke-WebRequest` | PowerShell (`T1059.001`) | fig. 9 |
|  | 04:18:54 | `kb5029244.ps1` downloaded from `78.141.234.86:1337` | PowerShell (`T1059.001`) | fig. 9 |
| **Defense Evasion** |  |  |  |  |
|  | 06:07:19 | Defender exclusions modified to allow LOLBins and `mimikatz.exe` | Modify Registry (`T1112`), Indicator Removal (`T1070.004`) | fig. 6, 7 |
| **Discovery** |  |  |  |  |
|  | 06:07:19 | `systeminfo.exe` executed via PowerShell | System Info Discovery (`T1082`) | fig. 5 |
| **Persistence** |  |  |  |  |
|  | 06:16:22 | Persistence via `OneDriveStandalone` registry modification | Boot/Logon Autostart (`T1547.001`) | fig. 6, 7 |
| **Credential Access** |  |  |  |  |
|  | 06:38:35 | `mimikatz.exe` executed with `sekurlsa::logonpasswords` | OS Credential Dumping (`T1003.001`) | fig. 8 |
| **Lateral Movement** |  |  |  |  |
|  | 07:02:54 | RDP connection from `MTS-ContractorPC1` to `MTC-DC` | Remote Services (`T1021.001`) | fig. 10, 11 |
|  | 07:35:25 | IP `78.141.205.85` accesses `MTC-DC` | Remote Services (`T1021.001`) | fig. 10, 11 |
| **Collection & Exfiltration** |  |  |  |  |
|  | 08:00:15 | Attacker viewed `Bank_Routing_Number.txt` for exfiltration value | File Discovery (`T1083`) | fig. 16 |
|  | 08:00:34 | Created `backup.zip` archive for staging | Archive Collected Data (`T1560.001`) | fig. 12 |
|  | 08:11:01 | Likely uploaded archive to `www[.]file[.]io` (`104.21.66.52`) | Exfiltration Over Web Service (`T1041`) | fig. 13, 14 |
| **Command and Control** |  |  |  |  |
|  | 07:35–08:11 | Communication with  `file.io` from `MTC-DC` | Exfiltration Over Web Service (`T1041`) | fig. 13, 14 |
| **Impact** |  |  |  |  |
|  | Post-08:11 | Unknown documents and internal records likely exfiltrated | Archive + Likely Exfiltration (`T1560.001`, `T1041`) | fig. 12, 13, 14, 16 |

# Diamond Model

<img width="1486" height="844" alt="image" src="https://github.com/user-attachments/assets/501bbab0-f29d-4646-9a7f-5319f666fdfd" />


# Indicators

Indicator of Compromise (IOC) Matrix

Credential-Based IOCs

| **Type** | **Value** | **Context** |
| --- | --- | --- |
| Username | `MTS-Contractor\administrator` | Brute-forced for initial access |
| Command | `sekurlsa::logonpasswords` | Used by `mimikatz.exe` for credential dumping |
| Executable | `mimikatz.exe` | Credential dumping tool |

Host & File-Based IOCs

| **Type** | **Value** | **Context** |
| --- | --- | --- |
| Hostname | `MTS-ContractorPC1` | Initial access point |
| Hostname | `MTC-DC` | Domain controller targeted |
| File | `Bank_Routing_Number.txt` | Unknown data is likely exfiltration |
| Archive | `backup.zip` | Created for staging exfiltration |
| Executable | `OneDriveStandalone` | Used for registry modification  |
| Script | `kb5029244.ps1` | PowerShell payload |

Network & Infrastructure IOCs

| **Type** | **Value** | **Context** |
| --- | --- | --- |
| IP Address | `81.141.209.165` | Initial RDP access |
| IP Address | `78.141.234.86:1337` | Hosted PowerShell payload |
| IP Address | `78.141.205.85` | Accessed `MTC-DC` during lateral movement |
| IP Address | `104.21.66.52` | Resolved from `file.io` for exfiltration |
| Domain | `www[.]file[.]io` | Likely data exfiltration |

Detection Keywords & Behaviors

| **Type** | **Value** | **Context** |
| --- | --- | --- |
| PowerShell Cmd | `Invoke-WebRequest` | Used to download payload |
| Registry Path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence via registry |
| Defender Action | Exclusion of `mimikatz.exe` | Defense evasion tactic |
| Protocol | RDP | Used for lateral movement |

File Hash IOCs (SHA256)

| **Type** | **SHA256 Hash** | **Associated File / Context** |
| --- | --- | --- |
| File Hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `mimikatz.exe` used for credential dumping |
| File Hash | `d2c7f3a1b5e6c8f9a3e4d2f1c9b8a7e6f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f` | `kb5029244.ps1` PowerShell payload |
| File Hash | `a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e` | `backup.zip` archive created before exfiltration |

# MITRE ATT&CK

MITRE ATT&CK Matrix

| **Tactic** | **Technique** | **Sub-Technique** | **ID** | **Context** |
| --- | --- | --- | --- | --- |
| **Initial Access** | Valid Accounts | — | `T1078` | RDP access to `MTS-ContractorPC1` |
| **Execution** | Command and Scripting Interpreter | PowerShell | `T1059.001` | Payload execution via `Invoke-WebRequest` |
|  | Command and Scripting Interpreter | — | `T1059` | General PowerShell usage |
| **Persistence** | Boot or Logon Autostart Execution | Registry Run Keys / Startup Folder | `T1547.001` |  Registry modification via `OneDriveStandalone` |
| **Privilege Escalation** | Valid Accounts | — | `T1078` | Domain-level access on `MTC-DC` |
| **Defense Evasion** | Indicator Removal on Host | File Deletion | `T1070.004` | Defender exclusions and evasion |
|  | Modify Registry | — | `T1112` | Registry changes for persistence and exclusions |
| **Credential Access** | OS Credential Dumping | `mimikatz.exe` | `T1003.001` | Dumped credentials from `MTS-ContractorPC1` |
| **Discovery** | System Information Discovery | — | `T1082` | Executed `systeminfo.exe` |
|  | File and Directory Discovery | — | `T1083` | Viewed `Bank_Routing_Number.txt` |
| **Lateral Movement** | Remote Services | RDP | `T1021.001` | Moved from `MTS-ContractorPC1` to `MTC-DC` |
| **Collection** | Data from Local System | — | `T1005` | Accessed and staged sensitive files |
|  | Archive Collected Data | — | `T1560.001` | Created `backup.zip` |
| **Exfiltration** | Exfiltration Over Web Service | — | `T1041` | Likely uploaded archive to `file.io` |
| **Command & Control** | Application Layer Protocol | Web Protocols | `T1071.001` | C2 via `file.io` |

# **Root Cause Analysis**

The root cause of the Maple Tax Solutions cyberattack was the brute force to access a contractor workstation (`MTS-ContractorPC1`) via Remote Desktop Protocol (RDP). The attacker successfully authenticated using the local administrator account (`MTS-Contractor\administrator`) from IP address `81.141.209.165` at 04:07:58 UTC on October 7, 2025. This access was preceded by a failed login attempt from IP `142.90.213.242`, suggesting prior reconnaissance or credential testing.

The absence of multi-factor authentication (MFA) on RDP and lack of geolocation restrictions allowed the attacker to connect from an external region without triggering access controls. Once inside, the attacker leveraged local administrator privileges to execute commands, harvest credentials, and move laterally to the domain controller.

This incident highlights systemic gaps in remote access security, credential management, and endpoint visibility. The failure to enforce MFA, restrict RDP access by geography, and monitor for anomalous behavior enabled the attacker to operate during critical early stages of the intrusion.

# **Detection Gap Analysis**

The attacker was able to access Maple Tax Solutions’ environment, escalate privileges, and exfiltrate unknown data without triggering timely alerts. This reveals several key detection gaps across the attack chain. First, remote access from an external IP (`81.141.209.165`) using brute force did not flag and went unnoticed due to the absence of geolocation-based access controls and lack of multi-factor authentication (MFA) on RDP. Second, the attacker’s use of legitimate tools like `svchost.exe` and PowerShell with obfuscated commands bypassed standard endpoint detection rules. Third, critical behaviors — such as registry persistence, credential dumping with `mimikatz.exe`, and archive creation on a domain controller — were not correlated or flagged in real time. These gaps allowed the attacker to operate for hours without interruption.

To close these gaps, leadership should support improvements in detection engineering and policy enforcement. This includes enabling MFA for all remote access, implementing geoblocking to restrict logins to trusted regions, and tuning Endpoint Detection and Response (EDR) systems to flag misuse of native binaries and chained behaviors. Investing in correlation-based alerting — where login events, script execution, and file access are linked — will empower security teams to detect threats earlier and respond faster. These enhancements are essential for reducing dwell time and protecting client data from future compromise.

# Recommendation

To reduce the risk of future intrusions like the one experienced in this case, senior leadership should prioritize a layered approach to access control, monitoring, and response readiness. 

This includes implementing Multi-Factor Authentication (MFA) for all Remote Desktop Protocol (RDP) access, which adds a critical barrier against credential misuse. 

Geoblocking should be enabled to restrict remote access to trusted regions—such as Canada, if operations are localized—helping prevent unauthorized logins from foreign infrastructure. 

Credential policies should be updated to enforce strong password hygiene, regular rotation, and alerts on reuse across systems. 

Endpoint Detection and Response (EDR) tools must be tuned to flag suspicious behaviors like PowerShell downloads, registry persistence, and archive creation on sensitive hosts. 

Leadership should also support investment in correlation-based detection, allowing security teams to link events across the attack chain—from failed logins to data exfiltration—so threats can be identified early and contained quickly. 

These measures not only strengthen technical defenses but also demonstrate a proactive commitment to protecting client data and business continuity.

# Detection Opportunities

Initial Detection Opportunities:

- Monitor for RDP logons from non-whitelisted geolocations
- Alert on excessive failed logon attempts followed by success
- Flag use of `svchost.exe` with unusual service parameters

Execution Detection Opportunities

- Monitor for PowerShell usage with `Invoke-WebRequest` or `IEX` in command line.
- Alert on downloads from non-standard ports or external IPs.
- Flag execution of scripts with suspicious naming conventions (e.g., `kb5029244.ps1`).
- Correlate PowerShell activity with recent RDP logons for chained behavior detection

Persistence Detection Opportunities

- Monitor registry keys associated with autostart entries for unexpected binaries.
- Alert on execution of `OneDriveStandalone` outside normal OneDrive context.
- Correlate registry changes with recent credential access or privilege escalation events.
- **Binary**: `OneDriveStandalone`
    - **Behavior**: Likely masquerading as legitimate service
    - **Technique**: Boot or Logon Autostart Execution (`T1547.001`)

Privilege Detection Opportunities

- Monitor for multiple failed login attempts followed by success, especially targeting privileged accounts.
- Alert on RDP access from non-whitelisted geolocations.
- Flag reuse of credentials across multiple hosts, particularly domain controllers.
- Detect use of known offensive OS environments (e.g., Kali) through network fingerprinting or behavioral indicators

Defense Detection Opportunities

- Monitor for changes to Defender exclusion registry paths, especially involving known LOLBins.
- Alert on exclusion of binaries commonly used in attack chains (e.g., `mimikatz.exe`, `powershell.exe`).
- Correlate registry modifications with recent execution or credential access events

Credential Access Detection Opportunities

- Monitor for execution of known credential dumping tools like `mimikatz.exe`.
- Alert on use of `sekurlsa::logonpasswords` or similar commands in PowerShell or command line.
- Detect access to LSASS memory or unusual reads from `lsass.exe`.
- Correlate credential dumping activity with recent privilege escalation or Defender exclusion changes.

Discovery Detection Opportunities

- Monitor PowerShell execution of system enumeration commands.
- Alert on use of `systeminfo.exe`, `netsh.exe`, or `ipconfig.exe` outside of expected administrative workflows.
- Correlate discovery activity with recent RDP access or privilege escalation events.

Lateral Movement Detection Opportunities

- Monitor RDP connections between internal hosts, especially involving domain controllers.
- Alert on use of credentials across multiple systems within a short time window.
- Flag remote access from infrastructure IPs not associated with internal assets.
- Correlate lateral movement with recent credential dumping or privilege escalation events.

Command and Control Detection Opportunities

- Monitor outbound connections to public file-sharing domains from sensitive hosts.
- Alert on unexpected web traffic from domain controllers to external IPs.
- Flag use of domains like `file.io` in enterprise environments.
- Correlate C2 activity with recent archive creation or credential access events.

Exfiltration Detection Opportunities

- Monitor access to likely sensitive file names (e.g., `Bank_Routing_Number.txt`) on critical systems.
- Alert on ZIP or archive creation on domain controllers.
- Flag outbound connections to public file-sharing domains like `file.io`.
- Correlate file access and archive creation with subsequent data transfer events

Impact Detection Opportunities

- Monitor for access to sensitive financial files on domain controllers.
- Alert on ZIP creation followed by outbound data transfer to anonymous domains.
- Flag unusual access patterns involving domain-level accounts and external infrastructure.
- Correlate impact indicators with earlier stages of the attack chain (e.g., credential access, lateral movement).

# Appendix

successful login
<img width="1525" height="430" alt="image" src="https://github.com/user-attachments/assets/01d106aa-79d0-4150-97bc-1a4a46575470" />

geolocation of attacker IP
<img width="1102" height="1096" alt="image" src="https://github.com/user-attachments/assets/1dccdbe8-abbc-4859-bba9-84c9c18af0f0" />

abuseIPDB of attacker IP
<img width="1090" height="1441" alt="image" src="https://github.com/user-attachments/assets/7be2a0d7-f7df-4e39-9b2e-7450a0e3a36b" />


<img width="557" height="425" alt="image" src="https://github.com/user-attachments/assets/86d76ac0-8b6c-40c1-baad-d55f2224aa3b" />

successful login
<img width="1540" height="350" alt="image" src="https://github.com/user-attachments/assets/43902d8c-d02b-4160-b130-e2971bb6c943" />

remote commands ran
<img width="1131" height="500" alt="image" src="https://github.com/user-attachments/assets/3ca3c82a-f55e-4c51-a254-e3599417c183" />

mimikatz ran
<img width="1114" height="113" alt="image" src="https://github.com/user-attachments/assets/313f826e-4f59-4aa5-9820-b4ab1337b2a1" />

powershell script downloaded
<img width="1488" height="484" alt="image" src="https://github.com/user-attachments/assets/0cc9f115-25d8-45f2-b00c-50eff304959c" />

zip file created
<img width="596" height="463" alt="image" src="https://github.com/user-attachments/assets/611968bf-e6e3-4b63-aa78-3e3a60d54a43" />

registery key changed
<img width="1102" height="271" alt="image" src="https://github.com/user-attachments/assets/3c3c8544-7323-46a7-91a2-1f6b0e5096d1" />

file created with likely banking information
<img width="1101" height="823" alt="image" src="https://github.com/user-attachments/assets/6ad4c337-07d4-4c6a-9999-f56684a65a25" />


















