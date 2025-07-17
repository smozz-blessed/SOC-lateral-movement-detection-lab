# 🚨 Lateral Movement & Remote Command Execution Detection Lab

**Simulating a realistic attack scenario with detection using Splunk and Sysmon**

---

## 📚 Table of Contents

- [� Lateral Movement \& Remote Command Execution Detection Lab](#-lateral-movement--remote-command-execution-detection-lab)
	- [📚 Table of Contents](#-table-of-contents)
	- [📝 Overview](#-overview)
	- [🧰 Lab Setup](#-lab-setup)
		- [⚙️ Windows 11 Installation (Victim Machine)](#️-windows-11-installation-victim-machine)
		- [🛠️ Kali Linux Setup (Attacker Machine)](#️-kali-linux-setup-attacker-machine)
- [Disable Defender](#disable-defender)
- [Disable Firewall](#disable-firewall)
- [Enable Admin Shares](#enable-admin-shares)
- [Enable auditing policies](#enable-auditing-policies)
- [Enable command line logging](#enable-command-line-logging)
	- [🚀 **Prêt à copier-coller directement dans ton `README.md`**](#-prêt-à-copier-coller-directement-dans-ton-readmemd)

---

## 📝 Overview

This project simulates a **lateral movement and remote code execution attack** from a Kali Linux machine against a Windows 11 target.  
The detection is performed using **Splunk** and **Sysmon**, creating a realistic scenario for Blue Team training and portfolio building.

---

## 🧰 Lab Setup

| Machine           | Role                                |
|------------------|-------------------------------------|
| **Kali Linux**    | Attacker (Impacket, smbclient, CrackMapExec) |
| **Windows 11 VM** | Victim (Splunk, Sysmon, Logging configured) |
| **Splunk**        | Log Collection and Analysis         |

### ⚙️ Windows 11 Installation (Victim Machine)

1. Download Windows 11 ISO from Microsoft.
2. Create a Virtual Machine using VirtualBox, VMware, or UTM with Bridged or Host-Only Networking.
3. Set up Administrator user, disable UAC popups, configure networking, and install Remote Desktop if needed.

### 🛠️ Kali Linux Setup (Attacker Machine)

1. Download Kali ISO from [kali.org](https://kali.org).
2. Update Kali:

```bash
sudo apt update && sudo apt upgrade -y

	3.	Install attack tools:

sudo apt install impacket crackmapexec smbclient

	4.	Configure networking to communicate with the Windows VM.

⸻

⚙️ Windows 11 Vulnerable Configuration

Disable security features to simulate a vulnerable environment:

# Disable Defender
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true

# Disable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Enable Admin Shares
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# Enable auditing policies
AuditPol /set /subcategory:"Logon" /success:enable /failure:enable
AuditPol /set /subcategory:"Process Creation" /success:enable

# Enable command line logging
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f


⸻

🐾 Installing Sysmon

Download Sysmon:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

Use a pre-configured sysmonconfig.xml from Sysmon Modular.

Run as Administrator:

cd "C:\Users\Downloads\sysmon"
.\sysmon64.exe -i sysmonconfig.xml

Verify Sysmon is running:

Get-Process sysmon64


⸻

📈 Installing Splunk
	1.	Download Splunk Enterprise:
https://www.splunk.com/en_us/download/splunk-enterprise.html
	2.	Configure Splunk Inputs:

	•	WinEventLog: Security
	•	WinEventLog: System
	•	WinEventLog: Application
	•	Microsoft-Windows-PowerShell/Operational
	•	Sysmon Logs

	3.	Verify that logs are properly ingested into Splunk.

⸻

🛠️ Attack Simulation (Kali Linux)

1️⃣ Lateral Movement with impacket-psexec

impacket-psexec WORKGROUP/Administrator@192.168.56.10 -p <password>

Generates:
	•	Event ID 4624 (Logon Type 3) – Remote logon

2️⃣ Access Admin Shares with smbclient

smbclient \\\\192.168.56.10\\C$ -U Administrator

Generates:
	•	Event ID 4624 (Logon Type 3) – SMB logon
	•	Event ID 5140 – Share access

⸻

🔎 Detection & Analysis in Splunk

Detect Remote Logon (4624)

index=main sourcetype=WinEventLog:Security EventCode=4624 Logon_Type=3
| table _time Account_Name Source_Network_Address Workstation_Name Authentication_Package

Detect Process Creation (4688)

index=main sourcetype=WinEventLog:Security EventCode=4688
| table _time Account_Name New_Process_Name Process_Command_Line Parent_Process_Name

Correlate Lateral Movement and Execution

index=main sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4688)
| eval event=case(EventCode==4624,"Network Logon", EventCode==4688,"Process Created")
| table _time event Account_Name Source_Network_Address New_Process_Name Process_Command_Line Parent_Process_Name


⸻

🎯 Attack Mapping & Interpretation

Event ID	Meaning	Attack Phase
4624 (Type 3)	Remote network logon	Lateral Movement
4688	Command execution (cmd.exe)	Post-exploitation
5140	SMB share accessed	Recon / Access

MITRE ATT&CK Mapping

Tactic	Technique
Lateral Movement	T1021.002 - SMB/Windows Admin Shares
Execution	T1569.002 - Service Execution
Command Execution	T1059.003 - Windows Command Shell


⸻

📂 Artifacts

File/Folder	Description
README.md	Full lab documentation
screenshots/	Attack and detection screenshots
splunk_queries.txt	List of Splunk queries used
sysmonconfig.xml	Sysmon configuration (if customized)


⸻

🔮 Next Steps & Future Improvements

This lab is an initial step toward building a comprehensive detection engineering portfolio.

🛠️ Planned Enhancements:
	•	Real-Time Alerting
Configure Splunk alerts for lateral movement detection.
	•	MITRE ATT&CK Integration
Map events to ATT&CK directly in Splunk dashboards.
	•	Broader SIEM Use
Try Splunk Enterprise Security or open-source SIEM tools.
	•	PowerShell Attack Simulation
Simulate remote PowerShell attacks and analyze logs.
	•	Hybrid Cloud Monitoring
Integrate Azure or AWS logs.
	•	Automation
Use Terraform, Vagrant, or Ansible to automate the lab deployment.
	•	Sigma Rule Contribution
Convert detections to Sigma for community sharing.

⸻

🧪 Learning Focus Areas
	•	Advanced Splunk SPL Query Development
	•	Detection Engineering & Blue Team Operations
	•	Threat Hunting Based on Telemetry
	•	Red Team vs Blue Team Simulation

⸻

➕ How to Contribute
	•	Fork the repo and submit a pull request
	•	Open issues for suggestions
	•	Share new detection use cases or scenarios

⸻

🏁 Conclusion

This lab provides a practical end-to-end scenario for detecting lateral movement and remote code execution using Windows logs, Sysmon, and Splunk.

Use this project to:
	•	Train for SOC Analyst roles
	•	Build your cybersecurity portfolio
	•	Understand real-world attack detection pipelines

⸻

🔗 Credits & Tools
	•	Impacket
	•	Sysmon
	•	Splunk

⸻

📧 Connect with me

LinkedIn
GitHub

---

## 🚀 **Prêt à copier-coller directement dans ton `README.md`**

- Les titres sont hiérarchisés proprement  
- Les liens du sommaire fonctionneront parfaitement  
- Les captures doivent être placées dans `screenshots/` et référencées comme prévu

---

Si tu veux, je peux t’aider à faire un **post LinkedIn ou un badge visuel** pour mettre en avant ton projet.  
Veux-tu ça ?