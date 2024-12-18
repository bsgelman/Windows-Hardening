# Windows Hardening

This repository contains Microsoft Powershell scripts designed to secure Windows operating systems. Initially developed for the CyberPatriot competition, these tools are applicable to various scenarios, including personal, organizational, and competition environments. Please make sure to read the "Usage" section before attempting to use either of these scripts.

---

## Features

### **1. Harden\_Windows.ps1**

This script primarily focuses on automating critical security tasks, system hardening, and auditing. It modifies Windows Settings, registry, audit policies, services, and even configures certain apps like Google Chrome for maximum security. The script prompts the user with a menu of options to choose from.

- **System Overview:**

  - Scans the system's files and lists suspicious files, startup processes, scheduled tasks, processes with bigger loads, users/groups, and more.
  - Outputs results to .txt files located in a certain directory.

- **Firewall Configuration**:

  - Enables and configures advanced firewall settings.
  - Blocks insecure ports (e.g., Telnet, FTP, RDP) and logs dropped/allowed connections.

- **Windows Defender Configuration**:

  - Enables real-time protection, heuristic scanning, and other important settings.
  - Enforces attack surface reduction rules (ASR) to block malicious behavior.

- **User and Group Management**:

  - Validates users and administrator accounts.
  - Sets proper account properties and changes passwords to a secure one to ensure all passwords meet minimum complexity.

- **Registry and Policy Configuration**:

  - Updates registry keys to enforce security policies.
  - Configures Group Policy settings for updates, password caching, and security restrictions.

- **Critical Services Management:**

  - Enables system restore and ensures critical services are running.
  - Disables unnecessary or potentially insecure services like Telnet, FTP, and SMB1.

- **Additional Hardening**:

  - Disables Remote Desktop, NetBIOS, and auto-run features.
  - Flushes DNS cache.
  - Enables Windows "God Mode" for system control.

### **2. Purify\_Users.ps1**

A supporting script that validates and modifies users and administrators based on the HTML README file provided during the competition.

- Automatically re-prompts for administrative access if not already running with it.
- Scrapes the HTML document containing the intended user/administrator list and applies it to the operating system.

---

## Usage

**WARNING**

- Test the scripts out on a virtual machine BEFORE running them on your personal device since they harden your system to an extreme degree and it may become unusable for your needs.
- Make sure you read the `Harden_Windows.ps1` script and are aware of the password that is applied to all users so that you can log back in.
- Make sure you know what each feature does before running.
- `Purify_Users.ps1` is NOT intended for use outside of the competition, since it reads from a README HTML document provided.

### Prerequisites

- **Operating System**: Windows 7 and later
- **Permissions**: Must run with administrative privileges (will self-elevate)
- **PowerShell Version**: 5.1 or later

### Execution

1. Read the warnings listed above.
2. Clone the repository or download the scripts.
3. Open PowerShell as Administrator.
4. Run the primary script:
   ```powershell
   .\Harden_Windows.ps1
   ```
5. Follow the prompts to select hardening actions.
6. If needed, execute the secondary script:
   ```powershell
   .\Purify_Users.ps1
   ```

---

## Modular Hardening Options

The `Harden_Windows.ps1` script provides modular options for customization:

1. **Harden Networking**
2. **Harden Windows Defender**
3. **Disable Remote Desktop**
4. **Configure Registry**
5. **Configure Services**
6. **Disable SMB1**
7. **Audit Policies**
8. **Bulk Password Change**
9. **Set Up Backup**
10. **Update PowerShell**
11. **Download SysInternals**
12. **Download AVG Antivirus**
13. **Download Malwarebytes Anti-Malware**
14. **Flush DNS Cache**
15. **Configure Windows Features**
16. **Configure Internet Explorer**
17. **Disable NetBIOS**
18. **Delete Media Files**
19. **Harden Google Chrome**
20. **Run System File Checker**

---

## Notes

- Test the scripts in a non-production environment before deployment.
- Review the predefined configurations and tailor them to your specific requirements.
- Update scripts to align with emerging security threats and best practices.
