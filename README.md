# APK Security Analyzer

<div align="center">

![APK Security Analyzer](https://img.shields.io/badge/APK-Security_Analyzer-purple?style=for-the-badge)
![Version](https://img.shields.io/badge/version-7.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**Professional Android Security Analysis Framework**

[![Platform](https://img.shields.io/badge/Platform-Android-brightgreen)](https://www.android.com/)
[![Bash](https://img.shields.io/badge/Bash-5.0+-orange)](https://www.gnu.org/software/bash/)
[![OWASP](https://img.shields.io/badge/OWASP-MASVS-red)](https://owasp.org/www-project-mobile-security-testing-guide/)
[![JSON](https://img.shields.io/badge/Output-JSON-yellow)](https://www.json.org/)

Advanced command-line tool for comprehensive security analysis of Android APK files with **80+ security rules**, CWE/OWASP/MASVS mappings, and detailed JSON reporting.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-output-format) • [Security Checks](#-security-checks)

</div>

---

## 📋 Overview

APK Security Analyzer is a professional-grade static analysis tool designed for Android application security assessments. It performs comprehensive security scanning of APK files based on **OWASP MASVS guidelines** without requiring any server-side processing.

### 🔒 Key Highlights

- ✅ **80+ Security Rules** - Comprehensive coverage across all security domains
- ✅ **CWE/OWASP/MASVS Mappings** - Industry-standard vulnerability classifications
- ✅ **JSON Output** - Structured reports with detailed vulnerability information
- ✅ **File Path Detection** - Exact locations of vulnerabilities in source code
- ✅ **Evidence Extraction** - Code snippets and proof of vulnerabilities
- ✅ **Zero Dependencies** - Pure bash implementation with common tools

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Static Analysis** | 80+ security checks based on OWASP MASVS guidelines |
| 🗂️ **File Explorer** | Automatic APK decompilation and structure analysis |
| 🔐 **Secret Detection** | Find hardcoded API keys, tokens, and credentials |
| 📱 **Manifest Audit** | Review app permissions and component security |
| 🌐 **Network Analysis** | Identify cleartext traffic and SSL/TLS issues |
| 🔑 **Crypto Analysis** | Detect weak encryption and hashing algorithms |
| 💾 **Storage Security** | Analyze data storage mechanisms and risks |
| 🌍 **WebView Security** | Identify JavaScript bridge and WebView vulnerabilities |
| 📊 **JSON Reports** | Export detailed security assessment reports |
| 📍 **Path Tracking** | Exact file locations for each vulnerability |

---

## 🚀 Installation

### Prerequisites

The following tools must be installed on your system:

- **apktool** - APK decompilation
- **python3** - Required for processing
- **jadx** (optional) - Enhanced decompilation

### macOS Installation

```bash
# Install via Homebrew
brew install apktool python3

# Optional: Install jadx
brew install jadx
```

### Linux Installation

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install apktool python3

# Arch Linux
sudo pacman -S apktool python

# Optional: Install jadx
# Download from: https://github.com/skylot/jadx/releases
```

### Clone Repository

```bash
# Clone the repository
git clone https://github.com/0x2nac0nda/apk-security-analyzer.git

# Navigate to the directory
cd apk-security-analyzer

# Make executable
chmod +x apk-analyzer-v7.0-JSON.sh
```

---

## 💻 Usage

### Basic Usage

```bash
./apk-analyzer-v7.0-JSON.sh your-app.apk
```

### Interactive Mode

```bash
./apk-analyzer-v7.0-JSON.sh
# You will be prompted to enter the APK path
```

### Example Output

```
╔═══════════════════════════════════════════════════════════════════════════╗
║          APK SECURITY ANALYZER v7.0 - JSON EDITION                       ║
║        Professional Android Security Analysis Framework                   ║
║                                                                           ║
║                       Author: 0x2nac0nda                                 ║
║                                                                           ║
║   📊 80+ Rules  •  🎯 OWASP/CWE/MASVS  •  📄 JSON Output                ║
╚═══════════════════════════════════════════════════════════════════════════╝

System: linux | Output: JSON

📱 Target: /path/to/your/app.apk

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ ANALYSIS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Findings: 24

  🔴 CRITICAL: 5
  🔴 HIGH:     4
  🟡 MEDIUM:   6
  🟡 LOW:      1
  🔵 INFO:     4
  ✅ SECURE:   4

✅ JSON report generated: /tmp/apk-analysis-app-12345/security-report.json
File size: 45K
```

---

## 📄 Output Format

### JSON Report Structure

```json
{
  "scan_info": {
    "tool": "APK Security Analyzer",
    "version": "7.0",
    "author": "0x2nac0nda",
    "scan_date": "2024-02-04 15:30:45",
    "apk_name": "example-app.apk",
    "risk_level": "CRITICAL"
  },
  "summary": {
    "total_findings": 24,
    "critical": 5,
    "high": 4,
    "medium": 6,
    "low": 1,
    "info": 4,
    "secure": 4
  },
  "endpoints": [
    "/api/v1/users",
    "/api/v2/auth"
  ],
  "vulnerabilities": [
    {
      "id": 1,
      "severity": "CRITICAL",
      "title": "Weak Encryption: DES/3DES",
      "description": "DES and 3DES are cryptographically broken",
      "cwe": "CWE-327",
      "owasp": "M5",
      "masvs": "CRYPTO-4",
      "remediation": "Replace with AES-256-GCM or ChaCha20-Poly1305",
      "file_path": "smali/com/example/Crypto.smali",
      "evidence": "Cipher.getInstance(\"DES/ECB/PKCS5Padding\")"
    }
  ]
}
```

### Vulnerability Information

Each vulnerability includes:

- **ID** - Unique identifier
- **Severity** - CRITICAL, HIGH, MEDIUM, LOW, INFO, SECURE
- **Title** - Vulnerability name
- **Description** - Detailed explanation
- **CWE** - Common Weakness Enumeration
- **OWASP** - OWASP Mobile Top 10 mapping
- **MASVS** - Mobile Application Security Verification Standard
- **Remediation** - Fix recommendations
- **File Path** - Exact location in source code
- **Evidence** - Code snippets or proof

---

## 🛡️ Security Checks

### 📦 Data Storage (6 checks)

- Unencrypted SharedPreferences
- Unencrypted SQLite Database
- External Storage Usage
- World-Readable/Writable Files
- Excessive Logging
- Encrypted Storage Detection

### 🔐 Cryptography (8 checks)

- Weak Hash Algorithms (MD5, SHA-1)
- Weak Encryption (DES/3DES, RC4, Blowfish)
- ECB Mode Encryption
- Insecure Random Generator
- Hardcoded Secrets/Passwords
- Static Initialization Vectors
- Secure Practices (AES-GCM, SecureRandom)

### 🌐 Network Security (7 checks)

- Certificate Pinning Implementation
- Cleartext HTTP Traffic
- SSL/TLS Validation Disabled
- SSL Pinning Bypass
- Hostname Verification Issues
- Debug Trust Anchors
- HTTP URLs in Code

### 🛡️ App Security (5 checks)

- Debuggable Application
- Backup Configuration
- Code Obfuscation
- Root Detection
- Debugger Detection

### 📱 Platform Security (6 checks)

- Exported Components Analysis
- Deep Link Handlers
- Task Affinity Issues
- JavaScript Bridge Exposure
- WebView Security Settings
- Universal File Access

### 🔍 Secret Scanning (5 checks)

- AWS Access Keys (AKIA, AGPA, AIDA, AROA)
- Google API Keys (AIza pattern)
- Firebase Database URLs
- Private Cryptographic Keys
- JWT Tokens

---

## 📊 Security Categories

### 🔴 Critical Vulnerabilities

- Weak Encryption (DES/3DES/RC4)
- Cleartext HTTP Traffic
- SSL Errors Ignored
- JavaScript Bridge Exposed
- Hardcoded Encryption Keys
- AWS Credentials
- Debuggable Application

### 🔴 High Severity

- No Certificate Pinning
- Weak Hash Algorithms (MD5)
- Insecure Cipher Mode (ECB)
- Unprotected Exported Components
- Google API Keys Exposed
- Full Backup Allowed

### 🟡 Medium Severity

- Unencrypted SharedPreferences
- Unencrypted SQLite Database
- External Storage Usage
- Firebase Database URLs
- Deprecated Hash (SHA-1)

### 🟡 Low Severity

- No Code Obfuscation
- No Root Detection
- Excessive Logging

---

## 🎯 Use Cases

### Security Researchers

- **Penetration Testing** - Comprehensive vulnerability assessment
- **Bug Bounty Hunting** - Identify security flaws for responsible disclosure
- **Security Audits** - Professional security assessments

### Developers

- **Pre-Release Security** - Scan apps before deployment
- **Security Compliance** - Meet OWASP MASVS standards
- **Secure Development** - Identify and fix vulnerabilities early

### Organizations

- **App Vetting** - Assess third-party applications
- **Compliance Checks** - Ensure security standards
- **Risk Assessment** - Evaluate application security posture

---

## 📝 Example Findings

### Critical: Weak Encryption

```json
{
  "severity": "CRITICAL",
  "title": "Weak Encryption: DES/3DES",
  "cwe": "CWE-327",
  "owasp": "M5",
  "masvs": "CRYPTO-4",
  "file_path": "smali/com/app/Crypto.smali",
  "evidence": "Cipher.getInstance(\"DES/ECB/PKCS5Padding\")",
  "remediation": "Replace with AES-256-GCM or ChaCha20-Poly1305"
}
```

### High: Google API Keys

```json
{
  "severity": "HIGH",
  "title": "Google API Keys (4 unique)",
  "cwe": "CWE-798",
  "owasp": "M9",
  "masvs": "STORAGE-14",
  "file_path": "./res/values/strings.xml",
  "evidence": "AIzaSyC-YLm2eZTWBgWsB0wZG9P8cLc34sOdw40",
  "remediation": "Add API key restrictions in Cloud Console"
}
```

---

## 🔧 Advanced Features

### Detailed File Paths

Every vulnerability includes the exact file location:

```
Path: smali/com/example/MainActivity.smali, smali/com/util/NetworkHelper.smali
```

### Evidence Extraction

Code snippets showing the vulnerable code:

```
Evidence: Cipher.getInstance("DES/ECB/PKCS5Padding")
```

### API Endpoint Discovery

Automatically extracts API endpoints and URLs:

```
API Endpoints: 15 | URLs: 32
```

---

## 📖 Documentation

### CWE References

- **CWE-295** - Improper Certificate Validation
- **CWE-297** - Improper Validation of Certificate with Host Mismatch
- **CWE-312** - Cleartext Storage of Sensitive Information
- **CWE-319** - Cleartext Transmission of Sensitive Information
- **CWE-321** - Use of Hard-coded Cryptographic Key
- **CWE-327** - Use of a Broken or Risky Cryptographic Algorithm
- **CWE-489** - Active Debug Code
- **CWE-798** - Use of Hard-coded Credentials

### OWASP Mobile Top 10

- **M1** - Improper Platform Usage
- **M2** - Insecure Data Storage
- **M3** - Insecure Communication
- **M4** - Insecure Authentication
- **M5** - Insufficient Cryptography
- **M7** - Client Code Quality
- **M8** - Code Tampering
- **M9** - Reverse Engineering

### MASVS Categories

- **STORAGE** - Data Storage and Privacy
- **CRYPTO** - Cryptography Requirements
- **AUTH** - Authentication and Session Management
- **NETWORK** - Network Communication
- **PLATFORM** - Platform Interaction
- **CODE** - Code Quality
- **RESILIENCE** - Resilience Requirements

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### How to Contribute

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Users are responsible for ensuring they have proper authorization before analyzing any application. The authors are not responsible for any misuse of this tool.

**Note:** This is an automated pattern-matching scanner, **NOT** a comprehensive security audit. Results are indicative only and require manual verification by a qualified security professional.

---

## 👨‍💻 Author

**Abdalla Abdelrhman (0x2nac0nda)**

- GitHub: [@0x2nac0nda](https://github.com/0x2nac0nda)
- LinkedIn: [Abdalla Abdelrhman](https://www.linkedin.com/in/abdalla-abdelrhman/)
- Role: Senior Cybersecurity Consultant

---

## 🔗 Related Projects

- [IPA Auditor](https://github.com/thecybersandeep/ipaauditor) - iOS Security Analysis Tool
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - Mobile Security Framework
- [QARK](https://github.com/linkedin/qark) - Quick Android Review Kit

---

## 📊 Statistics

![GitHub stars](https://img.shields.io/github/stars/0x2nac0nda/apk-security-analyzer?style=social)
![GitHub forks](https://img.shields.io/github/forks/0x2nac0nda/apk-security-analyzer?style=social)
![GitHub issues](https://img.shields.io/github/issues/0x2nac0nda/apk-security-analyzer)
![GitHub license](https://img.shields.io/github/license/0x2nac0nda/apk-security-analyzer)

---

## 🙏 Acknowledgments

- Inspired by [IPA Auditor](https://github.com/thecybersandeep/ipaauditor) by @thecybersandeep
- OWASP Mobile Security Testing Guide
- Android Security Best Practices
- CWE/SANS Top 25

---

<div align="center">

**⭐ If you find this tool useful, please consider giving it a star! ⭐**

Made with ❤️ by [0x2nac0nda](https://github.com/0x2nac0nda)

</div>
