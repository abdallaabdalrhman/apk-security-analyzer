# APK Security Analyzer

<div align="center">

![APK Security Analyzer](https://img.shields.io/badge/APK-Security_Analyzer-purple?style=for-the-badge)
![Version](https://img.shields.io/badge/version-1.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

**Professional Android Security Analysis**

[![Platform](https://img.shields.io/badge/Platform-Android-brightgreen)](https://www.android.com/)
[![Bash](https://img.shields.io/badge/Bash-5.0+-orange)](https://www.gnu.org/software/bash/)
[![OWASP](https://img.shields.io/badge/OWASP-MASVS-red)](https://owasp.org/www-project-mobile-security-testing-guide/)
[![JSON](https://img.shields.io/badge/Output-JSON-yellow)](https://www.json.org/)

Advanced command-line tool for comprehensive security analysis of Android APK files with detailed JSON reporting.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-output-format)

</div>

---

## 📋 Overview

APK Security Analyzer is a professional-grade static analysis tool designed for Android application security assessments. It performs comprehensive security scanning of APK files based on **OWASP MASVS guidelines**.

### 🔒 Key Highlights

- ✅ **Security Rules** - Comprehensive coverage across all security domains
- ✅ **OWASP/MASVS Mappings** - Industry-standard vulnerability classifications
- ✅ **JSON Output** - Structured reports with detailed vulnerability information
- ✅ **File Path Detection** - Exact locations of vulnerabilities in source code
- ✅ **Evidence Extraction** - Code snippets and proof of vulnerabilities
- ✅ **Zero Dependencies** - Pure bash implementation with common tools

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Static Analysis** | security checks based on OWASP MASVS guidelines |
| 🗂️ **File Explorer** | Automatic APK decompilation and structure analysis |
| 🔐 **Secret Detection** | Find hardcoded API keys, tokens, and credentials |
| 📱 **Manifest Audit** | Review app permissions and component security |
| 🌐 **Network Analysis** | Identify cleartext traffic and SSL/TLS issues |
| 🔑 **Crypto Analysis** | Detect weak encryption and hashing algorithms |
| 💾 **Storage Security** | Analyze data storage mechanisms and risks |
| 🌍 **WebView Security** | Identify JavaScript bridge and WebView vulnerabilities |
| 📊 **JSON Reports** | Export detailed security assessment reports |

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
git clone https://github.com/abdallaabdalrhman/apk-security-analyzer.git

# Navigate to the directory
cd apk-security-analyzer

# Make executable
chmod +x apk-analyzer.sh
```

---

## 💻 Usage

### Basic Usage

```bash
./apk-analyzer.sh your-app.apk
```

### Interactive Mode

```bash
./apk-analyzer.sh
# You will be prompted to enter the APK path
```

### Example Output

```
╔═══════════════════════════════════════════════════════════════════════════╗
║          APK SECURITY ANALYZER v1.0 - JSON EDITION                        ║
║        Professional Android Security Analysis Framework                   ║
║                                                                           ║
║                       Author: 0x2nac0nda                                  ║
║                                                                           ║
║              •  🎯 OWASP/MASVS  •  📄 JSON Output                         ║
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
    "version": "1.0",
    "author": "0x2nac0nda",
    "scan_date": "2024-02-04 15:30:45",
    "apk_name": "example-app.apk",
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
---

## 📝 Example Findings

### Weak Encryption

```json
{
  "title": "Weak Encryption: DES/3DES",
  "cwe": "CWE-327",
  "owasp": "M5",
  "masvs": "CRYPTO-4",
  "file_path": "smali/com/app/Crypto.smali",
  "evidence": "Cipher.getInstance(\"DES/ECB/PKCS5Padding\")",
  "remediation": "Replace with AES-256-GCM or ChaCha20-Poly1305"
}
```

### Google API Keys

```json
{
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
