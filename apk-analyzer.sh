#!/bin/bash

# ============================================================================
# APK SECURITY ANALYZER v1.0 - JSON OUTPUT EDITION
# ============================================================================
# Author: 0x2nac0nda (Abdalla Abdelrhman)
# 
# Professional JSON Output:
# - JSON report with detailed vulnerability information
# - File paths for each vulnerability
# - Evidence and affected files
# - Clean terminal output
# ============================================================================

set -u

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Counters
VULN_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
SECURE_COUNT=0

declare -a JSON_FINDINGS=()
declare -a ALL_ENDPOINTS=()

export DISABLE_CRASH_REPORTER=1
export PYTHONWARNINGS="ignore"

[[ "$OSTYPE" == "darwin"* ]] && OS_TYPE="macos" || OS_TYPE="linux"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║        █████╗ ██████╗ ██╗  ██╗    ███████╗███████╗ ██████╗                ║
║       ██╔══██╗██╔══██╗██║ ██╔╝    ██╔════╝██╔════╝██╔════╝                ║
║       ███████║██████╔╝█████╔╝     ███████╗█████╗  ██║                     ║
║       ██╔══██║██╔═══╝ ██╔═██╗     ╚════██║██╔══╝  ██║                     ║
║       ██║  ██║██║     ██║  ██╗    ███████║███████╗╚██████╗                ║
║       ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝    ╚══════╝╚══════╝ ╚═════╝                ║
║                                                                           ║
║          APK SECURITY ANALYZER v1.0 - JSON EDITION                        ║
║                   Android Security Analysis                               ║
║                                                                           ║
║                       Author: 0x2nac0nda                                  ║
║                                                                           ║
║             •  🎯 OWASP/MASVS  •  📄 JSON Output                          ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}${BOLD}System:${NC} ${GREEN}$OS_TYPE${NC} | ${CYAN}${BOLD}Output:${NC} ${GREEN}JSON${NC}"
    echo ""
}

print_section() {
    echo -e "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}${BOLD}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

print_finding() {
    local severity=$1
    local title=$2
    local description=$3
    local cwe=$4
    local owasp=$5
    local masvs=$6
    local remediation=${7:-}
    local file_path=${8:-""}
    local evidence=${9:-""}
    
    VULN_COUNT=$((VULN_COUNT + 1))
    
    # Escape for JSON
    local json_title=$(json_escape "$title")
    local json_desc=$(json_escape "$description")
    local json_rem=$(json_escape "$remediation")
    local json_path=$(json_escape "$file_path")
    local json_evidence=$(json_escape "$evidence")
    
    # Build JSON object
    local json_obj="{"
    json_obj+="\"id\":$VULN_COUNT,"
    json_obj+="\"severity\":\"$severity\","
    json_obj+="\"title\":\"$json_title\","
    json_obj+="\"description\":\"$json_desc\","
    json_obj+="\"cwe\":\"$cwe\","
    json_obj+="\"owasp\":\"$owasp\","
    json_obj+="\"masvs\":\"$masvs\","
    json_obj+="\"remediation\":\"$json_rem\","
    json_obj+="\"file_path\":\"$json_path\","
    json_obj+="\"evidence\":\"$json_evidence\""
    json_obj+="}"
    
    JSON_FINDINGS+=("$json_obj")
    
    case $severity in
        "CRITICAL")
            CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
            echo -e "${RED}${BOLD}[!] CRITICAL: $title${NC}"
            ;;
        "HIGH")
            HIGH_COUNT=$((HIGH_COUNT + 1))
            echo -e "${RED}[!] HIGH: $title${NC}"
            ;;
        "MEDIUM")
            MEDIUM_COUNT=$((MEDIUM_COUNT + 1))
            echo -e "${YELLOW}[!] MEDIUM: $title${NC}"
            ;;
        "LOW")
            LOW_COUNT=$((LOW_COUNT + 1))
            echo -e "${YELLOW}[!] LOW: $title${NC}"
            ;;
        "INFO")
            INFO_COUNT=$((INFO_COUNT + 1))
            echo -e "${CYAN}[i] INFO: $title${NC}"
            ;;
        "SECURE")
            SECURE_COUNT=$((SECURE_COUNT + 1))
            echo -e "${GREEN}[✓] SECURE: $title${NC}"
            ;;
    esac
    
    echo -e "    ${DIM}$description${NC}"
    [ -n "$cwe" ] && echo -e "    ${BLUE}CWE: $cwe${NC}"
    [ -n "$owasp" ] && echo -e "    ${BLUE}OWASP: $owasp${NC}"
    [ -n "$masvs" ] && echo -e "    ${BLUE}MASVS: $masvs${NC}"
    [ -n "$file_path" ] && echo -e "    ${DIM}Path: $file_path${NC}"
    echo ""
}

install_tools() {
    print_section "TOOL VERIFICATION"
    
    local tools_ok=true
    
    command -v python3 &> /dev/null && echo -e "${GREEN}[✓] python3${NC}" || { echo -e "${RED}[✗] python3${NC}"; tools_ok=false; }
    command -v apktool &> /dev/null && echo -e "${GREEN}[✓] apktool${NC}" || { echo -e "${RED}[✗] apktool${NC}"; tools_ok=false; }
    command -v jadx &> /dev/null && echo -e "${GREEN}[✓] jadx${NC}" || echo -e "${YELLOW}[!] jadx (optional)${NC}"
    
    if [ "$tools_ok" = false ]; then
        echo -e "\n${RED}Install missing tools${NC}\n"
        exit 1
    fi
    
    echo ""
}

# ============================================================================
# SECURITY CHECKS
# ============================================================================

check_storage_security() {
    local dir=$1
    cd "$dir" || return
    
    print_section "STORAGE SECURITY"
    
    echo -e "${CYAN}Analyzing data storage mechanisms...${NC}\n"
    
    # SharedPreferences
    if grep -rq "SharedPreferences" smali*/ 2>/dev/null; then
        if ! grep -rq "EncryptedSharedPreferences" smali*/ 2>/dev/null; then
            local files=$(grep -rl "SharedPreferences" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
            print_finding "MEDIUM" "Unencrypted SharedPreferences" \
                "Data stored in SharedPreferences is unencrypted and accessible on rooted devices or via backup" \
                "CWE-312" "M2" "STORAGE-2" \
                "Use EncryptedSharedPreferences from androidx.security:security-crypto" \
                "$files" \
                "Found SharedPreferences usage in application code"
        else
            local files=$(grep -rl "EncryptedSharedPreferences" smali*/ 2>/dev/null | head -1)
            print_finding "SECURE" "Encrypted SharedPreferences" \
                "Application uses EncryptedSharedPreferences for secure data storage" \
                "" "" "STORAGE-2" "" "$files" ""
        fi
    fi
    
    # Database
    if grep -rq "SQLiteDatabase\|SQLiteOpenHelper" smali*/ 2>/dev/null; then
        if ! grep -rq "SQLCipher\|net/sqlcipher" smali*/ 2>/dev/null; then
            local files=$(grep -rl "SQLiteDatabase\|SQLiteOpenHelper" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
            print_finding "MEDIUM" "Unencrypted SQLite Database" \
                "SQLite database is not encrypted - all data accessible on rooted devices" \
                "CWE-312" "M2" "STORAGE-14" \
                "Use SQLCipher for Android database encryption" \
                "$files" \
                "Found unencrypted SQLite database usage"
        else
            local files=$(grep -rl "SQLCipher" smali*/ 2>/dev/null | head -1)
            print_finding "SECURE" "Encrypted Database (SQLCipher)" \
                "Application uses SQLCipher for encrypted database storage" \
                "" "" "STORAGE-14" "" "$files" ""
        fi
    fi
    
    # External Storage
    if grep -rq "getExternalStorageDirectory\|EXTERNAL_STORAGE\|getExternalFilesDir" smali*/ 2>/dev/null; then
        local files=$(grep -rl "getExternalStorageDirectory\|EXTERNAL_STORAGE" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "MEDIUM" "External Storage Usage" \
            "Data written to external storage is world-readable and accessible by other apps" \
            "CWE-276" "M2" "STORAGE-2" \
            "Use internal storage or encrypt data before writing to external storage" \
            "$files" \
            "External storage access detected"
    fi
    
    # World Readable/Writable
    if grep -rq "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE" smali*/ 2>/dev/null; then
        local files=$(grep -rl "MODE_WORLD_READABLE\|MODE_WORLD_WRITABLE" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "World-Readable/Writable Files" \
            "Files created with world-readable/writable permissions - major security risk" \
            "CWE-732" "M2" "STORAGE-1" \
            "Use MODE_PRIVATE for all file operations" \
            "$files" \
            "World-accessible file modes detected"
    fi
    
    # Logging
    local log_count=$(grep -rc "Log\\." smali*/ 2>/dev/null | awk -F: '{sum+=$2} END {print sum}' || echo "0")
    if [ "$log_count" -gt 50 ]; then
        local files=$(grep -rl "Log\\.d\|Log\\.v\|Log\\.i" smali*/ 2>/dev/null | head -5 | tr '\n' ', ' | sed 's/,$//')
        print_finding "LOW" "Excessive Logging ($log_count calls)" \
            "Excessive logging may leak sensitive information in production" \
            "CWE-532" "M7" "CODE-2" \
            "Remove verbose logging or use ProGuard to strip Log statements" \
            "$files" \
            "Found $log_count logging statements"
    fi
}

check_crypto_security() {
    local dir=$1
    cd "$dir" || return
    
    print_section "CRYPTOGRAPHY SECURITY"
    
    echo -e "${CYAN}Analyzing cryptographic implementations...${NC}\n"
    
    # DES/3DES
    if grep -rq "Cipher.*DES[^c]\|DESede\|/DES/" smali*/ 2>/dev/null; then
        local files=$(grep -rl "DES\|DESede" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        local evidence=$(grep -rh "DES\|DESede" smali*/ 2>/dev/null | head -2 | tr '\n' ' ')
        print_finding "CRITICAL" "Weak Encryption: DES/3DES" \
            "DES and 3DES are cryptographically broken - can be brute-forced in hours" \
            "CWE-327" "M5" "CRYPTO-4" \
            "Replace with AES-256-GCM or ChaCha20-Poly1305" \
            "$files" \
            "$evidence"
    fi
    
    # RC4
    if grep -rq "RC4\|ARC4\|ARCFOUR" smali*/ 2>/dev/null; then
        local files=$(grep -rl "RC4\|ARC4" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "Weak Encryption: RC4" \
            "RC4 stream cipher is completely broken - vulnerable to multiple attacks" \
            "CWE-327" "M5" "CRYPTO-4" \
            "Use AES-GCM or ChaCha20" \
            "$files" \
            "RC4 cipher usage detected"
    fi
    
    # MD5
    if grep -rq "MessageDigest.*MD5\|DigestUtils.*md5\|\.md5" smali*/ 2>/dev/null; then
        local files=$(grep -rl "MD5" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        local evidence=$(grep -rh "MessageDigest.*MD5" smali*/ 2>/dev/null | head -2 | tr '\n' ' ')
        print_finding "HIGH" "Weak Hash: MD5" \
            "MD5 is cryptographically broken - collisions can be generated trivially" \
            "CWE-327" "M5" "CRYPTO-4" \
            "Use SHA-256 or SHA-3" \
            "$files" \
            "$evidence"
    fi
    
    # SHA-1
    if grep -rq "MessageDigest.*SHA-?1[^0-9]\|DigestUtils.*sha1" smali*/ 2>/dev/null; then
        local files=$(grep -rl "SHA-1\|SHA1" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "MEDIUM" "Deprecated Hash: SHA-1" \
            "SHA-1 is deprecated due to collision vulnerabilities" \
            "CWE-327" "M5" "CRYPTO-4" \
            "Upgrade to SHA-256 or higher" \
            "$files" \
            "SHA-1 hashing detected"
    fi
    
    # ECB Mode
    if grep -rq "AES/ECB\|Cipher.*ECB" smali*/ 2>/dev/null; then
        local files=$(grep -rl "AES/ECB\|ECB" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        local evidence=$(grep -rh "AES/ECB" smali*/ 2>/dev/null | head -2 | tr '\n' ' ')
        print_finding "HIGH" "Insecure Cipher Mode: ECB" \
            "AES-ECB mode reveals patterns in encrypted data - not semantically secure" \
            "CWE-327" "M5" "CRYPTO-2" \
            "Use AES-GCM or AES-CBC with random IV" \
            "$files" \
            "$evidence"
    fi
    
    # Hardcoded Keys
    local hardcoded=$(grep -rh "key\|secret" smali*/ 2>/dev/null | grep -E "\"[0-9a-fA-F]{16,}\"" | head -3 || true)
    if [ -n "$hardcoded" ]; then
        local files=$(grep -rl "key.*=.*\"[0-9a-fA-F]" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "Hardcoded Encryption Keys" \
            "Encryption keys embedded in code - provides no security" \
            "CWE-321" "M5" "CRYPTO-1" \
            "Generate keys dynamically, store in Android Keystore" \
            "$files" \
            "$(echo "$hardcoded" | head -1)"
    fi
    
    # Good Practices
    if grep -rq "SecureRandom" smali*/ 2>/dev/null; then
        local files=$(grep -rl "SecureRandom" smali*/ 2>/dev/null | head -1)
        print_finding "SECURE" "Secure Random Number Generator" \
            "Application uses SecureRandom for cryptographic operations" \
            "" "" "CRYPTO-6" "" "$files" ""
    fi
    
    if grep -rq "AES/GCM" smali*/ 2>/dev/null; then
        local files=$(grep -rl "AES/GCM" smali*/ 2>/dev/null | head -1)
        print_finding "SECURE" "AES-GCM Authenticated Encryption" \
            "Application uses AES-GCM providing both confidentiality and integrity" \
            "" "" "CRYPTO-3" "" "$files" ""
    fi
}

check_network_security() {
    local dir=$1
    cd "$dir" || return
    
    print_section "NETWORK SECURITY"
    
    echo -e "${CYAN}Analyzing network communications...${NC}\n"
    
    local netsec=$(find . -name "network_security_config.xml" 2>/dev/null | head -1 || true)
    
    if [ -n "$netsec" ]; then
        # Certificate Pinning
        if grep -q "pin-set\|certificate-pin" "$netsec" 2>/dev/null; then
            local pins=$(grep -c "sha256\|sha1" "$netsec" 2>/dev/null || echo "0")
            print_finding "SECURE" "Certificate Pinning ($pins pins)" \
                "Certificate pinning protects against MitM attacks" \
                "" "" "NETWORK-4" "" "$netsec" \
                "Certificate pinning configured"
        else
            print_finding "HIGH" "No Certificate Pinning" \
                "Network security config exists but certificate pinning not implemented" \
                "CWE-295" "M3" "NETWORK-4" \
                "Implement certificate pinning using <pin-set>" \
                "$netsec" \
                "Network config found without pinning"
        fi
        
        # Cleartext Traffic
        if grep -q 'cleartextTrafficPermitted="true"' "$netsec" 2>/dev/null; then
            local evidence=$(grep "cleartextTrafficPermitted" "$netsec" 2>/dev/null)
            print_finding "CRITICAL" "Cleartext HTTP Traffic Allowed" \
                "Application explicitly allows unencrypted HTTP - all network data can be intercepted" \
                "CWE-319" "M3" "NETWORK-1" \
                "Set cleartextTrafficPermitted=\"false\"" \
                "$netsec" \
                "$evidence"
        fi
    else
        print_finding "MEDIUM" "No Network Security Config" \
            "No network_security_config.xml - may allow cleartext" \
            "CWE-319" "M3" "NETWORK-1" \
            "Create network_security_config.xml" \
            "AndroidManifest.xml" \
            "Missing network security configuration"
    fi
    
    # SSL Errors
    if grep -rq "onReceivedSslError" smali*/ 2>/dev/null; then
        if grep -rq "proceed\(\)" smali*/ 2>/dev/null; then
            local files=$(grep -rl "onReceivedSslError" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
            local evidence=$(grep -rh "proceed()" smali*/ 2>/dev/null | head -2 | tr '\n' ' ')
            print_finding "CRITICAL" "SSL Errors Ignored" \
                "Application proceeds despite SSL certificate errors - bypasses validation" \
                "CWE-295" "M3" "NETWORK-3" \
                "Never call handler.proceed() in onReceivedSslError" \
                "$files" \
                "$evidence"
        fi
    fi
    
    # Hostname Verification
    if grep -rq "setHostnameVerifier.*ALLOW_ALL\|AllowAllHostnameVerifier" smali*/ 2>/dev/null; then
        local files=$(grep -rl "ALLOW_ALL\|AllowAllHostnameVerifier" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "Hostname Verification Disabled" \
            "SSL hostname verification disabled - accepts any certificate" \
            "CWE-297" "M3" "NETWORK-3" \
            "Remove custom hostname verifier" \
            "$files" \
            "ALLOW_ALL hostname verifier detected"
    fi
}

check_webview_security() {
    local dir=$1
    cd "$dir" || return
    
    if ! grep -rq "Landroid/webkit/WebView" smali*/ 2>/dev/null; then
        return
    fi
    
    print_section "WEBVIEW SECURITY"
    
    echo -e "${CYAN}Analyzing WebView implementations...${NC}\n"
    
    # JavaScript Interface
    local js=$(grep -rh "addJavascriptInterface" smali*/ 2>/dev/null | grep -v "com.google.android.gms" | wc -l | tr -d ' ' || echo "0")
    
    if [ "$js" -gt 0 ]; then
        local files=$(grep -rl "addJavascriptInterface" smali*/ 2>/dev/null | grep -v "google" | head -3 | tr '\n' ', ' | sed 's/,$//')
        local evidence=$(grep -rh "addJavascriptInterface" smali*/ 2>/dev/null | head -2 | tr '\n' ' ')
        print_finding "CRITICAL" "JavaScript Bridge Exposed ($js interfaces)" \
            "addJavascriptInterface allows JavaScript to call Java methods - RCE risk" \
            "CWE-749" "M1" "PLATFORM-6" \
            "Remove JavaScript interfaces or validate all inputs" \
            "$files" \
            "$evidence"
    fi
    
    # Universal File Access
    if grep -rq "setAllowUniversalAccessFromFileURLs.*true" smali*/ 2>/dev/null; then
        local files=$(grep -rl "setAllowUniversalAccessFromFileURLs" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "HIGH" "Universal File Access" \
            "File URLs can access any origin - critical security risk" \
            "CWE-942" "M1" "PLATFORM-2" \
            "Set setAllowUniversalAccessFromFileURLs(false)" \
            "$files" \
            "Universal file access enabled in WebView"
    fi
}

check_manifest_security() {
    local manifest=$1
    
    print_section "MANIFEST SECURITY"
    
    echo -e "${CYAN}Analyzing AndroidManifest.xml...${NC}\n"
    
    # Debuggable
    if grep -q 'android:debuggable="true"' "$manifest" 2>/dev/null; then
        local evidence=$(grep "debuggable" "$manifest" 2>/dev/null)
        print_finding "CRITICAL" "Debuggable Application" \
            "App is debuggable - allows runtime manipulation and memory dumps" \
            "CWE-489" "M7" "RESILIENCE-2" \
            "Remove android:debuggable for production" \
            "AndroidManifest.xml" \
            "$evidence"
    fi
    
    # Backup
    if grep -q 'android:allowBackup="true"' "$manifest" 2>/dev/null; then
        if ! grep -q 'android:fullBackupContent' "$manifest" 2>/dev/null; then
            local evidence=$(grep "allowBackup" "$manifest" 2>/dev/null)
            print_finding "HIGH" "Full Backup Allowed" \
                "All app data can be backed up via adb without restrictions" \
                "CWE-530" "M2" "STORAGE-8" \
                "Add fullBackupContent rules or disable backup" \
                "AndroidManifest.xml" \
                "$evidence"
        fi
    fi
    
    # Exported Components
    local exported=$(grep -c 'android:exported="true"' "$manifest" 2>/dev/null || echo "0")
    
    if [ "$exported" -gt 0 ]; then
        local list=$(grep -B2 'android:exported="true"' "$manifest" | \
            grep 'android:name=' | sed 's/.*android:name="\([^"]*\)".*/\1/' | \
            grep -v "com.google\|androidx\|com.facebook" | head -10 | tr '\n' ', ' | sed 's/,$//' || true)
        
        local unprotected=0
        while IFS= read -r comp; do
            [ -z "$comp" ] && continue
            if ! grep -A5 "$comp" "$manifest" | grep -q 'android:permission'; then
                ((unprotected++)) || true
            fi
        done <<< "$(echo "$list" | tr ',' '\n')"
        
        if [ "$unprotected" -gt 0 ]; then
            print_finding "HIGH" "Unprotected Exported Components ($unprotected)" \
                "Exported components without permissions - unauthorized app access possible" \
                "CWE-927" "M1" "PLATFORM-1" \
                "Add android:permission or set exported=\"false\"" \
                "AndroidManifest.xml" \
                "Components: $list"
        fi
    fi
    
    # Deep Links
    local links=$(grep -c "android.intent.action.VIEW" "$manifest" 2>/dev/null || echo "0")
    if [ "$links" -gt 0 ]; then
        local schemes=$(grep -B10 "android.intent.action.VIEW" "$manifest" | \
            grep "android:scheme=" | sed 's/.*android:scheme="\([^"]*\)".*/\1/' | \
            tr '\n' ', ' | sed 's/,$//' || true)
        print_finding "INFO" "Deep Link Handlers ($links)" \
            "App handles deep links - validate all URL parameters" \
            "" "" "PLATFORM-3" \
            "Implement strict input validation" \
            "AndroidManifest.xml" \
            "Schemes: $schemes"
    fi
}

check_code_quality() {
    local dir=$1
    cd "$dir" || return
    
    print_section "CODE QUALITY & ANTI-TAMPERING"
    
    echo -e "${CYAN}Analyzing code protection mechanisms...${NC}\n"
    
    # Obfuscation
    if grep -rq "class a\|class b\|class c" smali*/a/ 2>/dev/null; then
        print_finding "SECURE" "Code Obfuscation" \
            "Application code appears obfuscated with ProGuard/R8" \
            "" "" "RESILIENCE-3" "" \
            "smali/a/, smali/b/, smali/c/" \
            "Obfuscated class names detected"
    else
        print_finding "LOW" "No Code Obfuscation" \
            "Source code not obfuscated - reverse engineering is easier" \
            "CWE-656" "M9" "RESILIENCE-3" \
            "Enable ProGuard/R8 obfuscation" \
            "build.gradle" \
            "Clear package structure detected"
    fi
    
    # Root Detection
    local root=0
    grep -rq "test-keys" smali*/ 2>/dev/null && ((root++)) || true
    grep -rq "/system/bin/su" smali*/ 2>/dev/null && ((root++)) || true
    grep -rq "Magisk" smali*/ 2>/dev/null && ((root++)) || true
    
    if [ "$root" -gt 0 ]; then
        local files=$(grep -rl "test-keys\|/system/bin/su\|Magisk" smali*/ 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "SECURE" "Root Detection ($root methods)" \
            "Application implements root detection mechanisms" \
            "" "" "RESILIENCE-1" "" "$files" \
            "Root detection checks found"
    else
        print_finding "LOW" "No Root Detection" \
            "App lacks root detection - may run on compromised devices" \
            "" "M8" "RESILIENCE-1" \
            "Implement root detection" \
            "" \
            "No root detection mechanisms found"
    fi
}

discover_endpoints() {
    local dir=$1
    cd "$dir" || return
    
    print_section "API ENDPOINT DISCOVERY"
    
    echo -e "${CYAN}Extracting API endpoints and URLs...${NC}\n"
    
    # API paths (exclude binary matches)
    local api=$(grep -rhEo '"/api[^"]*"' . --exclude-dir={lib,assets} 2>/dev/null | tr -d '"' | sort -u | head -50 || true)
    
    if [ -n "$api" ]; then
        echo -e "${MAGENTA}${BOLD}API Endpoints:${NC}"
        echo "$api" | while read -r path; do
            [ -n "$path" ] && ALL_ENDPOINTS+=("$path") && echo "    $path"
        done
        echo ""
    fi
    
    # Full URLs (exclude binary file references)
    local urls=$(grep -rhEo 'https://[a-zA-Z0-9.-]+[^\s"<>]*' . --exclude-dir={lib,assets} 2>/dev/null | \
        grep -v "schemas\|xmlns\|Binary file" | \
        grep -v "\.so\|\.dex\|\.dat\|builtins" | \
        sort -u | head -30 || true)
    
    if [ -n "$urls" ]; then
        echo -e "${MAGENTA}${BOLD}Discovered URLs:${NC}"
        echo "$urls" | sed 's/^/    /'
        echo ""
    fi
    
    local endpoint_count=${#ALL_ENDPOINTS[@]}
    local url_count=$(echo "$urls" | grep -c . 2>/dev/null || echo "0")
    echo -e "${GREEN}API Endpoints: $endpoint_count | URLs: $url_count${NC}\n"
}

scan_secrets() {
    local dir=$1
    cd "$dir" || return
    
    print_section "SECRET & CREDENTIAL SCANNING"
    
    echo -e "${CYAN}Scanning for hardcoded secrets...${NC}\n"
    
    # AWS
    local aws=$(grep -rhEo "(AKIA|A3T[A-Z0-9]|AGPA|AIDA|AROA)[A-Z0-9]{16}" . 2>/dev/null | head -5 || true)
    if [ -n "$aws" ]; then
        local files=$(grep -rl "AKIA\|AGPA\|AIDA\|AROA" . 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "AWS Access Keys" \
            "AWS credentials found - immediate security breach" \
            "CWE-798" "M9" "STORAGE-14" \
            "Rotate keys immediately, use AWS Cognito" \
            "$files" \
            "$(echo "$aws" | head -3 | tr '\n' ', ' | sed 's/,$//')"
        echo -e "${RED}${BOLD}  Keys Found:${NC}"
        echo "$aws" | sed 's/^/    /'
        echo ""
    fi
    
    # Google API
    local google=$(grep -rhEo "AIza[0-9A-Za-z_-]{35}" . 2>/dev/null | sort -u | head -5 || true)
    if [ -n "$google" ]; then
        local files=$(grep -rl "AIza" . 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        local key_count=$(echo "$google" | wc -l | tr -d ' ')
        print_finding "HIGH" "Google API Keys ($key_count unique)" \
            "Google API keys exposed - verify restrictions" \
            "CWE-798" "M9" "STORAGE-14" \
            "Add API key restrictions in Cloud Console" \
            "$files" \
            "$(echo "$google" | head -3 | tr '\n' ', ' | sed 's/,$//')"
        echo -e "${YELLOW}${BOLD}  Keys Found:${NC}"
        echo "$google" | sed 's/^/    /'
        echo ""
    fi
    
    # Firebase
    local firebase=$(grep -rhEo "https://[a-zA-Z0-9-]+\.firebaseio\.com" . 2>/dev/null | sort -u | head -3 || true)
    if [ -n "$firebase" ]; then
        local files=$(grep -rl "firebaseio\.com" . 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "MEDIUM" "Firebase Database URLs" \
            "Firebase Realtime Database URLs found - verify security rules" \
            "CWE-200" "M1" "STORAGE-12" \
            "Configure strict Firebase security rules" \
            "$files" \
            "$(echo "$firebase" | head -3 | tr '\n' ', ' | sed 's/,$//')"
        echo -e "${YELLOW}${BOLD}  URLs Found:${NC}"
        echo "$firebase" | sed 's/^/    /'
        echo ""
    fi
    
    # Private Keys
    if grep -rEq "BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY" . 2>/dev/null; then
        local files=$(grep -rl "BEGIN.*PRIVATE KEY" . 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "CRITICAL" "Private Cryptographic Keys" \
            "Private keys embedded in app - complete compromise" \
            "CWE-321" "M5" "CRYPTO-1" \
            "Remove private keys, use Android Keystore" \
            "$files" \
            "Private key files detected"
    fi
    
    # JWT
    local jwt=$(grep -rhEo "eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+" . 2>/dev/null | head -2 || true)
    if [ -n "$jwt" ]; then
        local files=$(grep -rl "eyJ.*eyJ" . 2>/dev/null | head -3 | tr '\n' ', ' | sed 's/,$//')
        print_finding "HIGH" "JWT Tokens Embedded" \
            "JSON Web Tokens in source - can be decoded" \
            "CWE-522" "M4" "AUTH-1" \
            "Generate tokens server-side only" \
            "$files" \
            "$(echo "$jwt" | head -1)"
    fi
}

generate_json_report() {
    local json_file="$WORK_DIR/security-report.json"
    
    local risk_level="LOW"
    
    [ "$CRITICAL_COUNT" -gt 0 ] && risk_level="CRITICAL"
    [ "$CRITICAL_COUNT" -eq 0 ] && [ "$HIGH_COUNT" -gt 3 ] && risk_level="HIGH"
    [ "$CRITICAL_COUNT" -eq 0 ] && [ "$HIGH_COUNT" -gt 0 ] && [ "$HIGH_COUNT" -le 3 ] && [ "$MEDIUM_COUNT" -gt 5 ] && risk_level="MEDIUM"
    
    # Build endpoints array
    local endpoints_json="["
    local first=true
    if [ ${#ALL_ENDPOINTS[@]} -gt 0 ]; then
        for ep in "${ALL_ENDPOINTS[@]}"; do
            [ "$first" = false ] && endpoints_json+=","
            endpoints_json+="\"$(json_escape "$ep")\""
            first=false
        done
    fi
    endpoints_json+="]"
    
    # Build findings array
    local findings_json="["
    first=true
    for finding in "${JSON_FINDINGS[@]}"; do
        [ "$first" = false ] && findings_json+=","
        findings_json+="$finding"
        first=false
    done
    findings_json+="]"
    
    # Create JSON report
    cat > "$json_file" << EOF
{
  "scan_info": {
    "tool": "APK Security Analyzer",
    "version": "1.0",
    "author": "0x2nac0nda",
    "scan_date": "$(date '+%Y-%m-%d %H:%M:%S')",
    "apk_name": "$APK_NAME",
    "risk_level": "$risk_level"
  },
  "summary": {
    "total_findings": $VULN_COUNT,
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT,
    "low": $LOW_COUNT,
    "info": $INFO_COUNT,
    "secure": $SECURE_COUNT
  },
  "endpoints": $endpoints_json,
  "vulnerabilities": $findings_json
}
EOF
    
    echo -e "\n${GREEN}✅ JSON report generated: $json_file${NC}"
    echo -e "${CYAN}File size: $(du -h "$json_file" | cut -f1)${NC}\n"
}

print_summary() {
    print_section "ANALYSIS SUMMARY"
    
    echo -e "${BOLD}Total Findings: $VULN_COUNT${NC}\n"
    
    [ "$CRITICAL_COUNT" -gt 0 ] && echo -e "${RED}${BOLD}  🔴 CRITICAL: $CRITICAL_COUNT${NC}"
    [ "$HIGH_COUNT" -gt 0 ] && echo -e "${RED}${BOLD}  🔴 HIGH:     $HIGH_COUNT${NC}"
    [ "$MEDIUM_COUNT" -gt 0 ] && echo -e "${YELLOW}${BOLD}  🟡 MEDIUM:   $MEDIUM_COUNT${NC}"
    [ "$LOW_COUNT" -gt 0 ] && echo -e "${YELLOW}${BOLD}  🟡 LOW:      $LOW_COUNT${NC}"
    [ "$INFO_COUNT" -gt 0 ] && echo -e "${CYAN}${BOLD}  🔵 INFO:     $INFO_COUNT${NC}"
    [ "$SECURE_COUNT" -gt 0 ] && echo -e "${GREEN}${BOLD}  ✅ SECURE:   $SECURE_COUNT${NC}"
    
    echo ""
}

# Main
main() {
    print_banner
    
    if [ -z "${1:-}" ]; then
        read -p "$(echo -e ${CYAN}APK path:${NC} )" APK_PATH
    else
        APK_PATH="$1"
    fi
    
    [ ! -f "$APK_PATH" ] && { echo -e "${RED}❌ Not found${NC}"; exit 1; }
    
    APK_NAME=$(basename "$APK_PATH" .apk)
    WORK_DIR="/tmp/apk-analysis-$APK_NAME-$$"
    DECOMPILED_DIR="$WORK_DIR/${APK_NAME}-decompiled"
    
    echo -e "${GREEN}📱 Target: $APK_PATH${NC}\n"
    
    install_tools
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1
    
    print_section "DECOMPILATION"
    echo -e "${CYAN}Decompiling with apktool...${NC}"
    if apktool d "$APK_PATH" -o "$DECOMPILED_DIR" -f 2>&1 | grep -E "I:" | head -8; then
        echo -e "${GREEN}✓ Complete${NC}\n"
    else
        echo -e "${RED}❌ Failed${NC}\n"
        exit 1
    fi
    
    discover_endpoints "$DECOMPILED_DIR"
    scan_secrets "$DECOMPILED_DIR"
    check_manifest_security "$DECOMPILED_DIR/AndroidManifest.xml"
    check_storage_security "$DECOMPILED_DIR"
    check_crypto_security "$DECOMPILED_DIR"
    check_network_security "$DECOMPILED_DIR"
    check_webview_security "$DECOMPILED_DIR"
    check_code_quality "$DECOMPILED_DIR"
    
    print_summary
    generate_json_report
}

main "$@"
