# 🕵️‍♂️ Hunt Sexy Smali :
### Hunt URLs, IoC, IPs, Base64 encoded C2s & secrets in Smali files with 95% reduction of false positives

**APK Smali Forensics & IOC Hunter**  
*Author: [github.com/gigachad80](https://github.com/gigachad80)*

**Hunt Sexy Smali** is a powerful, regex-driven forensics tool designed for analyzing decompiled Android applications (APK). It scans `.smali` files to hunt down Indicators of Compromise (IOCs), Command & Control (C2) servers, hidden database endpoints, hardcoded credentials, and encoded payloads.

---

## ✨ Features

*   **Endpoint & DB Hunter**: Detects HTTP/HTTPS URLs, Firebase, Supabase, MongoDB Atlas, MySQL, SQLite, RealmDB, and Redis connection strings.
*   **Secret & API Key Scanner**: Identifies hardcoded tokens, API keys, and access secrets.
*   **IP Address Extraction**: Finds hardcoded IP addresses with port validation.
*   **Mail Spy**: Extracts email addresses (Gmail, Outlook, Proton, Yahoo, and custom domains).
*   **Advanced Base64 Decoding**: Not just standard UTF-8. HSS attempts to decode Base64 strings across multiple encodings:
    *   UTF-8 / ASCII, UTF-16 (LE/BE), ISO-8859-1 (Latin-1), Windows-1252
    *   KOI8-R (Russian), GB18030 (Chinese), Shift-JIS & EUC-JP (Japanese)
    *   Falls back to a binary Hex Dump if text decoding fails.
*   **Automated Reporting**: Generates categorized `.txt` reports and optionally emails them via SMTP.

---

## 🚀 Installation

Ensure you have [Go](https://golang.org/doc/install) installed. Clone the repository and compile the binary:

```bash
go build -o hunt-sexy-smali main.go
```

---

## 🛠️ Modes of Operation

The tool operates in two primary modes to accommodate different workflows:

### 1. Standard Mode (`-i`)
Scans a freshly decompiled APK folder (e.g., via `apktool`).
*   **Phase 1 (Collection)**: Recursively finds all `.smali` files, flattens them into a single `All_Smali` directory (preserving the original path in a custom file header).
*   **Phase 2 (Hunting)**: Scans the collected files for IOCs.
```bash
./hunt-sexy-smali -i /path/to/decompiled_apk -o /path/to/output
```

### 2. Reload Mode (`-reload`)
If you have already extracted and flattened `.smali` files using Standard Mode, you can bypass the time-consuming collection phase and re-hunt the existing `All_Smali` folder instantly with different flags . It's useful in case if you want to scan again in future .
```bash
./hunt-sexy-smali -reload /path/to/output/All_Smali -b -fl 2
```

---

## 🎛️ The Base64 False Positive Filter (`-fl`)

Smali code is notoriously filled with benign Base64-like strings (e.g., class descriptors, library signatures). HSS includes a robust, 3-tier filtering system to eliminate noise when hunting Base64 (`-b`):

*   **FL 0 (RAW)**: Zero filters. Everything passes through. *Use for research or paranoid scanning. Expect high noise.*
*   **FL 1 (BASIC)**: Structural filters only. Drops strings under 20 chars, strings lacking standard Base64 characters (`+`, `=`, `/`), file paths, and hex colors. *(~65% noise reduction)*
*   **FL 2 (FULL)**: Basic + Known Library Filter. Ignores over 60+ benign Android, Java, Kotlin, and common third-party SDK class descriptors (e.g., Firebase, OkHttp, Glide, Facebook SDK). **(Recommended: ~95-97% noise reduction)**

*Note: If you use the `-b` flag without providing `-fl`, the tool will launch an interactive menu for you to select the level.*

---

## 💻 Usage & Flags

```text
Usage: hunt-sexy-smali -i <apk> -o <out> [FLAGS]

Input / Output:
  -i string      Input path of the decompiled APK folder
  -o string      Output folder for findings and All_Smali (default "HSS_Output")
  -reload string Re-hunt on existing All_Smali folder (skips collection)

Hunting Flags (If none are specified, defaults to ALL):
  -h             Hunt HTTP/HTTPS URLs + Firebase/Supabase/DB endpoints
  -ip            Hunt IP addresses
  -b             Hunt and decode Base64 (multi-encoding aware)
  -m             Hunt email addresses
  -fl int        Base64 filter level: 0=raw, 1=basic, 2=full

Reporting/Email:
  -ms string     SMTP server:port (e.g., smtp.gmail.com:587)
  -mf string     From address for emailed report
  -mt string     To address for emailed report
```

### Examples

**1. The "Kitchen Sink" Scan (Default)**  
Run all modules (URLs, IPs, Base64, Mail) with standard output.
```bash
./hunt-sexy-smali -i ./malware_apk
```

**2. Targeted Network & DB Hunting**  
Only look for URLs, endpoints, and IP addresses.
```bash
./hunt-sexy-smali -i ./malware_apk -h -ip
```

**3. Stealth/Paranoid Base64 Extraction**  
Hunt *only* for Base64 using the raw filter level (FL 0), dropping all other checks.
```bash
./hunt-sexy-smali -i ./malware_apk -b -fl 0
```

**4. Automated Scan & Email Report**  
Run all checks and email the final IOC report to a SOC analyst.
```bash
./hunt-sexy-smali -i ./malware_apk -ms "smtp.example.com:587" -mf "bot@example.com" -mt "analyst@example.com"
```

---

## 📁 Output Structure

Upon completion, your output directory (`HSS_Output` by default) will contain:
1.  **`All_Smali/`**: A flattened directory of every single `.smali` file extracted from the APK.
2.  **`HSS_findings_YYYYMMDD_HHMMSS.txt`**: A cleanly formatted summary report categorizing every finding, its source file, the raw extracted value, and the decoded plaintext (if applicable).
