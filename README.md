<div align="center">

# Hunt Sexy Smali

[![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square)]()
[![Type](https://img.shields.io/badge/Type-Static%20Analysis-red?style=flat-square)]()
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=flat-square)]()
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)
![Development Time](https://img.shields.io/badge/Development%20Time-%20Approx%202%20hour%207%20min-blue.svg)

**Regex-driven IOC hunter for decompiled Android APK smali files.**  
Hunt URLs, IPs, secrets, Base64 encoded C2s, and database endpoints - with up to 97% false positive reduction.

[Installation](#installation) · [Modes](#modes-of-operation) · [Flags](#cli-reference) · [Examples](#usage-examples) · [Output](#output-structure)

</div>

## Demo


<img width="1506" height="808" alt="Screenshot 2026-04-28 164735" src="https://github.com/user-attachments/assets/a5501aeb-8588-4b6e-a687-829ea0d67c88" />



---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Modes of Operation](#modes-of-operation)
  - [Standard Mode](#1-standard-mode--i)
  - [Reload Mode](#2-reload-mode--reload)
- [Base64 Filter Levels](#base64-false-positive-filter--fl)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
- [Output Structure](#output-structure)
- [False Positive Reduction : How It Works](#false-positive-reduction--how-it-works)
- [License](#license)

---

## Overview

Hunt Sexy Smali (HSS) is a command-line Dmali forensics tool written in Go for static analysis of decompiled Android applications. It recursively walks `.smali` files produced by tools like `apktool`, `jadx`, or `apkeasy` and applies regex-based hunting across multiple IOC categories.

The tool is designed for malware analysts, mobile security researchers who need to extract indicators from APKs quickly and with minimal noise.

> [!NOTE]
> HSS operates entirely on decompiled smali source - it does not decompile APKs itself. Run `apktool d target.apk` first, then point HSS at the output folder and then it start hunting recursively for all smali files.

---

## Features

| Category | What It Hunts |
|----------|--------------|
| Network Endpoints | HTTP and HTTPS URLs |
| Database / BaaS | Firebase, Supabase, MongoDB Atlas, MySQL, SQLite, RealmDB, Redis |
| Secrets | Hardcoded API keys, access tokens, auth tokens |
| IP Addresses | IPv4 with port validation (ports 1–65535 only) |
| Email Addresses | Gmail, Outlook/Hotmail/Live, ProtonMail, Yahoo, custom domains |
| Base64 Payloads | Multi-encoding decode: UTF-8, UTF-16 LE/BE, ISO-8859-1, Windows-1252, KOI8-R, GB18030, Shift-JIS, EUC-JP, binary hex fallback |


---

## Installation

 Directly download it from 👉[here](https://github.com/gigachad80/Hunt-Sexy-Smali/releases/tag/v1.0.0)👈

OR 

Go 1.20 or later is required.

```bash
git clone https://github.com/gigachad80/Hunt-Sexy-Smali.git
cd Hunt-Sexy-Smali
go build -o hunt-sexy-smali sexysmali.go
```

Verify the build:

```bash
./hunt-sexy-smali -help
```

## Modes of Operation

HSS offers three operation modes. When using `-i`, an interactive prompt asks you to choose between Batch and Stream before scanning begins.

---

### 1. Standard Mode (`-i`)

HSS recursively walks the decompiled APK folder and hunts for IOCs. At startup, an interactive prompt asks you to select one of two sub-modes:

```bash
./hunt-sexy-smali -i /path/to/decompiled_apk -o ./output -h -ip -b -m
```

**Batch (prompt choice `1`)**

- Copies all `.smali` files into a flat `All_Smali/` directory, embedding the original relative path as a header comment inside each file
- Hunt runs after full collection is complete
- `All_Smali/` persists on disk, enabling `-reload` for future re-scans without re-copying
- Best for: small/medium APKs, repeated analysis sessions
- Disk: HIGH - Memory: LOW

**Stream (prompt choice `2`)**

- No `All_Smali/` folder is created
- Each file is read into memory, hunted immediately, then discarded if no hits are found
- Only the findings report is written to disk
- Best for: large APKs (100 MB+), one-time scans
- Disk: ZERO - Memory: LOW

> [!IMPORTANT]
> Stream Mode is incompatible with `-reload`. The reload flag requires an existing `All_Smali/` folder, which Stream Mode never creates. When `-reload` is provided, HSS skips the scan mode prompt entirely.

---

### 2. Reload Mode (`-reload`)

USeful for incase you want to run scan again inf future . Re-hunts an existing `All_Smali/` folder from a previous Batch Mode run without re-copying any files. Useful for changing filter levels, hunting new categories, or re-extracting Base64 with a different `-fl` value.

```bash
./hunt-sexy-smali -reload ./HSS_Output/All_Smali -b -fl 2
```

Output is written to `HSS_Reload_Output/` next to the `All_Smali/` folder.

> [!NOTE]
> Reload Mode always operates as Batch - no scan mode prompt is shown. Stream Mode has no reload equivalent since it never persists smali files to disk.

---

## Base64 False Positive Filter (`-fl`)

Smali files are dense with Base64-like strings that are not encoded payloads - class descriptors, library signatures, resource identifiers. HSS applies a layered filter system to eliminate this noise when the `-b` flag is used.

> [!NOTE]
> Base64 padding (`=` or `==`) is enforced at the regex level and applies across all filter levels including FL0.

> [!NOTE]
> If you use `-b` without providing `-fl`, an interactive menu launches automatically. You can also pass `-fl` directly to skip the prompt.

| Level | Name | What It Removes | Noise Reduction |
|-------|------|-----------------|-----------------|
| `0` | RAW | Nothing. Every matching string passes through. Use for paranoid research or unknown custom APKs. | 0% |
| `1` | BASIC | Strings under 20 characters. Strings with no `+`, `=`, or `/` (not valid base64 structure). Strings with 3+ slashes (path-like). Strings starting with `#` (resource IDs, hex colors). | ~65% |
| `2` | FULL (recommended) | Everything FL1 removes, plus 60+ known Android/JVM/third-party library class descriptor prefixes: Android, AndroidX, Dalvik, Java stdlib, Kotlin, Google GMS/Firebase/Material, OkHttp v2+v3, Okio, Retrofit, RxJava 2+3, ReactiveStreams, Glide, Picasso, Coil, Fresco, Dagger, Facebook SDK, Apache, BouncyCastle, Crashlytics, Mixpanel, AppsFlyer, Timber, JetBrains, Dexter, EasyDeviceInfo, Toasty, Klinker SMS, and more. | ~95–97% |

**Multi-encoding decode chain** (applied after filtering):

When a valid Base64 string passes all filters, HSS attempts to decode it through this chain in order, stopping at the first successful result:

```
UTF-8 → UTF-16LE → UTF-16BE → Windows-1252 → ISO-8859-1 → KOI8-R → Shift-JIS → EUC-JP → GB18030 → Hex dump
```

---

## CLI Reference

```
Usage: hunt-sexy-smali -i <path> [flags]
       hunt-sexy-smali -reload <All_Smali_path> [flags]
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-i` | string | - | Input path of the decompiled APK folder |
| `-o` | string | `HSS_Output` | Output folder for findings and `All_Smali/` |
| `-reload` | string | - | Re-hunt on existing `All_Smali/` folder, skips collection |
| `-h` | bool | false | Hunt HTTP/HTTPS URLs + Firebase/Supabase/DB endpoints |
| `-ip` | bool | false | Hunt IPv4 addresses with port validation (1–65535) |
| `-b` | bool | false | Hunt and decode Base64 strings (multi-encoding aware) |
| `-m` | bool | false | Hunt email addresses (Gmail, Outlook, Proton, Yahoo, custom) |
| `-fl` | int | interactive | Base64 filter level: `0`=raw, `1`=basic, `2`=full |
|

> [!NOTE]
> If no hunting flags (`-h`, `-ip`, `-b`, `-m`) are provided, HSS defaults to enabling all four modules.

---

## Usage Examples

**Full scan, all modules, interactive mode selection:**
```bash
./hunt-sexy-smali -i ./decompiled_apk
```

**Hunt only network endpoints and IPs:**
```bash
./hunt-sexy-smali -i ./decompiled_apk -h -ip -o ./findings
```

**Hunt Base64 with full library filter (no prompt):**
```bash
./hunt-sexy-smali -i ./decompiled_apk -b -fl 2
```

**Paranoid raw Base64 scan - no filters, everything included:**
```bash
./hunt-sexy-smali -i ./decompiled_apk -b -fl 0
```

**Re-hunt existing All_Smali with email and IP modules:**
```bash
./hunt-sexy-smali -reload ./HSS_Output/All_Smali -m -ip
```

---

## Output Structure

**Batch Mode:**

```
HSS_Output/
├── All_Smali/
│   ├── smali__com__example__MainActivity.smali
│   ├── smali__com__example__network__ApiClient.smali
│   └── smali_classes2__com__evil__Dropper.smali
│
└── HSS_findings_20260428_153045.txt
```

**Stream Mode:**

```
HSS_Output/
└── HSS_findings_20260428_153045.txt
```

**Reload Mode:**

```
HSS_Reload_Output/
└── HSS_findings_20260428_160012.txt
```


---

## False Positive Reduction : How It Works

HSS applies filters in layers. FL1 filters run first; FL2 adds the library prefix layer on top.

| Filter | Level | Technique | Targets |
|--------|-------|-----------|---------|
| Minimum length 20 | FL1 | Length check | Short noise strings |
| No `+`/`=`/`/` present | FL1 | Char check | Plain identifiers with no base64 structure |
| Slash density ≥ 3 | FL1 | Count check | File paths disguised as base64 |
| `#` prefix | FL1 | Prefix check | Android resource IDs and hex color values |
| Smali `L` descriptor + 2+ slashes | FL2 | Structural | Generic class paths like `Lcom/example/Foo` |
| 60+ known library prefixes | FL2 | Prefix list | `Landroid/`, `Ljava/`, `Lkotlin/`, `Lokhttp3/`, `Lcom/google/`, `Lcom/facebook/`, etc. |
| Array descriptors `[B`, `[I` | FL2 | Prefix check | Dalvik primitive array type signatures |
| Terminating `;` | FL2 | Suffix check | Smali class reference terminators |
| Dot-separated lowercase paths | FL2 | Heuristic | Package paths encoded as strings |

---

## License

GNU Affero General Public License v3.0 - see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Go - Stay sexy.

Contact :
[github.com/gigachad80](https://github.com/gigachad80) · `pookielinuxuser@tutamail.com`

</div>

##### First release : April 28, 2026
##### Last updated : April 28,2026
