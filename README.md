# 🕵️ Ultimate Forensics Toolbox

**Lead Developer:** Jason Peixoto  
**Repository:** <https://github.com/jpeixoto/UltimateForensicsToolbox>  
**Current Build:** v67 Integrated Workstation  
**Application Title:** `Ultimate Forensics Toolbox V1.10 - Jason Peixoto.`  
**Platform:** macOS host + Android USB device  

Ultimate Forensics Toolbox is a PyQt5 Android reverse-engineering, forensic extraction, dynamic-analysis, malware/PHA review, network/proxy, and report-generation workstation.

It brings together Frida instrumentation, Android ADB workflows, Logcat, file extraction, APK exploration, APK extraction, static decrypt workflows, Unity IL2CPP preparation, Cocos decryption, PHA notes, manifest triage, Rubiks risk scoring, and Security Review report generation into one desktop UI.

> Use this only on devices, applications, networks, and accounts that you own or are explicitly authorized to test.

---

## Table of Contents

- [What is included](#what-is-included)
- [Known-good test environment](#known-good-test-environment)
- [Install on macOS](#install-on-macos)
- [Python requirements](#python-requirements)
- [Optional toolchain requirements](#optional-toolchain-requirements)
- [Android device setup](#android-device-setup)
- [Frida setup](#frida-setup)
- [First run checklist](#first-run-checklist)
- [Feature guide](#feature-guide)
- [Integrated workspaces](#integrated-workspaces)
- [Runtime folders and config files](#runtime-folders-and-config-files)
- [Troubleshooting and diagnostics](#troubleshooting-and-diagnostics)
- [Useful commands](#useful-commands)
- [Development workflow](#development-workflow)
- [License](#license)

---

## What is included

### Core Android / Frida / Forensic capabilities

- Device Status dashboard.
- Android process and package discovery.
- Frida Manager with full script editor.
- Two Frida injection engines:
  - **Command Line / frida-tools**
  - **Python API / frida module**
- Frida 17-compatible Python API Java bridge support.
- Frida version diagnostics.
- Color-coded Frida Logs with search, filters, pause, clear, and double-click jump-to-line.
- Buffered Logcat viewer with level filters, presets, non-destructive display filtering, and export.
- ADB File Explorer.
- Screenshot Gallery.
- Android Remote screen stream and input injection.
- ADB Console.
- Android global proxy and Frida per-app proxy routing.
- Network monitor / socket snapshot / PCAP workflow.
- Settings grouped by workspace/menu.

### Integrated reverse-engineering / review workspaces

Enabled workspaces now include:

- **Apk Explorer**
- **Apk Extractor**
- **Beautifier**
- **Decrypt Cocoas**
- **PHA Notes**
- **Rubiks**
- **Security Review Workstation**
- **Static Decrypter**
- **Strip Manifest**
- **Unity App Prepare**

Removed / not used:

- **De Obfuscator**

---

## Known-good test environment

| Component | Known working value |
|---|---:|
| Host OS | macOS |
| Python path example | `/opt/homebrew/bin/python3` or project venv |
| Frida Python module | `17.9.1` |
| Frida CLI runtime | `17.9.1` |
| Android frida-server | `17.9.1` |
| Frida CLI path example | `/opt/homebrew/bin/frida` |
| Android frida-server path | `/data/local/tmp/frida-server` |
| Android test device | Pixel 9a |
| Android test version | Android 16 |
| Toolbox file | `UltimateForensicsToolbox.py` |

The Frida Python module, local Frida CLI runtime, and Android `frida-server` should match.

---

## Install on macOS

### 1. Install Homebrew dependencies

```bash
brew install --cask android-platform-tools
brew install scrcpy
brew install node
```

Verify:

```bash
which adb
which scrcpy
which node
which npm

adb version
scrcpy --version
node --version
npm --version
```

Common Apple Silicon/Homebrew paths:

```text
/opt/homebrew/bin/adb
/opt/homebrew/bin/scrcpy
/opt/homebrew/bin/node
/opt/homebrew/bin/npm
/opt/homebrew/bin/frida
```

### 2. Create a Python virtual environment

```bash
cd /Users/jasonpeixoto/PythonProjects/AndroidReverseProjects/UltimateForensicsToolbox

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
```

### 3. Install Python dependencies

Recommended full install:

```bash
pip install PyQt5==5.15.10
pip install frida==17.9.1 frida-tools==14.8.2
pip install jsbeautifier requests "requests[socks]"
pip install pandas openpyxl
pip install androguard quickjs
pip install pyenchant
```

Minimal install for core toolbox:

```bash
pip install PyQt5 frida frida-tools jsbeautifier requests "requests[socks]"
```

Optional dependency notes:

| Package | Used by |
|---|---|
| `PyQt5` | Main GUI |
| `frida` | Python API Frida engine |
| `frida-tools` | CLI Frida engine |
| `jsbeautifier` | Frida Manager, Beautifier, APK tools |
| `requests` | Proxy validation |
| `requests[socks]` / `PySocks` | SOCKS proxy validation |
| `pandas` | Rubiks, Static Decrypter |
| `openpyxl` | Static Decrypter Excel export |
| `androguard` | APK Explorer / Static Decrypter DEX decompile |
| `quickjs` | Static Decrypter JavaScript decrypt scripts |
| `pyenchant` | Security Review Workstation spellcheck |

---

## Optional toolchain requirements

Some workspaces depend on external tools.

### Frida / Android

- `adb`
- `frida`
- `frida-server`
- `scrcpy`

### Decrypt Cocoas

Configure paths in **Settings → Decrypt Cocoas**:

- Apktool path
- Reverse tool path
- Prettier path

Suggested installs:

```bash
brew install apktool
brew install node
npm install -g prettier
```

The reverse/decrypt binary is project-specific and must be pointed to in Settings.

### Unity App Prepare

Configure in **Settings → Unity App Prepare**:

- `Il2CppDumper.dll`
- Default output folder
- `dotnet` path

Install .NET if needed:

```bash
brew install --cask dotnet-sdk
```

Common dotnet locations:

```text
/usr/local/share/dotnet/dotnet
/opt/homebrew/bin/dotnet
```

Unity App Prepare expects Il2CppDumper and related helper scripts near the dumper DLL when available:

```text
Il2CppDumper.dll
ghidra_with_struct.py
ghidra.py
il2cpp_header_to_ghidra.py
```

### APK Explorer / Static Decrypter DEX decompile

```bash
pip install androguard
```

### Static Decrypter JavaScript decrypt scripts

```bash
pip install quickjs
```

### Security Review Workstation spellcheck

```bash
pip install pyenchant
```

If `pyenchant` is not installed, the Security Review Workstation still runs without spellcheck.

---

## Android device setup

### Enable developer mode

1. Open Android **Settings**.
2. Go to **About phone**.
3. Tap **Build number** repeatedly until Developer Options are enabled.
4. Open **Developer Options**.
5. Enable **USB debugging**.

### Authorize USB debugging

```bash
adb devices
```

Expected:

```text
List of devices attached
<serial>    device
```

If it shows `unauthorized`, unlock the phone and accept the RSA prompt.

### Root requirement

Full Frida server control and protected data access require root.

Test root:

```bash
adb shell su -c id
```

Expected:

```text
uid=0(root) gid=0(root) ...
```

---

## Frida setup

### Match versions

These should match:

```text
Python frida module version == local Frida CLI runtime == Android frida-server version
```

Check manually:

```bash
python -c "import frida; print(frida.__version__)"
frida --version
adb shell su -c "/data/local/tmp/frida-server --version"
```

### Check Android CPU ABI

```bash
adb shell getprop ro.product.cpu.abi
```

Common values:

| ABI | frida-server build |
|---|---|
| `arm64-v8a` | Android arm64 |
| `armeabi-v7a` | Android arm |
| `x86_64` | Android x86_64 |

### Push and start frida-server

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
adb shell su -c "setenforce 0"
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0 >/dev/null 2>&1 &"
```

Verify:

```bash
adb shell su -c "ps -A | grep frida"
adb shell su -c "/data/local/tmp/frida-server --version"
```

---

## First run checklist

Start the toolbox:

```bash
source .venv/bin/activate
python UltimateForensicsToolbox.py
```

Recommended first steps:

1. Open **Device Status**.
2. Click **Refresh Status**.
3. Confirm:
   - ADB found
   - Device connected
   - Root / `su`
   - SELinux status
   - Node.js / npm
   - Frida Python module
   - Frida CLI
   - frida-server running/version
   - Android global proxy state
4. Open **Processes** and refresh.
5. Select target package.
6. Open **Frida Manager**.
7. Select CLI or Python API engine.
8. Validate script.
9. Inject.

Minimal Java test:

```javascript
Java.perform(function() {
    console.log("Frida Java bridge active on Android " + Java.androidVersion);
});
```

---

## Feature guide

### 🩺 Device Status

Checks:

- Local ADB
- Python Frida module
- Frida CLI
- Node.js
- npm
- Android device connection
- Android model/version
- Battery
- Root / `su`
- SELinux
- frida-server process
- frida-server version
- Android global proxy
- Foreground app
- Selected target package status

Actions:

- Refresh Status
- Copy Report
- Frida Versions
- Start Frida Server
- Stop Frida Server
- Clear Android Proxy
- Auto refresh

---

### 🔍 Processes

- Lists installed/running apps.
- Filters packages.
- Clicking a package populates Frida target package fields.

---

### 🛠️ Frida Manager

Features:

- Dedicated Frida script folder.
- File tree with adjustable splitter width.
- New Script creates an unsaved blank buffer.
- Save / Save As.
- Reload.
- Beautify.
- Validate.
- Snippets menu.
- Full search/replace controls.
- Line numbers.
- Current-line/search gutter markers.
- Font gear popup.
- CLI / Python API engine selector.
- Frida CLI path auto-detect.
- Forge & Inject.
- Stop Script.

Script folder:

```text
~/.jpeixoto/UltimateForensicsToolbox/FridaScripts
```

---

### 💉 Frida Logs

Features:

- `[FRIDA]` / `[LOG]`
- `[SYSTEM]`
- `[SCRIPT]`
- `[WARN]`
- `[ERROR]`
- Search
- Category checkboxes
- Pause
- Clear
- Font gear popup
- Double-click JS stack location to jump to editor line/column.

---

### 🕵️ LogCat

Features:

- Buffered capture model.
- Non-destructive filters.
- Minimum level dropdown.
- Per-level checkboxes.
- Presets:
  - App Errors
  - Frida Only
  - Network
  - ActivityManager
  - Current Package Only
- Search.
- Pause Display.
- Export visible rows.
- Font gear popup.

---

### 📁 File Explorer

Features:

- Browse Android filesystem.
- Push / Pull.
- Rename / Delete.
- Preview file contents.
- Path history.
- Root path support when device permits it.

Common paths:

```text
/
/sdcard
/sdcard/Download
/data/local/tmp
/data/data/<package>
```

---

### 📸 Gallery

Features:

- ADB screenshot capture.
- Local screenshot history.
- Previous / Next.
- Delete / Clear.
- Clipboard scaling.
- First-load image scaling fix.

Screenshots:

```text
~/.jpeixoto/UltimateForensicsToolbox/Scrap
```

---

### 🌐 Proxy

Features:

- Proxy import sources.
- Country counts.
- HTTP/HTTPS and optional SOCKS.
- Validation queue.
- Ranking/cache.
- Dead proxy cleanup.
- Named proxy profiles.
- Android global proxy mode.
- Frida Java proxy hook mode.
- Backup / restore proxy JSON.
- Import status table.

Proxy database:

```text
~/.jpeixoto/UltimateForensicsToolbox/manual_proxies.json
```

---

### 🌐 Network

Features:

- Android network socket snapshots.
- TCP / UDP filters.
- State filters.
- Host/IP filter.
- Process/package filter.
- Port/range filter.
- Selection/scroll-preserving refresh.
- Row hover details.
- Double-click details dialog.
- tcpdump PCAP start/stop/pull.
- Payload view options:
  - Auto Text
  - Text
  - JSON Pretty
  - Hex
  - Hex + ASCII
- Frida snippets:
  - REST / OkHttp request + response
  - URLConnection
  - Chrome/Cronet Java
  - Native TLS SSL_read/write
  - OkHttp WebSocket
  - MQTT/Paho
  - Native connect/send/recv

PCAP captures:

```text
~/.jpeixoto/UltimateForensicsToolbox/NetworkCaptures
```

---

### 🔌 Frida/ADB Control

Features:

- APK install.
- Split APK install.
- App launch/kill.
- Frida server controls.
- Custom ADB command grid.
- Android global proxy helpers.

---

### 📱 Remote

Features:

- Embedded screen stream using ADB screencap.
- External `scrcpy`.
- Tap and drag/swipe injection.

---

### 📟 ADB Console

Features:

- ADB command history.
- Console output.
- Font gear popup.

---

### ⚙️ Settings

Settings are grouped by menu/workspace:

- General / Gallery
- Navigation / Layout
- Frida Manager
- Logs / Console Text
- Proxy
- Decrypt Cocoas
- Unity App Prepare
- Investigation Session

Settings file:

```text
~/.jpeixoto/UltimateForensicsToolbox/config_DecryptCocoas.json
```

---

## Integrated workspaces

### 📦 Apk Explorer

Purpose: inspect APK/ZIP/APKS contents without fully extracting everything manually.

Features:

- Open APK / ZIP / APKS.
- Explore internal tree.
- Preview on click.
- Open files in tabs.
- Nested archive loading.
- Android binary XML decode.
- JS/XML/HTML beautify on export.
- Global search.
- Image preview.
- DEX preview/decompile with `androguard`.
- Export selected files.
- Export full archive with options.

Cache:

```text
~/.jpeixoto/ApkExplorer/dex_cache
```

---

### 📤 Apk Extractor

Purpose: extract one or more archives into a temporary workspace and search/preview/export contents.

Features:

- Load multiple APK/ZIP/APKS files.
- Merge All or Separate Folders modes.
- Recursive nested archive extraction.
- Tree filter.
- Smart / Raw / Hex preview.
- Preview search.
- Global regex search.
- Search result CSV export.
- Export extracted files to disk.
- Preview beautifier for JS/HTML/XML/JSON.

---

### ✨ Beautifier

Purpose: standalone JavaScript beautifier and search workspace.

Features:

- JavaScript editor.
- Syntax highlighting.
- Load JS file.
- Beautify with `jsbeautifier`.
- Find all.
- Search results grid.
- Double-click result to jump.
- Save / Save As.
- Send beautified code to Frida Manager.

---

### 🧊 Decrypt Cocoas

Purpose: Cocos/JS reverse-engineering helper pipeline.

Features:

- Zip container input.
- Output folder.
- Decryption key field.
- Binary settings:
  - Apktool
  - Reverse
  - Prettier
- Pipeline:
  - Unzip container.
  - Extract APKs with apktool.
  - Find JS/JSC/Lua/Luac.
  - Inspect encrypted assets.
  - Hex signatures.
  - Bruteforce key using `libcocos*.so` and `.jsc`.
  - Global decrypt.
  - Prettier cleanup.
- Clickable output links.

Config:

```text
~/.jpeixoto/DecryptCocoas/config_DecryptCocoas.json
```

---

### 📝 PHA Notes

Purpose: structured rich-text notes for PHA/security work.

Features:

- Category tree.
- Search notes.
- Add category.
- Add note.
- Preview pane.
- Rich-text editor tabs.
- Bold / italic / underline / strikeout.
- Alignment.
- Bullet and numbered lists.
- Insert image.
- Insert hyperlink.
- Shift-click link to open.
- Text color.
- Font family and size.
- Dark/light note theme.
- Export PDF.
- Auto-save.

Storage:

```text
~/.jpeixoto/PhaNotes
```

---

### 🧩 Rubiks

Purpose: riskware signal scoring/tracking.

Features:

- CSV templates.
- Draft save/load.
- Profiles:
  - Corporate
  - Personal
  - Government
- Weak/Medium/Strong scoring.
- Discovered checkbox tracking.
- Category filter.
- Search.
- Merge template.
- Evidence attachment.
- Link/evidence opening.
- Analytics summary.
- Dark/light mode.
- Autosave.
- Export report.

Folders:

```text
~/.jpeixoto/Rubiks/templates_Rubiks
~/.jpeixoto/Rubiks/drafts_Rubiks
```

---

### 🛡️ Security Review Workstation

Purpose: template-driven security review report generation.

Features:

- Report templates with tag insertion.
- Draft gallery.
- Move drafts to Root / Completed / OldReports.
- App metadata.
- Play Store details.
- Static and dynamic analysis points.
- Bread indicators.
- Risk points.
- Cloaked / uncloaked URLs.
- Steps to uncloak.
- NSR section.
- Handling context.
- Summary / verdict / notes.
- Rendered Markdown preview.
- Raw Markdown preview.
- Copy raw Markdown.
- Export Markdown.
- Export HTML.
- Create Bug button.
- Optional spellcheck.

Folders:

```text
~/.jpeixoto/GenReport/reports_GenReport
~/.jpeixoto/GenReport/templates_GenReport
```

---

### 🔐 Static Decrypter

Purpose: run regex-driven static decryption workflows against source/decompiled code.

Features:

- Projects.
- Saved decrypt scripts.
- Language selector:
  - Python
  - C#
  - JavaScript
- Script editor.
- Source editor.
- Load any file.
- DEX decompile with `androguard`.
- XML decode.
- Regex extraction.
- Run `decrypt(p1, p2)`.
- Results grid.
- Copy CSV to clipboard.
- Export Excel.
- Session persistence.

Folders:

```text
~/.jpeixoto/StaticDecrypter/saved_scripts_StaticDecrypter
~/.jpeixoto/StaticDecrypter/projects_StaticDecrypter
~/.jpeixoto/StaticDecrypter/dex_cache
```

---

### 🧾 Strip Manifest

Purpose: Android manifest triage for PHA/security review.

Features:

- Paste or load `AndroidManifest.xml`.
- Permission table.
- BNL match.
- Protection/risk level.
- Risk pattern matcher:
  - SMS/Toll Fraud
  - Spyware/Audio
  - Hostile Downloader
  - Ransomware/Privilege
  - Click Fraud
  - Rooting/Backdoor
- Component tree.
- Exported status.
- Intent filter actions.
- Persistence trigger detection.
- Deep link / URL table.
- Copy executive summary.

---

### 🎮 Unity App Prepare

Purpose: prepare Unity IL2CPP apps for Ghidra/DnSpy workflows.

Features:

- Select `Il2CppDumper.dll`.
- Select APK/ZIP/APKS.
- Select output folder.
- Deep scan nested archives.
- Extract:
  - `libil2cpp.so`
  - `global-metadata.dat`
- Run Il2CppDumper.
- Copy helper scripts.
- Generate `il2cpp_ghidra.h` when helper exists.
- Open output folder.
- Built-in master guide.

Config:

```text
~/.jpeixoto/Frameworks/UnityAppPrep/unity_prep_config.json
```

---

## Runtime folders and config files

Base workspace:

```text
~/.jpeixoto/UltimateForensicsToolbox
```

Important paths:

| Path | Purpose |
|---|---|
| `FridaScripts/` | Frida script library |
| `Scrap/` | Screenshots |
| `NetworkCaptures/` | PCAP captures |
| `manual_proxies.json` | Proxy database |
| `proxy_cache.json` | Proxy rank/cache |
| `proxy_profiles.json` | Named proxy profiles |
| `proxy_backups/` | Proxy backups |
| `frida_proxy_template.js` | Proxy hook template |
| `frida_api_agent_bridge/` | Frida 17 Python API Java bridge |
| `Sessions/` | Investigation session saves |
| `commands.json` | Custom ADB buttons |
| `config_DecryptCocoas.json` | Main toolbox settings |

Other workspace folders:

```text
~/.jpeixoto/PhaNotes
~/.jpeixoto/Rubiks
~/.jpeixoto/GenReport
~/.jpeixoto/StaticDecrypter
~/.jpeixoto/ApkExplorer
~/.jpeixoto/DecryptCocoas
~/.jpeixoto/Frameworks/UnityAppPrep
```

---

## Troubleshooting and diagnostics

### Quick diagnostic checklist

```bash
adb devices
python -c "import frida; print(frida.__version__)"
which frida
frida --version
adb shell su -c "/data/local/tmp/frida-server --version"
adb shell su -c "ps -A | grep frida"
node --version
npm --version
```

### Common problems

| Problem | Likely cause | Fix |
|---|---|---|
| `adb: command not found` | Platform tools missing | `brew install --cask android-platform-tools` |
| Device `unauthorized` | RSA prompt not accepted | Unlock phone and accept prompt |
| `su` denied | Root missing/denied | Configure Magisk/root permission |
| Frida version mismatch | Python/CLI/server mismatch | Align all to same runtime version |
| `Java is not defined` | Python API bridge not bundled | Install Node/npm, allow bridge compile, or use CLI |
| `frida.Compiler` missing | Frida tooling mismatch | Upgrade `frida` / `frida-tools` |
| SOCKS proxy fails | PySocks missing | `pip install PySocks` |
| DEX decompile fails | Androguard missing | `pip install androguard` |
| StaticDecrypter JS fails | QuickJS missing | `pip install quickjs` |
| Excel export fails | openpyxl missing | `pip install openpyxl` |
| Spellcheck unavailable | pyenchant missing | `pip install pyenchant` |
| Unity dumper fails | dotnet or dumper path wrong | Fix Unity settings |
| Decrypt Cocoas fails | Apktool/reverse/prettier path wrong | Fix Decrypt Cocoas settings |

---

## Useful commands

### ADB

```bash
adb devices
adb kill-server
adb start-server
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.version.release
adb shell pm list packages -3
adb shell ps -A
```

### Frida

```bash
python -c "import frida; print(frida.__version__)"
which frida
frida --version
frida-ps -Uai
adb shell su -c "/data/local/tmp/frida-server --version"
```

### Frida server

```bash
adb shell su -c "setenforce 0"
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0 >/dev/null 2>&1 &"
adb shell su -c "ps -A | grep frida"
adb shell su -c "pkill -9 frida-server"
```

### Android global proxy

```bash
adb shell settings get global http_proxy
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy
```

### Manual Frida injection

```bash
frida -U -f com.example.app -l script.js
```

---

## Development workflow

Recommended branch workflow:

```bash
git checkout main
git pull
git checkout -b FeatureName
```

Before committing:

```bash
python3 -m py_compile UltimateForensicsToolbox.py
wc -l UltimateForensicsToolbox.py
git diff --stat
```

Commit:

```bash
git add UltimateForensicsToolbox.py README.md
git commit -m "Add <feature name> workspace"
git push -u origin FeatureName
```

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

Copyright (c) 2026 **Jason Peixoto**
