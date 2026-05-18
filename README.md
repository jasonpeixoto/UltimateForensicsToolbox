# 🕵️ Ultimate Forensics Toolbox

**Lead Developer:** Jason Peixoto  
**Repository:** <https://github.com/jpeixoto/UltimateForensicsToolbox>  
**Current Version:** 1.08 "Dual Frida Engine + Advanced Log Viewer"  
**Platform:** macOS host + Android USB device  

Ultimate Forensics Toolbox is a PyQt5 Android dynamic-analysis, forensic extraction, Frida-instrumentation, Logcat, ADB, proxy, screenshot, and remote-control workstation. It is designed to keep the most common Android security-analysis tasks in one interface: process discovery, Frida script editing/injection, Frida server control, Logcat viewing, ADB command execution, remote file browsing, screenshots, app install/control, and device mirroring.

> Use this only on devices and applications you own or have explicit authorization to test.

---

## Table of Contents

- [What is included](#what-is-included)
- [Known-good test environment](#known-good-test-environment)
- [Install on macOS](#install-on-macos)
- [Android device setup](#android-device-setup)
- [Frida setup](#frida-setup)
- [First run](#first-run)
- [Frida injection modes](#frida-injection-modes)
- [Frida 17 Python API Java bridge notes](#frida-17-python-api-java-bridge-notes)
- [How to test the setup](#how-to-test-the-setup)
- [Feature guide](#feature-guide)
- [Troubleshooting and diagnostics](#troubleshooting-and-diagnostics)
- [Runtime folders and config files](#runtime-folders-and-config-files)
- [Useful commands](#useful-commands)
- [Development notes](#development-notes)
- [License](#license)

---

## What is included

### Core capabilities

- Android ADB command console.
- Android package/process discovery.
- Frida script editor and injection manager.
- Two Frida injection engines:
  - **Command Line / frida-tools** engine.
  - **Python API / frida module** engine.
- Frida 17-compatible Python API Java bridge support through `frida-java-bridge`.
- Frida version diagnostics for:
  - Python API module.
  - Local CLI/frida-tools binary.
  - Android `/data/local/tmp/frida-server`.
  - Python API compiler availability.
  - API Java bridge package status.
- Color-coded Frida log viewer with checkbox category filters and text search.
- Real-time Logcat viewer with priority filtering and search.
- ADB file explorer with push, pull, delete, rename, folder navigation, and preview.
- Embedded remote screen stream using `adb shell screencap -p`.
- Optional high-speed external mirroring with `scrcpy`.
- Remote tap and swipe injection from the preview window.
- Screenshot capture, local gallery, clipboard copy, and portal workflow.
- APK and split APK deployment.
- App launch/kill controls.
- Burp/global proxy helper.
- Manual proxy pool management.
- Frida proxy script template editor.
- Custom ADB command button grid.
- System tray behavior.
- Persistent settings and command history.

---

## Known-good test environment

This README matches the current tested setup from development:

| Component | Known working value |
|---|---:|
| Host OS | macOS |
| Python path example | `/opt/homebrew/bin/python3` |
| Frida Python module | `17.9.1` |
| Frida CLI/frida-tools | `17.9.1` at `/opt/homebrew/bin/frida` |
| Android frida-server | `17.9.1` at `/data/local/tmp/frida-server` |
| Android test device | Pixel 9a |
| Android test version | Android 16 |

The exact device can vary, but the **Frida Python module**, **Frida CLI**, and **Android frida-server** should match.

---

## Install on macOS

### 1. Install Homebrew dependencies

```bash
brew install --cask android-platform-tools
brew install scrcpy
brew install node
```

Why these are needed:

| Dependency | Purpose |
|---|---|
| `adb` | Device communication, shell, install, file transfer, input, screenshots |
| `scrcpy` | Optional high-speed external mirroring |
| `node` / `npm` | Required for Python API Java bridge mode with Frida 17+ |

Verify paths:

```bash
which adb
which scrcpy
which node
which npm
```

On Apple Silicon/Homebrew, common paths are:

```text
/opt/homebrew/bin/adb
/opt/homebrew/bin/scrcpy
/opt/homebrew/bin/node
/opt/homebrew/bin/npm
```

### 2. Create a Python virtual environment

From the project folder:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

### 3. Install Python requirements

If your repository includes `requirements.txt`:

```bash
pip install -r requirements.txt
```

If you are installing manually:

```bash
pip install PyQt5 frida frida-tools jsbeautifier requests "requests[socks]"
```

Package purpose:

| Package | Purpose |
|---|---|
| `PyQt5` | Desktop GUI |
| `frida` | Python API injection engine |
| `frida-tools` | CLI `frida` command and related tooling |
| `jsbeautifier` | JavaScript formatter for Frida scripts |
| `requests` | Proxy validation / HTTP testing |
| `requests[socks]` | SOCKS proxy support for proxy rotation |

### 4. Confirm local Frida tools

```bash
python -c "import frida; print(frida.__version__)"
which frida
frida --version
```

Expected example:

```text
17.9.1
/opt/homebrew/bin/frida
17.9.1
```

---

## Android device setup

### 1. Enable developer options

On the Android device:

1. Open **Settings**.
2. Go to **About phone**.
3. Tap **Build number** repeatedly until developer options are enabled.
4. Open **Developer options**.
5. Enable **USB debugging**.

### 2. Authorize USB debugging

Connect the device by USB, then run:

```bash
adb devices
```

Expected:

```text
List of devices attached
<serial>    device
```

If it says `unauthorized`, unlock the phone and accept the RSA debugging prompt.

### 3. Root requirement

Full Frida server control and protected file access require root, usually through Magisk or equivalent.

Test root:

```bash
adb shell su -c id
```

Expected:

```text
uid=0(root) gid=0(root) groups=0(root) ...
```

---

## Frida setup

### 1. Match frida-server to the local Frida version

All three should match:

```text
Python frida module version == local frida CLI version == Android frida-server version
```

Use the toolbox **Frida version** button to check this from the GUI, or check manually:

```bash
python -c "import frida; print(frida.__version__)"
frida --version
adb shell su -c "/data/local/tmp/frida-server --version"
```

### 2. Check Android CPU architecture

```bash
adb shell getprop ro.product.cpu.abi
```

Common values:

| ABI | frida-server build |
|---|---|
| `arm64-v8a` | Android arm64 |
| `armeabi-v7a` | Android arm |
| `x86_64` | Android x86_64 |

### 3. Push frida-server to the device

After downloading the matching `frida-server` binary for your Android ABI and local Frida version:

```bash
adb push frida-server /data/local/tmp/frida-server
adb shell su -c "chmod 755 /data/local/tmp/frida-server"
```

### 4. Start frida-server manually

```bash
adb shell su -c "setenforce 0"
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0 > /dev/null 2>&1 &"
```

Or use the GUI:

```text
Frida/ADB Control -> START SERVER
```

### 5. Confirm frida-server is running

```bash
adb shell su -c "ps -A | grep frida"
```

Expected example:

```text
root  14558  1  ...  S frida-server
```

---

## First run

Start the toolbox:

```bash
python UltimateForensicsToolbox.py
```

Recommended first steps:

1. Open **Frida/ADB Control**.
2. Click **Frida version**.
3. Confirm Python API, CLI, and Android server versions match.
4. Click **START SERVER** if the Android frida-server is not already running.
5. Open **Processes** and click **Refresh List**.
6. Select a target package.
7. Open **Frida Manager**.
8. Select either **Command Line / frida-tools** or **Python API / frida module**.
9. Paste a test script.
10. Click **FORGE & INJECT**.

---

## Frida injection modes

The Frida Manager tab includes a **Frida Engine** selector.

### Command Line / frida-tools mode

This mode launches the local `frida` CLI binary.

Behavior:

- Uses the configured CLI path, commonly `/opt/homebrew/bin/frida`.
- Injects with `frida -U -f <package> -l <temp_script.js>`.
- Captures CLI output and displays it as `[FRIDA]` log lines.
- Closely matches what works in Terminal.
- Good fallback if Python API mode has module/compiler/bridge issues.

Use this mode when:

- Terminal `frida -U -f package -l script.js` works.
- You want the most CLI-like behavior.
- Python API compiler or Java bridge setup is broken.

### Python API / frida module mode

This mode uses the Python `frida` package directly.

Behavior:

- Uses `frida.get_usb_device()`.
- Spawns the target app.
- Attaches to the spawned PID.
- Creates and loads a script through the Python API.
- Resumes the target app.
- Routes script messages into the PyQt Frida log view.
- Bridges `console.log`, `console.warn`, and `console.error` into UI messages.
- For Java scripts on Frida 17+, automatically compiles an agent using `frida-java-bridge`.

Use this mode when:

- You want everything controlled from Python.
- You want cleaner programmatic lifecycle control.
- The Python API, compiler, npm, and Java bridge package are installed correctly.

---

## Frida 17 Python API Java bridge notes

Frida 17 changed Java bridge behavior. In CLI mode, `Java` may be available automatically. In Python API mode, Java scripts need the `frida-java-bridge` package bundled into the agent.

The toolbox handles this by creating this folder on demand:

```text
~/.jpeixoto/UltimateForensicsToolbox/frida_api_agent_bridge
```

It creates a tiny npm project and installs:

```bash
npm install frida-java-bridge
```

Then it uses `frida.Compiler()` to compile the Python API Java agent.

### Test Java script

Use this as the first test:

```javascript
Java.perform(function() {
    console.log("Frida is hooked into Android " + Java.androidVersion);
});
```

Expected Python API output:

```text
[SYSTEM] Launching Frida Python API Engine for <package>...
[SYSTEM] Python frida module version: 17.9.1
[SYSTEM] Connected USB device: <device>
[SYSTEM] Spawned <package> with PID <pid>
[SYSTEM] Compiling Python API Java agent with frida-java-bridge...
[SYSTEM] Python API script loaded; message bridge armed. Resuming process now...
[SCRIPT] [UFT] Frida 17 API Java bridge imported from frida-java-bridge.
[SCRIPT] [UFT] Python API console bridge installed; console.log/warn/error will appear here.
[SCRIPT] [UFT] Java bridge is loaded and Java.available=true; running user script now.
[LOG] Frida is hooked into Android 16
```

---

## How to test the setup

### 1. ADB connectivity test

In the **ADB Console** tab, type:

```text
devices
```

Expected:

```text
<serial>    device
```

### 2. Frida server test

In **Frida/ADB Control**, click:

```text
Frida version
```

Expected:

```text
[FRIDA VERSION] Python API module: 17.9.1
[FRIDA VERSION] Local CLI/frida-tools: 17.9.1 (/opt/homebrew/bin/frida)
[FRIDA VERSION] Android frida-server: 17.9.1 (/data/local/tmp/frida-server)
[FRIDA VERSION] Versions appear aligned: 17.9.1
```

### 3. Process list test

Open **Processes**, click **Refresh List**, and verify installed apps are shown.

### 4. CLI Frida injection test

In **Frida Manager**:

1. Select **Command Line / frida-tools**.
2. Select a package.
3. Paste:

```javascript
Java.perform(function() {
    console.log("CLI Frida Java bridge active: " + Java.androidVersion);
});
```

Expected:

```text
[FRIDA] CLI Frida Java bridge active: 16
```

### 5. Python API Frida injection test

In **Frida Manager**:

1. Select **Python API / frida module**.
2. Select a package.
3. Paste:

```javascript
Java.perform(function() {
    console.log("Python API Frida Java bridge active: " + Java.androidVersion);
});
```

Expected:

```text
[LOG] Python API Frida Java bridge active: 16
```

### 6. Remote screen test

Open **Remote** and click:

```text
EMBEDDED STREAM
```

You should see the Android screen in the app.

### 7. Input injection test

Click/tap or drag/swipe on the embedded remote screen. The Android device should receive matching input events.

### 8. Scrcpy test

Open **Remote** and click:

```text
EXTERNAL TURBO
```

A scrcpy window should open.

---

## Feature guide

### 🔍 Processes tab

Purpose: discover installed/running Android apps and populate Frida targets.

Features:

- Refresh process/application list from the connected USB device.
- Search/filter package list.
- Click an app to populate the Frida target package field.
- Uses the Frida USB device application enumeration path.

### 🛠️ Frida Manager tab

Purpose: write, manage, beautify, and inject Frida scripts.

Features:

- Built-in JavaScript editor.
- Frida-specific syntax highlighting.
- Project/script tree under the toolbox workspace.
- New project creation.
- New script/folder context menu.
- Rename/delete script files.
- Save current script.
- Beautify JavaScript.
- Editable target package combo box.
- Engine selector:
  - Command Line / frida-tools.
  - Python API / frida module.
- Editable Frida CLI path.
- Auto-detect Frida CLI path.
- Forge/inject button.
- Stop/detach button.

### 💉 Frida Logs tab

Purpose: show Frida output from both CLI mode and Python API mode.

Features:

- Color-coded log categories.
- `[FRIDA]` and `[LOG]` share one color for runtime script output.
- `[SYSTEM]` uses a separate system color.
- `[SCRIPT]` uses a separate script/bridge color.
- `[ERROR]`, `[CRITICAL]`, and `[WARN]` use alert coloring.
- Checkbox category filters:
  - FRIDA / LOG.
  - SYSTEM.
  - SCRIPT.
  - ERROR / CRITICAL.
- Search field for live text filtering.
- Pause/resume viewer.
- Clear viewer and internal buffer.
- Rolling buffer of the last 5,000 Frida log entries.

### 🕵️ LogCat tab

Purpose: monitor Android Logcat from inside the toolbox.

Features:

- Real-time `adb logcat -v threadtime` stream.
- Priority selector:
  - Verbose.
  - Debug.
  - Info.
  - Warning.
  - Error.
  - Fatal.
- Text search.
- Hard filter option to hide non-matching lines.
- Pause/resume.
- Clear output.
- Priority-based color coding.

### 📁 File Explorer tab

Purpose: browse, preview, push, pull, rename, and delete files from the Android device.

Features:

- Path history.
- Quick paths:
  - `/`
  - `/sdcard`
  - `/sdcard/Download`
  - `/data/local/tmp`
- Folder filter.
- File/folder table with name, size, date/time, and permissions.
- Double-click folder navigation.
- Up button.
- Push file to current remote folder.
- Pull file to Mac.
- Rename remote file/folder.
- Delete remote file/folder.
- Preview first bytes/text of selected file.

### 📸 Gallery tab

Purpose: capture and manage screenshots.

Features:

- Snapshot capture through ADB.
- Local screenshot history.
- Previous/next image navigation.
- Delete current image.
- Clear all images.
- Double-click image to copy to clipboard and open configured portal flow.
- Scale percentage from Settings tab.

### 🔌 Frida/ADB Control tab

Purpose: common device-control, Frida-server, proxy, install, and app-management workflows.

Features:

#### Burp Proxy

- Set Android global HTTP proxy.
- Clear Android global HTTP proxy.
- Auto-fill local Mac IP with port `8080`.

#### Global Proxy Rotator / Frida Engine Proxy

- Country selector.
- Manual proxy input list.
- Auto-fallback on failed proxy validation.
- Proxy validation using HTTP/S request checks.
- Proxy cache/ranking.
- Edit raw proxy JSON file.
- Edit Frida proxy script template.
- Inject validated proxy into selected app through Frida.
- Remove proxy and detach script.

#### Deployment

- Browse APK or ZIP.
- Install standard APK.
- Install split APK bundles from ZIP using `adb install-multiple`.

#### App Control Center

- Refresh installed third-party apps.
- Refresh currently running apps.
- Launch selected app.
- Force-stop selected app.

#### ADB Arsenal

Default command buttons include:

- Reboot.
- Boot Frida.
- Kill Frida.
- Frida Running?.
- Frida version.
- Unlock.
- Top App.
- Apps.

Custom buttons can be added and stored in `commands.json`.

#### Frida Server Management

- Start frida-server.
- Stop frida-server.
- Set SELinux permissive before start.

### 📟 ADB Console tab

Purpose: run quick ADB commands without leaving the GUI.

Features:

- Editable command history.
- Auto-prefixes commands with the configured `adb` path unless you type a full `adb ...` command.
- Displays stdout/stderr in the console panel.
- Saves command history in the config file.

### 📱 Remote tab

Purpose: interact with the Android device from the desktop.

Features:

- Embedded stream using repeated `adb shell screencap -p`.
- External high-speed mirroring through `scrcpy`.
- Click/tap input injection.
- Drag/swipe input injection.
- Coordinate mapping from scaled preview to device screen coordinates.

### ⚙️ Settings tab

Purpose: general toolbox preferences.

Features:

- Screenshot clipboard scaling percentage.
- Persistent saved settings.

---

## Troubleshooting and diagnostics

### Quick diagnostic checklist

Run these first:

```bash
adb devices
python -c "import frida; print(frida.__version__)"
which frida
frida --version
adb shell su -c "/data/local/tmp/frida-server --version"
adb shell su -c "ps -A | grep frida"
```

Then click the GUI button:

```text
Frida/ADB Control -> Frida version
```

### Problem table

| Problem | Likely cause | Fix |
|---|---|---|
| `zsh: command not found: adb` | Android platform tools not installed or not in PATH | `brew install --cask android-platform-tools`, then reopen terminal |
| `adb devices` shows no device | Cable, USB mode, debugging disabled | Use data cable, enable USB debugging, reconnect, run `adb kill-server && adb start-server` |
| `adb devices` shows `unauthorized` | RSA prompt not accepted | Unlock phone, accept prompt, or revoke USB debugging authorizations and reconnect |
| `su: not found` or permission denied | Device is not rooted or root denied | Install/configure Magisk or grant shell root permission |
| `frida not found` in GUI | App cannot see CLI path | Set CLI path to `/opt/homebrew/bin/frida`, click Detect, or install `frida-tools` |
| CLI version line is blank or garbage | ANSI control-code parsing issue | Use current toolbox version; the version parser strips ANSI codes |
| Python API version differs from CLI | Python environment mismatch | Activate venv and run `pip install --upgrade frida frida-tools` |
| Android frida-server version differs | Wrong frida-server binary on device | Download/push frida-server matching local Frida version |
| `unable to connect to remote frida-server` | Server not running or blocked | Click START SERVER or run frida-server manually with root |
| `Address already in use` starting frida-server | frida-server already running | Kill it first: `adb shell su -c "pkill -9 frida-server"` |
| Python API says `ReferenceError: Java is not defined` | Frida 17 Java bridge package not bundled | Install Node/npm, use v7+ toolbox, allow `frida-java-bridge` install, or use CLI mode |
| Python API waits forever for Java bridge | Missing/broken `frida-java-bridge` or compiler | Click Frida version, confirm compiler/bridge status, run `cd ~/.jpeixoto/UltimateForensicsToolbox/frida_api_agent_bridge && npm install` |
| `frida.Compiler` missing | Frida Python module/tooling mismatch | `pip install --upgrade frida frida-tools`; use CLI mode until fixed |
| `npm: command not found` | Node/npm not installed | `brew install node` |
| `console.log()` not visible in Python API mode | Raw console output not routed to Python UI | Current toolbox bridges `console.log/warn/error` into `[LOG]/[WARN]/[ERROR]` messages |
| CLI works but Python API fails | API bridge/compiler issue | Use CLI mode, then diagnose Python API version/compiler/bridge status |
| App immediately crashes after injection | Hook timing or bad script | Test with minimal `Java.perform` script, then add hooks one at a time |
| `No frontmost app` or top app command fails | Android version output changed | Use package list/process list instead |
| Remote stream blank | ADB screencap failed or device locked | Unlock device, test `adb shell screencap -p > test.png` |
| Tap/swipe coordinates off | Device resolution assumption mismatch | Update remote coordinate mapping constants in code if needed |
| `scrcpy` not found | scrcpy missing or path different | `brew install scrcpy`, confirm `which scrcpy` |
| PyQt5 fails to start | Python/PyQt install issue | Reinstall venv, `pip install --force-reinstall PyQt5` |
| SOCKS proxy test fails | Missing SOCKS dependency | `pip install "requests[socks]"` |
| Manual proxy list empty | No matching country records | Edit `manual_proxies.json` or use the UI manual list commit button |

---

## Runtime folders and config files

The toolbox creates its runtime workspace here:

```text
~/.jpeixoto/UltimateForensicsToolbox
```

Important paths:

| Path | Purpose |
|---|---|
| `Global_Vault/` | Shared Frida scripts |
| `Projects/` | Project-specific Frida scripts |
| `Scrap/` | Captured screenshots |
| `commands.json` | Custom ADB Arsenal buttons |
| `config_DecryptCocoas.json` | GUI settings, command history, last target, Frida mode/path |
| `manual_proxies.json` | Manual proxy pool |
| `proxy_cache.json` | Proxy rank/cache data |
| `frida_proxy_template.js` | Frida proxy redirection template |
| `frida_api_agent_bridge/` | Frida 17 Python API Java bridge npm project |

### Reset app settings

To reset only GUI settings/history:

```bash
rm ~/.jpeixoto/UltimateForensicsToolbox/config_DecryptCocoas.json
```

### Reset Python API Java bridge package

```bash
rm -rf ~/.jpeixoto/UltimateForensicsToolbox/frida_api_agent_bridge
```

The toolbox will recreate it on the next Python API Java injection.

---

## Useful commands

### ADB basics

```bash
adb devices
adb kill-server
adb start-server
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.version.release
adb shell pm list packages -3
adb shell ps -A
```

### Frida server management

```bash
adb shell su -c "setenforce 0"
adb shell su -c "/data/local/tmp/frida-server -l 0.0.0.0 > /dev/null 2>&1 &"
adb shell su -c "ps -A | grep frida"
adb shell su -c "pkill -9 frida-server"
adb shell su -c "/data/local/tmp/frida-server --version"
```

### Local Frida checks

```bash
python -c "import frida; print(frida.__version__)"
which frida
frida --version
frida-ps -Uai
```

### Manual CLI injection test

```bash
frida -U -f com.example.app -l test.js
```

### Minimal Java Frida script

```javascript
Java.perform(function() {
    console.log("Frida Java bridge active on Android " + Java.androidVersion);
});
```

### Android global proxy

Set proxy:

```bash
adb shell settings put global http_proxy 192.168.1.10:8080
```

Clear proxy:

```bash
adb shell settings put global http_proxy :0
```

---

## Development notes

### Why two Frida engines exist

The toolbox supports both engines because they solve different real-world problems:

- CLI mode is closest to a known-working Terminal command and is excellent for troubleshooting.
- Python API mode gives the GUI full lifecycle control and better integration, but Frida 17+ requires explicit Java bridge bundling for Java hooks.

### Logging behavior

CLI output is displayed as `[FRIDA]`.

Python API script output is normalized as:

| Script call | UI category |
|---|---|
| `console.log(...)` | `[LOG]` |
| `console.warn(...)` | `[WARN]` |
| `console.error(...)` | `[ERROR]` |
| `send(...)` | `[SCRIPT]` |
| Internal lifecycle messages | `[SYSTEM]` |

The Frida Logs tab groups `[FRIDA]` and `[LOG]` together because both represent runtime script output.

### Current target package example

A package such as this can be used for testing if authorized on your device:

```text
com.google.android.youtube
```

Use the **Processes** tab to populate the target package safely instead of typing it manually.

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

Copyright (c) 2026 **Jason Peixoto**
