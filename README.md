# 🕵️ Ultimate Forensics Toolbox

**Lead Developer:** Jason Peixoto  
**Repository:** <https://github.com/jpeixoto/UltimateForensicsToolbox>  
**Current Version:** 1.10 "Device Status + Proxy Workspace + Full Frida Editor"  
**Platform:** macOS host + Android USB device  

Ultimate Forensics Toolbox is a PyQt5 Android dynamic-analysis, forensic extraction, Frida-instrumentation, Logcat, ADB, proxy, screenshot, and remote-control workstation. It is designed to keep the most common Android security-analysis tasks in one interface: device health checks, process discovery, Frida script editing/injection, Frida server control, Logcat viewing, ADB command execution, proxy import/validation/routing, remote file browsing, screenshots, app install/control, and device mirroring.

> Use this only on devices, applications, networks, and accounts that you own or have explicit authorization to test.

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
- [Proxy workspace](#proxy-workspace)
- [Troubleshooting and diagnostics](#troubleshooting-and-diagnostics)
- [Runtime folders and config files](#runtime-folders-and-config-files)
- [Useful commands](#useful-commands)
- [Development notes](#development-notes)
- [License](#license)

---

## What is included

### Core capabilities

- **Device Status dashboard** for ADB, root, SELinux, Frida, Android proxy, foreground app, and target app checks.
- Android ADB command console.
- Android package/process discovery.
- Full Frida script editor and injection manager.
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
- Full Frida script editor with:
  - Line numbers.
  - Search and replace.
  - Regex / whole-word / case-sensitive search.
  - Gutter markers for search hits.
  - Go-to-line.
  - Font zoom controls.
  - Save / Save As / Reload.
  - JavaScript syntax validation.
  - Frida 17 migration warnings.
- Color-coded Frida log viewer with checkbox category filters, search, font sizing, and error double-click jump-to-line.
- Buffered Logcat viewer with non-destructive filtering, level checkboxes, search, export, font controls, and freeze-safe batched rendering.
- Dedicated **Proxy** workspace tab:
  - Multi-source proxy import.
  - Merge/deduplicate into `manual_proxies.json`.
  - Clear list and reimport all sources.
  - Country/protocol counts.
  - HTTP/SOCKS-aware validation.
  - Android global proxy mode.
  - Frida Java property proxy hook mode.
  - Backup/restore/recover tools.
- ADB file explorer with push, pull, delete, rename, folder navigation, auto-sized columns, and preview.
- Embedded remote screen stream using `adb shell screencap -p`.
- Optional high-speed external mirroring with `scrcpy`.
- Remote tap and swipe injection from the preview window.
- Screenshot capture, local gallery, clipboard copy, and portal workflow.
- APK and split APK deployment.
- App launch/kill controls.
- Burp/local proxy helper.
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
| Frida CLI/frida-tools runtime | `17.9.1` at `/opt/homebrew/bin/frida` |
| Recommended `frida-tools` package | `14.8.2` |
| Android frida-server | `17.9.1` at `/data/local/tmp/frida-server` |
| Android test device | Pixel 9a |
| Android test version | Android 16 |
| App title | `Ultimate Forensics Toolbox V1.10 - Jason Peixoto.` |

The exact device can vary, but the **Frida Python module**, **Frida CLI runtime**, and **Android frida-server** should match.

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

Recommended requirements:

```text
PyQt5==5.15.10
frida==17.9.1
frida-tools==14.8.2
jsbeautifier==1.14.11
requests==2.32.3
PySocks
```

If installing manually:

```bash
pip install PyQt5==5.15.10 frida==17.9.1 frida-tools==14.8.2 jsbeautifier==1.14.11 requests==2.32.3 PySocks
```

Package purpose:

| Package | Purpose |
|---|---|
| `PyQt5` | Desktop GUI |
| `frida` | Python API injection engine |
| `frida-tools` | CLI `frida` command and related tooling |
| `jsbeautifier` | JavaScript formatter for Frida scripts |
| `requests` | Proxy validation/import HTTP testing |
| `PySocks` / `requests[socks]` | SOCKS proxy validation support |

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

### 1. Match frida-server to the local Frida runtime version

All three runtime versions should match:

```text
Python frida module version == local frida CLI runtime == Android frida-server version
```

Use the toolbox **Frida Versions** button from **Device Status** or **Frida/ADB Control**, or check manually:

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
Device Status -> Start Frida Server
```

or:

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

1. Open **Device Status**.
2. Click **Refresh Status**.
3. Confirm ADB, root, SELinux, Frida server, Frida versions, and Android proxy state.
4. Click **Start Frida Server** if the Android frida-server is not already running.
5. Open **Processes** and click **Refresh List**.
6. Select a target package.
7. Open **Frida Manager**.
8. Select either **Command Line / frida-tools** or **Python API / frida module**.
9. Paste a test script.
10. Click **Validate**.
11. Click **FORGE & INJECT**.

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

### 1. Device Status test

Open **Device Status** and click:

```text
Refresh Status
```

Verify:

- ADB found.
- Device connected.
- Root available.
- SELinux state shown.
- frida-server running.
- Frida versions match.
- Android global proxy state shown.

### 2. ADB connectivity test

In the **ADB Console** tab, type:

```text
devices
```

Expected:

```text
<serial>    device
```

### 3. Frida server test

In **Device Status** or **Frida/ADB Control**, click:

```text
Frida Versions
```

Expected:

```text
[FRIDA VERSION] Python API module: 17.9.1
[FRIDA VERSION] Local CLI/frida-tools: 17.9.1 (/opt/homebrew/bin/frida)
[FRIDA VERSION] Android frida-server: 17.9.1 (/data/local/tmp/frida-server)
[FRIDA VERSION] Versions appear aligned: 17.9.1
```

### 4. Process list test

Open **Processes**, click **Refresh List**, and verify installed apps are shown.

### 5. CLI Frida injection test

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

### 6. Python API Frida injection test

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

### 7. Remote screen test

Open **Remote** and click:

```text
EMBEDDED STREAM
```

You should see the Android screen in the app.

### 8. Input injection test

Click/tap or drag/swipe on the embedded remote screen. The Android device should receive matching input events.

### 9. Scrcpy test

Open **Remote** and click:

```text
EXTERNAL TURBO
```

A scrcpy window should open.

---

## Feature guide

### 🩺 Device Status tab

Purpose: quickly confirm that the host, Android device, root, Frida, and proxy environment are ready.

Features:

- Refresh status manually.
- Optional auto refresh with configurable interval.
- Copy a full diagnostic report to clipboard.
- Quick actions:
  - Frida Versions.
  - Start Frida Server.
  - Stop Frida Server.
  - Clear Android Proxy.
- Checks:
  - ADB path.
  - Python Frida version.
  - Local Frida CLI version.
  - Connected device.
  - Android model/version.
  - Battery.
  - Root.
  - SELinux.
  - frida-server process.
  - frida-server version.
  - Android global proxy state.
  - Foreground app.
  - Target app installed/running.

### 🔍 Processes tab

Purpose: discover installed/running Android apps and populate Frida targets.

Features:

- Refresh process/application list from the connected USB device.
- Search/filter package list.
- Click an app to populate the Frida target package field.
- Uses the Frida USB device application enumeration path.

### 🛠️ Frida Manager tab

Purpose: write, manage, validate, beautify, and inject Frida scripts.

Script folder:

```text
~/.jpeixoto/UltimateForensicsToolbox/FridaScripts
```

Editor features:

- `.js` file/folder browser.
- Line-number gutter.
- Current line highlight.
- Search-hit gutter highlighting.
- Find next / previous.
- Replace one / replace all.
- Regex / whole-word / case-sensitive search.
- Go to line.
- Save / Save As / Reload.
- JavaScript beautifier.
- Font size controls and shortcuts.
- Script validation with `node --check`.
- Frida 17 API migration warnings.

Frida controls:

- Engine selector:
  - Command Line / frida-tools.
  - Python API / frida module.
- Editable Frida CLI path.
- Auto-detect Frida CLI path.
- Editable target package combo box.
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
- Font size controls.
- Double-click error stack location to jump to the editor line/column when possible.

### 🕵️ LogCat tab

Purpose: monitor Android Logcat from inside the toolbox.

Features:

- Real-time `adb logcat -v threadtime` stream.
- Buffered capture model.
- Non-destructive filters.
- Minimum visible priority selector:
  - Verbose.
  - Debug.
  - Info.
  - Warning.
  - Error.
  - Fatal.
- Per-level checkboxes.
- Search.
- Hard filter option to hide non-matching lines.
- Pause Display without stopping capture.
- Auto-scroll toggle.
- Export visible logs.
- Configurable buffer size.
- Batched UI rendering to reduce freezes.
- Font size controls.

### 🌐 Proxy tab

Purpose: manage proxy sources, proxy pool records, validation, and Android/Frida routing.

Main areas:

- Proxy Source Import.
- Proxy Router / Validator.
- Android Global Proxy tools.
- Country proxy pool editor.
- Backup / restore / recover tools.
- Status table and proxy log.

See [Proxy workspace](#proxy-workspace) for details.

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
- Auto-sized columns.
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

Purpose: device-control, Frida-server, APK install, and app-management workflows.

Features:

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
- Font size controls.

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

## Proxy workspace

### Proxy Source Import

The Proxy tab can import one or more public proxy lists, normalize them, and merge them into the toolbox format.

Features:

- Select one or more sources.
- Select all / none.
- HTTP-only / SOCKS-only source shortcuts.
- Import selected / merge.
- Import all / merge.
- Clear list + import all.
- Backup before destructive operations.
- Open proxy JSON.
- Import status table:
  - Source.
  - Status.
  - Raw.
  - Normalized.
  - Unique.
  - Skipped/Error.

Duplicate detection uses:

```text
protocol + ip + port
```

If a source does not include country metadata, imported records are assigned to:

```text
UNKNOWN
```

### Proxy JSON format

Proxy records are normalized into this general shape:

```json
{
  "proxy": "http://1.2.3.4:8080",
  "protocol": "http",
  "ip": "1.2.3.4",
  "port": 8080,
  "https": false,
  "anonymity": "unknown",
  "score": 1,
  "geolocation": {
    "country": "UNITED STATES",
    "city": "Unknown"
  }
}
```

Supported protocol values:

```text
http
https
socks
socks4
socks5
```

Plain `host:port` entries are treated as HTTP.

### Proxy Router / Validator

The validator supports:

- Target country dropdown with counts.
- HTTP/HTTPS proxies always included.
- Optional SOCKS proxies checkbox.
- Timeout control.
- Auto-fallback across a country pool.
- Failure reason details:
  - Node dropped.
  - Connection refused.
  - Connection reset.
  - Proxy error.
  - SSL error.
  - Bad response.
  - Timeout.
- Egress IP check.
- Rank/cache updates.

### Routing modes

| Mode | What it does | Best for |
|---|---|---|
| Frida Java Property Hook | Hooks Java `System.getProperty()` inside one app process | Java networking stacks |
| Android Global Proxy | Sets Android device-wide `http_proxy` through ADB | Device-wide HTTP proxy testing |
| Android Global Only | Validate and apply global proxy without Frida injection | Browser/system proxy checks |
| Proxy Tester Only | Validate proxies without changing device or Mac proxy settings | Cleaning/ranking lists |

Important notes:

- Frida Java property hooks do not guarantee that native network stacks will use the proxy.
- Android global `http_proxy` supports HTTP-style proxy settings, not SOCKS directly.
- Proxy validation uses an isolated Python `requests.Session()` and does not modify macOS proxy settings.

### Frida proxy template placeholders

The Frida proxy template supports:

```text
{protocol}
{ip}
{port}
```

Template path:

```text
~/.jpeixoto/UltimateForensicsToolbox/frida_proxy_template.js
```

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
Device Status -> Frida Versions
```

### Problem table

| Problem | Likely cause | Fix |
|---|---|---|
| `zsh: command not found: adb` | Android platform tools not installed or not in PATH | `brew install --cask android-platform-tools`, then reopen terminal |
| `adb devices` shows no device | Cable, USB mode, debugging disabled | Use data cable, enable USB debugging, reconnect, run `adb kill-server && adb start-server` |
| `adb devices` shows `unauthorized` | RSA prompt not accepted | Unlock phone, accept prompt, or revoke USB debugging authorizations and reconnect |
| `su: not found` or permission denied | Device is not rooted or root denied | Install/configure Magisk or grant shell root permission |
| `frida not found` in GUI | App cannot see CLI path | Set CLI path to `/opt/homebrew/bin/frida`, click Detect, or install `frida-tools` |
| Python API version differs from CLI | Python environment mismatch | Activate venv and run `pip install --upgrade frida frida-tools` |
| Android frida-server version differs | Wrong frida-server binary on device | Download/push frida-server matching local Frida version |
| `unable to connect to remote frida-server` | Server not running or blocked | Click START SERVER or run frida-server manually with root |
| `Address already in use` starting frida-server | frida-server already running | Kill it first: `adb shell su -c "pkill -9 frida-server"` |
| Python API says `ReferenceError: Java is not defined` | Frida 17 Java bridge package not bundled | Install Node/npm, use Python API bridge support, or use CLI mode |
| Python API waits forever for Java bridge | Missing/broken `frida-java-bridge` or compiler | Click Frida Versions, confirm compiler/bridge status, rerun npm install in the bridge folder |
| `frida.Compiler` missing | Frida Python module/tooling mismatch | `pip install --upgrade frida frida-tools`; use CLI mode until fixed |
| `npm: command not found` | Node/npm not installed | `brew install node` |
| `console.log()` not visible in Python API mode | Raw console output not routed to Python UI | Current toolbox bridges `console.log/warn/error` into `[LOG]/[WARN]/[ERROR]` |
| CLI works but Python API fails | API bridge/compiler issue | Use CLI mode, then diagnose Python API version/compiler/bridge status |
| App immediately crashes after injection | Hook timing or bad script | Test with minimal `Java.perform` script, then add hooks one at a time |
| Remote stream blank | ADB screencap failed or device locked | Unlock device, test `adb shell screencap -p > test.png` |
| Tap/swipe coordinates off | Device resolution assumption mismatch | Update remote coordinate mapping constants in code if needed |
| `scrcpy` not found | scrcpy missing or path different | `brew install scrcpy`, confirm `which scrcpy` |
| PyQt5 fails to start | Python/PyQt install issue | Reinstall venv, `pip install --force-reinstall PyQt5` |
| SOCKS proxy test fails | Missing SOCKS dependency | `pip install PySocks` |
| Proxy imports but country count does not change | Source lacks geolocation | Entries are imported as `UNKNOWN` |
| Proxy validates but target still shows local IP | App bypasses Java proxy or Android global proxy not applied | Use Android Global Proxy mode, force-stop/relaunch target, verify `settings get global http_proxy` |

---

## Runtime folders and config files

The toolbox creates its runtime workspace here:

```text
~/.jpeixoto/UltimateForensicsToolbox
```

Important paths:

| Path | Purpose |
|---|---|
| `FridaScripts/` | User Frida script library |
| `Scrap/` | Captured screenshots |
| `commands.json` | Custom ADB Arsenal buttons |
| `config_DecryptCocoas.json` | GUI settings, command history, last target, Frida mode/path |
| `manual_proxies.json` | Proxy pool |
| `proxy_cache.json` | Proxy rank/cache data |
| `proxy_backups/` | Proxy backups |
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

Check proxy:

```bash
adb shell settings get global http_proxy
```

Clear proxy:

```bash
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy
```

---

## Development notes

### Why two Frida engines exist

The toolbox supports both engines because they solve different real-world problems:

- CLI mode is closest to a known-working Terminal command and is excellent for troubleshooting.
- Python API mode gives the GUI full lifecycle control and better integration, but Frida 17+ requires explicit Java bridge bundling for Java hooks.

### Frida 17 migration reminders

Older scripts may fail with:

```text
TypeError: not a function
```

Common updates:

```javascript
// Old
Module.findExportByName("libc.so", "fwrite");

// New
Process.getModuleByName("libc.so").findExportByName("fwrite");
```

```javascript
// Old
Memory.readCString(args[1]);

// New
args[1].readCString();
```

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

---

## License

This project is licensed under the MIT License. See `LICENSE` for details.

Copyright (c) 2026 **Jason Peixoto**
