# 🕵️ Ultimate Forensics Toolbox

**Lead Developer:** Jason Peixoto

**Repository:** [https://github.com/jpeixoto/UltimateForensicsToolbox](https://www.google.com/search?q=https://github.com/jpeixoto/UltimateForensicsToolbox)

**Version:** 1.03 "Master"

A high-performance Android dynamic analysis and forensic extraction suite. This tool unifies Frida instrumentation, real-time Logcat analysis, and high-speed device mirroring into a single, professional PyQt5 interface.

----------

## 🚀 Installation & Setup

### 1. System Dependencies (macOS)

The toolbox relies on industry-standard binaries for device communication and mirroring. These must be installed via Homebrew:

Bash

```
# Install ADB (Android Debug Bridge)
brew install --cask android-platform-tools

# Install Scrcpy (High-speed Mirroring)
brew install scrcpy

```

### 2. Python Environment

It is recommended to use a virtual environment to avoid dependency conflicts.

Bash

```
# Create and activate venv
python3 -m venv .venv
source .venv/bin/activate

# Install requirements
pip install -r requirements.txt

```

### 3. Device Preparation

-   **Developer Options**: Enable **USB Debugging** on your Android device.
    
-   **Authorization**: Connect via USB and authorize the Mac's RSA fingerprint.
    
-   **Root Access**: Ensure Magisk or a similar root manager is installed for full forensic capabilities.
    
-   **SELinux Enforcement**: Use the **"Start Server"** button within the app to set the device to **Permissive** mode (`setenforce 0`).
    

----------

## 🛠 Features

### 📱 Remote Control & Interaction (Vysor Protocol)

-   **Zero-Footprint Streaming**: Features an embedded preview using raw memory piping via `screencap -p` to bypass the device's internal storage, maintaining forensic integrity by minimizing disk I/O.
    
-   **High-Speed Mirroring (Scrcpy)**: Integrated support for 60 FPS hardware-accelerated mirroring. The tool automatically handles ADB environment injection to ensure connectivity even from isolated virtual environments.
    
-   **Precision Coordinate Mapping**: A custom math engine translates Mac UI coordinates to the device's native resolution, allowing for pixel-perfect taps and complex swipe gestures.
    

### 💉 Advanced Frida Instrumentation

-   **Live Script Forging**: A built-in JavaScript IDE with specialized syntax highlighting for the Frida-Java bridge.
    
-   **Atomic Injection Engine**: Automatically detects package states to either **Attach** to existing PIDs or **Spawn** fresh instances for early-stage execution hooks.
    
-   **Beautifier**: Integrated `jsbeautifier` to instantly clean up messy or obfuscated forensic scripts for better readability.
    

### 🕵️ Forensic Logcat & System Analysis

-   **Real-time Streaming**: Continuous log capture with color-coded priority levels from Verbose (Gray) to Fatal (Red).
    
-   **Smart Filtering**: Search logs in real-time or use "Hard Filtering" to hide non-matching entries instantly.
    
-   **HID Logic Injection**: Simulates hardware keys (Home, Back, Recents) via `adb shell input` commands.
    

### 📁 Forensic File Explorer & Extraction

-   **Root-Level Navigation**: Integrated `su -c` wrappers allow navigation of protected `/data/data/` directories to extract SQLite databases and artifacts.
    
-   **On-the-Fly Previews**: Instant hex/text preview of files to identify headers before performing a full pull.
    
-   **Atomic Installation**: Specialized installer handling Split APKs and standard packages via `install-multiple`.
    

### 📸 Snap-to-Portal Workflow

-   **Clipboard Synchronization**: Automatically scales and copies screenshots to the Mac clipboard at user-defined percentages.
    
-   **Portal Automation**: Instantly launches a web browser to specified forensic portals, streamlining the evidence upload process.
    

----------

## 🧪 Testing the Setup

To verify your environment is ready, perform the following checklist:

1.  **ADB Connectivity**: Launch the app and check the **ADB Console** tab. Type `devices` and hit **SEND**. You should see your serial number.
    
2.  **Server Permissive Mode**: Go to the **Frida/ADB Control** tab and click **🚀 START SERVER**. This sets `setenforce 0` and launches the daemon.
    
3.  **Mirroring Test**: Go to the **Remote** tab and toggle **▶ EMBEDDED STREAM**. If you see your phone screen, the memory pipe is working.
    
4.  **Input Test**: Try swiping on the **Remote** tab image. If the phone screen moves, coordinate mapping and input injection are successful.
    

----------

## ⚖️ License

This project is licensed under the MIT License - see the `LICENSE` file for details.

Copyright (c) 2026 **Jason Peixoto**
