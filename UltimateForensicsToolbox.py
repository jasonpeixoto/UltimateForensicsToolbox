import sys
import os
import frida
import subprocess
import shutil
import socket
import jsbeautifier
import time
import json
import re
import html
import zipfile
import tempfile
import requests  # Retained for proxy validation connection handshakes
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QTextEdit, QListWidget, QLabel,
                             QTabWidget, QHeaderView, QFrame, QLineEdit,
                             QMessageBox, QListWidgetItem, QGridLayout, QGroupBox,
                             QInputDialog, QTreeView, QFileSystemModel, QProxyStyle,
                             QStyle, QComboBox, QCompleter, QSpinBox, QMenu, QCheckBox,
                             QFileDialog, QSplitter, QSystemTrayIcon, QAction,
                             QSizePolicy, QDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRegExp, QProcess, QDir, QSize, QModelIndex, QTimer
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QPixmap, QImage, QTextCursor, QIcon

# --- SYSTEM SETTINGS ---
BASE_DIR = os.path.expanduser("~/.jpeixoto/UltimateForensicsToolbox")
VAULT_DIR, PROJECTS_DIR, SCRAP_DIR = [os.path.join(BASE_DIR, x) for x in ["Global_Vault", "Projects", "Scrap"]]
CMD_FILE = os.path.join(BASE_DIR, "commands.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config_DecryptCocoas.json")
MANUAL_PROXY_FILE = os.path.join(BASE_DIR, "manual_proxies.json")
FRIDA_TEMPLATE_FILE = os.path.join(BASE_DIR, "frida_proxy_template.js")

for d in [BASE_DIR, VAULT_DIR, PROJECTS_DIR, SCRAP_DIR]:
    os.makedirs(d, exist_ok=True)

ADB_PATH = shutil.which("adb") or "/usr/local/bin/adb"
FRIDA_CLI_PATH = shutil.which("frida") or "/opt/homebrew/bin/frida"
FRIDA_INJECTION_MODE_CLI = "cli"
FRIDA_INJECTION_MODE_PYTHON = "python_api"
FRIDA_API_AGENT_DIR = os.path.join(BASE_DIR, "frida_api_agent_bridge")


class DepressStyle(QProxyStyle):
    def pixelMetric(self, metric, option=None, widget=None):
        if metric in [QStyle.PM_ButtonShiftHorizontal, QStyle.PM_ButtonShiftVertical]: return 3
        return super().pixelMetric(metric, option, widget)


# --- GLOBAL COUNTRY DICTIONARY DEFINITION ---
GLOBAL_COUNTRY_MAP = {
    "AF": "AFGHANISTAN", "AX": "ALAND ISLANDS", "AL": "ALBANIA", "DZ": "ALGERIA", "AS": "AMERICAN SAMOA",
    "AD": "ANDORRA", "AO": "ANGOLA", "AI": "ANGUILLA", "AQ": "ANTARCTICA", "AG": "ANTIGUA AND BARBUDA",
    "AR": "ARGENTINA", "AM": "ARMENIA", "AW": "ARUBA", "AU": "AUSTRALIA", "AT": "AUSTRIA", "AZ": "AZERBAIJAN",
    "BS": "BAHAMAS", "BH": "BAHRAIN", "BD": "BANGLADESH", "BB": "BARBADOS", "BY": "BELARUS", "BE": "BELGIUM",
    "BZ": "BELIZE", "BJ": "BENIN", "BM": "BERMUDA", "BT": "BHUTAN", "BO": "BOLIVIA", "BA": "BOSNIA AND HERZEGOVINA",
    "BW": "BOTSWANA", "BV": "BOUVET ISLAND", "BR": "BRAZIL", "IO": "BRITISH INDIAN OCEAN TERRITORY",
    "BN": "BRUNEI DARUSSALAM", "BG": "BULGARIA", "BF": "BURKINA FASO", "BI": "BURUNDI", "KH": "CAMBODIA",
    "CM": "CAMEROON", "CA": "CANADA", "CV": "CAPE VERDE", "KY": "CAYMAN ISLANDS", "CF": "CENTRAL AFRICAN REPUBLIC",
    "TD": "CHAD", "CL": "CHILE", "CN": "CHINA", "CX": "CHRISTMAS ISLAND", "CC": "COCOS (KEELING) ISLANDS",
    "CO": "COLOMBIA", "KM": "COMOROS", "CG": "CONGO", "CD": "CONGO, THE DEMOCRATIC REPUBLIC OF THE",
    "CK": "COOK ISLANDS", "CR": "COSTA RICA", "CI": "COTE D'IVOIRE", "HR": "CROATIA", "CU": "CUBA",
    "CY": "CYPRUS", "CZ": "CZECH REPUBLIC", "DK": "DENMARK", "DJ": "DJIBOUTI", "DM": "DOMINICA",
    "DO": "DOMINICAN REPUBLIC", "EC": "ECUADOR", "EG": "EGYPT", "SV": "EL SALVADOR", "GQ": "EQUATORIAL GUINEA",
    "ER": "ERITREA", "EE": "ESTONIA", "ET": "ETHIOPIA", "FK": "FALKLAND ISLANDS (MALVINAS)", "FO": "FAROE ISLANDS",
    "FJ": "FIJI", "FI": "FINLAND", "FR": "FRANCE", "GP": "GUADELOUPE", "GU": "GUAM", "GT": "GUATEMALA",
    "GG": "GUERNSEY", "GN": "GUINEA", "GW": "GUINEA-BISSAU", "GY": "GUYANA", "HT": "HAITI", "HK": "HONG KONG",
    "HU": "HUNGARY", "IS": "ICELAND", "IN": "INDIA", "ID": "INDONESIA", "IR": "IRAN", "IQ": "IRAQ",
    "IE": "IRELAND", "IM": "ISLE OF MAN", "IL": "ISRAEL", "IT": "ITALY", "JM": "JAMAICA", "JP": "JAPAN",
    "JE": "JERSEY", "JO": "JORDAN", "KZ": "KAZAKHSTAN", "KE": "KENYA", "KI": "KIRIBATI", "KW": "KUWAIT",
    "KG": "KYRGYZSTAN", "LV": "LATVIA", "LB": "LEBANON", "LS": "LESOTHO", "LR": "LIBERIA", "LY": "LIBYA",
    "LI": "LIECHTENSTEIN", "LT": "LITHUANIA", "LU": "LUXEMBOURG", "MO": "MACAO", "MG": "MADAGASCAR",
    "MW": "MALAWI", "MY": "MALAYSIA", "MV": "MALDIVES", "ML": "MALI", "MT": "MALTA", "MX": "MEXICO",
    "MD": "MOLDOVA", "MC": "MONACO", "MN": "MONGOLIA", "ME": "MONTENEGRO", "MA": "MOROCCO", "MZ": "MOZAMBIQUE",
    "MM": "MYANMAR", "NA": "NAMIBIA", "NP": "NEPAL", "NL": "NETHERLANDS", "NZ": "NEW ZEALAND", "NI": "NICARAGUA",
    "NE": "NIGER", "NG": "NIGERIA", "NO": "NORWAY", "OM": "OMAN", "PK": "PAKISTAN", "PW": "PALAU",
    "PA": "PANAMA", "PG": "PAPUA NEW GUINEA", "PY": "PARAGUAY", "PE": "PERU", "PH": "PHILIPPINES",
    "PL": "POLAND", "PT": "PORTUGAL", "PR": "PUERTO RICO", "QA": "QATAR", "RO": "ROMANIA", "RU": "RUSSIA",
    "RW": "RWANDA", "SA": "SAUDI ARABIA", "SN": "SENEGAL", "RS": "SERBIA", "SC": "SEYCHELLES",
    "SG": "SINGAPORE", "SK": "SLOVAKIA", "SI": "SLOVENIA", "ZA": "SOUTH AFRICA", "ES": "SPAIN",
    "LK": "SRI LANKA", "SD": "SUDAN", "SE": "SWEDEN", "CH": "SWITZERLAND", "SY": "SYRIA", "TW": "TAIWAN",
    "TJ": "TAJIKISTAN", "TZ": "TANZANIA", "TH": "THAILAND", "TR": "TURKEY", "TM": "TURKMENISTAN",
    "UG": "UGANDA", "UA": "UKRAINE", "AE": "UNITED ARAB EMIRATES", "GB": "UNITED KINGDOM", "US": "UNITED STATES",
    "UY": "URUGUAY", "UZ": "UZBEKISTAN", "VE": "VENEZUELA", "VN": "VIETNAM", "YE": "YEMEN", "ZM": "ZAMBIA",
    "ZW": "ZIMBABWE"
}


# --- WORKER THREADS ---

class ProxyTesterWorker(QThread):
    status_signal = pyqtSignal(str, str)
    proxy_found_signal = pyqtSignal(str, str)

    def __init__(self, country_code, auto_fallback):
        super().__init__()
        self.country_code = str(country_code).upper().strip() if country_code else "IN"
        self.auto_fallback = auto_fallback
        self.running = True
        self.cache_file = os.path.join(BASE_DIR, "proxy_cache.json")

    def load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    return json.load(f)
            except:
                pass
        return {}

    def save_cache(self, cache):
        try:
            with open(self.cache_file, "w") as f:
                json.dump(cache, f, indent=4)
        except Exception as e:
            self.status_signal.emit("WARN", f"Cache save failure: {str(e)}")

    def load_manual_proxies(self):
        if os.path.exists(MANUAL_PROXY_FILE):
            try:
                with open(MANUAL_PROXY_FILE, "r") as f:
                    return json.load(f)
            except Exception as e:
                self.status_signal.emit("ERROR", f"Failed to parse manual proxy file: {str(e)}")
        return []

    def run(self):
        cache = self.load_cache()
        country_pool = []

        self.status_signal.emit("INFO", f"Loading local file array for [{self.country_code}]...")
        target_full_name = GLOBAL_COUNTRY_MAP.get(self.country_code, "")

        manual_data = self.load_manual_proxies()
        if isinstance(manual_data, list):
            for item in manual_data:
                geo_block = item.get("geolocation")
                c_code = ""

                if isinstance(geo_block, dict):
                    c_code = str(geo_block.get("country", "")).upper().strip()

                if not c_code:
                    c_code = str(item.get("country", "")).upper().strip()

                # Robust validation logic handles short ISO abbreviations and long form strings seamlessly
                if c_code == self.country_code or (target_full_name and target_full_name in c_code):
                    ip_val = item.get("ip")
                    port_val = str(item.get("port")) if item.get("port") is not None else ""
                    proto = str(item.get("protocol", "http")).lower().strip()

                    if ip_val and port_val:
                        historical_rank = 0
                        cached_nodes = cache.get(self.country_code, [])
                        for cn in cached_nodes:
                            if cn.get("ip") == ip_val and str(cn.get("port")) == port_val:
                                historical_rank = cn.get("rank", 0)
                                break

                        country_pool.append(
                            {"ip": ip_val, "port": port_val, "rank": historical_rank, "protocol": proto})

        if not country_pool:
            self.status_signal.emit("CRITICAL",
                                    f"No records matching country [{self.country_code}] found inside your manual_proxies.json file.")
            return

        country_pool.sort(key=lambda x: x.get("rank", 0), reverse=True)
        self.status_signal.emit("INFO",
                                f"Pool targeted with {len(country_pool)} local nodes. Beginning verification sweep...")

        for idx, node in enumerate(country_pool):
            if not self.running: break

            ip, port = node["ip"], str(node["port"])
            proto = node.get("protocol", "http")
            self.status_signal.emit("TESTING",
                                    f"[{idx + 1}/{len(country_pool)}] Handshake target -> {ip}:{port} (Rank: {node.get('rank', 0)})")

            try:
                proxy_url = f"{proto}://{ip}:{port}" if "socks" in proto else f"http://{ip}:{port}"
                test_proxies = {"http": proxy_url, "https": proxy_url}
                test_res = requests.get("https://www.google.com", proxies=test_proxies, timeout=3)

                if test_res.status_code == 200:
                    self.status_signal.emit("SUCCESS", f"Validated active pipeline path: {ip}:{port}!")
                    node["rank"] = node.get("rank", 0) + 1

                    if self.country_code not in cache: cache[self.country_code] = []
                    existing = next((x for x in cache[self.country_code] if x["ip"] == ip and str(x["port"]) == port),
                                    None)
                    if existing:
                        existing["rank"] = node["rank"]
                    else:
                        cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"]})

                    self.save_cache(cache)
                    self.proxy_found_signal.emit(ip, port)
                    return

            except Exception:
                node["rank"] = node.get("rank", 0) - 5
                if self.country_code not in cache: cache[self.country_code] = []
                existing = next((x for x in cache[self.country_code] if x["ip"] == ip and str(x["port"]) == port), None)
                if existing:
                    existing["rank"] = node["rank"]
                else:
                    cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"]})
                self.save_cache(cache)

                if self.auto_fallback:
                    self.status_signal.emit("WARN", "Node dropped or timed out. Moving to next baseline option...")
                    continue
                else:
                    self.status_signal.emit("ERROR", f"Connection dropped on test candidate: {ip}:{port}")
                    return

        self.status_signal.emit("CRITICAL", "Validation matrix exhausted. Zero candidate responses logged.")

    def stop(self):
        self.running = False


class LogcatWorker(QThread):
    new_log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        process = subprocess.Popen([ADB_PATH, "logcat", "-v", "threadtime"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while self.running:
            line = process.stdout.readline()
            if line:
                self.new_log_signal.emit(line.strip())
            else:
                break
        process.terminate()

    def stop(self):
        self.running = False


class FridaWorker(QThread):
    log_signal = pyqtSignal(str, str)

    def __init__(self, pkg, code, injection_mode=FRIDA_INJECTION_MODE_CLI, frida_bin=None):
        super().__init__()
        self.pkg = str(pkg).strip()
        self.code = code or ""
        self.injection_mode = injection_mode or FRIDA_INJECTION_MODE_CLI
        self.frida_bin = frida_bin or FRIDA_CLI_PATH
        self.session = None
        self.script = None
        self.process = None
        self.device = None
        self.spawned_pid = None

    def on_message(self, message, data):
        mtype = message.get('type')
        if mtype == 'send':
            payload = message.get('payload')
            if isinstance(payload, dict):
                ptype = str(payload.get('type', '')).lower()
                level = str(payload.get('level', '')).upper()
                text = payload.get('text', payload.get('message', payload))

                if ptype == 'console':
                    label = level if level else 'CONSOLE'
                    self.log_signal.emit(label, str(text))
                    return
                if ptype == 'system':
                    self.log_signal.emit('SCRIPT', str(text))
                    return
                if ptype == 'error':
                    self.log_signal.emit('ERROR', str(text))
                    return

            self.log_signal.emit("SCRIPT", str(payload))
        elif mtype == 'log':
            self.log_signal.emit("LOG", str(message.get('payload')))
        elif mtype == 'error':
            desc = message.get('description') or message.get('stack') or str(message)
            self.log_signal.emit("ERROR", str(desc))
        else:
            self.log_signal.emit("MESSAGE", str(message))

    def _wrap_script_for_python_api(self, user_code):
        """
        Build the JavaScript payload used by Python API mode.

        Frida 17 changed the Java bridge behavior: scripts loaded through API bindings
        must explicitly import/bundle frida-java-bridge, while the Frida CLI/REPL still
        bundles the bridge for compatibility. This method keeps the user's script simple
        and adds only our logging/wait wrapper.
        """
        user_code = user_code or ""

        console_bridge = r"""
(function () {
    var __uftOriginalConsole = (typeof console !== 'undefined') ? console : {};
    var __uftGlobal = (typeof globalThis !== 'undefined') ? globalThis : (function () { return this; })();

    function __uftStringify(value) {
        try {
            if (value === null) return 'null';
            if (value === undefined) return 'undefined';
            if (typeof value === 'string') return value;
            if (typeof value === 'number' || typeof value === 'boolean') return String(value);
            if (value && value.toString && value.toString !== Object.prototype.toString) return value.toString();
            return JSON.stringify(value);
        } catch (e) {
            try { return String(value); } catch (_) { return '<unprintable>'; }
        }
    }

    function __uftEmitConsole(level, args) {
        var parts = [];
        for (var i = 0; i < args.length; i++) {
            parts.push(__uftStringify(args[i]));
        }
        send({ type: 'console', level: level, text: parts.join(' ') });
    }

    if (typeof console === 'undefined') {
        __uftGlobal.console = {};
    }

    var __uftLog = __uftOriginalConsole.log;
    var __uftWarn = __uftOriginalConsole.warn;
    var __uftError = __uftOriginalConsole.error;

    console.log = function () {
        __uftEmitConsole('LOG', arguments);
        if (__uftLog) { try { __uftLog.apply(__uftOriginalConsole, arguments); } catch (_) {} }
    };

    console.warn = function () {
        __uftEmitConsole('WARN', arguments);
        if (__uftWarn) { try { __uftWarn.apply(__uftOriginalConsole, arguments); } catch (_) {} }
    };

    console.error = function () {
        __uftEmitConsole('ERROR', arguments);
        if (__uftError) { try { __uftError.apply(__uftOriginalConsole, arguments); } catch (_) {} }
    };

    send({ type: 'system', text: '[UFT] Python API console bridge installed; console.log/warn/error will appear here.' });
})();
"""

        needs_java_bridge = re.search(r'\bJava\b', user_code) is not None

        if not needs_java_bridge:
            return console_bridge + r"""
(function () {
    try {
""" + user_code + r"""
    } catch (e) {
        send({ type: 'error', text: '[UFT] User script exception: ' + (e.stack || e.message || e) });
    }
})();
"""

        java_wait_wrapper_start = r"""
(function () {
    var __uftUserScriptStarted = false;
    var __uftJavaWaitTimer = null;
    var __uftJavaWaitTicks = 0;

    function __uftIsJavaReady() {
        try {
            return (typeof Java !== 'undefined') && Java && Java.available === true;
        } catch (_) {
            return false;
        }
    }

    function __uftRunUserScript() {
        if (__uftUserScriptStarted) return;
        __uftUserScriptStarted = true;
        send({ type: 'system', text: '[UFT] Java bridge is loaded and Java.available=true; running user script now.' });
        try {
            __uftUserMain();
        } catch (e) {
            send({ type: 'error', text: '[UFT] User script exception: ' + (e.stack || e.message || e) });
        }
    }

    function __uftUserMain() {
"""

        java_wait_wrapper_end = r"""
    }

    if (__uftIsJavaReady()) {
        __uftRunUserScript();
    } else {
        send({ type: 'system', text: '[UFT] Waiting for Frida Java bridge / Java VM. In Frida 17 API mode this requires the bundled frida-java-bridge agent.' });
        __uftJavaWaitTimer = setInterval(function () {
            __uftJavaWaitTicks += 1;
            if (__uftIsJavaReady()) {
                clearInterval(__uftJavaWaitTimer);
                __uftRunUserScript();
            } else if ((__uftJavaWaitTicks % 50) === 0) {
                var hasBridge = (typeof Java !== 'undefined');
                var available = false;
                try { available = hasBridge && Java.available === true; } catch (_) {}
                send({ type: 'system', text: '[UFT] Still waiting for Java bridge / VM... bridge=' + hasBridge + ', Java.available=' + available });
            }
        }, 100);
    }
})();
"""
        return console_bridge + java_wait_wrapper_start + user_code + java_wait_wrapper_end

    def _ensure_frida_java_bridge_agent(self):
        """Prepare the tiny npm project used by frida.Compiler for Python API Java scripts."""
        if not hasattr(frida, "Compiler"):
            self.log_signal.emit(
                "CRITICAL",
                "Python frida module does not expose frida.Compiler. Install/upgrade frida-tools/frida 17+ or use CLI mode."
            )
            return False

        os.makedirs(FRIDA_API_AGENT_DIR, exist_ok=True)
        package_json = os.path.join(FRIDA_API_AGENT_DIR, "package.json")
        node_module_dir = os.path.join(FRIDA_API_AGENT_DIR, "node_modules", "frida-java-bridge")

        if not os.path.exists(package_json):
            with open(package_json, "w", encoding="utf-8") as f:
                json.dump({
                    "name": "uft-frida-api-agent",
                    "private": True,
                    "version": "1.0.0",
                    "dependencies": {
                        "frida-java-bridge": "latest"
                    }
                }, f, indent=2)

        if os.path.isdir(node_module_dir):
            return True

        npm_path = shutil.which("npm") or "/opt/homebrew/bin/npm"
        if not npm_path or not os.path.exists(npm_path):
            self.log_signal.emit(
                "CRITICAL",
                "Frida 17 Python API Java mode needs npm to install frida-java-bridge. Install Node/npm or switch to CLI mode."
            )
            return False

        self.log_signal.emit("SYSTEM", f"Installing frida-java-bridge for Python API mode in {FRIDA_API_AGENT_DIR}...")
        try:
            result = subprocess.run(
                [npm_path, "install", "--silent"],
                cwd=FRIDA_API_AGENT_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    if line.strip():
                        self.log_signal.emit("SYSTEM", f"npm: {line.strip()}")
            if result.returncode != 0 or not os.path.isdir(node_module_dir):
                self.log_signal.emit(
                    "CRITICAL",
                    f"npm install frida-java-bridge failed with exit code {result.returncode}. Use CLI mode until this is installed."
                )
                return False
            return True
        except subprocess.TimeoutExpired:
            self.log_signal.emit("CRITICAL", "npm install frida-java-bridge timed out. Use CLI mode or install it manually.")
            return False
        except Exception as e:
            self.log_signal.emit("CRITICAL", f"Failed to prepare frida-java-bridge agent: {str(e)}")
            return False

    def _build_python_api_agent_source(self, wrapped_code, needs_java_bridge):
        """Return plain JS for non-Java scripts, or a compiled bundle with frida-java-bridge for Java scripts."""
        if not needs_java_bridge:
            return wrapped_code

        if not self._ensure_frida_java_bridge_agent():
            return None

        agent_source_path = os.path.join(FRIDA_API_AGENT_DIR, "uft_agent.js")
        bridge_header = (
            'import JavaBridge from "frida-java-bridge";\n\n'
            'const Java = JavaBridge;\n'
            'globalThis.Java = JavaBridge;\n'
            "send({ type: 'system', text: '[UFT] Frida 17 API Java bridge imported from frida-java-bridge.' });\n\n"
        )
        with open(agent_source_path, "w", encoding="utf-8") as f:
            f.write(bridge_header)
            f.write(wrapped_code)

        try:
            compiler = frida.Compiler()
            try:
                compiler.on("diagnostics", lambda diag: self.log_signal.emit("SYSTEM", f"frida-compiler: {diag}"))
            except Exception:
                pass
            self.log_signal.emit("SYSTEM", "Compiling Python API Java agent with frida-java-bridge...")
            bundle = compiler.build("uft_agent.js", project_root=FRIDA_API_AGENT_DIR)
            self.log_signal.emit("SYSTEM", "Compiled Python API Java bridge agent successfully.")
            return bundle
        except Exception as e:
            self.log_signal.emit(
                "CRITICAL",
                "Failed to compile frida-java-bridge agent. Try: cd " + FRIDA_API_AGENT_DIR + " && npm install frida-java-bridge. Error: " + str(e)
            )
            return None

    def stop(self):
        self.requestInterruption()
        try:
            if self.process and self.process.poll() is None:
                self.process.terminate()
        except Exception:
            pass
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass

    def run(self):
        if self.injection_mode == FRIDA_INJECTION_MODE_PYTHON:
            self._run_python_api()
        else:
            self._run_cli()

    def _run_cli(self):
        script_path = None
        try:
            frida_bin = self.frida_bin or FRIDA_CLI_PATH
            if not os.path.exists(frida_bin):
                auto_path = shutil.which("frida")
                if auto_path:
                    frida_bin = auto_path

            if not frida_bin or not os.path.exists(frida_bin):
                self.log_signal.emit("CRITICAL", "Frida CLI binary not found. Set the path to /opt/homebrew/bin/frida or install frida-tools.")
                return

            self.log_signal.emit("SYSTEM", f"Launching Frida CLI Engine for {self.pkg}...")
            self.log_signal.emit("SYSTEM", f"Frida CLI path: {frida_bin}")

            # Use a temp script file instead of --eval so large scripts and quotes/newlines are reliable.
            fd, script_path = tempfile.mkstemp(prefix="uft_frida_", suffix=".js")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(self.code)

            env = os.environ.copy()
            env["PATH"] = os.path.dirname(frida_bin) + os.pathsep + env.get("PATH", "")
            cmd = [frida_bin, "-U", "-f", self.pkg, "-l", script_path]

            # Older Frida builds support --no-pause; newer ones may ignore/remove it.
            # We do not force it here because keeping the CLI defaults avoids version-specific breakage.
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env
            )

            while self.process.poll() is None:
                if self.isInterruptionRequested():
                    self.process.terminate()
                    break
                line = self.process.stdout.readline()
                if line:
                    clean_line = re.sub(r"\[[^\]]+::[^\]]+\]\s*->", "", line).strip()
                    if clean_line:
                        self.log_signal.emit("FRIDA", clean_line)
                else:
                    time.sleep(0.05)

            rc = self.process.poll()
            self.log_signal.emit("SYSTEM", f"Frida CLI session ended. Exit code: {rc}")
        except Exception as e:
            self.log_signal.emit("CRITICAL", f"CLI Engine Error: {str(e)}")
        finally:
            if script_path:
                try:
                    os.remove(script_path)
                except Exception:
                    pass

    def _run_python_api(self):
        try:
            self.log_signal.emit("SYSTEM", f"Launching Frida Python API Engine for {self.pkg}...")
            self.log_signal.emit("SYSTEM", f"Python frida module version: {getattr(frida, '__version__', 'unknown')}")

            self.device = frida.get_usb_device(timeout=7)
            self.log_signal.emit("SYSTEM", f"Connected USB device: {getattr(self.device, 'name', 'USB device')}")

            needs_java_bridge = re.search(r'\bJava\b', self.code or "") is not None

            # Mirror CLI spawn behavior: spawn, attach, load script, then resume.
            # In Frida 17 Python/API mode Java is not globally provided unless bundled,
            # so Java scripts are compiled with frida-java-bridge first.
            try:
                self.spawned_pid = self.device.spawn([self.pkg])
            except TypeError:
                self.spawned_pid = self.device.spawn(self.pkg)
            self.log_signal.emit("SYSTEM", f"Spawned {self.pkg} with PID {self.spawned_pid}")

            self.session = self.device.attach(self.spawned_pid)
            try:
                self.session.on('detached', lambda reason, crash=None: self.log_signal.emit("SYSTEM", f"Frida session detached: {reason}"))
            except Exception:
                pass

            wrapped_code = self._wrap_script_for_python_api(self.code)
            agent_source = self._build_python_api_agent_source(wrapped_code, needs_java_bridge)
            if agent_source is None:
                try:
                    self.device.resume(self.spawned_pid)
                    self.log_signal.emit("SYSTEM", "Process resumed after Python API setup failure to avoid leaving it paused.")
                except Exception:
                    pass
                return

            self.script = self.session.create_script(agent_source)
            self.script.on('message', self.on_message)
            self.script.load()
            self.log_signal.emit("SYSTEM", "Python API script loaded; message bridge armed. Resuming process now...")

            self.device.resume(self.spawned_pid)
            self.log_signal.emit("SYSTEM", "Python API process resumed.")

            while not self.isInterruptionRequested():
                time.sleep(0.1)

            self.log_signal.emit("SYSTEM", "Python API interruption requested; detaching...")
        except Exception as e:
            self.log_signal.emit("CRITICAL", f"Python API Engine Error: {str(e)}")
        finally:
            try:
                if self.script:
                    self.script.unload()
            except Exception:
                pass
            try:
                if self.session:
                    self.session.detach()
            except Exception:
                pass
            self.log_signal.emit("SYSTEM", "Frida Python API session ended.")


# --- UI COMPONENTS ---

class JSHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []
        f1, f2 = QTextCharFormat(), QTextCharFormat()
        f1.setForeground(QColor("#61afef"))
        f2.setForeground(QColor("#c678dd"))
        kw = ["Java.perform", "Java.use", "implementation", "overload", "return", "function", "var", "let", "const"]
        for w in kw: self.rules.append((QRegExp(f"\\b{w}\\b"), f2))
        self.rules.append((QRegExp(r"\b[A-Za-z0-9_]+(?=\()"), f1))

    def highlightBlock(self, text):
        for p, f in self.rules:
            expr = QRegExp(p)
            i = expr.indexIn(text)
            while i >= 0:
                self.setFormat(i, expr.matchedLength(), f)
                i = expr.indexIn(text, i + expr.matchedLength())


class ClickableImage(QLabel):
    doubleClicked = pyqtSignal(str)
    input_event = pyqtSignal(int, int, int, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.start_pos = None
        self.current_path = None
        self.setMouseTracking(True)

    def setPixmap(self, pixmap):
        super().setPixmap(pixmap)

    def update_image(self, pixmap, path):
        self.current_path = path
        self.setPixmap(pixmap)

    def mousePressEvent(self, event):
        self.start_pos = event.pos()

    def mouseReleaseEvent(self, event):
        if self.start_pos:
            end_pos = event.pos()
            dist = (end_pos - self.start_pos).manhattanLength()
            if dist < 10:
                self.input_event.emit(self.start_pos.x(), self.start_pos.y(), 0, 0, "tap")
            else:
                self.input_event.emit(self.start_pos.x(), self.start_pos.y(), end_pos.x(), end_pos.y(), "drag")
            self.start_pos = None

    def mouseDoubleClickEvent(self, event):
        if self.current_path: self.doubleClicked.emit(self.current_path)


# --- FORENSICS MASTER APPLICATION ---

class Forensics(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ultimate Forensics Toolbox V1.01 - Jason Peixoto")
        self.resize(1750, 1000)
        self.setStyle(DepressStyle())
        self.setStyleSheet(self.get_theme())

        self.current_file_path, self.captured_images, self.current_image_index = None, [], -1
        self.log_paused, self.frida_paused, self.current_remote_dir, self.worker = False, False, "/", None
        self.frida_log_entries = []  # Buffered tuples: (level, message). Used by Frida log filters/search.
        self.frida_log_max_entries = 5000
        self.path_history = ["/", "/sdcard", "/sdcard/Download", "/data/local/tmp"]

        if not os.path.exists(FRIDA_TEMPLATE_FILE):
            default_template = (
                "Java.perform(function () {\n"
                "    console.log('\\n[+] [FRIDA ENGINE] Global Proxy Redirection Script Active!');\n"
                "    console.log('[+] Target Tunnel Pipeline Route: {ip}:{port}\\n');\n"
                "    var System = Java.use('java.lang.System');\n"
                "    var proxy_host = \"{ip}\";\n"
                "    var proxy_port = \"{port}\";\n\n"
                "    System.getProperty.overload('java.lang.String').implementation = function (prop) {\n"
                "        if (prop === 'http.proxyHost' || prop === 'https.proxyHost') {\n"
                "            console.log('[~] Intercepted getProperty(' + prop + ') -> Routing over custom host proxy!');\n"
                "            return proxy_host;\n"
                "        }\n"
                "        if (prop === 'http.proxyPort' || prop === 'https.proxyPort') {\n"
                "            console.log('[~] Intercepted getProperty(' + prop + ') -> Routing over custom port proxy!');\n"
                "            return proxy_port;\n"
                "        }\n"
                "        return this.getProperty(prop);\n"
                "    };\n"
                "});\n"
            )
            with open(FRIDA_TEMPLATE_FILE, 'w') as f: f.write(default_template)

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        tm = QMenu()
        tm.addAction("Show Toolbox").triggered.connect(self.show)
        tm.addSeparator()
        tm.addAction("Quit Jason's Toolbox").triggered.connect(self.actual_quit)
        self.tray_icon.setContextMenu(tm)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

        self.adb_process = QProcess(self)
        self.adb_process.readyReadStandardOutput.connect(self.handle_adb_stdout)
        self.adb_process.readyReadStandardError.connect(self.handle_adb_stdout)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.setup_processes_tab()
        self.setup_frida_manager_tab()
        self.setup_frida_logs_tab()
        self.setup_logcat_tab()
        self.setup_file_explorer_tab()
        self.setup_gallery_tab()
        self.setup_adb_tab()
        self.setup_remote_tab()
        self.setup_console_tab()
        self.setup_settings_tab()

        self.load_settings()
        self.load_image_history()
        self.update_viewer_ui()
        self.start_logcat_stream()
        self.load_manual_proxies_to_ui()

    def detect_frida_cli_path(self):
        detected = shutil.which("frida") or FRIDA_CLI_PATH
        self.frida_cli_path.setText(detected)
        try:
            self.adb_out.append(f"<font color='#58a6ff'>[FRIDA] Auto-detected CLI path: {detected}</font>")
        except Exception:
            pass
        self.save_settings()

    def send_remote_input(self, x1, y1, x2, y2, mode):
        dev_w, dev_h = 1080, 2400
        pix = self.remote_viewer.pixmap()
        if not pix: return

        offset_x = (self.remote_viewer.width() - pix.width()) / 2
        offset_y = (self.remote_viewer.height() - pix.height()) / 2

        rx1 = int(((x1 - offset_x) / pix.width()) * dev_w)
        ry1 = int(((y1 - offset_y) / pix.height()) * dev_h)
        rx2 = int(((x2 - offset_x) / pix.width()) * dev_w)
        ry2 = int(((y2 - offset_y) / pix.height()) * dev_h)

        if mode == "tap":
            subprocess.Popen([ADB_PATH, "shell", "input", "tap", str(rx1), str(ry1)])
        elif mode == "drag":
            subprocess.Popen([ADB_PATH, "shell", "input", "swipe", str(rx1), str(ry1), str(rx2), str(ry2), "200"])
        self.console.append(f"<font color='#8b949e'>[REMOTE] {mode.upper()} at {rx1},{ry1}</font>")

    def start_frida_server(self):
        self.run_adb_cmd(f"{ADB_PATH} shell \"su -c setenforce 0\"")
        self.run_adb_cmd(f"{ADB_PATH} shell \"su -c '/data/local/tmp/frida-server -l 0.0.0.0 > /dev/null 2>&1 &'\"")
        self.adb_out.append("[SYSTEM] Frida Server: Permissive mode set and start command sent.")

    def stop_frida_server(self):
        self.run_adb_cmd(f"{ADB_PATH} shell \"su -c pkill -9 frida-server\"")
        self.adb_out.append("[SYSTEM] Frida Server: Stop command sent.")

    def get_theme(self):
        return """QMainWindow, QTabWidget { background-color: #0d1117; } 
                  QTabWidget::pane { border: 1px solid #30363d; }
                  QTabBar::tab { background: #161b22; color: #8b949e; padding: 12px 25px; border: 1px solid #30363d; }
                  QTabBar::tab:selected { background: #1f6feb; color: white; }
                  QTableWidget, QTreeView, QTextEdit, QLineEdit, QListWidget, QComboBox, QSpinBox { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; border-radius: 4px; padding: 5px;}
                  QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; padding: 10px; border-radius: 6px; }
                  QPushButton:pressed { background: #161b22; border: 1px solid #1f6feb; color: #1f6feb; }
                  #forgeBtn { background: #238636; color: white; font-weight: bold; }
                  #stopBtn { background: #da3633; color: white; font-weight: bold; }
                  #runBtn { background: #1f6feb; color: white; font-weight: bold; }
                  #editFridaScriptBtn { background: #8957e5; color: white; font-weight: bold; }
                  #editListBtn { background: #d29922; color: white; font-weight: bold; }
                  #killBtn { background: #f85149; color: white; font-weight: bold; }
                  #installBtn { background: #8957e5; color: white; font-weight: bold; }
                  #addBtn { background: #1f6feb; color: white; font-weight: bold; border-radius: 15px; min-width: 30px; }"""

    def handle_adb_stdout(self):
        out_raw = self.adb_process.readAllStandardOutput().data().decode();
        err_raw = self.adb_process.readAllStandardError().data().decode()
        if out_raw:
            self.adb_out.append(out_raw.strip());
            lines = out_raw.splitlines()
            for line in lines: self.console.append(f"<font color='#7ee787'>{line}</font>")
        if err_raw:
            lines = err_raw.splitlines()
            for line in lines: self.console.append(f"<font color='#ff7b72'>[!] {line}</font>")

    def execute_console_command(self):
        full_cmd = self.cmd_input.currentText().strip()
        if not full_cmd: return
        self.console.append(f"<font color='#58a6ff'><b>> {full_cmd}</b></font>")
        exec_cmd = full_cmd if full_cmd.startswith("adb") else f"{ADB_PATH} {full_cmd}"
        self.run_adb_cmd(exec_cmd)
        existing_index = self.cmd_input.findText(full_cmd)
        if existing_index != -1: self.cmd_input.removeItem(existing_index)
        self.cmd_input.insertItem(0, full_cmd)
        self.cmd_input.setCurrentIndex(0)
        self.save_settings()
        self.cmd_input.setEditText("")

    def setup_processes_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        h = QHBoxLayout()
        self.p_search = QLineEdit();
        self.p_search.setPlaceholderText("Filter Processes...")
        self.p_search.textChanged.connect(self.run_proc_filter)
        btn_refresh = QPushButton("Refresh List");
        btn_refresh.clicked.connect(self.refresh_procs)
        h.addWidget(self.p_search);
        h.addWidget(btn_refresh);
        layout.addLayout(h)
        self.proc_table = QTableWidget(0, 2);
        self.proc_table.setHorizontalHeaderLabels(["Name", "Package ID"])
        self.proc_table.setSortingEnabled(True);
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.proc_table.itemClicked.connect(self.on_process_clicked)
        layout.addWidget(self.proc_table);
        self.tabs.addTab(tab, "🔍 Processes")

    def setup_frida_manager_tab(self):
        tab = QWidget();
        layout = QHBoxLayout(tab)
        self.f_model = QFileSystemModel();
        self.f_model.setRootPath(BASE_DIR);
        self.f_model.setReadOnly(False)
        self.f_model.setNameFilters(["Global_Vault", "Projects", "*.js"]);
        self.f_model.setNameFilterDisables(False)
        self.f_tree = QTreeView();
        self.f_tree.setModel(self.f_model);
        self.f_tree.setRootIndex(self.f_model.index(BASE_DIR))
        self.f_tree.setHeaderHidden(False);
        self.f_tree.header().setSectionResizeMode(0, QHeaderView.Interactive)
        for i in range(1, 4): self.f_tree.setColumnHidden(i, True)
        self.f_tree.clicked.connect(self.on_file_clicked);
        self.f_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.f_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.f_tree, 1)

        r_box = QVBoxLayout();
        tools = QHBoxLayout()
        btn_proj = QPushButton("📁 Project");
        btn_proj.clicked.connect(self.create_new_project)
        btn_s = QPushButton("💾 Save");
        btn_s.clicked.connect(self.save_script)
        btn_b = QPushButton("✨ Beautify");
        btn_b.clicked.connect(self.beautify_code)
        tools.addWidget(btn_proj);
        tools.addWidget(btn_s);
        tools.addWidget(btn_b);
        r_box.addLayout(tools)
        self.editor = QTextEdit();
        self.highlighter = JSHighlighter(self.editor.document());
        r_box.addWidget(self.editor)

        self.target_pkg = QComboBox();
        self.target_pkg.setEditable(True)
        self.target_pkg.setCompleter(QCompleter([]))
        self.target_completer = self.target_pkg.completer()
        self.target_completer.setCaseSensitivity(Qt.CaseInsensitive);
        self.target_completer.setFilterMode(Qt.MatchContains)
        r_box.addWidget(QLabel("Target Package ID:"));
        r_box.addWidget(self.target_pkg)

        engine_row = QHBoxLayout()
        self.frida_injection_mode = QComboBox()
        self.frida_injection_mode.addItem("Command Line / frida-tools", FRIDA_INJECTION_MODE_CLI)
        self.frida_injection_mode.addItem("Python API / frida module", FRIDA_INJECTION_MODE_PYTHON)
        self.frida_injection_mode.currentIndexChanged.connect(self.save_settings)

        self.frida_cli_path = QLineEdit(FRIDA_CLI_PATH)
        self.frida_cli_path.setPlaceholderText("Frida CLI path, e.g. /opt/homebrew/bin/frida")
        self.frida_cli_path.textChanged.connect(self.save_settings)

        btn_detect_frida = QPushButton("🔎 Auto")
        btn_detect_frida.clicked.connect(self.detect_frida_cli_path)

        engine_row.addWidget(QLabel("Frida Engine:"))
        engine_row.addWidget(self.frida_injection_mode)
        engine_row.addWidget(QLabel("CLI Path:"))
        engine_row.addWidget(self.frida_cli_path, 1)
        engine_row.addWidget(btn_detect_frida)
        r_box.addLayout(engine_row)

        btns = QHBoxLayout()
        fb = QPushButton("FORGE & INJECT");
        fb.setObjectName("forgeBtn");
        fb.clicked.connect(self.start_forge)
        sb = QPushButton("🛑 STOP SCRIPT");
        sb.setObjectName("stopBtn");
        sb.clicked.connect(self.stop_frida_worker)
        btns.addWidget(fb);
        btns.addWidget(sb);
        r_box.addLayout(btns);
        layout.addLayout(r_box, 3)
        self.tabs.addTab(tab, "🛠️ Frida Manager")

    def setup_frida_logs_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);

        controls = QHBoxLayout()
        self.frida_filter = QLineEdit();
        self.frida_filter.setPlaceholderText("Search Frida logs...")
        self.frida_filter.textChanged.connect(lambda _=None: self.refresh_frida_log_display())

        self.btn_frida_pause = QPushButton("⏸ Pause");
        self.btn_frida_pause.clicked.connect(self.toggle_frida_pause)
        btn_c = QPushButton("🧹 Clear");
        btn_c.clicked.connect(self.clear_frida_logs)

        controls.addWidget(QLabel("Search:"));
        controls.addWidget(self.frida_filter, 1);
        controls.addWidget(self.btn_frida_pause);
        controls.addWidget(btn_c);
        layout.addLayout(controls)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Show:"))

        self.chk_frida_log = QCheckBox("FRIDA / LOG")
        self.chk_frida_system = QCheckBox("SYSTEM")
        self.chk_frida_script = QCheckBox("SCRIPT")
        self.chk_frida_error = QCheckBox("ERROR / CRITICAL")

        for chk, color in [
            (self.chk_frida_log, "#7ee787"),
            (self.chk_frida_system, "#58a6ff"),
            (self.chk_frida_script, "#d2a8ff"),
            (self.chk_frida_error, "#ff7b72"),
        ]:
            chk.setChecked(True)
            chk.setStyleSheet(f"color: {color}; font-weight: bold;")
            chk.toggled.connect(lambda _=None: self.refresh_frida_log_display())
            filter_row.addWidget(chk)

        filter_row.addStretch()
        layout.addLayout(filter_row)

        self.frida_display = QTextEdit();
        self.frida_display.setReadOnly(True);
        self.frida_display.setFont(QFont("Monospace", 10))
        self.frida_display.setStyleSheet("background: #010409; color: #d1d5da;");
        layout.addWidget(self.frida_display)
        self.tabs.addTab(tab, "💉 Frida Logs")

    def setup_logcat_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        h = QHBoxLayout()
        self.log_filter = QLineEdit();
        self.log_level_box = QComboBox()
        self.log_levels = {"Verbose": "V", "Debug": "D", "Info": "I", "Warning": "W", "Error": "E", "Fatal": "F"}
        self.log_level_box.addItems(list(self.log_levels.keys()));
        self.log_hard_filter = QCheckBox("Hide Non-Matching")
        self.log_hard_filter.setChecked(True);
        self.log_hard_filter.setStyleSheet("color: white;")
        self.btn_log_pause = QPushButton("⏸ Pause");
        self.btn_log_pause.clicked.connect(self.toggle_log_pause)
        btn_clear = QPushButton("🧹 Clear");
        btn_clear.clicked.connect(lambda: self.log_display.clear())
        h.addWidget(QLabel("Level:"));
        h.addWidget(self.log_level_box);
        h.addWidget(self.log_filter, 1)
        h.addWidget(self.log_hard_filter);
        h.addWidget(self.btn_log_pause);
        h.addWidget(btn_clear);
        layout.addLayout(h)
        self.log_display = QTextEdit();
        self.log_display.setReadOnly(True);
        self.log_display.setFont(QFont("Monospace", 10))
        self.log_display.setStyleSheet("background: #010409; color: #d1d5da;");
        layout.addWidget(self.log_display)
        self.tabs.addTab(tab, "🕵️ LogCat")

    def setup_file_explorer_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        nav = QHBoxLayout()
        btn_up = QPushButton("⤴ Up");
        btn_up.clicked.connect(self.remote_dir_up)
        self.path_box = QComboBox();
        self.path_box.setEditable(True);
        self.path_box.addItems(self.path_history)
        self.path_box.lineEdit().returnPressed.connect(self.jump_to_remote_path)
        btn_go = QPushButton("GO");
        btn_go.clicked.connect(self.jump_to_remote_path)
        btn_push = QPushButton("📥 Push");
        btn_push.clicked.connect(self.push_remote_file)
        btn_refresh = QPushButton("🔄 Refresh");
        btn_refresh.clicked.connect(self.refresh_remote_fs)
        nav.addWidget(btn_up);
        nav.addWidget(self.path_box, 1);
        nav.addWidget(btn_go);
        nav.addWidget(btn_push);
        nav.addWidget(btn_refresh);
        layout.addLayout(nav)
        self.fs_filter = QLineEdit();
        self.fs_filter.setPlaceholderText("Filter folder...");
        self.fs_filter.textChanged.connect(self.run_fs_filter);
        layout.addWidget(self.fs_filter)
        self.fs_splitter = QSplitter(Qt.Horizontal);
        self.remote_table = QTableWidget(0, 4)
        self.remote_table.setHorizontalHeaderLabels(["Name", "Size", "Date/Time", "Perms"]);
        self.remote_table.setSortingEnabled(True)
        self.remote_table.setContextMenuPolicy(Qt.CustomContextMenu);
        self.remote_table.customContextMenuRequested.connect(self.show_remote_context_menu)
        self.remote_table.itemSelectionChanged.connect(self.preview_remote_file);
        self.remote_table.itemDoubleClicked.connect(self.on_remote_item_double_click)
        self.fs_splitter.addWidget(self.remote_table);
        self.preview_box = QTextEdit();
        self.preview_box.setReadOnly(True)
        self.preview_box.setFont(QFont("Monospace", 9));
        self.preview_box.setStyleSheet("background: #0d1117; color: #8b949e; border-left: 1px solid #30363d;")
        self.fs_splitter.addWidget(self.preview_box);
        self.fs_splitter.setStretchFactor(0, 3);
        self.fs_splitter.setStretchFactor(1, 1);
        layout.addWidget(self.fs_splitter)
        self.tabs.addTab(tab, "📁 File Explorer");
        self.refresh_remote_fs()

    def setup_gallery_tab(self):
        tab = QWidget();
        layout = QHBoxLayout(tab);
        ctrl = QVBoxLayout()
        btn_shot = QPushButton("📸 Snapshot + Portal");
        btn_shot.clicked.connect(self.take_snapshot);
        ctrl.addWidget(btn_shot)
        self.img_info = QLabel("Empty");
        self.img_info.setAlignment(Qt.AlignCenter);
        ctrl.addWidget(self.img_info);
        nav = QHBoxLayout()
        btn_p = QPushButton("<- Prev");
        btn_p.clicked.connect(lambda: self.cycle_image(-1));
        btn_n = QPushButton("Next ->");
        btn_n.clicked.connect(lambda: self.cycle_image(1))
        nav.addWidget(btn_p);
        nav.addWidget(btn_n);
        ctrl.addLayout(nav);
        mg = QHBoxLayout()
        btn_del = QPushButton("Delete");
        btn_del.clicked.connect(self.delete_current_image);
        btn_cl = QPushButton("Clear All");
        btn_cl.clicked.connect(self.clear_all_images)
        mg.addWidget(btn_del);
        mg.addWidget(btn_cl);
        ctrl.addLayout(mg);
        ctrl.addStretch();
        layout.addLayout(ctrl, 1)
        self.viewer = ClickableImage();
        self.viewer.setAlignment(Qt.AlignCenter);
        self.viewer.doubleClicked.connect(self.copy_image_to_clipboard_and_portal);
        layout.addWidget(self.viewer, 2)
        self.tabs.addTab(tab, "📸 Gallery")

    def setup_adb_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab)
        p_box = QGroupBox("Burp Proxy");
        px_layout = QHBoxLayout(p_box)
        self.px_in = QLineEdit(f"{self.get_ip()}:8080");
        btn_rip = QPushButton("🔄 IP");
        btn_rip.clicked.connect(self.refresh_local_ip)
        btn_set = QPushButton("Set");
        btn_set.clicked.connect(self.set_burp_proxy);
        btn_cl = QPushButton("Clear");
        btn_cl.clicked.connect(self.clear_burp_proxy)
        px_layout.addWidget(QLabel("Proxy:"));
        px_layout.addWidget(self.px_in);
        px_layout.addWidget(btn_rip);
        px_layout.addWidget(btn_set);
        px_layout.addWidget(btn_cl);
        layout.addWidget(p_box)

        global_px_box = QGroupBox("Global Proxy Rotator (Frida Engine Proxy)");
        global_px_layout = QVBoxLayout(global_px_box)

        control_row = QHBoxLayout()
        self.country_selector = QComboBox()

        priority_countries = {
            "Brazil (BR)": "BR", "India (IN)": "IN", "Philippines (PH)": "PH",
            "Pakistan (PK)": "PK", "Russia (RU)": "RU", "Vietnam (VN)": "VN"
        }
        standard_countries = {
            "Argentina (AR)": "AR", "Australia (AU)": "AU", "Austria (AT)": "AT",
            "Bangladesh (BD)": "BD", "Belgium (BE)": "BE", "Bulgaria (BG)": "BG",
            "Canada (CA)": "CA", "Chile (CL)": "CL", "China (CN)": "CN",
            "Colombia (CO)": "CO", "Czech Republic (CZ)": "CZ", "Denmark (DK)": "DK",
            "Egypt (EG)": "EG", "Finland (FI)": "FI", "France (FR)": "FR",
            "Germany (DE)": "DE", "Greece (GR)": "GR", "Hong Kong (HK)": "HK",
            "Hungary (HU)": "HU", "Indonesia (ID)": "ID", "Iran (IR)": "IR",
            "Iraq (IQ)": "IQ", "Ireland (IE)": "IE", "Israel (IL)": "IL",
            "Italy (IT)": "IT", "Japan (JP)": "JP", "Kenya (KE)": "KE",
            "Malaysia (MY)": "MY", "Mexico (MX)": "MX", "Moldova (MD)": "MD",
            "Netherlands (NL)": "NL", "New Zealand (NZ)": "NZ", "Nigeria (NG)": "NG",
            "Norway (NO)": "NO", "Peru (PE)": "PE", "Poland (PL)": "PL",
            "Portugal (PT)": "PT", "Romania (RO)": "RO", "Saudi Arabia (SA)": "SA",
            "Singapore (SG)": "SG", "Slovakia (SK)": "SK", "South Africa (ZA)": "ZA",
            "South Korea (KR)": "KR", "Spain (ES)": "ES", "Sweden (SE)": "SE",
            "Switzerland (CH)": "CH", "Taiwan (TW)": "TW", "Thailand (TH)": "TH",
            "Turkey (TR)": "TR", "Ukraine (UA)": "UA", "United Arab Emirates (AE)": "AE",
            "United Kingdom (GB)": "GB", "United States (US)": "US"
        }

        self.country_selector.addItem("--- ⭐ Priority Targets ---", None)
        for name, code in priority_countries.items(): self.country_selector.addItem(name, code)
        self.country_selector.addItem("--- 🌐 Global Regions ---", None)
        for name, code in sorted(standard_countries.items()): self.country_selector.addItem(name, code)

        self.country_selector.setCurrentIndex(2)  # Default points to India
        self.country_selector.currentIndexChanged.connect(self.load_manual_proxies_to_ui)

        self.chk_auto_fallback = QCheckBox("Auto-Fallback On Noise/Fail");
        self.chk_auto_fallback.setChecked(True);
        self.chk_auto_fallback.setStyleSheet("color: white;")

        btn_edit_frida_script = QPushButton("📜 Frida Proxy Script")
        btn_edit_frida_script.setObjectName("editFridaScriptBtn")
        btn_edit_frida_script.clicked.connect(self.open_frida_template_editor_modal)

        btn_edit_list = QPushButton("📝 Edit Proxy File")
        btn_edit_list.setObjectName("editListBtn")
        btn_edit_list.clicked.connect(self.open_proxy_file_in_system_editor)

        btn_route_proxy = QPushButton("🚀 Route Global Proxy");
        btn_route_proxy.setObjectName("runBtn");
        btn_route_proxy.clicked.connect(self.start_global_proxy_routing)

        btn_remove_proxy = QPushButton("🛑 Remove Proxy");
        btn_remove_proxy.setObjectName("killBtn");
        btn_remove_proxy.clicked.connect(self.remove_global_proxy)

        control_row.addWidget(QLabel("Target Country:"));
        control_row.addWidget(self.country_selector);
        control_row.addWidget(self.chk_auto_fallback)
        control_row.addWidget(btn_edit_frida_script)
        control_row.addWidget(btn_edit_list)
        control_row.addWidget(btn_route_proxy)
        control_row.addWidget(btn_remove_proxy)
        global_px_layout.addLayout(control_row)

        manual_row = QHBoxLayout()
        self.manual_proxy_input = QLineEdit()
        self.manual_proxy_input.setPlaceholderText(
            "Enter custom static targets here (e.g. 192.168.1.50:8080, 200.16.4.2:3128)")
        btn_save_manual = QPushButton("💾 Commit Manual List")
        btn_save_manual.clicked.connect(self.save_manual_proxies_from_ui)
        manual_row.addWidget(QLabel("Manual Override Pool: "))
        manual_row.addWidget(self.manual_proxy_input, 1)
        manual_row.addWidget(btn_save_manual)
        global_px_layout.addLayout(manual_row)

        layout.addWidget(global_px_box)

        apk_box = QGroupBox("Deployment");
        apk_layout = QHBoxLayout(apk_box);
        self.apk_path_display = QLineEdit()
        btn_b = QPushButton("📁 Browse");
        btn_b.clicked.connect(self.browse_deployment_file);
        btn_i = QPushButton("🚀 Atomic Install");
        btn_i.setObjectName("installBtn");
        btn_i.clicked.connect(self.start_installation_process)
        apk_layout.addWidget(self.apk_path_display, 1);
        apk_layout.addWidget(btn_b);
        apk_layout.addWidget(btn_i);
        layout.addWidget(apk_box)

        ctrl_box = QGroupBox("App Control Center");
        ctrl_layout = QVBoxLayout(ctrl_box);
        r1 = QHBoxLayout()
        self.app_selector = QComboBox();
        self.app_selector.setEditable(True);
        btn_all = QPushButton("🔄 Refresh All");
        btn_all.clicked.connect(self.fetch_all_apps)
        btn_run = QPushButton("📋 Running");
        btn_run.clicked.connect(self.fetch_running_apps);
        r1.addWidget(QLabel("ID:"));
        r1.addWidget(self.app_selector, 1);
        r1.addWidget(btn_all);
        r1.addWidget(btn_run)
        r2 = QHBoxLayout();
        btn_launch = QPushButton("▶ START APP");
        btn_launch.setObjectName("runBtn");
        btn_launch.clicked.connect(self.launch_selected_app)
        btn_kill = QPushButton("💀 KILL APP");
        btn_kill.setObjectName("killBtn");
        btn_kill.clicked.connect(self.kill_selected_app);
        r2.addStretch();
        r2.addWidget(btn_launch);
        r2.addWidget(btn_kill)
        ctrl_layout.addLayout(r1);
        ctrl_layout.addLayout(r2);
        layout.addWidget(ctrl_box)

        self.adb_grid_box = QGroupBox("ADB Arsenal");
        self.adb_grid_layout = QGridLayout(self.adb_grid_box);
        h = QHBoxLayout();
        h.addWidget(QLabel("Commands (4 per Row):"))
        btn_add = QPushButton("+");
        btn_add.setObjectName("addBtn");
        btn_add.clicked.connect(self.add_custom_command);
        h.addStretch();
        h.addWidget(btn_add);
        layout.addLayout(h);
        self.load_adb_buttons();
        layout.addWidget(self.adb_grid_box)
        self.adb_out = QTextEdit();
        self.adb_out.setStyleSheet("background: black; color: #00FF00; font-family: Monospace;");
        layout.addWidget(self.adb_out);
        self.tabs.addTab(tab, "🔌 Frida/ADB Control")

        frida_box = QGroupBox("Frida Server Management");
        frida_layout = QHBoxLayout(frida_box);
        btn_start = QPushButton("🚀 START SERVER");
        btn_start.setObjectName("runBtn");
        btn_start.clicked.connect(self.start_frida_server)
        btn_stop = QPushButton("🛑 STOP SERVER");
        btn_stop.setObjectName("killBtn");
        btn_stop.clicked.connect(self.stop_frida_server);
        frida_layout.addWidget(btn_start);
        frida_layout.addWidget(btn_stop);
        layout.addWidget(frida_box)

    def setup_settings_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        group = QGroupBox("Configuration");
        glay = QGridLayout(group);
        glay.addWidget(QLabel("Scale %:"), 0, 0)
        self.scale_spin = QSpinBox();
        self.scale_spin.setRange(10, 100);
        self.scale_spin.setValue(100);
        self.scale_spin.valueChanged.connect(self.save_settings);
        glay.addWidget(self.scale_spin, 0, 1);
        layout.addWidget(group);
        layout.addStretch();
        self.tabs.addTab(tab, "⚙️ Settings")

    def setup_console_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        h_layout = QHBoxLayout()
        self.cmd_input = QComboBox();
        self.cmd_input.setEditable(True);
        self.cmd_input.setInsertPolicy(QComboBox.InsertAtTop);
        self.cmd_input.setPlaceholderText("Enter ADB command...");
        self.cmd_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f);
                    self.cmd_input.addItems(d.get("console_history", []))
            except:
                pass
        self.cmd_input.lineEdit().returnPressed.connect(self.execute_console_command);
        btn_send = QPushButton("SEND");
        btn_send.clicked.connect(self.execute_console_command)
        h_layout.addWidget(QLabel("ADB:"), 0);
        h_layout.addWidget(self.cmd_input, 1);
        h_layout.addWidget(btn_send, 0);
        layout.addLayout(h_layout)
        self.console = QTextEdit();
        self.console.setReadOnly(True);
        self.console.setStyleSheet("background: #010409; color: #d1d5da; font-family: 'Monospace';");
        layout.addWidget(self.console);
        self.tabs.addTab(tab, "📟 ADB Console")

    def setup_remote_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        head = QHBoxLayout()
        self.btn_live = QPushButton("▶ EMBEDDED STREAM");
        self.btn_live.setCheckable(True);
        self.btn_live.toggled.connect(self.toggle_live_stream)
        btn_scrcpy = QPushButton("⚡ EXTERNAL TURBO");
        btn_scrcpy.setObjectName("runBtn");
        btn_scrcpy.clicked.connect(self.launch_high_speed_mirror)
        head.addWidget(self.btn_live);
        head.addWidget(btn_scrcpy);
        head.addStretch();
        layout.addLayout(head)
        self.remote_viewer = ClickableImage();
        self.remote_viewer.setAlignment(Qt.AlignCenter);
        self.remote_viewer.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored);
        self.remote_viewer.setMinimumSize(100, 100);
        self.remote_viewer.input_event.connect(self.send_remote_input);
        layout.addWidget(self.remote_viewer, 1);
        self.tabs.addTab(tab, "📱 Remote")

    def toggle_live_stream(self, started):
        if started:
            self.btn_live.setText("🛑 STOP STREAM");
            self.live_timer = QTimer();
            self.live_timer.timeout.connect(self.take_live_frame);
            self.live_timer.start(200)
        else:
            self.btn_live.setText("▶ START LIVE STREAM")
            if hasattr(self, 'live_timer'): self.live_timer.stop()

    def launch_high_speed_mirror(self):
        scrcpy_path = "/opt/homebrew/bin/scrcpy"
        if hasattr(self, 'live_timer') and self.live_timer.isActive(): self.live_timer.stop(); self.btn_live.setChecked(
            False); self.btn_live.setText("▶ START LIVE STREAM")
        if os.path.exists(scrcpy_path):
            try:
                self.console.append(
                    f"<font color='#58a6ff'>[SYSTEM] Launching High-Speed Mirror with ADB Injection...</font>")
                env = os.environ.copy();
                env["ADB"] = ADB_PATH
                subprocess.Popen([scrcpy_path, "--max-fps", "60", "-b", "8M", "--always-on-top"], env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as e:
                self.console.append(f"<font color='#ff7b72'>[ERROR] Failed to start: {str(e)}</font>")
        else:
            self.console.append(f"<font color='#ff7b72'>[ERROR] Scrcpy not found at {scrcpy_path}</font>")

    def take_live_frame(self):
        try:
            process = subprocess.run([ADB_PATH, "shell", "screencap", "-p"], capture_output=True, check=True)
            pix = QPixmap();
            pix.loadFromData(process.stdout)
            if not pix.isNull():
                scaled_pix = pix.scaled(self.remote_viewer.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation);
                self.remote_viewer.setPixmap(scaled_pix)
        except:
            pass

    def send_remote_tap(self, x, y):
        label_w = self.remote_viewer.width();
        label_h = self.remote_viewer.height();
        dev_w, dev_h = 1080, 1920
        real_x = int((x / label_w) * dev_w);
        real_y = int((y / label_h) * dev_h)
        subprocess.run([ADB_PATH, "shell", "input", "tap", str(real_x), str(real_y)])
        self.console.append(f"<font color='#8b949e'>[REMOTE] Tap sent to {real_x}, {real_y}</font>")

    # --- PROXY CONTROLLER LOGIC ---
    def open_frida_template_editor_modal(self):
        current_script = ""
        try:
            with open(FRIDA_TEMPLATE_FILE, 'r') as f:
                current_script = f.read()
        except Exception as e:
            current_script = f"// Error reading template file: {str(e)}"

        dlg = QDialog(self)
        dlg.setWindowTitle("Frida Proxy Instrumentation Payload Editor")
        dlg.resize(800, 600)
        dlg_layout = QVBoxLayout(dlg)

        hint = QLabel(
            "Modify the runtime payload template wrapper below. Use raw {ip} and {port} strings as injection keys.")
        hint.setStyleSheet("color: #8b949e; font-style: italic; padding-bottom: 5px;")
        dlg_layout.addWidget(hint)

        txt_editor = QTextEdit()
        txt_editor.setFont(QFont("Monospace", 10))
        txt_editor.setStyleSheet("background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;")
        txt_editor.setText(current_script)
        highlighter = JSHighlighter(txt_editor.document())
        dlg_layout.addWidget(txt_editor)

        btn_layout = QHBoxLayout()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)

        btn_save = QPushButton("💾 Save Template Structure")
        btn_save.setStyleSheet("background-color: #238636; color: white; font-weight: bold;")

        def commit_template_changes():
            try:
                with open(FRIDA_TEMPLATE_FILE, 'w') as f:
                    f.write(txt_editor.toPlainText())
                self.adb_out.append(
                    "<font color='#7ee787'>[PROXY EDITOR] Frida instrumentation script template updated successfully.</font>")
                dlg.accept()
            except Exception as e:
                QMessageBox.critical(dlg, "Write Error", f"Could not save changes to disk: {str(e)}")

        btn_save.clicked.connect(commit_template_changes)
        btn_layout.addWidget(btn_cancel)
        btn_layout.addWidget(btn_save)
        dlg_layout.addLayout(btn_layout)
        dlg.exec_()

    def open_proxy_file_in_system_editor(self):
        if not os.path.exists(MANUAL_PROXY_FILE):
            try:
                with open(MANUAL_PROXY_FILE, 'w') as f:
                    f.write("[]")
            except:
                pass

        self.adb_out.append(
            f"<font color='#58a6ff'>[PROXY EDITOR] Opening master raw JSON array: {MANUAL_PROXY_FILE}</font>")

        try:
            if sys.platform == "win32":
                os.startfile(MANUAL_PROXY_FILE)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", MANUAL_PROXY_FILE])
            else:
                subprocess.Popen(["xdg-open", MANUAL_PROXY_FILE])

            QTimer.singleShot(1500, self.load_manual_proxies_to_ui)
        except Exception as e:
            QMessageBox.warning(self, "Editor Error", f"Could not launch system editor: {str(e)}")

    def get_resolved_country_code(self):
        idx = self.country_selector.currentIndex()
        country_code = self.country_selector.itemData(idx)
        if not country_code:
            current_text = self.country_selector.currentText()
            match = re.search(r'\(([A-Z]{2})\)', current_text)
            country_code = match.group(1) if match else None
        return country_code

    def load_manual_proxies_to_ui(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            self.manual_proxy_input.clear()
            return

        target_full_name = GLOBAL_COUNTRY_MAP.get(country_code, "")

        if os.path.exists(MANUAL_PROXY_FILE):
            try:
                with open(MANUAL_PROXY_FILE, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        matches = []
                        for x in data:
                            geo = x.get("geolocation", {})
                            c_val = geo.get("country", "").upper().strip() if isinstance(geo, dict) else ""
                            if not c_val:
                                c_val = x.get("country", "").upper().strip()

                            if (c_val == country_code or (target_full_name and target_full_name in c_val)) and x.get(
                                    "ip") and x.get("port"):
                                matches.append(f"{x['ip']}:{x['port']}")

                        self.manual_proxy_input.setText(", ".join(matches))
                        return
            except:
                pass
        self.manual_proxy_input.clear()

    def save_manual_proxies_from_ui(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            QMessageBox.warning(self, "Selection Error", "Please select a valid target country.")
            return

        target_full_name = GLOBAL_COUNTRY_MAP.get(country_code, "")
        raw_text = self.manual_proxy_input.text().strip()
        existing_data = []
        if os.path.exists(MANUAL_PROXY_FILE):
            try:
                with open(MANUAL_PROXY_FILE, "r") as f:
                    existing_data = json.load(f)
                    if not isinstance(existing_data, list): existing_data = []
            except:
                pass

        purged_data = []
        for x in existing_data:
            geo = x.get("geolocation", {})
            c_val = geo.get("country", "").upper().strip() if isinstance(geo, dict) else ""
            if not c_val:
                c_val = x.get("country", "").upper().strip()

            if c_val != country_code and (not target_full_name or target_full_name not in c_val):
                purged_data.append(x)

        if raw_text:
            tokens = [t.strip() for t in re.split(r'[,\s;]+', raw_text) if t.strip()]
            for token in tokens:
                if ":" in token:
                    parts = token.split(":")
                    if len(parts) == 2:
                        ip = parts[0]
                        port = int(parts[1]) if parts[1].isdigit() else parts[1]
                        purged_data.append({
                            "proxy": f"socks5://{ip}:{port}",
                            "protocol": "socks5",
                            "ip": ip,
                            "port": port,
                            "https": False,
                            "anonymity": "transparent",
                            "score": 1,
                            "geolocation": {
                                "country": target_full_name if target_full_name else country_code,
                                "city": "Unknown"
                            }
                        })

        try:
            with open(MANUAL_PROXY_FILE, "w") as f:
                json.dump(purged_data, f, indent=4)
            self.load_manual_proxies_to_ui()
            self.adb_out.append(
                f"<font color='#7ee787'>[PROXY EDITOR] Successfully committed fields targeting [{country_code}].</font>")
        except Exception as e:
            self.adb_out.append(
                f"<font color='#ff7b72'>[PROXY EDITOR] Failed to write master list array: {str(e)}</font>")

    def start_global_proxy_routing(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            self.adb_out.append(
                "<font color='#f85149'>[ERROR] Invalid region selector option placeholder targeted.</font>")
            return

        auto_fallback = self.chk_auto_fallback.isChecked()
        if hasattr(self, 'proxy_tester_worker') and self.proxy_tester_worker.isRunning():
            self.proxy_tester_worker.stop();
            self.proxy_tester_worker.wait()

        self.proxy_tester_worker = ProxyTesterWorker(country_code, auto_fallback)
        self.proxy_tester_worker.status_signal.connect(self.handle_proxy_worker_status)
        self.proxy_tester_worker.proxy_found_signal.connect(self.inject_validated_proxy)
        self.proxy_tester_worker.start()

    def handle_proxy_worker_status(self, status_type, message):
        colors = {"INFO": "#58a6ff", "TESTING": "#8b949e", "WARN": "#ffa657", "SUCCESS": "#7ee787", "ERROR": "#ff7b72",
                  "CRITICAL": "#f85149"}
        color = colors.get(status_type, "#c9d1d9")
        self.adb_out.append(f"<font color='{color}'>[PROXY ROTATOR] {message}</font>")

    def inject_validated_proxy(self, ip, port):
        self.px_in.setText(f"{ip}:{port}")

        raw_template = ""
        try:
            with open(FRIDA_TEMPLATE_FILE, 'r') as f:
                raw_template = f.read()
        except:
            raw_template = "Java.perform(function() { console.log('Proxy connection: {ip}:{port}'); });"

        full_payload = raw_template.replace("{ip}", str(ip)).replace("{port}", str(port))

        self.editor.setText(full_payload)
        self.adb_out.append(
            "<font color='#7ee787'>[+] Archipelago instrumentation script compiled. Launching injection...</font>")
        self.start_forge()

    def remove_global_proxy(self):
        if hasattr(self,
                   'proxy_tester_worker') and self.proxy_tester_worker.isRunning(): self.proxy_tester_worker.stop()
        self.clear_burp_proxy();
        self.stop_frida_worker()
        self.adb_out.append(
            "<font color='#ff7b72'>[-] Global proxy rules unlinked and app session detached successfully.</font>")

    # --- CORE METHODS ---
    def actual_quit(self):
        self.tray_icon.hide();
        QApplication.quit()

    def closeEvent(self, event):
        (self.tray_icon.isVisible()) and self.hide() or event.ignore()

    def tray_icon_activated(self, reason):
        (reason == QSystemTrayIcon.Trigger) and (self.show() if not self.isVisible() else self.hide())

    def save_settings(self):
        console_history = [self.cmd_input.itemText(i) for i in range(self.cmd_input.count())]
        frida_mode = FRIDA_INJECTION_MODE_CLI
        frida_cli_path = FRIDA_CLI_PATH
        if hasattr(self, 'frida_injection_mode'):
            frida_mode = self.frida_injection_mode.currentData() or FRIDA_INJECTION_MODE_CLI
        if hasattr(self, 'frida_cli_path'):
            frida_cli_path = self.frida_cli_path.text().strip() or FRIDA_CLI_PATH
        d = {"scale": self.scale_spin.value(), "last_pkg": self.target_pkg.currentText(),
             "path_history": self.path_history, "console_history": console_history,
             "frida_injection_mode": frida_mode, "frida_cli_path": frida_cli_path}
        with open(CONFIG_FILE, 'w') as f: json.dump(d, f)

    def load_settings(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f);
                    self.scale_spin.setValue(d.get("scale", 100));
                    self.target_pkg.setCurrentText(d.get("last_pkg", ""))
                    self.path_history = d.get("path_history", ["/", "/sdcard"]);
                    self.cmd_input.clear();
                    history = d.get("console_history", [])
                    if history: self.cmd_input.addItems(history)
                    self.path_box.clear();
                    self.path_box.addItems(self.path_history)

                    frida_mode = d.get("frida_injection_mode", FRIDA_INJECTION_MODE_CLI)
                    if hasattr(self, 'frida_injection_mode'):
                        idx = self.frida_injection_mode.findData(frida_mode)
                        self.frida_injection_mode.setCurrentIndex(idx if idx >= 0 else 0)
                    if hasattr(self, 'frida_cli_path'):
                        self.frida_cli_path.setText(d.get("frida_cli_path", FRIDA_CLI_PATH))
            except Exception as e:
                print(f"Load error: {e}")

    def refresh_local_ip(self):
        ip = self.get_ip();
        self.px_in.setText(f"{ip}:8080");
        self.adb_out.append(f"[SYSTEM] IP Refreshed: {ip}")

    def set_burp_proxy(self):
        self.run_adb_cmd(f"{ADB_PATH} shell settings put global http_proxy {self.px_in.text()}")

    def clear_burp_proxy(self):
        self.run_adb_cmd(f"{ADB_PATH} shell settings put global http_proxy :0")

    def fetch_all_apps(self):
        try:
            res = subprocess.check_output(f"{ADB_PATH} shell pm list packages -3", shell=True, text=True).splitlines()
            pkgs = [l.replace("package:", "").strip() for l in res if l.startswith("package:")]
            self.app_selector.clear();
            self.app_selector.addItems(sorted(pkgs))
        except:
            pass

    def fetch_running_apps(self):
        try:
            res = subprocess.check_output(f"{ADB_PATH} shell ps -A", shell=True, text=True).splitlines();
            running = set()
            for l in res:
                p = l.split()
                if len(p) > 8 and "." in p[-1] and not p[-1].startswith("/"): running.add(p[-1])
            self.app_selector.clear();
            self.app_selector.addItems(sorted(list(running)))
        except:
            pass

    def launch_selected_app(self):
        p = self.app_selector.currentText().strip()
        if p: self.run_adb_cmd(f"{ADB_PATH} shell monkey -p {p} -c android.intent.category.LAUNCHER 1")

    def kill_selected_app(self):
        p = self.app_selector.currentText().strip()
        if p and QMessageBox.question(self, "Kill", f"Stop {p}?") == QMessageBox.Yes: self.run_adb_cmd(
            f"{ADB_PATH} shell am force-stop {p}")

    def browse_deployment_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select Package", "", "Android Package (*.apk *.zip)")
        if p: self.apk_path_display.setText(p)

    def start_installation_process(self):
        path = self.apk_path_display.text()
        if not path: return
        if path.lower().endswith(".apk"):
            self.run_adb_cmd(f"{ADB_PATH} install -r '{path}'")
        elif path.lower().endswith(".zip"):
            tmp = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(path, 'r') as z:
                    apks = [f for f in z.namelist() if f.lower().endswith('.apk')];
                    z.extractall(tmp);
                    paths = [f"'{os.path.join(tmp, a)}'" for a in apks]
                    self.run_adb_cmd(f"{ADB_PATH} install-multiple -r {' '.join(paths)}")
            except:
                pass

    def refresh_remote_fs(self):
        self.remote_table.setRowCount(0);
        self.remote_table.setSortingEnabled(False)
        try:
            res = subprocess.check_output(f"{ADB_PATH} shell ls -al '{self.current_remote_dir}'", shell=True,
                                          text=True).splitlines()
            for line in res[1:]:
                p = line.split()
                if len(p) < 8: continue
                r = self.remote_table.rowCount();
                self.remote_table.insertRow(r)
                perm, sz, date, time_v, name = p[0], p[3], p[5], p[6], " ".join(p[7:])
                it = QTableWidgetItem(f"{'[D] ' if perm.startswith('d') else '[F] '}{name}")
                if perm.startswith('d'): it.setForeground(QColor("#58a6ff")); it.setFont(
                    QFont("Arial", weight=QFont.Bold))
                self.remote_table.setItem(r, 0, it);
                self.remote_table.setItem(r, 1, QTableWidgetItem(sz))
                self.remote_table.setItem(r, 2, QTableWidgetItem(f"{date} {time_v}"));
                self.remote_table.setItem(r, 3, QTableWidgetItem(perm))
        except:
            pass
        self.remote_table.setSortingEnabled(True);
        self.path_box.setCurrentText(self.current_remote_dir)

    def on_remote_item_double_click(self, item):
        if item.column() == 0 and item.text().startswith("[D] "):
            t = os.path.normpath(os.path.join(self.current_remote_dir, item.text()[4:]));
            self.current_remote_dir = t;
            self.path_box.setCurrentText(t)
            if t not in self.path_history: self.path_history.append(t); self.path_box.addItem(t); self.save_settings()
            self.refresh_remote_fs()

    def jump_to_remote_path(self):
        p = self.path_box.currentText().strip()
        if p: self.current_remote_dir = p
        if p not in self.path_history: self.path_history.append(p); self.path_box.addItem(p); self.save_settings()
        self.refresh_remote_fs()

    def remote_dir_up(self):
        if self.current_remote_dir != "/": self.current_remote_dir = os.path.dirname(
            self.current_remote_dir); self.path_box.setCurrentText(self.current_remote_dir); self.refresh_remote_fs()

    def show_remote_context_menu(self, pos):
        it = self.remote_table.itemAt(pos);
        if not it: return
        n = self.remote_table.item(it.row(), 0).text()[4:];
        full = os.path.normpath(os.path.join(self.current_remote_dir, n))
        m = QMenu();
        pull, ren, dele = m.addAction("📤 Pull"), m.addAction("✏️ Rename"), m.addAction("🗑️ Delete")
        act = m.exec_(self.remote_table.mapToGlobal(pos))
        if act == pull:
            (loc := QFileDialog.getSaveFileName(self, "Save", n)[0]) and self.run_adb_cmd(
                f"{ADB_PATH} pull '{full}' '{loc}'")
        elif act == ren:
            (new, ok) = QInputDialog.getText(self, "Rename", "Name:", text=n);
            ok and self.run_adb_cmd(
                f"{ADB_PATH} shell mv '{full}' '{os.path.join(self.current_remote_dir, new)}'");
            self.refresh_remote_fs()
        elif act == dele:
            (QMessageBox.question(self, "Del", f"Delete {n}?")) == QMessageBox.Yes and self.run_adb_cmd(
                f"{ADB_PATH} shell rm -rf '{full}'");
            self.refresh_remote_fs()

    def push_remote_file(self):
        loc = QFileDialog.getOpenFileName(self, "Push")[0]
        if loc: self.run_adb_cmd(f"{ADB_PATH} push '{loc}' '{self.current_remote_dir}'"); self.refresh_remote_fs()

    def preview_remote_file(self):
        sel = self.remote_table.selectedItems()
        if sel and sel[0].text().startswith("[F] "):
            try:
                cmd = f"{ADB_PATH} shell \"head -c 2048 '{os.path.normpath(os.path.join(self.current_remote_dir, sel[0].text()[4:]))}'\""
                self.preview_box.setText(
                    subprocess.check_output(cmd, shell=True, text=False).decode('utf-8', errors='replace'))
            except Exception as e:
                self.preview_box.setText(f"Preview Error: {str(e)}")
        else:
            self.preview_box.clear()

    def refresh_procs(self):
        try:
            self.proc_table.setRowCount(0);
            self.proc_table.setSortingEnabled(False);
            dev = frida.get_usb_device();
            pkgs = [];
            apps = dev.enumerate_applications()
            for app in apps:
                r = self.proc_table.rowCount();
                self.proc_table.insertRow(r)
                self.proc_table.setItem(r, 0, QTableWidgetItem(app.name));
                self.proc_table.setItem(r, 1, QTableWidgetItem(app.identifier));
                pkgs.append(app.identifier)
            self.target_pkg.clear();
            self.target_pkg.addItems(sorted(list(set(pkgs))));
            self.target_completer.setModel(self.target_pkg.model());
            self.proc_table.setSortingEnabled(True)
        except Exception as e:
            self.adb_out.append(f"[ERROR] Failed to fetch apps: {str(e)}")

    def on_process_clicked(self, item):
        self.target_pkg.setCurrentText(self.proc_table.item(item.row(), 1).text())

    def on_file_clicked(self, i):
        p = self.f_model.filePath(i);
        (os.path.isfile(p)) and open(p).read() and self.editor.setText(
            open(p).read());
        self.current_file_path = p

    def start_forge(self):
        self.stop_frida_worker();
        pkg, code = self.target_pkg.currentText().strip(), self.editor.toPlainText()
        if not pkg:
            self.route_frida_log("ERROR", "No target package selected.")
            return
        mode = self.frida_injection_mode.currentData() if hasattr(self, 'frida_injection_mode') else FRIDA_INJECTION_MODE_CLI
        frida_bin = self.frida_cli_path.text().strip() if hasattr(self, 'frida_cli_path') else FRIDA_CLI_PATH
        self.worker = FridaWorker(pkg, code, mode, frida_bin)
        self.worker.log_signal.connect(self.route_frida_log)
        self.worker.start()
        self.tabs.setCurrentIndex(2)
        self.save_settings()

    def stop_frida_worker(self):
        if self.worker:
            try:
                self.worker.stop()
                self.worker.wait(1500)
            except Exception:
                pass
            self.route_frida_log("SYSTEM", "Detached.")
            self.worker = None

    def start_logcat_stream(self):
        self.log_worker = LogcatWorker();
        self.log_worker.new_log_signal.connect(
            self.process_new_log);
        self.log_worker.start()

    def process_new_log(self, line):
        if self.log_paused: return
        cur_lvl = self.log_levels[self.log_level_box.currentText()];
        order = ["V", "D", "I", "W", "E", "F"];
        line_lvl = "V"
        for code in order[::-1]:
            if f" {code} " in line or f" {code}/" in line: line_lvl = code; break
        if order.index(line_lvl) < order.index(cur_lvl) or (
                self.log_filter.text().lower() not in line.lower() and self.log_hard_filter.isChecked()): return
        c = {"V": "#8b949e", "D": "#79c0ff", "I": "#aff5b4", "W": "#ffa657", "E": "#ff7b72", "F": "#f85149"}.get(
            line_lvl, "#d1d5da")
        self.log_display.append(f'<font color="{c}">{line}</font>');
        self.log_display.moveCursor(QTextCursor.End)

    def _clean_terminal_text(self, value):
        """Remove ANSI escape/control characters before writing into QTextEdit HTML."""
        text = str(value or "")
        # ANSI CSI/OSC/style sequences such as ESC[0m can hide or corrupt text in QTextEdit.
        text = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
        return text.strip()

    def _append_toolbox_status(self, tag, message, color="#c9d1d9"):
        safe_tag = html.escape(self._clean_terminal_text(tag), quote=False)
        safe_message = html.escape(self._clean_terminal_text(message), quote=False)
        line = f"<font color='{color}'>[{safe_tag}] {safe_message}</font>"
        try:
            self.adb_out.append(line)
        except Exception:
            pass
        try:
            self.console.append(line)
        except Exception:
            pass

    def _read_subprocess_version(self, cmd, timeout=8, env=None, shell=False):
        try:
            result = subprocess.run(
                cmd,
                shell=shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                env=env
            )
            output = self._clean_terminal_text(result.stdout or "")
            if output:
                # Prefer a real semantic version if present anywhere in the tool output.
                # This avoids returning stray terminal reset strings or banner text.
                m = re.search(r"(\d+\.\d+\.\d+)", output)
                if m:
                    return m.group(1)
                lines = [ln.strip() for ln in output.splitlines() if ln.strip()]
                return lines[-1] if lines else f"no output (exit {result.returncode})"
            return f"no output (exit {result.returncode})"
        except FileNotFoundError:
            return "not found"
        except subprocess.TimeoutExpired:
            return "timeout"
        except Exception as e:
            return f"error: {str(e)}"

    def show_frida_versions(self):
        """Report local Frida CLI, Python frida API, and Android frida-server versions."""
        self._append_toolbox_status("FRIDA VERSION", "Checking local CLI, Python API module, and Android frida-server...", "#58a6ff")

        # Python API version. This is the version used by Python API injection mode.
        py_ver = getattr(frida, "__version__", None) or "unknown"
        self._append_toolbox_status("FRIDA VERSION", f"Python API module: {py_ver}", "#7ee787")

        compiler_state = "available" if hasattr(frida, "Compiler") else "missing"
        bridge_dir = os.path.join(FRIDA_API_AGENT_DIR, "node_modules", "frida-java-bridge")
        bridge_state = "installed" if os.path.isdir(bridge_dir) else "not installed yet"
        self._append_toolbox_status("FRIDA VERSION", f"Python API compiler: {compiler_state}; Java bridge package: {bridge_state}", "#7ee787" if compiler_state == "available" else "#ffa657")

        # Local CLI / frida-tools version. This is the version used by CLI injection mode.
        frida_bin = FRIDA_CLI_PATH
        try:
            if hasattr(self, 'frida_cli_path'):
                frida_bin = self.frida_cli_path.text().strip() or FRIDA_CLI_PATH
        except Exception:
            pass

        if not frida_bin or not os.path.exists(frida_bin):
            auto_path = shutil.which("frida")
            if auto_path:
                frida_bin = auto_path

        if frida_bin and os.path.exists(frida_bin):
            env = os.environ.copy()
            env["PATH"] = os.path.dirname(frida_bin) + os.pathsep + env.get("PATH", "")
            cli_ver = self._read_subprocess_version([frida_bin, "--version"], timeout=8, env=env)
            self._append_toolbox_status("FRIDA VERSION", f"Local CLI/frida-tools: {cli_ver} ({frida_bin})", "#7ee787")
        else:
            self._append_toolbox_status("FRIDA VERSION", f"Local CLI/frida-tools: not found. Current path: {frida_bin}", "#ff7b72")

        # Android frida-server version. Try normal shell first, then su -c fallback.
        server_cmd = [ADB_PATH, "shell", "/data/local/tmp/frida-server --version"]
        server_ver = self._read_subprocess_version(server_cmd, timeout=8)
        needs_su_retry = (
            not server_ver or
            "permission denied" in server_ver.lower() or
            "not found" in server_ver.lower() or
            "inaccessible" in server_ver.lower() or
            "no such file" in server_ver.lower()
        )
        if needs_su_retry:
            su_cmd = [ADB_PATH, "shell", "su -c '/data/local/tmp/frida-server --version'"]
            server_ver = self._read_subprocess_version(su_cmd, timeout=8)

        self._append_toolbox_status("FRIDA VERSION", f"Android frida-server: {server_ver} (/data/local/tmp/frida-server)", "#7ee787")

        # Quick mismatch warning. Matching major/minor is normally the important part.
        parsed = []
        for val in [str(py_ver), str(locals().get('cli_ver', '')), str(server_ver)]:
            m = re.search(r"(\d+)\.(\d+)\.(\d+)", val)
            parsed.append(m.group(0) if m else None)
        known = [p for p in parsed if p]
        if len(set(known)) > 1:
            self._append_toolbox_status(
                "FRIDA VERSION",
                "WARNING: Version mismatch detected. Keep Python frida, frida-tools, and frida-server on the same version when possible.",
                "#ffa657"
            )
        elif known:
            self._append_toolbox_status("FRIDA VERSION", f"Versions appear aligned: {known[0]}", "#7ee787")

    def load_adb_buttons(self):
        for i in reversed(range(self.adb_grid_layout.count())):
            if self.adb_grid_layout.itemAt(i).widget(): self.adb_grid_layout.itemAt(i).widget().setParent(None)
        cmds = {"🔄 Reboot": "reboot",
                "🚀 Boot Frida": "shell \"su -c '/data/local/tmp/frida-server -l 0.0.0.0 > /dev/null 2>&1 &'\"",
                "💀 Kill Frida": "shell \"su -c pkill -9 frida-server\"",
                "Frida Running?": "shell \"su -c ps -A | grep frida\"",
                "🔓 Unlock": "shell \"input keyevent 82\"",
                "📍 Top App": "shell \"dumpsys activity responses | grep -E 'mFocusedApp'\"",
                "📦 Apps": "shell \"pm list packages -3\""}
        if os.path.exists(CMD_FILE):
            try:
                custom_cmds = json.load(open(CMD_FILE))
                if isinstance(custom_cmds, dict):
                    cmds.update(custom_cmds)
            except:
                pass

        # Force the built-in Frida version checker to remain diagnostic even if commands.json
        # contains an older simple frida-server-only command with the same name.
        cmds["Frida version"] = self.show_frida_versions

        r, c = 0, 0
        for n, cmd in cmds.items():
            btn = QPushButton(n);
            if callable(cmd):
                btn.clicked.connect(cmd)
            else:
                btn.clicked.connect(lambda _, x=cmd: self.run_adb_cmd(f"{ADB_PATH} {x}"));
            btn.setContextMenuPolicy(Qt.CustomContextMenu);
            btn.customContextMenuRequested.connect(lambda pos, name=n: self.show_cmd_context(name));
            self.adb_grid_layout.addWidget(btn, r, c);
            c += 1
            if c > 3: r += 1; c = 0

    def add_custom_command(self):
        n, ok1 = QInputDialog.getText(self, "New", "Title:")
        if ok1 and n:
            c, ok2 = QInputDialog.getText(self, "Cmd", "ADB Cmd:")
            if ok2 and c: cust = {}; (os.path.exists(CMD_FILE)) and (cust := json.load(open(CMD_FILE))); cust[
                n] = c; json.dump(cust, open(CMD_FILE, 'w')); self.load_adb_buttons()

    def show_cmd_context(self, name):
        m = QMenu();
        d = m.addAction("Delete");
        (m.exec_(self.cursor().pos()) == d) and (cust := json.load(open(CMD_FILE))) and (cust.pop(name, None)) and (
            json.dump(cust, open(CMD_FILE, 'w'))) or self.load_adb_buttons()

    def show_file_context_menu(self, pos):
        idx = self.f_tree.indexAt(pos);
        if not idx.isValid(): return
        p, d = self.f_model.filePath(idx), self.f_model.isDir(idx);
        m = QMenu();
        n_s = m.addAction("📄 New Script");
        n_f = m.addAction("📁 New Folder");
        ren = m.addAction("✏️ Rename");
        dele = m.addAction("🗑️ Delete")
        act = m.exec_(self.f_tree.mapToGlobal(pos));
        t = p if d else os.path.dirname(p)
        if act == n_s:
            self.create_new_script(t)
        elif act == n_f:
            self.create_new_folder(t)
        elif act == ren:
            (new, ok) = QInputDialog.getText(self, "Rename", "Name:",
                                             text=self.f_model.fileName(idx));
            ok and self.f_model.setData(idx, new)
        elif act == dele:
            (QMessageBox.question(self, "Del", "Delete?")) == QMessageBox.Yes and self.f_model.remove(idx)

    def create_new_project(self):
        (n := QInputDialog.getText(self, "Project", "Name:")[0]) and os.makedirs(os.path.join(PROJECTS_DIR, n),
                                                                                 exist_ok=True)

    def create_new_script(self, p):
        (n := QInputDialog.getText(self, "Script", "Name:")[0]) and open(os.path.join(p, n + ".js"), 'w').write(
            "// Frida\nJava.perform(function() {});")

    def create_new_folder(self, p):
        (n := QInputDialog.getText(self, "Folder", "Name:")[0]) and os.makedirs(os.path.join(p, n), exist_ok=True)

    def beautify_code(self):
        try:
            raw_code = self.editor.toPlainText()
            if not raw_code.strip(): return
            opts = jsbeautifier.default_options();
            opts.indent_size = 4;
            opts.space_in_empty_paren = True
            self.editor.setText(jsbeautifier.beautify(raw_code, opts));
            self.adb_out.append("[SYSTEM] Code beautified successfully.")
        except Exception as e:
            QMessageBox.warning(self, "Beautify Error", f"Could not beautify: {str(e)}")

    def save_script(self):
        (self.current_file_path) and open(self.current_file_path, 'w').write(self.editor.toPlainText())

    def run_proc_filter(self):
        (q := self.p_search.text().lower()) and [
            self.proc_table.setRowHidden(i, q not in self.proc_table.item(i, 0).text().lower()) for i in
            range(self.proc_table.rowCount())]

    def run_fs_filter(self):
        (q := self.fs_filter.text().lower()) and [
            self.remote_table.setRowHidden(i, q not in self.remote_table.item(i, 0).text().lower()) for i in
            range(self.remote_table.rowCount())]

    def normalize_frida_log_level(self, level):
        return str(level or "LOG").upper().strip()

    def frida_log_group(self, level):
        level = self.normalize_frida_log_level(level)
        if level in ("FRIDA", "LOG"):
            return "FRIDA_LOG"
        if level == "SYSTEM":
            return "SYSTEM"
        if level == "SCRIPT":
            return "SCRIPT"
        if level in ("ERROR", "CRITICAL", "WARN", "WARNING"):
            return "ERROR"
        return "FRIDA_LOG"

    def frida_log_color(self, level):
        group = self.frida_log_group(level)
        return {
            "FRIDA_LOG": "#7ee787",
            "SYSTEM": "#58a6ff",
            "SCRIPT": "#d2a8ff",
            "ERROR": "#ff7b72",
        }.get(group, "#d1d5da")

    def frida_log_group_enabled(self, level):
        group = self.frida_log_group(level)
        checkbox_name = {
            "FRIDA_LOG": "chk_frida_log",
            "SYSTEM": "chk_frida_system",
            "SCRIPT": "chk_frida_script",
            "ERROR": "chk_frida_error",
        }.get(group)
        checkbox = getattr(self, checkbox_name, None)
        return True if checkbox is None else checkbox.isChecked()

    def frida_log_matches_filter(self, level, message):
        if not self.frida_log_group_enabled(level):
            return False

        search_box = getattr(self, "frida_filter", None)
        search_text = search_box.text().strip().lower() if search_box else ""
        if not search_text:
            return True

        combined = f"[{self.normalize_frida_log_level(level)}] {message}".lower()
        return search_text in combined

    def format_frida_log_html(self, level, message):
        safe_level = html.escape(self.normalize_frida_log_level(level), quote=False)
        safe_msg = html.escape(str(message), quote=False)
        color = self.frida_log_color(level)
        return (
            f"<span style='color:{color}; font-weight:bold;'>[{safe_level}]</span> "
            f"<span style='color:{color};'>{safe_msg}</span>"
        )

    def refresh_frida_log_display(self):
        if not hasattr(self, "frida_display"):
            return
        self.frida_display.clear()
        for level, message in getattr(self, "frida_log_entries", []):
            if self.frida_log_matches_filter(level, message):
                self.frida_display.append(self.format_frida_log_html(level, message))
        self.frida_display.moveCursor(QTextCursor.End)

    def clear_frida_logs(self):
        self.frida_log_entries = []
        if hasattr(self, "frida_display"):
            self.frida_display.clear()

    def route_frida_log(self, l, m):
        level = self.normalize_frida_log_level(l)
        message = str(m)

        if self.frida_paused:
            if hasattr(self, "frida_display"):
                self.frida_display.moveCursor(QTextCursor.End)
            return

        self.frida_log_entries.append((level, message))
        if len(self.frida_log_entries) > self.frida_log_max_entries:
            self.frida_log_entries = self.frida_log_entries[-self.frida_log_max_entries:]

        if hasattr(self, "frida_display") and self.frida_log_matches_filter(level, message):
            self.frida_display.append(self.format_frida_log_html(level, message))
            self.frida_display.moveCursor(QTextCursor.End)

    def toggle_frida_pause(self):
        self.frida_paused = not self.frida_paused
        if hasattr(self, "btn_frida_pause"):
            self.btn_frida_pause.setText("▶ Resume" if self.frida_paused else "⏸ Pause")

    def toggle_log_pause(self):
        self.log_paused = not self.log_paused

    def get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
            s.connect(("8.8.8.8", 80));
            ip = s.getsockname()[0];
            s.close();
            return ip
        except:
            return "127.0.0.1"

    def take_snapshot(self):
        ts = int(time.time());
        filename = f"screen_{ts}.png";
        target_path = os.path.join(SCRAP_DIR, filename);
        temp_phone_path = "/data/local/tmp/s.png"
        try:
            self.console.append(f"<font color='#58a6ff'><b>></b> Capturing Framebuffer...</font>")
            subprocess.run([ADB_PATH, "shell", "su", "-c", f"screencap -p {temp_phone_path}"], check=True)
            subprocess.run([ADB_PATH, "pull", temp_phone_path, target_path], check=True);
            timeout = 10
            while not os.path.exists(target_path) and timeout > 0: time.sleep(0.1); timeout -= 1
            if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                self.load_image_history();
                self.update_viewer_ui();
                self.copy_image_to_clipboard_and_portal(target_path)
                self.console.append(f"<font color='#7ee787'>[SUCCESS] Loaded {filename}</font>")
            subprocess.run([ADB_PATH, "shell", "su", "-c", f"rm {temp_phone_path}"])
        except Exception as e:
            self.console.append(f"<font color='#ff7b72'>[ERROR] Snapshot failed: {str(e)}</font>")

    def copy_image_to_clipboard_and_portal(self, path=None):
        if not path:
            if self.current_image_index >= 0 and self.captured_images:
                path = self.captured_images[self.current_image_index]
            else:
                return
        if not os.path.exists(path): self.console.append(
            f"<font color='red'>[ERROR] File missing: {path}</font>"); return
        img = QImage(path)
        if not img.isNull():
            clip = QApplication.clipboard()
            scale_val = self.scale_spin.value() / 100.0
            if scale_val != 1.0: img = img.scaled(img.size() * scale_val, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            clip.setImage(img);
            self.console.append(f"<font color='#7ee787'>[CLIPBOARD] Copied {os.path.basename(path)}</font>")
            portal_url = "https://screenshot.googleplex.com/";
            os.system(f"open {portal_url}")
            self.console.append(f"<font color='#58a6ff'>[PORTAL] Opening browser...</font>")

    def load_image_history(self):
        self.captured_images = sorted([os.path.join(SCRAP_DIR, f) for f in os.listdir(SCRAP_DIR) if f.endswith(".png")],
                                      key=os.path.getmtime)
        self.current_image_index = len(self.captured_images) - 1 if self.captured_images else -1

    def update_viewer_ui(self):
        if self.current_image_index >= 0 and self.captured_images:
            path = self.captured_images[self.current_image_index];
            pixmap = QPixmap(path)
            if not pixmap.isNull():
                self.viewer.setPixmap(pixmap.scaled(self.viewer.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation));
                self.img_info.setText(os.path.basename(path))
            else:
                self.console.append(f"<font color='red'>Error: Pixmap is null for {path}</font>")
        else:
            self.viewer.clear();
            self.img_info.setText("Empty")

    def cycle_image(self, d):
        (self.captured_images) and (setattr(self, 'current_image_index', (self.current_image_index + d) % len(
            self.captured_images)) or self.update_viewer_ui())

    def delete_current_image(self):
        (self.current_image_index >= 0) and (os.remove(
            self.captured_images[self.current_image_index]) or self.load_image_history() or self.update_viewer_ui())

    def clear_all_images(self):
        if self.captured_images:
            for f in self.captured_images:
                try:
                    os.remove(f)
                except:
                    pass
            setattr(self, 'captured_images', []);
            setattr(self, 'current_image_index', -1);
            self.update_viewer_ui()

    def run_adb_cmd(self, cmd):
        if self.adb_process.state() == QProcess.Running:
            self.adb_process.terminate()
            self.adb_process.waitForFinished(1000)
        self.adb_process.start(cmd)


if __name__ == "__main__":
    app = QApplication(sys.argv);
    app.setQuitOnLastWindowClosed(False);
    window = Forensics();
    window.show();
    sys.exit(app.exec_())
