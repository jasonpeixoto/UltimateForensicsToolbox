import sys
import os
import glob
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
import webbrowser
import io
import csv
import struct
import hashlib
import base64
import xml.dom.minidom
import requests  # Retained for proxy validation connection handshakes
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QTextEdit, QTextBrowser, QPlainTextEdit, QListWidget, QLabel,
                             QTabWidget, QStackedWidget, QScrollArea, QHeaderView, QFrame, QLineEdit,
                             QRadioButton, QButtonGroup,
                             QMessageBox, QListWidgetItem, QTreeWidget, QTreeWidgetItem, QGridLayout, QGroupBox,
                             QInputDialog, QTreeView, QFileSystemModel, QProxyStyle,
                             QStyle, QComboBox, QCompleter, QSpinBox, QMenu, QCheckBox, QColorDialog,
                             QFileDialog, QSplitter, QSystemTrayIcon, QAction,
                             QSizePolicy, QDialog, QToolBar, QFontComboBox, QShortcut, QTabBar, QSpacerItem, QAbstractItemView, QProgressBar, QDialogButtonBox, QFormLayout, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRegExp, QProcess, QDir, QSize, QModelIndex, QTimer, QRect, QEvent, QUrl, QProcessEnvironment, QObject, QRegularExpression, QSortFilterProxyModel, QPoint
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QBrush, QPixmap, QImage, QTextCursor, QIcon, QPainter, QTextListFormat, QDesktopServices, QKeySequence, QTextDocument, QStandardItemModel, QStandardItem

from PyQt5.QtPrintSupport import QPrinter

# Optional spellcheck support for Security Review Workstation
try:
    import enchant
    HAS_ENCHANT = True
except ImportError:
    HAS_ENCHANT = False

# --- SYSTEM SETTINGS ---
BASE_DIR = os.path.expanduser("~/.jpeixoto/UltimateForensicsToolbox")
VAULT_DIR, PROJECTS_DIR, SCRAP_DIR = [os.path.join(BASE_DIR, x) for x in ["Global_Vault", "Projects", "Scrap"]]
CMD_FILE = os.path.join(BASE_DIR, "commands.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config_DecryptCocoas.json")
MANUAL_PROXY_FILE = os.path.join(BASE_DIR, "manual_proxies.json")
FRIDA_TEMPLATE_FILE = os.path.join(BASE_DIR, "frida_proxy_template.js")
FRIDA_SCRIPTS_DIR = os.path.join(BASE_DIR, "FridaScripts")
PROXY_PROFILES_FILE = os.path.join(BASE_DIR, "proxy_profiles.json")
SESSIONS_DIR = os.path.join(BASE_DIR, "Sessions")
NETWORK_CAPTURE_DIR = os.path.join(BASE_DIR, "NetworkCaptures")
APK_EXPLORER_CACHE_DIR = os.path.expanduser("~/.jpeixoto/ApkExplorer/dex_cache")
PROXIFLY_ALL_PROXY_JSON_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json"

PROXY_IMPORT_SOURCES = [
    {"id": "proxifly_all_json", "name": "Proxifly - All protocols JSON", "url": PROXIFLY_ALL_PROXY_JSON_URL, "format": "json", "protocol": "auto", "source": "proxifly/free-proxy-list"},
    {"id": "proxyscrape_http", "name": "ProxyScrape - HTTP", "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", "format": "text", "protocol": "http", "source": "proxyscrape"},
    {"id": "proxyscrape_socks4", "name": "ProxyScrape - SOCKS4", "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all", "format": "text", "protocol": "socks4", "source": "proxyscrape"},
    {"id": "proxyscrape_socks5", "name": "ProxyScrape - SOCKS5", "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all", "format": "text", "protocol": "socks5", "source": "proxyscrape"},
    {"id": "thespeedx_http", "name": "TheSpeedX - HTTP", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "format": "text", "protocol": "http", "source": "TheSpeedX/PROXY-List"},
    {"id": "thespeedx_socks4", "name": "TheSpeedX - SOCKS4", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "format": "text", "protocol": "socks4", "source": "TheSpeedX/PROXY-List"},
    {"id": "thespeedx_socks5", "name": "TheSpeedX - SOCKS5", "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "format": "text", "protocol": "socks5", "source": "TheSpeedX/PROXY-List"},
    {"id": "monosans_json", "name": "monosans - Detailed JSON", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json", "format": "json", "protocol": "auto", "source": "monosans/proxy-list"},
    {"id": "monosans_http", "name": "monosans - HTTP", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "format": "text", "protocol": "http", "source": "monosans/proxy-list"},
    {"id": "monosans_socks4", "name": "monosans - SOCKS4", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "format": "text", "protocol": "socks4", "source": "monosans/proxy-list"},
    {"id": "monosans_socks5", "name": "monosans - SOCKS5", "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "format": "text", "protocol": "socks5", "source": "monosans/proxy-list"},
    {"id": "jetkai_http", "name": "jetkai - HTTP", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt", "format": "text", "protocol": "http", "source": "jetkai/proxy-list"},
    {"id": "jetkai_https", "name": "jetkai - HTTPS", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt", "format": "text", "protocol": "https", "source": "jetkai/proxy-list"},
    {"id": "jetkai_socks4", "name": "jetkai - SOCKS4", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt", "format": "text", "protocol": "socks4", "source": "jetkai/proxy-list"},
    {"id": "jetkai_socks5", "name": "jetkai - SOCKS5", "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", "format": "text", "protocol": "socks5", "source": "jetkai/proxy-list"},
]

for d in [BASE_DIR, VAULT_DIR, PROJECTS_DIR, SCRAP_DIR, FRIDA_SCRIPTS_DIR, SESSIONS_DIR, NETWORK_CAPTURE_DIR, APK_EXPLORER_CACHE_DIR]:
    os.makedirs(d, exist_ok=True)

ADB_PATH = shutil.which("adb") or "/usr/local/bin/adb"
FRIDA_CLI_PATH = shutil.which("frida") or "/opt/homebrew/bin/frida"
FRIDA_INJECTION_MODE_CLI = "cli"
FRIDA_INJECTION_MODE_PYTHON = "python_api"
FRIDA_API_AGENT_DIR = os.path.join(BASE_DIR, "frida_api_agent_bridge")

UNITY_APP_PREP_BASE_PATH = os.path.expanduser("~/.jpeixoto/Frameworks/UnityAppPrep")
os.makedirs(UNITY_APP_PREP_BASE_PATH, exist_ok=True)
UNITY_APP_PREP_CONFIG_FILE = os.path.join(UNITY_APP_PREP_BASE_PATH, "unity_prep_config.json")


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
    proxy_found_signal = pyqtSignal(str, str, str)

    def __init__(self, country_code, auto_fallback, include_socks=False, proxy_timeout_seconds=10):
        super().__init__()
        self.country_code = str(country_code).upper().strip() if country_code else "IN"
        self.auto_fallback = auto_fallback
        # HTTP/HTTPS proxies are always included. SOCKS/SOCKS4/SOCKS5 proxies are optional
        # because they require PySocks support in requests and use different Java properties.
        self.include_socks = bool(include_socks)
        try:
            self.proxy_timeout_seconds = max(3, min(60, int(proxy_timeout_seconds)))
        except Exception:
            self.proxy_timeout_seconds = 10
        self.running = True
        self.cache_file = os.path.join(BASE_DIR, "proxy_cache.json")

    def normalize_proxy_protocol(self, proto):
        proto = str(proto or "http").lower().strip()
        if proto in ("socks", "socks4", "socks5"):
            return proto
        if proto in ("http", "https"):
            return proto
        return "http"

    def protocol_family(self, proto):
        proto = self.normalize_proxy_protocol(proto)
        return "socks" if proto.startswith("socks") else "http"

    def protocol_allowed(self, proto):
        family = self.protocol_family(proto)
        return family == "http" or self.include_socks

    def describe_proxy_failure(self, exc, elapsed_seconds):
        """Return a user-friendly failure category for proxy validation.

        A node can fail immediately without waiting for the timeout when the remote host
        refuses the TCP connection, resets it, closes the proxy tunnel, returns a proxy
        protocol error, or fails TLS negotiation. Only actual connect/read timeouts should
        be labelled as TIMEOUT.
        """
        detail = str(exc).replace("\n", " ").strip()
        if len(detail) > 220:
            detail = detail[:217] + "..."

        if isinstance(exc, requests.exceptions.Timeout):
            return "TIMEOUT", f"Timeout after {elapsed_seconds:.1f}s"

        if isinstance(exc, requests.exceptions.ProxyError):
            low = detail.lower()
            if "connection refused" in low:
                return "NODE DROPPED", "Connection refused by proxy host"
            if "connection reset" in low or "reset by peer" in low:
                return "NODE DROPPED", "Connection reset by proxy host"
            if "remote end closed" in low or "closed connection" in low:
                return "NODE DROPPED", "Proxy closed the connection"
            if "tunnel" in low:
                return "PROXY ERROR", "Proxy tunnel failed"
            return "PROXY ERROR", detail or "Proxy protocol failure"

        if isinstance(exc, requests.exceptions.SSLError):
            return "SSL ERROR", detail or "TLS/SSL negotiation failed"

        if isinstance(exc, requests.exceptions.ConnectionError):
            low = detail.lower()
            if "connection refused" in low:
                return "NODE DROPPED", "Connection refused immediately"
            if "connection reset" in low or "reset by peer" in low:
                return "NODE DROPPED", "Connection reset by peer"
            if "no route to host" in low or "network is unreachable" in low:
                return "NODE DROPPED", "Network unreachable / no route to host"
            if "remote end closed" in low or "closed connection" in low:
                return "NODE DROPPED", "Remote side closed connection"
            return "CONNECTION ERROR", detail or "Connection failed"

        if isinstance(exc, requests.exceptions.InvalidProxyURL):
            return "BAD PROXY URL", detail or "Invalid proxy URL"

        if isinstance(exc, requests.exceptions.RequestException):
            return "REQUEST ERROR", detail or "Request failed"

        return "ERROR", detail or exc.__class__.__name__

    def mark_proxy_failure(self, cache, node, proto, ip, port, failure_type="FAIL"):
        node["rank"] = node.get("rank", 0) - 5
        if self.country_code not in cache:
            cache[self.country_code] = []
        existing = next((x for x in cache[self.country_code] if x.get("ip") == ip and str(x.get("port")) == str(port)), None)
        if existing:
            existing["rank"] = node["rank"]
            existing["protocol"] = proto
            existing["last_status"] = failure_type
            existing["last_checked"] = int(time.time())
        else:
            cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"], "protocol": proto, "last_status": failure_type, "last_checked": int(time.time())})
        self.save_cache(cache)

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

        proxy_mode = "HTTP/HTTPS + SOCKS" if self.include_socks else "HTTP/HTTPS only"
        self.status_signal.emit("INFO", f"Loading local file array for [{self.country_code}] ({proxy_mode})...")
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
                    proto = self.normalize_proxy_protocol(item.get("protocol", "http"))
                    # HTTP/HTTPS records are always eligible. SOCKS records are only eligible when enabled.
                    if not self.protocol_allowed(proto):
                        continue

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
        self.status_signal.emit("INFO", f"Proxy testing uses an isolated requests session and will not modify macOS proxy settings. Timeout: {self.proxy_timeout_seconds}s.")
        self.status_signal.emit("INFO", "Proxy failure diagnostics v27 active: fast failures show NODE DROPPED / CONNECTION ERROR / PROXY ERROR / SSL ERROR / TIMEOUT with elapsed seconds.")

        session = requests.Session()
        # Do not inherit HTTP_PROXY/HTTPS_PROXY/NO_PROXY or macOS/system proxy environment.
        # The candidate proxy below is used only for this one validation request.
        session.trust_env = False

        for idx, node in enumerate(country_pool):
            if not self.running: break

            ip, port = node["ip"], str(node["port"])
            proto = node.get("protocol", "http")
            self.status_signal.emit("TESTING",
                                    f"[{idx + 1}/{len(country_pool)}] Handshake target -> {proto}://{ip}:{port} (Rank: {node.get('rank', 0)})")

            proxy_url = f"{proto}://{ip}:{port}" if "socks" in proto else f"http://{ip}:{port}"
            test_proxies = {"http": proxy_url, "https": proxy_url}
            start_time = time.monotonic()

            try:
                test_res = session.get("https://www.google.com", proxies=test_proxies, timeout=self.proxy_timeout_seconds)
                elapsed = time.monotonic() - start_time

                if test_res.status_code == 200:
                    self.status_signal.emit("SUCCESS", f"Validated active pipeline path: {proto}://{ip}:{port}! ({elapsed:.1f}s)")
                    try:
                        ip_start = time.monotonic()
                        ip_res = session.get("https://api.ipify.org", proxies=test_proxies, timeout=max(self.proxy_timeout_seconds, 10))
                        ip_elapsed = time.monotonic() - ip_start
                        egress_ip = ip_res.text.strip()
                        if egress_ip:
                            self.status_signal.emit("INFO", f"Proxy egress IP reported by api.ipify.org: {egress_ip} ({ip_elapsed:.1f}s)")
                    except Exception as ip_err:
                        self.status_signal.emit("WARN", f"Could not verify proxy egress IP: {str(ip_err)}")
                    node["rank"] = node.get("rank", 0) + 1

                    if self.country_code not in cache: cache[self.country_code] = []
                    existing = next((x for x in cache[self.country_code] if x["ip"] == ip and str(x["port"]) == port),
                                    None)
                    if existing:
                        existing["rank"] = node["rank"]
                        existing["protocol"] = proto
                        existing["last_status"] = "OK"
                        existing["last_checked"] = int(time.time())
                    else:
                        cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"], "protocol": proto, "last_status": "OK", "last_checked": int(time.time())})

                    self.save_cache(cache)
                    self.proxy_found_signal.emit(ip, port, proto)
                    return

                self.mark_proxy_failure(cache, node, proto, ip, port, failure_type=f"HTTP {test_res.status_code}")
                self.status_signal.emit("WARN", f"Bad response from node: HTTP {test_res.status_code} after {elapsed:.1f}s. Moving to next baseline option...")
                if self.auto_fallback:
                    continue
                return

            except Exception as e:
                elapsed = time.monotonic() - start_time
                if "socks" in str(proto).lower() and ("SOCKS" in str(e) or "Missing dependencies" in str(e)):
                    self.status_signal.emit("ERROR", "SOCKS proxy validation requires PySocks. Install it with: pip install PySocks")

                failure_type, failure_reason = self.describe_proxy_failure(e, elapsed)
                self.mark_proxy_failure(cache, node, proto, ip, port, failure_type=failure_type)

                if self.auto_fallback:
                    self.status_signal.emit("WARN", f"{failure_type}: {failure_reason} ({elapsed:.1f}s). Moving to next baseline option...")
                    continue
                else:
                    self.status_signal.emit("ERROR", f"{failure_type} on test candidate {proto}://{ip}:{port}: {failure_reason} ({elapsed:.1f}s)")
                    return

        self.status_signal.emit("CRITICAL", "Validation matrix exhausted. Zero candidate responses logged.")

    def stop(self):
        self.running = False


class ProxiflyImportWorker(QThread):
    status_signal = pyqtSignal(str, str)
    result_signal = pyqtSignal(object, int, int, int, str)

    def __init__(self, url=PROXIFLY_ALL_PROXY_JSON_URL, timeout_seconds=30):
        super().__init__()
        self.url = url
        try:
            self.timeout_seconds = max(10, min(120, int(timeout_seconds)))
        except Exception:
            self.timeout_seconds = 30
        self.running = True

    def normalize_protocol(self, proto):
        proto = str(proto or "http").lower().strip()
        if proto in ("socks", "socks4", "socks5"):
            return proto
        if proto in ("http", "https"):
            return proto
        return "http"

    def parse_proxy_string(self, value):
        raw = str(value or "").strip()
        if not raw:
            return None
        proto = "http"
        m = re.match(r'^([a-zA-Z0-9+.-]+)://(.+)$', raw)
        if m:
            proto = self.normalize_protocol(m.group(1))
            raw = m.group(2)
        if ":" not in raw:
            return None
        host, port = raw.rsplit(":", 1)
        host = host.strip().strip("[]")
        port = str(port).strip()
        if not host or not port.isdigit():
            return None
        return {"ip": host, "port": int(port), "protocol": proto}

    def country_from_record(self, item):
        if not isinstance(item, dict):
            return ""
        geo = item.get("geolocation") or item.get("geo") or item.get("location") or {}
        if isinstance(geo, dict):
            for key in ("country", "countryCode", "country_code", "iso", "code"):
                val = geo.get(key)
                if val:
                    return str(val).upper().strip()
        for key in ("country", "countryCode", "country_code", "iso", "code"):
            val = item.get(key)
            if val:
                return str(val).upper().strip()
        return ""

    def city_from_record(self, item):
        if not isinstance(item, dict):
            return "Unknown"
        geo = item.get("geolocation") or item.get("geo") or item.get("location") or {}
        if isinstance(geo, dict):
            city = geo.get("city") or geo.get("region") or geo.get("state")
            if city:
                return str(city)
        city = item.get("city") or item.get("region") or item.get("state")
        return str(city) if city else "Unknown"

    def records_from_payload(self, payload):
        if isinstance(payload, dict):
            for key in ("data", "proxies", "items", "results"):
                if isinstance(payload.get(key), list):
                    return payload.get(key)
            return []
        if isinstance(payload, list):
            return payload
        return []

    def parse_item(self, item):
        if isinstance(item, str):
            parsed = self.parse_proxy_string(item)
            if not parsed:
                return None
            return {
                "proxy": f"{parsed['protocol']}://{parsed['ip']}:{parsed['port']}",
                "protocol": parsed["protocol"],
                "ip": parsed["ip"],
                "port": parsed["port"],
                "https": parsed["protocol"] in ("http", "https"),
                "anonymity": "proxifly-import",
                "score": 1,
                "source": "proxifly/free-proxy-list",
                "geolocation": {"country": "UNKNOWN", "city": "Unknown"},
            }

        if not isinstance(item, dict):
            return None

        proxy_value = item.get("proxy") or item.get("url") or item.get("address") or item.get("server")
        parsed = self.parse_proxy_string(proxy_value) if proxy_value else None

        proto = self.normalize_protocol(item.get("protocol") or item.get("type") or (parsed or {}).get("protocol") or "http")
        ip = str(item.get("ip") or item.get("host") or item.get("addr") or (parsed or {}).get("ip") or "").strip()
        port_val = item.get("port") if item.get("port") is not None else (parsed or {}).get("port")

        if not ip or port_val is None:
            return None
        try:
            port = int(str(port_val).strip())
        except Exception:
            return None

        country = self.country_from_record(item) or "UNKNOWN"
        city = self.city_from_record(item)
        anonymity = item.get("anonymity") or item.get("anonymityLevel") or item.get("level") or "proxifly-import"
        score = item.get("score", item.get("latency", item.get("uptime", 1)))

        return {
            "proxy": f"{proto}://{ip}:{port}",
            "protocol": proto,
            "ip": ip,
            "port": port,
            "https": proto in ("http", "https"),
            "anonymity": str(anonymity),
            "score": score,
            "source": "proxifly/free-proxy-list",
            "geolocation": {
                "country": country,
                "city": city,
            },
        }

    def run(self):
        try:
            self.status_signal.emit("INFO", f"Fetching free proxy list from Proxifly: {self.url}")
            session = requests.Session()
            session.trust_env = False
            res = session.get(self.url, timeout=self.timeout_seconds)
            res.raise_for_status()
            payload = res.json()
            raw_items = self.records_from_payload(payload)
            total_items = len(raw_items)
            self.status_signal.emit("INFO", f"Downloaded {total_items} raw proxy record(s). Normalizing...")

            normalized = []
            skipped = 0
            seen = set()
            for item in raw_items:
                if not self.running:
                    self.result_signal.emit(normalized, total_items, skipped, 0, "cancelled")
                    return
                rec = self.parse_item(item)
                if not rec:
                    skipped += 1
                    continue
                key = (rec.get("protocol"), rec.get("ip"), str(rec.get("port")))
                if key in seen:
                    skipped += 1
                    continue
                seen.add(key)
                normalized.append(rec)

            self.result_signal.emit(normalized, total_items, skipped, len(normalized), "")
        except Exception as e:
            self.result_signal.emit([], 0, 0, 0, str(e))

    def stop(self):
        self.running = False


class ProxySourceImportWorker(QThread):
    status_signal = pyqtSignal(str, str)
    result_signal = pyqtSignal(object, object, str)

    def __init__(self, sources, timeout_seconds=30):
        super().__init__()
        self.sources = list(sources or [])
        try:
            self.timeout_seconds = max(10, min(180, int(timeout_seconds)))
        except Exception:
            self.timeout_seconds = 30
        self.running = True

    def normalize_protocol(self, proto):
        proto = str(proto or "http").lower().strip()
        if proto in ("socks", "socks4", "socks5"):
            return proto
        if proto in ("http", "https"):
            return proto
        return "http"

    def parse_proxy_string(self, value, default_protocol="http"):
        raw = str(value or "").strip()
        if not raw or raw.startswith("#"):
            return None
        proto = self.normalize_protocol(default_protocol)
        m = re.match(r'^([a-zA-Z0-9+.-]+)://(.+)$', raw)
        if m:
            proto = self.normalize_protocol(m.group(1))
            raw = m.group(2)
        # Strip credentials if present: user:pass@host:port -> host:port
        if "@" in raw:
            raw = raw.rsplit("@", 1)[1]
        if ":" not in raw:
            return None
        host, port = raw.rsplit(":", 1)
        host = host.strip().strip("[]")
        port = str(port).strip()
        if not host or not port.isdigit():
            return None
        port_i = int(port)
        if port_i <= 0 or port_i > 65535:
            return None
        return {"ip": host, "port": port_i, "protocol": proto}

    def extract_records_from_json(self, payload):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("data", "proxies", "items", "results", "list"):
                val = payload.get(key)
                if isinstance(val, list):
                    return val
            # Some JSON lists are dictionaries keyed by proxy string.
            proxy_like = []
            for key, val in payload.items():
                if isinstance(val, dict):
                    item = dict(val)
                    item.setdefault("proxy", key)
                    proxy_like.append(item)
                elif isinstance(val, str):
                    proxy_like.append(val)
            return proxy_like
        return []

    def country_from_record(self, item):
        if not isinstance(item, dict):
            return ""
        geo = item.get("geolocation") or item.get("geo") or item.get("location") or item.get("country") or {}
        if isinstance(geo, dict):
            for key in ("country", "countryCode", "country_code", "iso", "code"):
                val = geo.get(key)
                if val:
                    return str(val).upper().strip()
        elif isinstance(geo, str) and geo.strip():
            return geo.upper().strip()
        for key in ("country", "countryCode", "country_code", "iso", "code"):
            val = item.get(key)
            if val:
                return str(val).upper().strip()
        return ""

    def city_from_record(self, item):
        if not isinstance(item, dict):
            return "Unknown"
        geo = item.get("geolocation") or item.get("geo") or item.get("location") or {}
        if isinstance(geo, dict):
            city = geo.get("city") or geo.get("region") or geo.get("state")
            if city:
                return str(city)
        city = item.get("city") or item.get("region") or item.get("state")
        return str(city) if city else "Unknown"

    def parse_item(self, item, source):
        default_proto = self.normalize_protocol(source.get("protocol", "http"))
        source_name = source.get("source") or source.get("name") or "proxy-import"

        if isinstance(item, str):
            parsed = self.parse_proxy_string(item, default_protocol=default_proto)
            if not parsed:
                return None
            return {
                "proxy": f"{parsed['protocol']}://{parsed['ip']}:{parsed['port']}",
                "protocol": parsed["protocol"],
                "ip": parsed["ip"],
                "port": parsed["port"],
                "https": parsed["protocol"] in ("http", "https"),
                "anonymity": "source-import",
                "score": 1,
                "source": source_name,
                "geolocation": {"country": "UNKNOWN", "city": "Unknown"},
            }

        if not isinstance(item, dict):
            return None

        proxy_value = item.get("proxy") or item.get("url") or item.get("address") or item.get("server")
        parsed = self.parse_proxy_string(proxy_value, default_protocol=default_proto) if proxy_value else None

        proto = self.normalize_protocol(item.get("protocol") or item.get("type") or item.get("scheme") or (parsed or {}).get("protocol") or default_proto)
        ip = str(item.get("ip") or item.get("host") or item.get("addr") or item.get("hostname") or (parsed or {}).get("ip") or "").strip()
        port_val = item.get("port") if item.get("port") is not None else (parsed or {}).get("port")
        if not ip or port_val is None:
            return None
        try:
            port = int(str(port_val).strip())
        except Exception:
            return None
        if port <= 0 or port > 65535:
            return None

        country = self.country_from_record(item) or "UNKNOWN"
        city = self.city_from_record(item)
        anonymity = item.get("anonymity") or item.get("anonymityLevel") or item.get("level") or "source-import"
        score = item.get("score", item.get("latency", item.get("uptime", 1)))

        return {
            "proxy": f"{proto}://{ip}:{port}",
            "protocol": proto,
            "ip": ip,
            "port": port,
            "https": proto in ("http", "https"),
            "anonymity": str(anonymity),
            "score": score,
            "source": source_name,
            "geolocation": {"country": country, "city": city},
        }

    def parse_text_payload(self, text_payload, source):
        records = []
        skipped = 0
        seen = set()
        for line in str(text_payload or "").splitlines():
            raw = line.strip()
            if not raw or raw.startswith("#") or raw.startswith("//"):
                continue
            parsed = self.parse_proxy_string(raw, default_protocol=source.get("protocol", "http"))
            if not parsed:
                skipped += 1
                continue
            key = (parsed["protocol"], parsed["ip"], str(parsed["port"]))
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            records.append({
                "proxy": f"{parsed['protocol']}://{parsed['ip']}:{parsed['port']}",
                "protocol": parsed["protocol"],
                "ip": parsed["ip"],
                "port": parsed["port"],
                "https": parsed["protocol"] in ("http", "https"),
                "anonymity": "text-import",
                "score": 1,
                "source": source.get("source") or source.get("name") or "proxy-import",
                "geolocation": {"country": "UNKNOWN", "city": "Unknown"},
            })
        return records, skipped

    def fetch_one_source(self, session, source):
        name = source.get("name", source.get("url", "Unknown Source"))
        url = source.get("url")
        fmt = str(source.get("format", "text")).lower().strip()
        self.status_signal.emit("TESTING", f"Importing source: {name}")
        res = session.get(url, timeout=self.timeout_seconds)
        res.raise_for_status()

        if fmt == "json":
            payload = res.json()
            raw_items = self.extract_records_from_json(payload)
            total = len(raw_items)
            normalized = []
            skipped = 0
            seen = set()
            for item in raw_items:
                if not self.running:
                    break
                rec = self.parse_item(item, source)
                if not rec:
                    skipped += 1
                    continue
                key = (rec.get("protocol"), rec.get("ip"), str(rec.get("port")))
                if key in seen:
                    skipped += 1
                    continue
                seen.add(key)
                normalized.append(rec)
            return normalized, total, skipped

        normalized, skipped = self.parse_text_payload(res.text, source)
        return normalized, len(str(res.text or "").splitlines()), skipped

    def run(self):
        all_records = []
        stats = {"sources": [], "total_raw": 0, "total_normalized": 0, "total_skipped": 0}
        try:
            if not self.sources:
                self.result_signal.emit([], stats, "No proxy sources selected.")
                return
            session = requests.Session()
            session.trust_env = False
            global_seen = set()
            for source in self.sources:
                if not self.running:
                    break
                name = source.get("name", "Unknown Source")
                try:
                    records, raw_count, skipped = self.fetch_one_source(session, source)
                    added_here = 0
                    duplicate_here = 0
                    for rec in records:
                        key = (rec.get("protocol"), rec.get("ip"), str(rec.get("port")))
                        if key in global_seen:
                            duplicate_here += 1
                            continue
                        global_seen.add(key)
                        all_records.append(rec)
                        added_here += 1
                    stats["sources"].append({
                        "name": name,
                        "status": "OK",
                        "raw": raw_count,
                        "normalized": len(records),
                        "deduped": added_here,
                        "skipped": skipped + duplicate_here,
                        "error": "",
                    })
                    stats["total_raw"] += raw_count
                    stats["total_normalized"] += added_here
                    stats["total_skipped"] += skipped + duplicate_here
                    self.status_signal.emit("SUCCESS", f"{name}: raw={raw_count}, normalized={len(records)}, unique added to import batch={added_here}, skipped={skipped + duplicate_here}")
                except Exception as e:
                    stats["sources"].append({"name": name, "status": "ERROR", "raw": 0, "normalized": 0, "deduped": 0, "skipped": 0, "error": str(e)})
                    self.status_signal.emit("ERROR", f"{name}: {str(e)}")
            self.result_signal.emit(all_records, stats, "")
        except Exception as e:
            self.result_signal.emit(all_records, stats, str(e))

    def stop(self):
        self.running = False



class ProxyBulkValidatorWorker(QThread):
    status_signal = pyqtSignal(str, str)
    done_signal = pyqtSignal(int, int, int, int)  # total, good, bad, skipped

    def __init__(self, mode="all", include_socks=False, timeout_seconds=10):
        super().__init__()
        self.mode = str(mode or "all").lower().strip()
        self.include_socks = bool(include_socks)
        try:
            self.timeout_seconds = max(3, min(60, int(timeout_seconds)))
        except Exception:
            self.timeout_seconds = 10
        self.running = True
        self.cache_file = os.path.join(BASE_DIR, "proxy_cache.json")

    def normalize_proxy_protocol(self, proto):
        proto = str(proto or "http").lower().strip()
        if proto in ("socks", "socks4", "socks5"):
            return proto
        if proto in ("http", "https"):
            return proto
        return "http"

    def protocol_family(self, proto):
        proto = self.normalize_proxy_protocol(proto)
        return "socks" if proto.startswith("socks") else "http"

    def protocol_allowed(self, proto):
        family = self.protocol_family(proto)
        return family == "http" or self.include_socks

    def proxy_country_value(self, record):
        geo = record.get("geolocation", {}) if isinstance(record, dict) else {}
        country = geo.get("country", "") if isinstance(geo, dict) else ""
        if not country and isinstance(record, dict):
            country = record.get("country", "")
        return str(country or "UNKNOWN").upper().strip()

    def country_code_for_record(self, record):
        country = self.proxy_country_value(record)
        if len(country) == 2:
            return country
        for code, name in GLOBAL_COUNTRY_MAP.items():
            if country == name or name in country:
                return code
        return "UNKNOWN"

    def is_imported_record(self, record):
        if not isinstance(record, dict):
            return False
        src = str(record.get("source", "") or "").lower()
        anon = str(record.get("anonymity", "") or "").lower()
        return bool(src) or "import" in anon or "proxifly" in anon or "source" in anon

    def load_manual_proxies(self):
        try:
            if os.path.exists(MANUAL_PROXY_FILE):
                with open(MANUAL_PROXY_FILE, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            self.status_signal.emit("ERROR", f"Could not read manual_proxies.json: {e}")
        return []

    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def save_cache(self, cache):
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=4)
        except Exception as e:
            self.status_signal.emit("WARN", f"Could not save proxy cache: {e}")

    def describe_failure(self, exc, elapsed):
        detail = str(exc).replace("\n", " ").strip()
        if len(detail) > 180:
            detail = detail[:177] + "..."
        if isinstance(exc, requests.exceptions.Timeout):
            return "TIMEOUT", f"Timeout after {elapsed:.1f}s"
        if isinstance(exc, requests.exceptions.ProxyError):
            return "PROXY ERROR", detail or "Proxy error"
        if isinstance(exc, requests.exceptions.SSLError):
            return "SSL ERROR", detail or "SSL failure"
        if isinstance(exc, requests.exceptions.ConnectionError):
            low = detail.lower()
            if "refused" in low:
                return "NODE DROPPED", "Connection refused"
            if "reset" in low:
                return "NODE DROPPED", "Connection reset"
            return "CONNECTION ERROR", detail or "Connection error"
        return "ERROR", detail or exc.__class__.__name__

    def update_cache_rank(self, cache, record, rank_delta, status):
        country = self.country_code_for_record(record)
        proto = self.normalize_proxy_protocol(record.get("protocol", "http"))
        ip = str(record.get("ip", "")).strip()
        port = str(record.get("port", "")).strip()
        cache.setdefault(country, [])
        existing = next((x for x in cache[country] if str(x.get("ip")) == ip and str(x.get("port")) == port and self.normalize_proxy_protocol(x.get("protocol", proto)) == proto), None)
        if not existing:
            existing = {"ip": ip, "port": port, "rank": 0, "protocol": proto}
            cache[country].append(existing)
        existing["rank"] = int(existing.get("rank", 0) or 0) + int(rank_delta)
        existing["protocol"] = proto
        existing["last_status"] = status
        existing["last_checked"] = int(time.time())

    def run(self):
        records = self.load_manual_proxies()
        selected = []
        for rec in records:
            if not isinstance(rec, dict) or not rec.get("ip") or not rec.get("port"):
                continue
            proto = self.normalize_proxy_protocol(rec.get("protocol", "http"))
            if not self.protocol_allowed(proto):
                continue
            if self.mode == "imported" and not self.is_imported_record(rec):
                continue
            selected.append(rec)

        total = len(selected)
        if total == 0:
            self.status_signal.emit("WARN", f"Bulk validation queue has no records for mode={self.mode}.")
            self.done_signal.emit(0, 0, 0, 0)
            return

        self.status_signal.emit("INFO", f"Bulk proxy validation started: mode={self.mode}, records={total}, timeout={self.timeout_seconds}s")
        session = requests.Session()
        session.trust_env = False
        cache = self.load_cache()
        good = bad = skipped = 0

        for idx, rec in enumerate(selected, 1):
            if not self.running:
                skipped += (total - idx + 1)
                break
            proto = self.normalize_proxy_protocol(rec.get("protocol", "http"))
            ip = str(rec.get("ip"))
            port = str(rec.get("port"))
            proxy_url = f"{proto}://{ip}:{port}" if "socks" in proto else f"http://{ip}:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}
            self.status_signal.emit("TESTING", f"[{idx}/{total}] Bulk validate -> {proto}://{ip}:{port}")
            start = time.monotonic()
            try:
                res = session.get("https://www.google.com", proxies=proxies, timeout=self.timeout_seconds)
                elapsed = time.monotonic() - start
                if res.status_code == 200:
                    good += 1
                    self.update_cache_rank(cache, rec, +1, "GOOD")
                    self.status_signal.emit("SUCCESS", f"GOOD {proto}://{ip}:{port} ({elapsed:.1f}s)")
                else:
                    bad += 1
                    self.update_cache_rank(cache, rec, -5, f"HTTP_{res.status_code}")
                    self.status_signal.emit("WARN", f"BAD HTTP {res.status_code} {proto}://{ip}:{port} ({elapsed:.1f}s)")
            except Exception as e:
                elapsed = time.monotonic() - start
                failure_type, reason = self.describe_failure(e, elapsed)
                bad += 1
                self.update_cache_rank(cache, rec, -5, failure_type)
                self.status_signal.emit("WARN", f"{failure_type}: {reason} {proto}://{ip}:{port} ({elapsed:.1f}s)")
            if idx % 10 == 0:
                self.save_cache(cache)
        self.save_cache(cache)
        self.status_signal.emit("INFO", f"Bulk proxy validation complete: total={total}, good={good}, bad={bad}, skipped={skipped}")
        self.done_signal.emit(total, good, bad, skipped)

    def stop(self):
        self.running = False



class NetworkSnapshotWorker(QThread):
    rows_signal = pyqtSignal(object)
    log_signal = pyqtSignal(str, str)

    def __init__(self, target_filter=""):
        super().__init__()
        self.target_filter = str(target_filter or "").lower().strip()

    def _run(self, cmd, timeout=8):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return result.returncode, result.stdout or ""
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except Exception as e:
            return 1, str(e)

    def _parse_ss_line(self, line):
        parts = line.split()
        if len(parts) < 5:
            return None
        proto = parts[0]
        state = parts[1] if proto.lower().startswith("tcp") else ""
        if proto.lower().startswith("udp"):
            local = parts[4] if len(parts) > 4 else ""
            remote = parts[5] if len(parts) > 5 else ""
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
        else:
            local = parts[4] if len(parts) > 4 else ""
            remote = parts[5] if len(parts) > 5 else ""
            proc = " ".join(parts[6:]) if len(parts) > 6 else ""
        raw = line.strip()
        if self.target_filter and self.target_filter not in raw.lower():
            return None
        return [proto, local, remote, state, proc, raw]

    def run(self):
        # Prefer ss because it exposes process names on rooted/newer Android. Fall back to netstat.
        command = "su -c 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || netstat -tun 2>/dev/null'"
        rc, out = self._run([ADB_PATH, "shell", command], timeout=10)
        if not out.strip() or out.strip() == "timeout":
            self.log_signal.emit("No network socket output returned. Device may need root/busybox/toybox ss/netstat.", "#ffa657")
            self.rows_signal.emit([])
            return
        rows = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith(("netid", "proto", "active", "recv-q", "state")):
                continue
            parsed = self._parse_ss_line(line)
            if parsed:
                rows.append(parsed)
        self.rows_signal.emit(rows)
        self.log_signal.emit(f"Network snapshot complete: {len(rows)} row(s).", "#7ee787")


# --- APK EXPLORER WORKSPACE ---
class ApkCodeBeautifier:
    @staticmethod
    def beautify(text, ext):
        if not text:
            return text
        if ext in ['.xml', '.html', '.axml']:
            text = re.sub(r'>\s*<', '>\n<', text)
            lines = text.split('\n')
            indent = 0
            new_lines = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('</'):
                    indent -= 1
                new_lines.append('  ' * max(0, indent) + line)
                if line.startswith('<') and not line.startswith('</') and not line.endswith('/>') and '</' not in line:
                    indent += 1
            return '\n'.join(new_lines)
        if ext == '.js':
            text = text.replace('{', '{\n').replace('}', '\n}\n').replace(';', ';\n')
            lines = text.split('\n')
            indent = 0
            new_lines = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if '}' in line:
                    indent -= 1
                new_lines.append('    ' * max(0, indent) + line)
                if '{' in line:
                    indent += 1
            return '\n'.join(new_lines)
        return text


class ApkExportOptionsDialog(QDialog):
    def __init__(self, parent=None, title="Export Settings"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.layout = QVBoxLayout(self)
        group = QGroupBox("Optimization & Formatting")
        grid = QVBoxLayout(group)
        self.cb_decode = QCheckBox("Decode Android Binary XML (AndroidManifest, etc.)")
        self.cb_decode.setChecked(True)
        self.cb_beautify = QCheckBox("Beautify Files (HTML, XML, JS)")
        self.cb_beautify.setChecked(True)
        self.cb_decompile = QCheckBox("Batch Decompile DEX to Java (as .zip)")
        self.cb_decompile.setChecked(True)
        self.cb_skip_media = QCheckBox("Skip Media Files (PNG, JPG, WEBP, MP3)")
        self.cb_flat = QCheckBox("Flat Export (Ignore folder structure)")
        self.cb_report = QCheckBox("Generate Export Report (txt)")
        for cb in [self.cb_decode, self.cb_beautify, self.cb_decompile, self.cb_skip_media, self.cb_flat, self.cb_report]:
            grid.addWidget(cb)
        self.layout.addWidget(group)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        self.layout.addWidget(buttons)

    def get_options(self):
        return {
            "decode": self.cb_decode.isChecked(),
            "beautify": self.cb_beautify.isChecked(),
            "decompile": self.cb_decompile.isChecked(),
            "skip_media": self.cb_skip_media.isChecked(),
            "flat": self.cb_flat.isChecked(),
            "report": self.cb_report.isChecked(),
        }


class ApkJavaHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.rules = []
        kw_fmt = QTextCharFormat()
        kw_fmt.setForeground(QColor("#569CD6"))
        kw_fmt.setFontWeight(QFont.Bold)
        for word in ["public", "private", "protected", "static", "final", "void", "int", "class", "extends", "return", "if", "else", "new", "import", "package"]:
            self.rules.append((QRegularExpression(f"\\b{word}\\b"), kw_fmt))
        str_fmt = QTextCharFormat()
        str_fmt.setForeground(QColor("#CE9178"))
        self.rules.append((QRegularExpression('".*"'), str_fmt))
        com_fmt = QTextCharFormat()
        com_fmt.setForeground(QColor("#6A9955"))
        self.rules.append((QRegularExpression("//[^\\n]*"), com_fmt))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


class ApkAXMLDecoder:
    def __init__(self, data):
        self.reader = io.BytesIO(data)
        self.strings = []

    def read_int(self):
        buf = self.reader.read(4)
        return struct.unpack('<I', buf)[0] if len(buf) == 4 else 0

    def read_short(self):
        buf = self.reader.read(2)
        return struct.unpack('<H', buf)[0] if len(buf) == 2 else 0

    def _read_one(self):
        b = self.reader.read(1)
        return b[0] if b else 0

    def decode(self):
        try:
            self.reader.seek(0)
            if self.read_short() != 0x0003:
                return None
            self.read_short()
            f_sz = self.read_int()
            out = '<?xml version="1.0" encoding="utf-8"?>\n'
            indent = 0
            while self.reader.tell() < f_sz:
                pos = self.reader.tell()
                c_type = self.read_short()
                self.reader.read(2)
                c_sz = self.read_int()
                if c_type == 0x0001:
                    self.parse_strings(c_sz, pos)
                elif c_type == 0x0102:
                    self.reader.read(8)
                    self.read_int()
                    name_idx = self.read_int()
                    self.reader.read(4)
                    attr_count = self.read_short()
                    self.reader.read(6)
                    tag = self.get_s(name_idx)
                    out += "  " * indent + f"<{tag}"
                    for _ in range(attr_count):
                        self.reader.read(4)
                        a_nm_idx = self.read_int()
                        self.reader.read(4)
                        a_tp = self._read_one()
                        self.reader.read(3)
                        a_vl_raw = self.read_int()
                        a_nm = self.get_s(a_nm_idx)
                        a_vl = self.get_s(a_vl_raw) if (a_tp == 3 or a_vl_raw < len(self.strings)) else str(a_vl_raw)
                        out += f' {a_nm}="{a_vl}"'
                    out += ">\n"
                    indent += 1
                elif c_type == 0x0103:
                    indent = max(0, indent - 1)
                    self.reader.read(8)
                    self.reader.read(4)
                    out += "  " * indent + f"</{self.get_s(self.read_int())}>\n"
                self.reader.seek(pos + c_sz)
            return out
        except Exception:
            return "[Parser Error]"

    def get_s(self, i):
        return self.strings[i] if 0 <= i < len(self.strings) else ""

    def parse_strings(self, size, pos):
        self.reader.seek(pos + 8)
        count = self.read_int()
        self.read_int()
        flags = self.read_int()
        str_start = self.read_int()
        self.read_int()
        offsets = [self.read_int() for _ in range(count)]
        is_utf8 = (flags & 0x100) != 0
        for off in offsets:
            self.reader.seek(pos + str_start + off)
            if is_utf8:
                u8_len = self._read_one()
                if u8_len & 0x80:
                    u8_len = (u8_len & 0x7f) << 8 | self._read_one()
                self.strings.append(self.reader.read(u8_len).decode('utf-8', errors='ignore'))
            else:
                u16_len = self.read_short()
                if u16_len & 0x8000:
                    u16_len = (u16_len & 0x7fff) << 16 | self.read_short()
                self.strings.append(self.reader.read(u16_len * 2).decode('utf-16le', errors='ignore'))


class ApkDecompileWorker(QThread):
    finished = pyqtSignal(str, str, bool)

    def __init__(self, filename, data, is_preview):
        super().__init__()
        self.filename = filename
        self.data = data
        self.is_preview = is_preview

    def run(self):
        h = hashlib.md5(self.data).hexdigest()
        cp = os.path.join(APK_EXPLORER_CACHE_DIR, f"{h}.java")
        if os.path.exists(cp):
            with open(cp, "r", encoding="utf-8", errors="replace") as f:
                self.finished.emit(self.filename, f.read(), self.is_preview)
            return
        try:
            from androguard.core.dex import DEX
            from androguard.core.analysis.analysis import Analysis
            from androguard.decompiler.decompile import DvMethod
            df = DEX(self.data)
            dx = Analysis(df)
            out = []
            for cls in df.get_classes()[:20]:
                for m in cls.get_methods():
                    src = None
                    mx = dx.get_method(m)
                    if mx:
                        d = DvMethod(mx)
                        d.process()
                        src = d.get_source()
                    if src:
                        out.append(src)
            code = "\n".join(out)
            with open(cp, "w", encoding="utf-8") as f:
                f.write(code)
            self.finished.emit(self.filename, code, self.is_preview)
        except Exception as e:
            self.finished.emit(self.filename, f"// Error: {e}", self.is_preview)


class ApkSearchWorker(QThread):
    match_found = pyqtSignal(str, str)
    finished = pyqtSignal()

    def __init__(self, data, query):
        super().__init__()
        self.data = data
        self.query = query.lower()

    def run(self):
        try:
            with zipfile.ZipFile(io.BytesIO(self.data)) as z:
                for n in z.namelist():
                    if any(n.endswith(x) for x in ['.png', '.jpg', '.so']):
                        continue
                    try:
                        raw = z.read(n)
                        content = ApkAXMLDecoder(raw).decode() if n.endswith('.xml') else raw.decode('utf-8', errors='ignore')
                        if content and self.query in content.lower():
                            idx = content.lower().find(self.query)
                            snippet = content[max(0, idx - 20):min(len(content), idx + 40)].replace('\n', ' ')
                            self.match_found.emit(n, f"...{snippet}...")
                    except Exception:
                        continue
        except Exception:
            pass
        self.finished.emit()


class ApkExplorerWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.preview_tab_index = -1
        self.init_ui()
        self.apply_style()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.splitter = QSplitter(Qt.Horizontal)
        left_pane = QWidget()
        vbox = QVBoxLayout(left_pane)
        btn_open = QPushButton("📂 OPEN APK")
        btn_open.clicked.connect(self.open_archive)
        btn_search = QPushButton("🔍 GLOBAL SEARCH")
        btn_search.clicked.connect(self.start_global_search)
        vbox.addWidget(btn_open)
        vbox.addWidget(btn_search)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter (Regex or 'word1 word2')...")
        self.filter.textChanged.connect(self.do_filter)
        vbox.addWidget(self.filter)

        self.tree = QTreeView()
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Explorer', 'Size'])
        self.tree.setModel(self.model)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.clicked.connect(lambda i: self.handle_click(i, True))
        self.tree.doubleClicked.connect(lambda i: self.handle_click(i, False))
        h = self.tree.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.Fixed)
        h.setDefaultSectionSize(100)
        vbox.addWidget(self.tree)

        right_container = QWidget()
        right_vbox = QVBoxLayout(right_container)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        right_vbox.addWidget(self.tabs)
        self.find_bar = QFrame()
        self.find_bar.setVisible(False)
        find_layout = QHBoxLayout(self.find_bar)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find in current tab...")
        self.find_input.returnPressed.connect(self.find_next)
        find_layout.addWidget(self.find_input)
        btn_next = QPushButton("Next")
        btn_next.clicked.connect(self.find_next)
        find_layout.addWidget(btn_next)
        btn_close_find = QPushButton("X")
        btn_close_find.setFixedWidth(30)
        btn_close_find.clicked.connect(lambda: self.find_bar.setVisible(False))
        find_layout.addWidget(btn_close_find)
        right_vbox.addWidget(self.find_bar)
        self.splitter.addWidget(left_pane)
        self.splitter.addWidget(right_container)
        self.splitter.setStretchFactor(1, 4)
        layout.addWidget(self.splitter)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

    def apply_style(self):
        self.setStyleSheet("""
            QWidget { background: #1E1E1E; color: #D4D4D4; }
            QTreeView { background: #252526; border: none; font-size: 12px; }
            QHeaderView::section { background: #333; color: #CCC; padding: 4px; border: 1px solid #111; }
            QTabBar::tab { background: #2D2D2D; padding: 10px; border-right: 1px solid #111; }
            QTabBar::tab:selected { background: #1E1E1E; border-bottom: 2px solid #007ACC; }
            QPushButton { background: #333; border: 1px solid #555; padding: 8px; font-weight: bold; }
        """)

    def keyPressEvent(self, event):
        if event.modifiers() == Qt.ControlModifier and event.key() == Qt.Key_F:
            self.find_bar.setVisible(True)
            self.find_input.setFocus()
        super().keyPressEvent(event)

    def find_next(self):
        curr = self.tabs.currentWidget()
        if isinstance(curr, QTextEdit):
            if not curr.find(self.find_input.text()):
                curr.moveCursor(QTextCursor.Start)
                curr.find(self.find_input.text())

    def load_zip(self, name, data):
        dn = os.path.basename(name)
        for i in range(self.model.rowCount()):
            if self.model.item(i).text() == dn:
                self.tree.setCurrentIndex(self.model.index(i, 0))
                self.tree.expand(self.model.index(i, 0))
                return
        root = QStandardItem(dn)
        root.setData(data, Qt.UserRole)
        root.setIcon(QApplication.style().standardIcon(QStyle.SP_DriveHDIcon))
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    fn_lower = info.filename.lower()
                    s = QApplication.style()
                    icon, color = s.standardIcon(QStyle.SP_FileIcon), QColor("#D4D4D4")
                    is_archive = fn_lower.endswith(('.apk', '.zip'))
                    if is_archive:
                        icon, color = s.standardIcon(QStyle.SP_DirIcon), QColor("#4EC9B0")
                    elif fn_lower.endswith('.dex'):
                        color = QColor("#FFD700")
                    elif fn_lower.endswith('.xml'):
                        icon, color = s.standardIcon(QStyle.SP_FileLinkIcon), QColor("#CE9178")
                    elif fn_lower.endswith(('.png', '.jpg')):
                        icon, color = s.standardIcon(QStyle.SP_FileDialogContentsView), QColor("#B5CEA8")
                    it = QStandardItem(icon, info.filename)
                    it.setForeground(color)
                    it.setData(data, Qt.UserRole + 1)
                    sz = QStandardItem(f"{info.file_size:,}")
                    sz.setForeground(QColor("#808080"))
                    root.appendRow([it, sz])
                    if is_archive:
                        try:
                            self.load_zip(info.filename, z.read(info.filename))
                        except Exception:
                            pass
            self.model.appendRow(root)
            self.tree.expand(root.index())
            self.do_filter()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load {dn}: {str(e)}")

    def handle_click(self, idx, is_preview):
        if idx.column() != 0:
            return
        it = self.model.itemFromIndex(idx)
        fn = it.text()
        pd = it.data(Qt.UserRole + 1)
        if not pd:
            return
        with zipfile.ZipFile(io.BytesIO(pd)) as z:
            raw = z.read(fn)
        if fn.lower().endswith(('.apk', '.zip')) and not is_preview:
            self.load_zip(fn, raw)
            return
        if fn.lower().endswith('.dex'):
            self.progress.setVisible(True)
            self.progress.setRange(0, 0)
            self.dw = ApkDecompileWorker(fn, raw, is_preview)
            self.dw.finished.connect(self.add_tab)
            self.dw.start()
        elif fn.lower().endswith('.xml'):
            self.add_tab(fn, ApkAXMLDecoder(raw).decode() or "[Error]", is_preview)
        elif fn.lower().endswith(('.png', '.jpg')):
            l = QLabel()
            p = QPixmap()
            p.loadFromData(raw)
            l.setPixmap(p.scaled(600, 600, Qt.KeepAspectRatio))
            l.setAlignment(Qt.AlignCenter)
            self.add_tab(fn, l, is_preview)
        else:
            try:
                txt = raw.decode('utf-8', errors='replace')
            except Exception:
                txt = "[Binary]"
            self.add_tab(fn, txt, is_preview)

    def add_tab(self, fn, content, is_preview):
        self.progress.setVisible(False)
        v = QTextEdit() if isinstance(content, str) else content
        if isinstance(content, str):
            v.setReadOnly(True)
            v.setPlainText(content)
            v.setFont(QFont("Consolas", 10))
        if fn.lower().endswith('.dex') and isinstance(content, str):
            self.highlighter = ApkJavaHighlighter(v.document())
        title = os.path.basename(fn)
        if is_preview:
            if self.preview_tab_index != -1:
                self.tabs.removeTab(self.preview_tab_index)
            self.preview_tab_index = self.tabs.insertTab(0, v, f"👁 {title}")
            self.tabs.setCurrentIndex(0)
        else:
            self.tabs.addTab(v, title)
            self.tabs.setCurrentIndex(self.tabs.count() - 1)

    def show_context_menu(self, pos):
        idxs = [i for i in self.tree.selectedIndexes() if i.column() == 0]
        if not idxs:
            return
        menu = QMenu()
        act_save = act_export_all = act_remove = None
        if len(idxs) > 1:
            act_save = menu.addAction(f"💾 Save {len(idxs)} Selected Files...")
        else:
            item = self.model.itemFromIndex(idxs[0])
            if not item.parent():
                act_export_all = menu.addAction("🚀 Export ALL (with Options)")
                act_remove = menu.addAction("❌ Remove Archive")
            else:
                act_save = menu.addAction("💾 Save File As...")
                act_remove = menu.addAction("❌ Remove From List")
        action = menu.exec_(self.tree.mapToGlobal(pos))
        if act_save is not None and action == act_save:
            self.export_selected_files(idxs)
        elif act_export_all is not None and action == act_export_all:
            self.export_full_archive(idxs[0])
        elif act_remove is not None and action == act_remove:
            for idx in sorted(idxs, key=lambda x: x.row(), reverse=True):
                if idx.parent().isValid():
                    self.model.itemFromIndex(idx.parent()).removeRow(idx.row())
                else:
                    self.model.removeRow(idx.row())

    def export_selected_files(self, idxs):
        dlg = ApkExportOptionsDialog(self, "Export Selected Files")
        if dlg.exec_() != QDialog.Accepted:
            return
        opts = dlg.get_options()
        dest = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if not dest:
            return
        for idx in idxs:
            item = self.model.itemFromIndex(idx)
            fn, pd = item.text(), item.data(Qt.UserRole + 1)
            if pd:
                self._save_file(pd, fn, dest, opts)

    def export_full_archive(self, root_idx):
        dlg = ApkExportOptionsDialog(self, "Full Export Options")
        if dlg.exec_() != QDialog.Accepted:
            return
        opts = dlg.get_options()
        dest = QFileDialog.getExistingDirectory(self, "Select Destination")
        if not dest:
            return
        root_item = self.model.itemFromIndex(root_idx)
        zip_data = root_item.data(Qt.UserRole)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        try:
            dex_files = []
            with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
                files = z.namelist()
                for fn in files:
                    if opts['skip_media'] and any(fn.lower().endswith(x) for x in ['.png', '.jpg', '.webp', '.mp3']):
                        continue
                    if fn.lower().endswith('.dex'):
                        dex_files.append((fn, z.read(fn)))
                    self._save_file(zip_data, fn, dest, opts)
            if opts['decompile'] and dex_files:
                src_zip_path = os.path.join(dest, "decompiled_source.zip")
                with zipfile.ZipFile(src_zip_path, 'w') as sz:
                    for dfn, ddata in dex_files:
                        try:
                            from androguard.core.dex import DEX
                            from androguard.core.analysis.analysis import Analysis
                            from androguard.decompiler.decompile import DvMethod
                            df = DEX(ddata)
                            dx = Analysis(df)
                            for cls in df.get_classes():
                                for m in cls.get_methods():
                                    mx = dx.get_method(m)
                                    if mx:
                                        d = DvMethod(mx)
                                        d.process()
                                        src = d.get_source()
                                        if src:
                                            p_path = cls.get_name().strip('L').strip(';').replace('/', os.sep) + ".java"
                                            sz.writestr(p_path, src)
                        except Exception:
                            pass
            if opts['report']:
                with open(os.path.join(dest, "export_report.txt"), "w") as r:
                    r.write(f"Export completed for: {root_item.text()}\nFiles processed: {len(files)}")
            QMessageBox.information(self, "Export", "Extraction complete.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")
        finally:
            self.progress.setVisible(False)

    def _save_file(self, zip_blob, inner_fn, dest_root, opts):
        try:
            with zipfile.ZipFile(io.BytesIO(zip_blob)) as z:
                raw = z.read(inner_fn)
                ext = os.path.splitext(inner_fn)[1].lower()
                final_path = os.path.join(dest_root, os.path.basename(inner_fn) if opts['flat'] else inner_fn)
                os.makedirs(os.path.dirname(final_path), exist_ok=True)
                if opts['decode'] and ext == '.xml':
                    dec = ApkAXMLDecoder(raw).decode()
                    if dec:
                        raw = dec.encode('utf-8')
                if opts['beautify'] and ext in ['.xml', '.html', '.js']:
                    try:
                        raw = ApkCodeBeautifier.beautify(raw.decode('utf-8', errors='ignore'), ext).encode('utf-8')
                    except Exception:
                        pass
                with open(final_path, 'wb') as f:
                    f.write(raw)
        except Exception:
            pass

    def start_global_search(self):
        query, ok = QInputDialog.getText(self, "Global Search", "String:")
        if not ok or not query or self.model.rowCount() == 0:
            return
        res = QTextEdit()
        res.setReadOnly(True)
        self.tabs.addTab(res, f"🔍 {query}")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.sw = ApkSearchWorker(self.model.item(0).data(Qt.UserRole), query)
        self.sw.match_found.connect(lambda f, s: res.append(f"<b>{f}</b>: {s}\n"))
        self.sw.finished.connect(lambda: self.progress.setVisible(False))
        self.sw.start()

    def do_filter(self):
        rt = self.filter.text().strip()
        rx = QRegularExpression(rt, QRegularExpression.CaseInsensitiveOption)
        kw = rt.lower().split(' ')
        for i in range(self.model.rowCount()):
            root = self.model.item(i)
            root_vis = False
            for j in range(root.rowCount()):
                fn = root.child(j).text().lower()
                try:
                    m = any(k in fn for k in kw) or rx.match(fn).hasMatch()
                except Exception:
                    m = any(k in fn for k in kw)
                self.tree.setRowHidden(j, root.index(), not m if rt else False)
                root_vis = root_vis or m
            self.tree.setRowHidden(i, self.tree.rootIndex(), not root_vis if rt else False)

    def open_archive(self):
        p, _ = QFileDialog.getOpenFileName(self, "Select APK", "", "Archives (*.apk *.zip *.apks);;All Files (*)")
        if p:
            with open(p, 'rb') as f:
                self.load_zip(p, f.read())

    def close_tab(self, i):
        if i == self.preview_tab_index:
            self.preview_tab_index = -1
        self.tabs.removeTab(i)

class DeviceStatusWorker(QThread):
    row_signal = pyqtSignal(str, str, str, str)  # check, status, detail, color
    log_signal = pyqtSignal(str, str)            # message, color
    done_signal = pyqtSignal()

    def __init__(self, target_pkg="", frida_cli_path=""):
        super().__init__()
        self.target_pkg = str(target_pkg or "").strip()
        self.frida_cli_path = str(frida_cli_path or FRIDA_CLI_PATH).strip()
        self.running = True

    def _clean(self, value):
        text = str(value or "")
        text = re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
        return text.strip()

    def _run(self, cmd, timeout=6):
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            return result.returncode, self._clean(result.stdout)
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except FileNotFoundError:
            return 127, "not found"
        except Exception as e:
            return 1, str(e)

    def _emit(self, check, status, detail, color):
        if self.running:
            self.row_signal.emit(check, status, detail, color)

    def _log(self, msg, color="#8b949e"):
        if self.running:
            self.log_signal.emit(msg, color)

    def _adb(self, *args, timeout=6):
        return self._run([ADB_PATH, *args], timeout=timeout)

    def _adb_shell(self, command, timeout=6):
        return self._run([ADB_PATH, "shell", command], timeout=timeout)

    def run(self):
        try:
            self._log("Starting device health check...", "#58a6ff")

            # Local tooling checks
            if os.path.exists(ADB_PATH) or shutil.which("adb"):
                rc, out = self._run([ADB_PATH, "version"], timeout=4)
                first = out.splitlines()[0] if out else "adb found"
                self._emit("Local ADB", "OK", f"{ADB_PATH} | {first}", "#7ee787")
            else:
                self._emit("Local ADB", "FAIL", f"ADB not found at {ADB_PATH}", "#ff7b72")

            py_ver = getattr(frida, "__version__", "unknown")
            self._emit("Python Frida", "OK", f"frida module {py_ver}", "#7ee787")

            cli_path = self.frida_cli_path or shutil.which("frida") or FRIDA_CLI_PATH
            if cli_path and os.path.exists(cli_path):
                rc, out = self._run([cli_path, "--version"], timeout=4)
                m = re.search(r"(\d+\.\d+\.\d+)", out or "")
                cli_ver = m.group(1) if m else (out or "unknown")
                self._emit("Frida CLI", "OK", f"{cli_ver} | {cli_path}", "#7ee787")
            else:
                self._emit("Frida CLI", "WARN", f"CLI not found at {cli_path}", "#ffa657")

            node_path = shutil.which("node") or "/opt/homebrew/bin/node"
            if node_path and os.path.exists(node_path):
                rc, out = self._run([node_path, "--version"], timeout=4)
                self._emit("Node.js", "OK", f"{out or 'found'} | {node_path}", "#7ee787")
            else:
                self._emit("Node.js", "WARN", "node not found. Install with: brew install node", "#ffa657")

            npm_path = shutil.which("npm") or "/opt/homebrew/bin/npm"
            if npm_path and os.path.exists(npm_path):
                rc, out = self._run([npm_path, "--version"], timeout=4)
                self._emit("npm", "OK", f"{out or 'found'} | {npm_path}", "#7ee787")
            else:
                self._emit("npm", "WARN", "npm not found. Required for Frida 17 Python API Java bridge setup.", "#ffa657")

            # Device connection
            rc, devices_out = self._run([ADB_PATH, "devices"], timeout=6)
            lines = [ln.strip() for ln in devices_out.splitlines() if ln.strip() and not ln.lower().startswith("list of devices")]
            active = [ln for ln in lines if "\tdevice" in ln]
            unauthorized = [ln for ln in lines if "unauthorized" in ln]
            offline = [ln for ln in lines if "offline" in ln]

            if unauthorized:
                self._emit("ADB Device", "WARN", "Device unauthorized. Accept the RSA prompt on the phone.", "#ffa657")
                self.done_signal.emit()
                return
            if offline:
                self._emit("ADB Device", "WARN", "Device is offline. Try reconnecting USB or restarting adb server.", "#ffa657")
                self.done_signal.emit()
                return
            if not active:
                self._emit("ADB Device", "FAIL", "No authorized Android device found. Run: adb devices", "#ff7b72")
                self.done_signal.emit()
                return

            serial = active[0].split()[0]
            self._emit("ADB Device", "OK", f"Connected: {serial}", "#7ee787")

            rc, model = self._adb_shell("getprop ro.product.model", timeout=4)
            rc, manufacturer = self._adb_shell("getprop ro.product.manufacturer", timeout=4)
            rc, android_ver = self._adb_shell("getprop ro.build.version.release", timeout=4)
            rc, sdk_ver = self._adb_shell("getprop ro.build.version.sdk", timeout=4)
            self._emit("Android Build", "OK", f"{manufacturer} {model} | Android {android_ver} / SDK {sdk_ver}", "#7ee787")

            rc, battery = self._adb_shell("dumpsys battery | grep -E 'level:|status:|temperature:'", timeout=5)
            if battery and "timeout" not in battery.lower():
                compact = "; ".join([ln.strip() for ln in battery.splitlines() if ln.strip()])
                self._emit("Battery", "OK", compact, "#7ee787")

            # Root and SELinux
            rc, id_out = self._adb_shell("su -c id", timeout=5)
            if "uid=0" in id_out:
                self._emit("Root / su", "OK", id_out, "#7ee787")
            else:
                self._emit("Root / su", "WARN", id_out or "Root unavailable or denied", "#ffa657")

            rc, selinux = self._adb_shell("getenforce", timeout=4)
            selinux_state = (selinux or "unknown").splitlines()[0].strip()
            if selinux_state.lower() == "permissive":
                self._emit("SELinux", "OK", "Permissive", "#7ee787")
            elif selinux_state.lower() == "enforcing":
                self._emit("SELinux", "WARN", "Enforcing. Frida may still work, but some actions may need permissive/root.", "#ffa657")
            else:
                self._emit("SELinux", "WARN", selinux_state, "#ffa657")

            # frida-server
            rc, frida_pid = self._adb_shell("su -c 'pidof frida-server || ps -A | grep frida-server'", timeout=5)
            if frida_pid and "not found" not in frida_pid.lower() and "permission" not in frida_pid.lower():
                self._emit("frida-server", "OK", f"Running: {frida_pid.splitlines()[0]}", "#7ee787")
            else:
                self._emit("frida-server", "WARN", "Not running or not visible. Use START SERVER.", "#ffa657")

            rc, server_ver = self._adb_shell("su -c '/data/local/tmp/frida-server --version'", timeout=5)
            m = re.search(r"(\d+\.\d+\.\d+)", server_ver or "")
            if m:
                self._emit("frida-server Version", "OK", m.group(1), "#7ee787")
            else:
                self._emit("frida-server Version", "WARN", server_ver or "Could not read /data/local/tmp/frida-server", "#ffa657")

            # Proxy state
            rc, proxy = self._adb_shell("settings get global http_proxy", timeout=4)
            proxy = (proxy or "").strip()
            if proxy and proxy.lower() not in ("null", ":0"):
                self._emit("Android Global Proxy", "WARN", proxy, "#ffa657")
            else:
                self._emit("Android Global Proxy", "OK", "clear", "#7ee787")

            # Current foreground app and optional selected target app
            rc, top = self._adb_shell("dumpsys activity activities | grep -E 'mResumedActivity|topResumedActivity' | tail -n 1", timeout=6)
            if top:
                self._emit("Foreground App", "INFO", top, "#58a6ff")

            if self.target_pkg:
                rc, pm = self._adb_shell(f"pm path {self.target_pkg}", timeout=5)
                if "package:" in pm:
                    rc, pid = self._adb_shell(f"pidof {self.target_pkg}", timeout=4)
                    if pid:
                        self._emit("Selected Target", "OK", f"{self.target_pkg} running pid={pid}", "#7ee787")
                    else:
                        self._emit("Selected Target", "INFO", f"{self.target_pkg} installed but not running", "#58a6ff")
                else:
                    self._emit("Selected Target", "WARN", f"{self.target_pkg} not installed or not visible", "#ffa657")

            self._log("Device health check complete.", "#7ee787")
        finally:
            self.done_signal.emit()

    def stop(self):
        self.running = False


class LogcatWorker(QThread):
    new_log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        process = subprocess.Popen([ADB_PATH, "logcat", "-v", "threadtime"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        while self.running:
            try:
                line = process.stdout.readline()
            except UnicodeDecodeError as e:
                self.new_log_signal.emit(f"[UFT-DECODE-WARN] Replaced undecodable logcat bytes: {e}")
                continue
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
                encoding="utf-8",
                errors="replace",
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
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env
            )

            while self.process.poll() is None:
                if self.isInterruptionRequested():
                    self.process.terminate()
                    break
                try:
                    line = self.process.stdout.readline()
                except UnicodeDecodeError as e:
                    self.log_signal.emit("WARN", f"CLI output contained undecodable bytes; replaced/ignored: {e}")
                    continue
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

class SideNavButton(QPushButton):
    """Compact sidebar button with fixed icon/text columns so labels do not shift behind emoji."""

    def __init__(self, icon, label, shortcut='', parent=None):
        super().__init__(parent)
        self.nav_icon = str(icon or '').strip() or '•'
        self.nav_label = str(label or '').strip() or 'Settings'
        self.nav_shortcut = str(shortcut or '').strip()
        self.setText('')
        self.setCheckable(True)
        self.setFixedHeight(34)
        self.setCursor(Qt.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.update_tooltip()

    def update_tooltip(self):
        self.setToolTip(f"{self.nav_icon} {self.nav_label}" + (f" — {self.nav_shortcut}" if self.nav_shortcut else ''))

    def set_nav_text(self, icon, label):
        self.nav_icon = str(icon or '').strip() or self.nav_icon
        self.nav_label = str(label or '').strip() or self.nav_label
        self.update_tooltip()
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        selected = self.isChecked()
        enabled = self.isEnabled()
        hover = self.underMouse() and enabled
        bg = QColor('#1f6feb') if selected else (QColor('#21262d') if hover else QColor(0, 0, 0, 0))
        if bg.alpha() != 0:
            painter.setBrush(bg)
            painter.setPen(Qt.NoPen)
            painter.drawRoundedRect(self.rect().adjusted(1, 1, -1, -1), 7, 7)

        icon_rect = QRect(8, 0, 30, self.height())
        text_rect = QRect(44, 0, max(10, self.width() - 52), self.height())

        icon_font = QFont(self.font())
        icon_font.setPointSize(14)
        painter.setFont(icon_font)
        painter.setPen(QColor('white') if selected else (QColor('#6e7681') if not enabled else QColor('#c9d1d9')))
        painter.drawText(icon_rect, Qt.AlignCenter, self.nav_icon)

        text_font = QFont(self.font())
        text_font.setPointSize(13)
        text_font.setBold(selected)
        painter.setFont(text_font)
        painter.setPen(QColor('white') if selected else (QColor('#6e7681') if not enabled else QColor('#c9d1d9')))
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft, self.nav_label)


class SideNavigationTabs(QWidget):
    """QTabWidget-like container with compact draggable left navigation and scrollable pages."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._titles = []
        self._raw_widgets = []
        self._scroll_wrappers = []
        self._shortcut_actions = []
        self._buttons = []
        self._disabled_indices = set()
        self._default_sidebar_width = 245
        self._save_pending = False

        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self.nav_container = QWidget()
        self.nav_container.setObjectName('sideNavContainer')
        self.nav_container.setFixedWidth(223)
        self.nav_container.setStyleSheet("QWidget#sideNavContainer { background: #010409; border-right: 1px solid #30363d; }")
        self.nav_layout = QVBoxLayout(self.nav_container)
        self.nav_layout.setContentsMargins(8, 8, 8, 8)
        self.nav_layout.setSpacing(4)
        self.nav_layout.setAlignment(Qt.AlignTop)

        self.nav_scroll = QScrollArea()
        self.nav_scroll.setWidgetResizable(False)
        self.nav_scroll.setFrameShape(QFrame.NoFrame)
        self.nav_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.nav_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.nav_scroll.setWidget(self.nav_container)
        self.nav_scroll.setMinimumWidth(190)
        self.nav_scroll.setMaximumWidth(520)
        self.nav_scroll.setStyleSheet(
            "QScrollArea { background: #010409; border: none; }"
            "QScrollBar:vertical { width: 10px; background: #010409; }"
            "QScrollBar::handle:vertical { background: #30363d; border-radius: 4px; }"
        )

        self.stack = QStackedWidget()
        self.stack.setObjectName('sideNavStack')

        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(7)
        self.splitter.addWidget(self.nav_scroll)
        self.splitter.addWidget(self.stack)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([self._default_sidebar_width, 1400])
        self.splitter.splitterMoved.connect(self._on_splitter_moved)

        self._layout.addWidget(self.splitter)
        QTimer.singleShot(0, lambda: self.set_sidebar_width(self._default_sidebar_width))

    def sidebar_width(self):
        try:
            sizes = self.splitter.sizes()
            if sizes:
                return max(180, int(sizes[0]))
        except Exception:
            pass
        return self._default_sidebar_width

    def set_sidebar_width(self, width):
        try:
            width = max(180, min(520, int(width)))
        except Exception:
            width = self._default_sidebar_width
        total = max(sum(self.splitter.sizes()) or self.width() or 1600, width + 600)
        self.splitter.setSizes([width, max(600, total - width)])
        self.nav_container.setFixedWidth(max(160, width - 22))
        for btn in self._buttons:
            btn.setMinimumWidth(max(150, width - 30))
        self.nav_container.adjustSize()

    def _on_splitter_moved(self, pos, index):
        self.nav_container.setFixedWidth(max(160, self.sidebar_width() - 22))
        for btn in self._buttons:
            btn.setMinimumWidth(max(150, self.sidebar_width() - 30))
        self.nav_container.adjustSize()
        if not self._save_pending:
            self._save_pending = True
            QTimer.singleShot(300, self._save_sidebar_width)

    def _save_sidebar_width(self):
        self._save_pending = False
        try:
            win = self.window()
            if win and hasattr(win, 'save_settings'):
                win.save_settings()
        except Exception:
            pass

    def _shortcut_text_for_index(self, index):
        if index < 9:
            return f"Ctrl+{index + 1}"
        if index == 9:
            return "Ctrl+0"
        if index < 19:
            return f"Ctrl+Shift+{index - 9}"
        return ""

    def _split_icon_title(self, title, index):
        raw = str(title or '').strip()
        if not raw:
            return '⚙', 'Settings'
        if 'settings' in raw.lower() or '⚙' in raw:
            return '⚙', 'Settings'
        parts = raw.split(maxsplit=1)
        if len(parts) == 1:
            return parts[0], ('Settings' if '⚙' in parts[0] else parts[0])
        icon, label = parts[0].strip(), parts[1].strip()
        if not label:
            label = 'Settings' if '⚙' in icon else raw
        return icon, label

    def _make_button(self, icon, label, index, shortcut):
        icon = str(icon or '').strip()
        label = str(label or '').strip()
        if not label or 'settings' in label.lower() or '⚙' in icon:
            icon, label = '⚙', 'Settings'
        btn = SideNavButton(icon, label, shortcut, self)
        btn.setMinimumWidth(max(150, self.sidebar_width() - 30))
        btn.clicked.connect(lambda checked=False, i=index: self.setCurrentIndex(i))
        return btn

    def _refresh_button_styles(self):
        current = self.stack.currentIndex()
        for idx, btn in enumerate(self._buttons):
            selected = idx == current
            title = self._titles[idx] if idx < len(self._titles) else ''
            if 'settings' in str(title).lower() or '⚙' in str(title):
                if hasattr(btn, 'set_nav_text'):
                    btn.set_nav_text('⚙', 'Settings')
                else:
                    btn.setText('⚙  Settings')
            btn.blockSignals(True)
            btn.setChecked(selected)
            btn.blockSignals(False)
            btn.update()

    def _register_shortcut(self, index, shortcut):
        if not shortcut:
            return
        action = QAction(self)
        action.setShortcut(shortcut)
        action.setShortcutContext(Qt.ApplicationShortcut)
        action.triggered.connect(lambda checked=False, i=index: self.setCurrentIndex(i))
        self.addAction(action)
        self._shortcut_actions.append(action)

    def addTab(self, widget, title):
        index = self.stack.count()
        raw_title = str(title)
        icon, label = self._split_icon_title(raw_title, index)
        if 'settings' in raw_title.lower() or '⚙' in raw_title:
            icon, label = '⚙', 'Settings'

        self._titles.append(raw_title)
        self._raw_widgets.append(widget)

        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 44, 0)
        host_layout.setSpacing(0)
        host_layout.addWidget(widget)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setViewportMargins(0, 0, 18, 0)
        scroll.setWidget(host)
        scroll.setStyleSheet(
            "QScrollArea { background: #0d1117; border: none; }"
            "QScrollBar:vertical { width: 12px; background: #010409; margin: 0px; }"
            "QScrollBar::handle:vertical { background: #30363d; border-radius: 5px; min-height: 24px; }"
            "QScrollBar:horizontal { height: 12px; background: #010409; margin: 0px; }"
            "QScrollBar::handle:horizontal { background: #30363d; border-radius: 5px; min-width: 24px; }"
        )
        self._scroll_wrappers.append(scroll)
        self.stack.addWidget(scroll)

        shortcut = self._shortcut_text_for_index(index)
        btn = self._make_button(icon, label, index, shortcut)
        self._buttons.append(btn)
        self.nav_layout.addWidget(btn)
        self._register_shortcut(index, shortcut)
        self.nav_container.adjustSize()
        self._refresh_button_styles()

        if index == 0:
            self.setCurrentIndex(0)
        return index

    def addDisabledTab(self, title, message='Coming soon'):
        """Add a visible disabled navigation entry reserved for a future workspace."""
        index = self.stack.count()
        raw_title = str(title)
        icon, label = self._split_icon_title(raw_title, index)
        if not label.strip() and '⚙' in icon:
            label = 'Settings'

        placeholder = QWidget()
        placeholder_layout = QVBoxLayout(placeholder)
        placeholder_label = QLabel(f"{label}\n\n{message}")
        placeholder_label.setAlignment(Qt.AlignCenter)
        placeholder_label.setWordWrap(True)
        placeholder_label.setStyleSheet("color: #8b949e; font-size: 18px; padding: 40px;")
        placeholder_layout.addWidget(placeholder_label, 1)

        host = QWidget()
        host_layout = QVBoxLayout(host)
        host_layout.setContentsMargins(0, 0, 44, 0)
        host_layout.setSpacing(0)
        host_layout.addWidget(placeholder)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setViewportMargins(0, 0, 18, 0)
        scroll.setWidget(host)
        scroll.setStyleSheet(
            "QScrollArea { background: #0d1117; border: none; }"
            "QScrollBar:vertical { width: 12px; background: #010409; margin: 0px; }"
            "QScrollBar::handle:vertical { background: #30363d; border-radius: 5px; min-height: 24px; }"
        )

        self._titles.append(raw_title)
        self._raw_widgets.append(placeholder)
        self._scroll_wrappers.append(scroll)
        self._disabled_indices.add(index)
        self.stack.addWidget(scroll)

        btn = self._make_button(icon, label, index, '')
        btn.setEnabled(False)
        btn.setToolTip(f"{icon} {label} — coming soon")
        self._buttons.append(btn)
        self.nav_layout.addWidget(btn)
        self.nav_container.adjustSize()
        self._refresh_button_styles()
        return index

    def setCurrentIndex(self, index):
        try:
            index = int(index)
        except Exception:
            return
        if 0 <= index < self.stack.count():
            if hasattr(self, '_disabled_indices') and index in self._disabled_indices:
                return
            self.stack.setCurrentIndex(index)
            self._refresh_button_styles()

    def currentIndex(self):
        return self.stack.currentIndex()

    def count(self):
        return self.stack.count()

    def widget(self, index):
        if 0 <= index < len(self._raw_widgets):
            return self._raw_widgets[index]
        return None

    def setCurrentWidget(self, widget):
        for idx, raw in enumerate(self._raw_widgets):
            if raw is widget:
                self.setCurrentIndex(idx)
                return
        for idx, wrapper in enumerate(self._scroll_wrappers):
            if wrapper is widget:
                self.setCurrentIndex(idx)
                return

    def indexOfTitleContains(self, text):
        needle = str(text).lower()
        for idx, title in enumerate(self._titles):
            if needle in title.lower():
                return idx
        return -1

    def tabText(self, index):
        if 0 <= index < len(self._titles):
            return self._titles[index]
        return ''

    def ensure_settings_label_visible(self):
        found = False
        for idx, title in enumerate(self._titles):
            title_s = str(title or '')
            if 'settings' in title_s.lower() or '⚙' in title_s:
                found = True
                if idx < len(self._buttons):
                    btn = self._buttons[idx]
                    if hasattr(btn, 'set_nav_text'):
                        btn.set_nav_text('⚙', 'Settings')
                    else:
                        btn.setText('⚙  Settings')
        if not found and self._buttons:
            self._titles[-1] = '⚙ Settings'
            btn = self._buttons[-1]
            if hasattr(btn, 'set_nav_text'):
                btn.set_nav_text('⚙', 'Settings')
            else:
                btn.setText('⚙  Settings')
        self._refresh_button_styles()


class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.code_editor = editor

    def sizeHint(self):
        return QSize(self.code_editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.code_editor.line_number_area_paint_event(event)


class FridaScriptEditor(QPlainTextEdit):
    """Plain-text Frida script editor with a left-side line-number gutter and zoom support."""

    fontSizeChanged = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.line_number_area = LineNumberArea(self)
        self.search_match_lines = set()
        self.active_search_match_line = None
        self.min_font_size = 8
        self.max_font_size = 40
        self.default_font_size = 12
        self._native_zoom_accum = 0.0
        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.update)
        self.cursorPositionChanged.connect(self.line_number_area.update)
        self.update_line_number_area_width(0)

    def set_script_font_size(self, size, emit_signal=True):
        """Set the editor + line-number gutter font size."""
        try:
            size = int(size)
        except Exception:
            size = self.default_font_size
        size = max(self.min_font_size, min(self.max_font_size, size))

        font = QFont(self.font())
        font.setPointSize(size)
        font.setFamily("Menlo" if sys.platform == "darwin" else "Monospace")
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.line_number_area.setFont(font)
        self.update_line_number_area_width(0)
        self.line_number_area.update()
        self.viewport().update()
        if emit_signal:
            self.fontSizeChanged.emit(size)

    def current_font_size(self):
        size = self.font().pointSize()
        return size if size > 0 else self.default_font_size

    def zoom_in_font(self):
        self.set_script_font_size(self.current_font_size() + 1)

    def zoom_out_font(self):
        self.set_script_font_size(self.current_font_size() - 1)

    def reset_font_zoom(self):
        self.set_script_font_size(self.default_font_size)

    def wheelEvent(self, event):
        # Standard editor zoom behavior for mouse wheels and Mac trackpad scroll gestures
        # while Command/Ctrl is held. Normal scrolling remains unchanged.
        if event.modifiers() & (Qt.ControlModifier | Qt.MetaModifier):
            delta = event.angleDelta().y()
            if delta > 0:
                self.zoom_in_font()
            elif delta < 0:
                self.zoom_out_font()
            event.accept()
            return
        super().wheelEvent(event)

    def event(self, event):
        # macOS pinch-to-zoom arrives as a NativeGesture event in Qt when available.
        try:
            if event.type() == QEvent.NativeGesture and hasattr(event, "gestureType"):
                if event.gestureType() == Qt.ZoomNativeGesture:
                    self._native_zoom_accum += float(event.value())
                    threshold = 0.15
                    if abs(self._native_zoom_accum) >= threshold:
                        steps = min(3, int(abs(self._native_zoom_accum) / threshold))
                        if self._native_zoom_accum > 0:
                            for _ in range(steps):
                                self.zoom_in_font()
                        else:
                            for _ in range(steps):
                                self.zoom_out_font()
                        self._native_zoom_accum = 0.0
                    event.accept()
                    return True
        except Exception:
            pass
        return super().event(event)

    def line_number_area_width(self):
        digits = len(str(max(1, self.blockCount())))
        # Extra room leaves space for a visible search-hit stripe on the left.
        return 18 + self.fontMetrics().horizontalAdvance('9') * digits

    def set_search_match_lines(self, block_numbers, active_block_number=None):
        """Update gutter markers for search hits. block_numbers are zero-based."""
        self.search_match_lines = set(block_numbers or [])
        self.active_search_match_line = active_block_number
        self.line_number_area.update()

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())

        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(), self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), QColor('#010409'))

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = int(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + int(self.blockBoundingRect(block).height())
        current_block = self.textCursor().blockNumber()
        fm_height = self.fontMetrics().height()

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                row_height = int(self.blockBoundingRect(block).height())

                # Search visibility in the gutter:
                #   amber = line contains a search hit
                #   purple = current/selected search hit line
                if block_number in self.search_match_lines:
                    match_color = QColor('#6b4b00')
                    stripe_color = QColor('#d29922')
                    if block_number == self.active_search_match_line:
                        match_color = QColor('#4c1d95')
                        stripe_color = QColor('#d2a8ff')
                    painter.fillRect(0, top, self.line_number_area.width(), row_height, match_color)
                    painter.fillRect(0, top, 4, row_height, stripe_color)
                elif block_number == current_block:
                    painter.fillRect(0, top, self.line_number_area.width(), row_height, QColor('#0d1117'))
                    painter.fillRect(0, top, 4, row_height, QColor('#1f6feb'))

                if block_number == current_block or block_number == self.active_search_match_line:
                    painter.setPen(QColor('#ffffff'))
                    font = QFont(self.font())
                    font.setBold(True)
                    painter.setFont(font)
                elif block_number in self.search_match_lines:
                    painter.setPen(QColor('#ffe8a3'))
                    painter.setFont(self.font())
                else:
                    painter.setPen(QColor('#8b949e'))
                    painter.setFont(self.font())
                painter.drawText(4, top, self.line_number_area.width() - 9, fm_height, Qt.AlignRight, number)

            block = block.next()
            top = bottom
            bottom = top + int(self.blockBoundingRect(block).height())
            block_number += 1


class ZoomableLogTextEdit(QTextEdit):
    """Read-only log viewer with adjustable monospace font size and Ctrl/Cmd+wheel zoom."""

    fontSizeChanged = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.min_font_size = 8
        self.max_font_size = 40
        self.default_font_size = 10
        self._native_zoom_accum = 0.0

    def set_log_font_size(self, size, emit_signal=True):
        try:
            size = int(size)
        except Exception:
            size = self.default_font_size
        size = max(self.min_font_size, min(self.max_font_size, size))

        font = QFont("Menlo" if sys.platform == "darwin" else "Monospace")
        font.setPointSize(size)
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        if emit_signal:
            self.fontSizeChanged.emit(size)

    def current_font_size(self):
        size = self.font().pointSize()
        return size if size > 0 else self.default_font_size

    def zoom_in_font(self):
        self.set_log_font_size(self.current_font_size() + 1)

    def zoom_out_font(self):
        self.set_log_font_size(self.current_font_size() - 1)

    def reset_font_zoom(self):
        self.set_log_font_size(self.default_font_size)

    def wheelEvent(self, event):
        # Standard macOS/Windows/Linux behavior: hold Command/Ctrl and scroll to zoom.
        if event.modifiers() & (Qt.ControlModifier | Qt.MetaModifier):
            delta = event.angleDelta().y()
            if delta > 0:
                self.zoom_in_font()
            elif delta < 0:
                self.zoom_out_font()
            event.accept()
            return
        super().wheelEvent(event)

    def event(self, event):
        # macOS trackpad pinch support where Qt exposes NativeGesture events.
        try:
            if event.type() == QEvent.NativeGesture:
                value = 0.0
                if hasattr(event, "value"):
                    value = float(event.value())
                self._native_zoom_accum += value
                if self._native_zoom_accum >= 0.15:
                    self.zoom_in_font()
                    self._native_zoom_accum = 0.0
                    return True
                if self._native_zoom_accum <= -0.15:
                    self.zoom_out_font()
                    self._native_zoom_accum = 0.0
                    return True
        except Exception:
            pass
        return super().event(event)


class FridaLogDisplay(ZoomableLogTextEdit):
    """Read-only Frida log viewer that emits the double-clicked plain-text line."""
    lineDoubleClicked = pyqtSignal(str)

    def mouseDoubleClickEvent(self, event):
        cursor = self.cursorForPosition(event.pos())
        line = cursor.block().text()
        if line:
            self.lineDoubleClicked.emit(line)
        super().mouseDoubleClickEvent(event)


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
        if pixmap and not pixmap.isNull():
            self.setPixmap(pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.clear()

    def set_image_path(self, path):
        self.current_path = path
        pixmap = QPixmap(path)
        self.update_image(pixmap, path)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.current_path and os.path.exists(self.current_path):
            pixmap = QPixmap(self.current_path)
            if not pixmap.isNull():
                self.setPixmap(pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))

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



# --- PHA NOTES EMBEDDED WORKSPACE ---

class PhaEditor(QTextEdit):
    """Rich-text note editor. Shift-click opens hyperlinks."""
    def mousePressEvent(self, event):
        if event.modifiers() & Qt.ShiftModifier:
            anchor = self.anchorAt(event.pos())
            if anchor:
                QDesktopServices.openUrl(QUrl(anchor))
                return
        super().mousePressEvent(event)


class PhaNotesWorkspace(QWidget):
    """Embedded version of the standalone PhaNotes app."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.root_dir = os.path.expanduser("~/.jpeixoto/PhaNotes")
        os.makedirs(self.root_dir, exist_ok=True)
        self.save_cache = {}
        self.is_dark_mode = False
        self.init_ui()
        self.init_shortcuts()
        self.load_from_disk()

    def init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(6)
        self.toolbar = QToolBar("PHA Notes Toolbar")
        self.toolbar.setIconSize(QSize(20, 20))
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet("QToolBar { background: #161b22; border: 1px solid #30363d; spacing: 8px; padding: 4px; }")
        root_layout.addWidget(self.toolbar)
        self.create_toolbar()

        self.main_splitter = QSplitter(Qt.Horizontal)
        root_layout.addWidget(self.main_splitter, 1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Search PHA notes...")
        self.search_bar.textChanged.connect(self.filter_tree)
        left_layout.addWidget(self.search_bar)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.itemClicked.connect(self.on_item_single_clicked)
        self.tree.itemDoubleClicked.connect(self.on_item_double_clicked)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.setStyleSheet("QTreeWidget { background: #010409; color: #c9d1d9; border: 1px solid #30363d; }")
        left_layout.addWidget(self.tree)
        self.main_splitter.addWidget(left_panel)

        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.handle_autosave)

        self.preview_pane = QTextEdit()
        self.preview_pane.setReadOnly(True)
        self.preview_pane.setPlaceholderText("Select a note to preview...")
        self.preview_pane.setStyleSheet("background-color: #ffffff; color: #333; padding: 30px;")
        self.tabs.addTab(self.preview_pane, "📖 PREVIEW")
        try:
            self.tabs.tabBar().setTabButton(0, QTabBar.RightSide, None)
        except Exception:
            pass

        self.main_splitter.addWidget(self.tabs)
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 4)
        self.main_splitter.setSizes([320, 1000])

    def init_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+S"), self, lambda: self.save_tab(self.tabs.currentIndex()))
        QShortcut(QKeySequence("Ctrl+W"), self, lambda: self.close_tab(self.tabs.currentIndex()))
        QShortcut(QKeySequence(Qt.CTRL + Qt.Key_Tab), self, self.next_tab)
        QShortcut(QKeySequence(Qt.CTRL + Qt.SHIFT + Qt.Key_Tab), self, self.prev_tab)

    def next_tab(self):
        if self.tabs.count():
            self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) % self.tabs.count())

    def prev_tab(self):
        if self.tabs.count():
            self.tabs.setCurrentIndex((self.tabs.currentIndex() - 1) % self.tabs.count())

    def create_toolbar(self):
        self.font_box = QFontComboBox()
        self.font_box.currentFontChanged.connect(lambda f: self.current_editor().setCurrentFont(f) if self.current_editor() else None)
        self.toolbar.addWidget(self.font_box)

        self.size_box = QComboBox()
        self.size_box.addItems([str(x) for x in [8, 10, 12, 14, 16, 18, 20, 24, 28, 36, 48, 72]])
        self.size_box.setCurrentText("12")
        self.size_box.currentTextChanged.connect(lambda s: self.current_editor().setFontPointSize(float(s)) if self.current_editor() else None)
        self.toolbar.addWidget(self.size_box)
        self.toolbar.addSeparator()

        self.add_act("<b>B</b>", "Bold", self.set_bold)
        self.add_act("<i>I</i>", "Italic", self.set_italic)
        self.add_act("<u>U</u>", "Underline", self.set_underline)
        self.add_act("<s>S</s>", "Strikeout", self.set_strikeout)
        self.toolbar.addSeparator()
        self.add_act("L", "Align Left", lambda: self.current_editor().setAlignment(Qt.AlignLeft) if self.current_editor() else None)
        self.add_act("C", "Align Center", lambda: self.current_editor().setAlignment(Qt.AlignCenter) if self.current_editor() else None)
        self.add_act("R", "Align Right", lambda: self.current_editor().setAlignment(Qt.AlignRight) if self.current_editor() else None)
        self.toolbar.addSeparator()
        self.add_style_act(QStyle.SP_FileDialogContentsView, "Bullet List", self.insert_bullets)
        self.add_act("1.", "Numbered List", self.insert_numbered_list)
        self.add_style_act(QStyle.SP_FileIcon, "Insert Image", self.insert_image)
        self.add_style_act(QStyle.SP_DriveNetIcon, "Insert Hyperlink (Shift+Click to Open)", self.insert_link)
        self.add_style_act(QStyle.SP_DialogSaveButton, "Export PDF", self.export_pdf)
        self.add_style_act(QStyle.SP_MessageBoxInformation, "Toggle Theme", self.toggle_editor_theme)
        self.toolbar.addSeparator()
        self.add_act("Color", "Text Color", self.set_text_color)
        self.add_style_act(QStyle.SP_DirIcon, "New Category", self.add_category)
        self.add_act("New Note", "New Note in Selected Category", self.add_note_from_selection)
        self.add_act("Reload", "Reload PHA Notes from disk", self.load_from_disk)

    def add_act(self, label, tip, func):
        act = QAction(label, self)
        act.setToolTip(tip)
        act.triggered.connect(func)
        self.toolbar.addAction(act)

    def add_style_act(self, style_icon, tip, func):
        icon = self.style().standardIcon(style_icon)
        act = QAction(icon, "", self)
        act.setToolTip(tip)
        act.triggered.connect(func)
        self.toolbar.addAction(act)

    def current_editor(self):
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, PhaEditor) else None

    def set_bold(self):
        if not self.current_editor(): return
        fmt = self.current_editor().currentCharFormat()
        fmt.setFontWeight(QFont.Bold if fmt.fontWeight() != QFont.Bold else QFont.Normal)
        self.current_editor().setCurrentCharFormat(fmt)

    def set_italic(self):
        if not self.current_editor(): return
        fmt = self.current_editor().currentCharFormat()
        fmt.setFontItalic(not fmt.fontItalic())
        self.current_editor().setCurrentCharFormat(fmt)

    def set_underline(self):
        if not self.current_editor(): return
        fmt = self.current_editor().currentCharFormat()
        fmt.setFontUnderline(not fmt.fontUnderline())
        self.current_editor().setCurrentCharFormat(fmt)

    def set_strikeout(self):
        if not self.current_editor(): return
        fmt = self.current_editor().currentCharFormat()
        fmt.setFontStrikeOut(not fmt.fontStrikeOut())
        self.current_editor().setCurrentCharFormat(fmt)

    def set_text_color(self):
        if not self.current_editor(): return
        color = QColorDialog.getColor(parent=self)
        if color.isValid():
            self.current_editor().setTextColor(color)

    def insert_bullets(self):
        if self.current_editor():
            cursor = self.current_editor().textCursor()
            fmt = QTextListFormat()
            fmt.setStyle(QTextListFormat.ListDisc)
            cursor.createList(fmt)

    def insert_numbered_list(self):
        if self.current_editor():
            cursor = self.current_editor().textCursor()
            fmt = QTextListFormat()
            fmt.setStyle(QTextListFormat.ListDecimal)
            cursor.createList(fmt)

    def insert_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.jpg *.jpeg *.bmp)")
        if path and self.current_editor():
            cursor = self.current_editor().textCursor()
            cursor.insertHtml(f'<br><img src="{path}" width="400"><br>')

    def insert_link(self):
        editor = self.current_editor()
        if not editor: return
        url, ok = QInputDialog.getText(self, "Insert Link", "URL:")
        if ok and url:
            cursor = editor.textCursor()
            text = cursor.selectedText() if cursor.hasSelection() else url
            fmt = QTextCharFormat()
            fmt.setAnchor(True)
            fmt.setAnchorHref(url)
            fmt.setForeground(QColor("#58a6ff"))
            fmt.setFontUnderline(True)
            cursor.insertText(text, fmt)
            cursor.setCharFormat(QTextCharFormat())

    def export_pdf(self):
        if not self.current_editor(): return
        path, _ = QFileDialog.getSaveFileName(self, "Export PDF", "", "PDF Files (*.pdf)")
        if path:
            if not path.lower().endswith('.pdf'):
                path += '.pdf'
            printer = QPrinter(QPrinter.HighResolution)
            printer.setOutputFormat(QPrinter.PdfFormat)
            printer.setOutputFileName(path)
            self.current_editor().document().print_(printer)

    def toggle_editor_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        bg = "#252525" if self.is_dark_mode else "white"
        fg = "#dcdcdc" if self.is_dark_mode else "black"
        self.preview_pane.setStyleSheet(f"background-color: {bg}; color: {fg}; padding: 30px;")
        for i in range(1, self.tabs.count()):
            widget = self.tabs.widget(i)
            if widget:
                widget.setStyleSheet(f"background-color: {bg}; color: {fg}; padding: 25px; font-size: 14px;")

    def load_from_disk(self):
        self.tree.clear()
        os.makedirs(self.root_dir, exist_ok=True)
        for cat_name in sorted(os.listdir(self.root_dir)):
            cat_path = os.path.join(self.root_dir, cat_name)
            if os.path.isdir(cat_path):
                cat_item = QTreeWidgetItem(self.tree)
                self.create_tree_row(cat_item, cat_name, is_category=True)
                for file_name in sorted(os.listdir(cat_path)):
                    if file_name.endswith(".html") and file_name != f"{cat_name}.html":
                        note_item = QTreeWidgetItem(cat_item)
                        self.create_tree_row(note_item, file_name, is_category=False)
                cat_item.setExpanded(True)

    def create_tree_row(self, item, text, is_category=False):
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setContentsMargins(5, 2, 5, 2)
        label = QLabel(text.replace(".html", ""))
        label.setStyleSheet("color: #c9d1d9;")
        layout.addWidget(label)
        layout.addStretch()
        if is_category:
            btn = QPushButton("+")
            btn.setFixedSize(QSize(22, 22))
            btn.setStyleSheet("background: #238636; color: white; border-radius: 3px;")
            btn.clicked.connect(lambda _=False, it=item: self.add_note(it))
            layout.addWidget(btn)
        item.setData(0, Qt.UserRole, text)
        self.tree.setItemWidget(item, 0, container)

    def on_item_single_clicked(self, item, col):
        path = self.get_path_from_item(item)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                self.preview_pane.setHtml(f.read())
            self.tabs.setCurrentIndex(0)

    def on_item_double_clicked(self, item, col):
        name = item.data(0, Qt.UserRole)
        path = self.get_path_from_item(item)
        for i in range(1, self.tabs.count()):
            if self.tabs.tabToolTip(i) == path:
                self.tabs.setCurrentIndex(i)
                return
        editor = PhaEditor()
        editor.setAcceptRichText(True)
        bg = "#252525" if self.is_dark_mode else "white"
        fg = "#dcdcdc" if self.is_dark_mode else "black"
        editor.setStyleSheet(f"background-color: {bg}; color: {fg}; padding: 25px; font-size: 14px;")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                editor.setHtml(f.read())
        index = self.tabs.addTab(editor, name.replace(".html", ""))
        self.tabs.setTabToolTip(index, path)
        self.tabs.setCurrentIndex(index)
        self.save_cache[path] = editor.toHtml()

    def get_path_from_item(self, item):
        name = item.data(0, Qt.UserRole)
        parent = item.parent()
        if parent:
            return os.path.join(self.root_dir, parent.data(0, Qt.UserRole), name)
        return os.path.join(self.root_dir, name, f"{name}.html")

    def handle_autosave(self, index):
        for i in range(1, self.tabs.count()):
            self.save_tab(i)

    def save_tab(self, index):
        if index < 1: return
        editor = self.tabs.widget(index)
        path = self.tabs.tabToolTip(index)
        if editor and path:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            html_doc = editor.toHtml()
            if html_doc != self.save_cache.get(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(html_doc)
                self.save_cache[path] = html_doc

    def close_tab(self, index):
        if index == 0: return
        self.save_tab(index)
        self.tabs.removeTab(index)

    def filter_tree(self, text):
        text = str(text or "").lower()
        for i in range(self.tree.topLevelItemCount()):
            cat = self.tree.topLevelItem(i)
            cat_name = str(cat.data(0, Qt.UserRole) or "").lower()
            matched_child = False
            for j in range(cat.childCount()):
                note = cat.child(j)
                note_name = str(note.data(0, Qt.UserRole) or "").lower()
                match = text in note_name
                note.setHidden(not match)
                if match:
                    matched_child = True
            cat.setHidden(bool(text) and text not in cat_name and not matched_child)

    def add_category(self):
        name, ok = QInputDialog.getText(self, "New Category", "Name:")
        if ok and name:
            safe = re.sub(r'[^A-Za-z0-9_. -]+', '_', name).strip()
            os.makedirs(os.path.join(self.root_dir, safe), exist_ok=True)
            open(os.path.join(self.root_dir, safe, f"{safe}.html"), 'a', encoding='utf-8').close()
            self.load_from_disk()

    def add_note_from_selection(self):
        item = self.tree.currentItem()
        if not item:
            QMessageBox.information(self, "New Note", "Select a category first.")
            return
        if item.parent():
            item = item.parent()
        self.add_note(item)

    def add_note(self, parent_item):
        cat_name = parent_item.data(0, Qt.UserRole)
        name, ok = QInputDialog.getText(self, "New Note", "Title:")
        if ok and name:
            safe = re.sub(r'[^A-Za-z0-9_. -]+', '_', name).strip()
            path = os.path.join(self.root_dir, cat_name, f"{safe}.html")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, 'a', encoding='utf-8').close()
            self.load_from_disk()

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item: return
        menu = QMenu(self)
        open_act = menu.addAction("Open")
        delete_act = menu.addAction("Delete Forever")
        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == open_act:
            self.on_item_double_clicked(item, 0)
        elif action == delete_act:
            path = self.get_path_from_item(item)
            if QMessageBox.question(self, "Delete PHA Note", f"Delete forever?\n\n{path}") != QMessageBox.Yes:
                return
            if not item.parent():
                shutil.rmtree(os.path.dirname(path), ignore_errors=True)
            elif os.path.exists(path):
                os.remove(path)
            self.load_from_disk()

# --- BEAUTIFIER EMBEDDED WORKSPACE ---

class BeautifierHighlighter(QSyntaxHighlighter):
    """Syntax highlighting for JavaScript keywords, strings, and comments."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        keyword_fmt = QTextCharFormat()
        keyword_fmt.setForeground(QColor("#C678DD"))
        keyword_fmt.setFontWeight(QFont.Bold)

        string_fmt = QTextCharFormat()
        string_fmt.setForeground(QColor("#98C379"))

        comment_fmt = QTextCharFormat()
        comment_fmt.setForeground(QColor("#5C6370"))

        keywords = [
            r'\bvar\b', r'\blet\b', r'\bconst\b', r'\bfunction\b', r'\breturn\b',
            r'\bif\b', r'\belse\b', r'\bfor\b', r'\bwhile\b', r'\bswitch\b',
            r'\bcase\b', r'\bbreak\b', r'\btry\b', r'\bcatch\b', r'\bnew\b',
            r'\bclass\b', r'\bextends\b', r'\bimport\b', r'\bexport\b', r'\basync\b', r'\bawait\b'
        ]

        for word in keywords:
            self.rules.append((re.compile(word), keyword_fmt))
        self.rules.append((re.compile(r'".*?"'), string_fmt))
        self.rules.append((re.compile(r"'.*?'"), string_fmt))
        self.rules.append((re.compile(r'`.*?`'), string_fmt))
        self.rules.append((re.compile(r'//.*'), comment_fmt))
        self.rules.append((re.compile(r'/\*.*?\*/'), comment_fmt))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class JSBeautifierWorkspace(QWidget):
    """Embedded version of the standalone Professional JS IDE & Beautifier."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_path = None
        self.init_ui()
        self.setup_shortcuts()

    def init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(6)

        toolbar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search JavaScript (Find All)...")
        self.search_input.setMinimumWidth(260)
        self.search_input.textChanged.connect(self.find_all_logic)

        btn_next = QPushButton("Next")
        btn_next.setToolTip("Find next — Ctrl+G")
        btn_next.clicked.connect(self.find_next)

        btn_prev = QPushButton("Prev")
        btn_prev.setToolTip("Find previous — Ctrl+Shift+G")
        btn_prev.clicked.connect(self.find_prev)

        btn_load = QPushButton("📂 Load File")
        btn_load.clicked.connect(self.load_file)

        btn_save = QPushButton("💾 Save")
        btn_save.clicked.connect(self.save_file)

        btn_save_as = QPushButton("💾 Save As")
        btn_save_as.clicked.connect(self.save_file_as)

        btn_beautify = QPushButton("✨ Beautify Code")
        btn_beautify.setObjectName("runBtn")
        btn_beautify.setToolTip("Beautify JavaScript — Ctrl+B")
        btn_beautify.clicked.connect(self.beautify_js)

        btn_to_frida = QPushButton("➡ Send to Frida Manager")
        btn_to_frida.setToolTip("Copy current beautified code into the main Frida Manager editor")
        btn_to_frida.clicked.connect(self.send_to_frida_manager)

        toolbar.addWidget(QLabel("Find:"))
        toolbar.addWidget(self.search_input, 1)
        toolbar.addWidget(btn_next)
        toolbar.addWidget(btn_prev)
        toolbar.addStretch(1)
        toolbar.addWidget(btn_load)
        toolbar.addWidget(btn_save)
        toolbar.addWidget(btn_save_as)
        toolbar.addWidget(btn_beautify)
        toolbar.addWidget(btn_to_frida)
        self.main_layout.addLayout(toolbar)

        self.editor = QPlainTextEdit()
        font = QFont("Menlo", 12) if sys.platform == "darwin" else QFont("Consolas", 11)
        self.editor.setFont(font)
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.editor.setStyleSheet("background: #010409; color: #d1d5da; border: 1px solid #30363d;")
        self.highlighter = BeautifierHighlighter(self.editor.document())
        self.main_layout.addWidget(self.editor, 1)

        result_label = QLabel("Search Results: double-click a row to jump to code")
        result_label.setStyleSheet("color: #8b949e;")
        self.main_layout.addWidget(result_label)

        self.results_table = QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels(["Line", "Position", "Snippet"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_table.setMaximumHeight(220)
        self.results_table.itemDoubleClicked.connect(self.navigate_to_result)
        self.main_layout.addWidget(self.results_table)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #8b949e; padding: 3px;")
        self.main_layout.addWidget(self.status_label)

    def setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self, lambda: self.search_input.setFocus())
        QShortcut(QKeySequence("Ctrl+G"), self, self.find_next)
        QShortcut(QKeySequence("Ctrl+Shift+G"), self, self.find_prev)
        QShortcut(QKeySequence("Ctrl+B"), self, self.beautify_js)
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_file)

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open JavaScript File", FRIDA_SCRIPTS_DIR if os.path.exists(FRIDA_SCRIPTS_DIR) else "", "JS Files (*.js);;All Files (*)")
        if path:
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    self.editor.setPlainText(f.read())
                self.current_path = path
                self.status_label.setText(f"Loaded: {path}")
                self.find_all_logic()
            except Exception as e:
                QMessageBox.warning(self, "Load Error", f"Could not load file:\n{e}")

    def save_file(self):
        if not self.current_path:
            return self.save_file_as()
        try:
            with open(self.current_path, 'w', encoding='utf-8') as f:
                f.write(self.editor.toPlainText())
            self.status_label.setText(f"Saved: {self.current_path}")
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Could not save file:\n{e}")

    def save_file_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save JavaScript File", FRIDA_SCRIPTS_DIR if os.path.exists(FRIDA_SCRIPTS_DIR) else "", "JS Files (*.js);;All Files (*)")
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ".js"
        self.current_path = path
        self.save_file()

    def beautify_js(self):
        code = self.editor.toPlainText()
        if not code.strip():
            self.status_label.setText("Nothing to beautify")
            return
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            self.editor.setPlainText(jsbeautifier.beautify(code, opts))
            self.status_label.setText("Beautified JavaScript")
            self.find_all_logic()
        except Exception as e:
            QMessageBox.warning(self, "Beautify Error", f"Could not beautify code:\n{e}")

    def find_all_logic(self):
        self.results_table.setRowCount(0)
        text = self.search_input.text()
        if not text:
            return
        doc = self.editor.document()
        cursor = QTextCursor(doc)
        while True:
            cursor = doc.find(text, cursor)
            if cursor.isNull():
                break
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)
            line = cursor.blockNumber() + 1
            col = cursor.columnNumber()
            snippet = cursor.block().text().strip()[:120]
            self.results_table.setItem(row, 0, QTableWidgetItem(str(line)))
            self.results_table.setItem(row, 1, QTableWidgetItem(str(col)))
            self.results_table.setItem(row, 2, QTableWidgetItem(snippet))
            self.results_table.item(row, 0).setData(Qt.UserRole, cursor.selectionStart())
        self.status_label.setText(f"Find results: {self.results_table.rowCount()}")

    def find_next(self):
        if self.search_input.text():
            self.editor.find(self.search_input.text())

    def find_prev(self):
        if self.search_input.text():
            self.editor.find(self.search_input.text(), QTextDocument.FindBackward)

    def navigate_to_result(self, item):
        pos = self.results_table.item(item.row(), 0).data(Qt.UserRole)
        cursor = self.editor.textCursor()
        cursor.setPosition(pos)
        self.editor.setTextCursor(cursor)
        self.editor.setFocus()

    def send_to_frida_manager(self):
        main = self.window()
        if hasattr(main, 'editor'):
            main.editor.setPlainText(self.editor.toPlainText())
            if hasattr(main, 'switch_to_tab_containing'):
                main.switch_to_tab_containing("Frida Manager")
            try:
                main.route_frida_log("SYSTEM", "Beautifier code sent to Frida Manager editor.")
            except Exception:
                pass
            self.status_label.setText("Sent code to Frida Manager")
        else:
            QMessageBox.information(self, "Frida Manager", "Main Frida editor is not available yet.")



# --- DECRYPT COCOAS EMBEDDED WORKSPACE ---
DECRYPT_COCOAS_BASE_PATH = os.path.expanduser("~/.jpeixoto/DecryptCocoas")
os.makedirs(DECRYPT_COCOAS_BASE_PATH, exist_ok=True)
DECRYPT_COCOAS_CONFIG_FILE = os.path.join(DECRYPT_COCOAS_BASE_PATH, "config_DecryptCocoas.json")

# --- SETTINGS DIALOG ---
class CocosSettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Global Binary Settings")
        self.setFixedWidth(600)
        self.layout = QVBoxLayout(self)

        self.at_edit = self.add_setting("Apktool Path:")
        self.rv_edit = self.add_setting("Reverse Path:")
        self.pt_edit = self.add_setting("Prettier Path:")

        self.btn_save = QPushButton("Save Settings")
        self.btn_save.setFixedHeight(35)
        self.btn_save.clicked.connect(self.accept)
        self.layout.addWidget(self.btn_save)
        self.load()

    def add_setting(self, label):
        h = QHBoxLayout()
        h.addWidget(QLabel(label))
        le = QLineEdit()
        h.addWidget(le)
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda: le.setText(QFileDialog.getOpenFileName(self, label, "", "")[0]))
        h.addWidget(btn)
        self.layout.addLayout(h)
        return le

    def load(self):
        if os.path.exists(DECRYPT_COCOAS_CONFIG_FILE):
            with open(DECRYPT_COCOAS_CONFIG_FILE, 'r') as f:
                d = json.load(f)
                self.at_edit.setText(d.get("at", ""))
                self.rv_edit.setText(d.get("rv", ""))
                self.pt_edit.setText(d.get("pt", ""))

    def get_data(self):
        return {"at": self.at_edit.text(), "rv": self.rv_edit.text(), "pt": self.pt_edit.text()}


# --- BASE PIPELINE STEP ---
class PipelineStep(QObject):
    finished_signal = pyqtSignal(bool)
    log_signal = pyqtSignal(str, str)

    def __init__(self, main_win):
        super().__init__()
        self.main_win = main_win
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.read_out)
        self.process.readyReadStandardError.connect(self.read_err)
        self.process.finished.connect(self.on_process_finished)
        self.spinner = ["|", "/", "-", "\\"]
        self.spinner_idx = 0

    def read_out(self):
        data = self.process.readAllStandardOutput().data().decode(errors='replace').strip()
        if not data: return
        if "✓ Found key:" in data:
            key_match = re.search(r'Found key: "([^"]+)"', data)
            if key_match:
                key = key_match.group(1)
                self.main_win.key_input.setText(key)
                self.log_signal.emit(f"<b>{data}</b>", "#4CAF50")
            return
        if "Trying key" in data:
            char = self.spinner[self.spinner_idx % 4]
            self.spinner_idx += 1
            self.main_win.update_status_line(f"{char} {data}", "#FFEB3B")
            return
        self.log_signal.emit(data, "#d4d4d4")

    def read_err(self):
        data = self.process.readAllStandardError().data().decode(errors='replace').strip()
        if not data: return
        if "Successfully" in data or "written to" in data:
            self.log_signal.emit(data, "#4CAF50")
        else:
            self.log_signal.emit(f"[LOG] {data}", "#d4d4d4")

    def on_process_finished(self):
        self.finished_signal.emit(True)

    def run_bash(self, cmd, cwd=None):
        env = QProcessEnvironment.systemEnvironment()
        path = env.value("PATH")
        new_path = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:" + path
        env.insert("PATH", new_path)
        self.process.setProcessEnvironment(env)
        if cwd: self.process.setWorkingDirectory(cwd)
        self.log_signal.emit(f"[EXEC] {cmd}", "#5c5c5c")
        self.process.start("bash", ["-c", cmd])


# --- STEP CLASSES ---
class Step0_Unzip(PipelineStep):
    def run(self):
        self.log_signal.emit(f"\n--- STEP 0: Unzipping Container ---", "#FF9800")
        try:
            with zipfile.ZipFile(self.main_win.zip_path.text(), 'r') as z:
                z.extractall(self.main_win.output_path.text())
            self.finished_signal.emit(True)
        except Exception as e:
            self.log_signal.emit(f"Unzip Failed: {e}", "#f44336")
            self.finished_signal.emit(False)


class Step1_Apktool(PipelineStep):
    def __init__(self, main_win):
        super().__init__(main_win)
        self.queue = []
        self.process.finished.disconnect()
        self.process.finished.connect(self.process_next)

    def run(self):
        self.log_signal.emit(f"\n--- STEP 1: Extracting APKs ---", "#2196F3")
        self.queue = glob.glob(os.path.join(self.main_win.output_path.text(), "*.apk"))
        self.process_next()

    def process_next(self):
        if not self.queue: self.finished_signal.emit(True); return
        apk = self.queue.pop(0)
        dest = os.path.join(self.main_win.output_path.text(), os.path.basename(apk).replace(".apk", ""))
        self.run_bash(f"'{self.main_win.binaries['at']}' d '{apk}' -o '{dest}' --force")


class Step2_FindFiles(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"\n--- STEP 2: Finding Script Files ---", "#4CAF50")
        self.run_bash("find . -name '*.js'; find . -name '*.jsc'; find . -name '*.lua'; find . -name '*.luac'",
                      cwd=folder_path)


class Step3_FindEncrypted(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"--- STEP 3: Checking Assets ---", "#E91E63")
        # Added 'r' for raw string to fix SyntaxWarning
        self.run_bash(r"find assets -name '*.jsc' -exec sh -c 'echo \"{}:\" && strings {} | head -n 5' \;",
                      cwd=folder_path)


class Step4_FindSignature(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"--- STEP 4: Hex Signatures ---", "#9C27B0")
        # Added 'r' for raw string to fix SyntaxWarning
        self.run_bash(r"find . -name '*.jsc' -exec sh -c 'echo \"{}:\" && hexdump -C {} | head -n 1' \;",
                      cwd=folder_path)


class Step5_Bruteforce(PipelineStep):
    def run(self):
        self.log_signal.emit(f"\n--- STEP 5: Bruteforcing Key ---", "#FFEB3B")
        out_base = self.main_win.output_path.text()

        # Updated to find libcocos.so, libcocosjs.so, and other variants across all architectures
        so = glob.glob(os.path.join(out_base, "**/lib/**/libcocos*.so"), recursive=True) or \
             glob.glob(os.path.join(out_base, "**/libcocos*.so"), recursive=True)

        jsc = glob.glob(os.path.join(out_base, "**/assets/assets/internal/index.jsc"), recursive=True) or \
              glob.glob(os.path.join(out_base, "**/assets/internal/index.jsc"), recursive=True) or \
              glob.glob(os.path.join(out_base, "**/*.jsc"), recursive=True)

        if so and jsc:
            self.run_bash(f"'{self.main_win.binaries['rv']}' --decrypt --bruteforce -w '{so[0]}' '{jsc[0]}'")
        else:
            self.log_signal.emit(f"[ERR] Assets not found. (SO: {len(so)}, JSC: {len(jsc)})", "#f44336")
            self.finished_signal.emit(False)


class Step6_Decrypt(PipelineStep):
    def run(self, base_path):
        key = self.main_win.key_input.text().strip()
        self.log_signal.emit(f"\n--- STEP 6: Global Decryption ---", "#00BCD4")
        # Added 'fr' for raw f-string to fix SyntaxWarning
        self.run_bash(
            fr"find . -name '*.jsc' -exec '{self.main_win.binaries['rv']}' --decrypt -w --key '{key}' {{}} \;",
            cwd=base_path)


class Step7_Prettier(PipelineStep):
    def run(self, base_path):
        self.log_signal.emit(f"\n--- STEP 7: Global Prettier Cleanup ---", "#8BC34A")
        # Added 'fr' for raw f-string to fix SyntaxWarning
        self.run_bash(fr"find . -name '*.js' -exec '{self.main_win.binaries['pt']}' -w {{}} \;", cwd=base_path)


# --- MAIN WINDOW ---
class DecryptCocoasWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("DecryptCocoasWorkspace")
        self.is_status_active = False
        self.binaries = {"at": "", "rv": "", "pt": ""}
        self.init_ui()
        self.init_pipeline()
        self.load_global_settings()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(15, 15, 15, 15)

        title = QLabel("🧊 Decrypt Cocoas / Cocos Decryptor Pipeline")
        title.setStyleSheet("color: #58a6ff; font-size: 18px; font-weight: bold; padding: 4px;")
        layout.addWidget(title)

        h_top = QHBoxLayout()
        self.btn_settings = QPushButton("⚙ Settings")
        self.btn_settings.setFixedWidth(120)
        self.btn_settings.clicked.connect(self.open_settings)
        h_top.addWidget(self.btn_settings)
        h_top.addStretch()
        layout.addLayout(h_top)

        self.zip_path = self.add_row(layout, "Zip Container:", "*.zip")
        self.output_path = self.add_row(layout, "Output Folder:", is_folder=True)

        h_key = QHBoxLayout()
        h_key.addWidget(QLabel("Decryption Key:"), 1)
        self.key_input = QLineEdit()
        h_key.addWidget(self.key_input, 5)
        layout.addLayout(h_key)

        self.btn_start = QPushButton("Decrypt Cocoa's")
        self.btn_start.setFixedHeight(50)
        self.btn_start.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold; font-size: 14px;")
        self.btn_start.clicked.connect(self.start_full_process)
        layout.addWidget(self.btn_start)

        self.console = QTextBrowser()
        self.console.setReadOnly(True)
        self.console.setOpenLinks(False)
        self.console.anchorClicked.connect(self.open_file_in_finder)
        # Updated font-family to 'Courier New', monospace to fix Qt alias warning
        self.console.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Courier New', monospace;")
        layout.addWidget(self.console)

    def add_row(self, layout, label, filt="*.*", is_folder=False):
        h = QHBoxLayout()
        lbl = QLabel(label)
        lbl.setFixedWidth(100)
        h.addWidget(lbl)
        le = QLineEdit()
        h.addWidget(le)
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda: le.setText(QFileDialog.getExistingDirectory(self, label) if is_folder else
                                               QFileDialog.getOpenFileName(self, label, "", filt)[0]))
        h.addWidget(btn)
        layout.addLayout(h)
        return le

    def open_settings(self):
        # When embedded in the toolbox, Decrypt Cocoas settings live in the main Settings page.
        parent = self.parent()
        if parent and hasattr(parent, "switch_to_tab_containing"):
            try:
                parent.switch_to_tab_containing("Settings")
                if hasattr(parent, "load_decrypt_cocoas_settings_into_settings"):
                    parent.load_decrypt_cocoas_settings_into_settings()
                return
            except Exception:
                pass
        dlg = CocosSettingsDialog(self)
        if dlg.exec_():
            self.binaries = dlg.get_data()
            with open(DECRYPT_COCOAS_CONFIG_FILE, 'w') as f: json.dump(self.binaries, f)

    def load_global_settings(self):
        if os.path.exists(DECRYPT_COCOAS_CONFIG_FILE):
            with open(DECRYPT_COCOAS_CONFIG_FILE, 'r') as f: self.binaries = json.load(f)

    def init_pipeline(self):
        self.s0 = Step0_Unzip(self)
        self.s1 = Step1_Apktool(self)
        self.s2 = Step2_FindFiles(self)
        self.s3 = Step3_FindEncrypted(self)
        self.s4 = Step4_FindSignature(self)
        self.s5 = Step5_Bruteforce(self)
        self.s6 = Step6_Decrypt(self)
        self.s7 = Step7_Prettier(self)
        for s in [self.s0, self.s1, self.s2, self.s3, self.s4, self.s5, self.s6, self.s7]:
            s.log_signal.connect(self.log)

        self.s0.finished_signal.connect(lambda ok: self.s1.run() if ok else None)
        self.s1.finished_signal.connect(self.begin_scan_loop)
        self.s2.finished_signal.connect(lambda: self.s3.run(self.current_folder))
        self.s3.finished_signal.connect(lambda: self.s4.run(self.current_folder))
        self.s4.finished_signal.connect(self.next_scan_folder)
        self.s5.finished_signal.connect(lambda ok: self.s6.run(self.output_path.text()) if ok else None)
        self.s6.finished_signal.connect(lambda ok: self.s7.run(self.output_path.text()) if ok else None)
        self.s7.finished_signal.connect(self.finalize_pipeline)

    def start_full_process(self):
        self.console.clear();
        self.key_input.setText("");
        self.s0.run()

    def finalize_pipeline(self):
        self.log("\n--- DECRYPTION PROCESS COMPLETE ---", "#00FF00")
        self.log("Decrypted Files (Click to reveal in Finder):", "#FFFFFF")

        files = glob.glob(os.path.join(self.output_path.text(), "**/*.js"), recursive=True)
        for f in sorted(files): self.log_link(f)

        final_key = self.key_input.text().strip()
        self.log(f"\nFinal Decryption Key: <b>{final_key}</b>", "#4CAF50")

        QTimer.singleShot(500, self.flash_key_field)

    def open_file_in_finder(self, url):
        p = url.toLocalFile()
        if os.path.exists(p): os.system(f"open -R '{p}'")

    def log_link(self, path):
        u = QUrl.fromLocalFile(path).toString()
        self.console.insertHtml(f"<br><a href='{u}' style='color: #2196F3;'>{path}</a>")
        self.scroll_to_bottom()

    def flash_key_field(self):
        s = self.key_input.styleSheet()
        self.key_input.setStyleSheet("background-color: #FFEB3B; color: black; border: 2px solid #D32F2F;")
        QTimer.singleShot(1500, lambda: self.key_input.setStyleSheet(s))

    def begin_scan_loop(self):
        p = self.output_path.text()
        if not os.path.exists(p):
            self.log("[ERR] Output directory does not exist.", "#f44336")
            return
        self.folders = [os.path.join(p, d) for d in os.listdir(p) if os.path.isdir(os.path.join(p, d))]
        self.idx = 0
        self.next_scan_folder()

    def next_scan_folder(self):
        if self.idx < len(self.folders):
            self.current_folder = self.folders[self.idx]
            self.idx += 1
            self.log(f"\n--- SCANNING: {os.path.basename(self.current_folder)} ---", "#FFFFFF")
            self.s2.run(self.current_folder)
        else:
            self.s5.run()

    def update_status_line(self, m, color="#d4d4d4"):
        cursor = self.console.textCursor()
        cursor.movePosition(QTextCursor.End)
        if self.is_status_active:
            cursor.movePosition(QTextCursor.StartOfBlock, QTextCursor.KeepAnchor)
            cursor.removeSelectedText()
        else:
            cursor.insertBlock()
            self.is_status_active = True
        cursor.insertHtml(f"<span style='color: {color};'>{m}</span>")
        self.console.setTextCursor(cursor)
        self.scroll_to_bottom()

    def log(self, m, color="#d4d4d4"):
        if self.is_status_active and "Trying key" not in m: self.is_status_active = False
        m_html = m.replace("\n", "<br>")
        self.console.append(f"<span style='color: {color};'>{m_html}</span>")
        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())



# --- UNITY APP PREP EMBEDDED WORKSPACE ---
class UnityGuideDialog(QDialog):
    """Embedded guide for Unity IL2CPP reverse engineering workflow."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Master Guide: Unity IL2CPP Reverse Engineering')
        self.resize(750, 700)
        layout = QVBoxLayout(self)
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                background-color: #ffffff;
                color: #2c3e50;
                border: 1px solid #dcdde1;
                padding: 15px;
            }
        """)
        html_content = """
                <body style='font-family: -apple-system, sans-serif; line-height: 1.6;'>
                    <h1 style='color: #2980b9; text-align: center;'>Phase-by-Phase Master Guide</h1>
                    <p style='text-align: center; color: #7f8c8d;'>Follow these steps to successfully label your Ghidra workspace.</p>
                    <hr>

                    <h3 style='color: #d35400;'>📁 Phase 1: Automated Extraction</h3>
                    <ul>
                        <li>The script treats the APK/ZIP as a filesystem.</li>
                        <li>It recursively hunts for <b>libil2cpp.so</b> (the binary) and <b>global-metadata.dat</b> (the strings).</li>
                        <li>Supports <b>Split APKs</b> by scanning nested archives automatically.</li>
                    </ul>

                    <h3 style='color: #d35400;'>⚙️ Phase 2: Il2CppDumper Execution</h3>
                    <ul>
                        <li>Correlates machine code addresses with C# metadata.</li>
                        <li><b>Key Outputs:</b>
                            <ul>
                                <li><b>script.json:</b> The address map for Ghidra.</li>
                                <li><b>DummyDll/:</b> C# DLLs for use in DnSpy (optional).</li>
                                <li><b>il2cpp.h:</b> Raw C++ header file.</li>
                            </ul>
                        </li>
                    </ul>

                    <h3 style='color: #d35400;'>🛠️ Phase 3: Script & Header Preparation</h3>
                    <ul>
                        <li>Copies Ghidra Python scripts into your output folder.</li>
                        <li>Runs <code>il2cpp_header_to_ghidra.py</code> to fix the C++ header.</li>
                        <li>Produces <b>il2cpp_ghidra.h</b> (Standardized for Ghidra's parser).</li>
                    </ul>

                    <hr>
                    <h2 style='color: #27ae60;'>🚀 Manual Steps (In Ghidra)</h2>

                    <h3 style='color: #2c3e50;'>Phase 4: Workspace Setup</h3>
                    <ul>
                        <li><b>Import:</b> Drag <code>libil2cpp.so</code> into Ghidra and run Auto-Analysis.</li>
                        <li><b>Parse Header:</b> 
                            <ul>
                                <li>Go to <b>File -> Parse C Source</b>.</li>
                                <li>Clear the "Source to Parse" list.</li>
                                <li>Add <code>il2cpp_ghidra.h</code> from your output folder.</li>
                                <li>Click <b>Parse to Program</b>.</li>
                            </ul>
                        </li>
                    </ul>

                    <h3 style='color: #2c3e50;'>Phase 5: Code Labeling</h3>
                    <ul>
                        <li>Open the <b>Script Manager</b> (Window -> Script Manager).</li>
                        <li>Click the "Bundle Manager" icon and add your <b>Output Folder</b>.</li>
                        <li>Search for <code>ghidra_with_struct.py</code> and run it.</li>
                        <li>When prompted, select the <code>script.json</code> in your output folder.</li>
                    </ul>

                    <h3 style='color: #2c3e50;'>Phase 6: Final Analysis</h3>
                    <ul>
                        <li>Your functions will now change from <code>FUN_00123...</code> to <code>Player$$Update</code>.</li>
                        <li>Use the Decompiler (Window -> Decompiler) to read the logic.</li>
                    </ul>
                </body>
                """
        self.text_edit.setHtml(html_content)
        layout.addWidget(self.text_edit)


class UnityAppPrepWorkspace(QWidget):
    """Embedded Unity IL2CPP Prep workspace adapted from UnityAppPrep.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.init_ui()
        self.load_settings()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        title = QLabel("🎮 Unity App Prepare / IL2CPP Prep Tool")
        title.setStyleSheet("color: #58a6ff; font-size: 18px; font-weight: bold; padding: 4px;")
        main_layout.addWidget(title)

        hint = QLabel("Extract libil2cpp.so + global-metadata.dat, run Il2CppDumper, copy Ghidra helper scripts, and prepare output for Ghidra.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8b949e; padding: 4px;")
        main_layout.addWidget(hint)

        grid = QGridLayout()
        grid.addWidget(QLabel('Il2CppDumper.dll:'), 0, 0)
        self.dumper_path = QLineEdit()
        self.dumper_path.setPlaceholderText("Path to Il2CppDumper.dll or its folder")
        grid.addWidget(self.dumper_path, 0, 1)
        btn_dumper = QPushButton('Browse')
        btn_dumper.clicked.connect(lambda: self.get_file(self.dumper_path, "Select Il2CppDumper.dll", "DLL (*.dll);;All Files (*)"))
        grid.addWidget(btn_dumper, 0, 2)

        grid.addWidget(QLabel('Select APK/ZIP/APKS:'), 1, 0)
        self.apk_path = QLineEdit()
        self.apk_path.setPlaceholderText("APK / ZIP / APKS container")
        grid.addWidget(self.apk_path, 1, 1)
        btn_apk = QPushButton('Browse')
        btn_apk.clicked.connect(lambda: self.get_file(self.apk_path, "Select APK/ZIP/APKS", "Archives (*.apk *.zip *.apks);;All Files (*)"))
        grid.addWidget(btn_apk, 1, 2)

        grid.addWidget(QLabel('Output Folder:'), 2, 0)
        self.out_path = QLineEdit()
        self.out_path.setPlaceholderText("Output folder for extracted/prepared files")
        grid.addWidget(self.out_path, 2, 1)
        btn_out = QPushButton('Browse')
        btn_out.clicked.connect(self.get_folder)
        grid.addWidget(btn_out, 2, 2)

        grid.addWidget(QLabel('dotnet path:'), 3, 0)
        self.dotnet_path = QLineEdit()
        self.dotnet_path.setPlaceholderText("dotnet or /usr/local/share/dotnet/dotnet")
        grid.addWidget(self.dotnet_path, 3, 1)
        btn_dotnet = QPushButton('Browse')
        btn_dotnet.clicked.connect(lambda: self.get_file(self.dotnet_path, "Select dotnet executable", "All Files (*)"))
        grid.addWidget(btn_dotnet, 3, 2)
        main_layout.addLayout(grid)

        actions = QHBoxLayout()
        self.prep_btn = QPushButton('🚀 START PREPARATION')
        self.prep_btn.setFixedHeight(44)
        self.prep_btn.setObjectName("runBtn")
        self.prep_btn.clicked.connect(self.process)
        self.guide_btn = QPushButton('📚 VIEW STEPS (MASTER GUIDE)')
        self.guide_btn.clicked.connect(self.show_guide)
        self.folder_btn = QPushButton('📂 OPEN OUTPUT FOLDER')
        self.folder_btn.setEnabled(False)
        self.folder_btn.clicked.connect(self.open_output_folder)
        btn_save_settings = QPushButton('💾 Save Unity Settings')
        btn_save_settings.clicked.connect(self.save_settings)
        btn_main_settings = QPushButton('⚙ Main Settings')
        btn_main_settings.clicked.connect(self.open_main_settings)
        actions.addWidget(self.prep_btn)
        actions.addWidget(self.guide_btn)
        actions.addWidget(self.folder_btn)
        actions.addWidget(btn_save_settings)
        actions.addWidget(btn_main_settings)
        actions.addStretch(1)
        main_layout.addLayout(actions)

        main_layout.addWidget(QLabel('<b>Console Status:</b>'))
        self.log_window = QTextEdit()
        self.log_window.setReadOnly(True)
        self.log_window.setFont(QFont('Menlo' if sys.platform == 'darwin' else 'Courier New', 11))
        self.log_window.setStyleSheet("background-color: #010409; color: #d1d5da; padding: 12px; border: 1px solid #30363d;")
        main_layout.addWidget(self.log_window, 1)

    def config_data(self):
        return {
            'dumper': self.dumper_path.text().strip(),
            'output': self.out_path.text().strip(),
            'dotnet': self.dotnet_path.text().strip(),
        }

    def load_settings(self):
        data = {}
        if os.path.exists(UNITY_APP_PREP_CONFIG_FILE):
            try:
                with open(UNITY_APP_PREP_CONFIG_FILE, 'r', encoding='utf-8', errors='replace') as f:
                    data = json.load(f) or {}
            except Exception:
                data = {}
        self.dumper_path.setText(str(data.get('dumper', '') or ''))
        self.out_path.setText(str(data.get('output', '') or ''))
        self.dotnet_path.setText(str(data.get('dotnet', '') or ("/usr/local/share/dotnet/dotnet" if os.path.exists("/usr/local/share/dotnet/dotnet") else "dotnet")))

    def save_settings(self):
        os.makedirs(UNITY_APP_PREP_BASE_PATH, exist_ok=True)
        with open(UNITY_APP_PREP_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.config_data(), f, indent=4)
        self.log("SETTINGS", f"Saved Unity App Prep settings to {UNITY_APP_PREP_CONFIG_FILE}", "#7ee787")
        main = self.window()
        if hasattr(main, 'load_unity_app_prep_settings_into_settings'):
            main.load_unity_app_prep_settings_into_settings()

    def open_main_settings(self):
        main = self.window()
        if hasattr(main, 'switch_to_tab_containing'):
            main.switch_to_tab_containing('Settings')
            if hasattr(main, 'load_unity_app_prep_settings_into_settings'):
                main.load_unity_app_prep_settings_into_settings()

    def log(self, phase, message, color="#f1c40f"):
        self.log_window.append(f"<b style='color: {color};'>[{html.escape(str(phase))}]</b> {html.escape(str(message))}")
        self.log_window.moveCursor(QTextCursor.End)
        QApplication.processEvents()

    def get_file(self, target, title='Select File', file_filter="All Files (*)"):
        fname, _ = QFileDialog.getOpenFileName(self, title, "", file_filter)
        if fname:
            target.setText(os.path.abspath(os.path.expanduser(fname)))

    def get_folder(self):
        folder = QFileDialog.getExistingDirectory(self, 'Select Output Directory')
        if folder:
            self.out_path.setText(os.path.abspath(os.path.expanduser(folder)))

    def open_output_folder(self):
        path = self.out_path.text().strip()
        if os.path.exists(path):
            if sys.platform == 'darwin':
                subprocess.run(['open', path])
            elif sys.platform == 'win32':
                os.startfile(path)
            else:
                subprocess.run(['xdg-open', path])

    def show_guide(self):
        UnityGuideDialog(self).exec_()

    def find_in_zip(self, zip_source, output_dir):
        so_name, meta_name = None, None
        try:
            with zipfile.ZipFile(zip_source, 'r') as z:
                for name in z.namelist():
                    if name.endswith('libil2cpp.so') and ('arm64-v8a' in name or 'armeabi-v7a' in name or '/lib/' in name):
                        t_name = os.path.basename(name)
                        t_path = os.path.join(output_dir, t_name)
                        with open(t_path, 'wb') as f:
                            f.write(z.read(name))
                        self.log('FOUND', f'Extracted {t_name}', '#2ecc71')
                        so_name = t_name
                    elif name.endswith('global-metadata.dat'):
                        t_name = 'global-metadata.dat'
                        t_path = os.path.join(output_dir, t_name)
                        with open(t_path, 'wb') as f:
                            f.write(z.read(name))
                        self.log('FOUND', f'Extracted {t_name}', '#2ecc71')
                        meta_name = t_name
                    elif name.endswith('.apk') or name.endswith('.zip'):
                        nested_data = io.BytesIO(z.read(name))
                        n_so, n_meta = self.find_in_zip(nested_data, output_dir)
                        if n_so:
                            so_name = n_so
                        if n_meta:
                            meta_name = n_meta
        except Exception as e:
            self.log('ZIP', f'Skipped nested/invalid zip segment: {e}', '#ffa657')
        return so_name, meta_name

    def process(self):
        self.save_settings()
        apk = os.path.abspath(os.path.expanduser(self.apk_path.text().strip()))
        out = os.path.abspath(os.path.expanduser(self.out_path.text().strip()))
        d_raw = os.path.expanduser(self.dumper_path.text().strip())

        if not d_raw:
            QMessageBox.warning(self, 'Paths', 'Please select Il2CppDumper.dll or its folder.')
            return
        if not d_raw.lower().endswith('.dll'):
            d_dll = os.path.join(d_raw, 'Il2CppDumper.dll') if os.path.isdir(d_raw) else d_raw + '.dll'
        else:
            d_dll = d_raw
        d_dll = os.path.abspath(d_dll)
        dotnet = self.dotnet_path.text().strip() or ("/usr/local/share/dotnet/dotnet" if os.path.exists("/usr/local/share/dotnet/dotnet") else "dotnet")

        if not apk or not out or not d_dll:
            QMessageBox.warning(self, 'Paths', 'Please fill all fields.')
            return
        if not os.path.exists(apk):
            QMessageBox.warning(self, 'APK/ZIP', 'The selected APK/ZIP/APKS file does not exist.')
            return
        if not os.path.exists(d_dll):
            QMessageBox.warning(self, 'Il2CppDumper', 'Il2CppDumper.dll was not found.')
            return
        os.makedirs(out, exist_ok=True)

        try:
            self.log_window.clear()
            self.log('PHASE 1', 'Deep-scanning archives...')
            so_n, meta_n = self.find_in_zip(apk, out)
            if not so_n or not meta_n:
                raise Exception('Unity engine files not found: libil2cpp.so/global-metadata.dat missing.')
            self.log('DONE', 'Extraction complete.', '#2ecc71')

            self.log('PHASE 2', 'Running Il2CppDumper...')
            cmd = [dotnet, d_dll, so_n, meta_n, '.']
            self.log('EXEC', ' '.join([str(x) for x in cmd]), '#8b949e')
            proc = subprocess.Popen(cmd, cwd=out, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(input='\n')
            if stdout:
                self.log('DUMPER', stdout, '#95a5a6')
            if stderr:
                self.log('DUMPER-ERR', stderr, '#ffa657')
            if 'Done!' in stdout or proc.returncode == 0:
                self.log('DONE', 'Dumper finished successfully.', '#2ecc71')
            else:
                raise Exception('Dumper failed to generate output.')

            self.log('FILES', 'Output contents:', '#3498db')
            for f in sorted(os.listdir(out)):
                if not f.startswith('.'):
                    self.log('>', f, '#bdc3c7')

            self.log('PHASE 3', 'Transferring scripts and fixing headers...')
            d_dir = os.path.dirname(d_dll)
            for s in ['ghidra_with_struct.py', 'ghidra.py', 'il2cpp_header_to_ghidra.py']:
                src = os.path.join(d_dir, s)
                if os.path.exists(src):
                    shutil.copy(src, out)
                    self.log('COPY', s, '#7ee787')

            h_script = os.path.join(out, 'il2cpp_header_to_ghidra.py')
            if os.path.exists(h_script):
                subprocess.run(['python3', h_script, 'il2cpp.h'], cwd=out, check=True)
                self.log('DONE', 'il2cpp_ghidra.h generated.', '#2ecc71')
            else:
                self.log('INFO', 'Header conversion script not present; skipping il2cpp_ghidra.h generation.', '#ffa657')

            self.log('SUCCESS', 'Ready for Ghidra!', '#2ecc71')
            self.folder_btn.setEnabled(True)
        except Exception as e:
            self.log('ERROR', str(e), '#e74c3c')
            QMessageBox.critical(self, 'Unity App Prepare Failed', str(e))



class StripManifestWorkspace(QWidget):
    """Embedded Android Manifest PHA triage workspace adapted from stripmanifest.py."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.bnl = [
            'android.permission.INTERNET', 'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WAKE_LOCK', 'android.permission.VIBRATE',
            'android.permission.ACCESS_WIFI_STATE', 'android.permission.FOREGROUND_SERVICE',
            'android.permission.RECEIVE_BOOT_COMPLETED'
        ]
        self.red_flag_intents = [
            "android.intent.action.BOOT_COMPLETED",
            "android.provider.Telephony.SMS_RECEIVED",
            "android.intent.action.USER_PRESENT",
            "android.intent.action.PACKAGE_ADDED",
            "android.intent.action.PACKAGE_REMOVED",
        ]
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        title = QLabel("🧾 Strip Manifest / Android PHA Triage")
        title.setStyleSheet("color: #58a6ff; font-size: 18px; font-weight: bold; padding: 4px;")
        main_layout.addWidget(title)

        hint = QLabel("Paste a decoded AndroidManifest.xml to strip/triage permissions, exported components, persistence triggers, deep links, and PHA risk patterns.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8b949e; padding: 4px;")
        main_layout.addWidget(hint)

        body = QHBoxLayout()

        left_layout = QVBoxLayout()
        self.xml_input = QTextEdit()
        self.xml_input.setPlaceholderText("Paste AndroidManifest.xml here...")
        self.xml_input.setStyleSheet("background: #010409; color: #d1d5da; font-family: Menlo, Courier New, monospace;")

        buttons = QHBoxLayout()
        btn_load = QPushButton("📂 Load Manifest")
        btn_load.clicked.connect(self.load_manifest_file)
        analyze_btn = QPushButton("🚀 Run Full PHA Analysis")
        analyze_btn.setObjectName("runBtn")
        analyze_btn.clicked.connect(self.run_analysis)
        self.copy_summary_btn = QPushButton("📋 Copy Executive Summary")
        self.copy_summary_btn.clicked.connect(self.copy_executive_summary)
        buttons.addWidget(btn_load)
        buttons.addWidget(analyze_btn)
        buttons.addWidget(self.copy_summary_btn)

        left_layout.addWidget(QLabel("1. Input Manifest XML:"))
        left_layout.addWidget(self.xml_input, 1)
        left_layout.addLayout(buttons)
        body.addLayout(left_layout, 1)

        self.tabs = QTabWidget()
        self.summary_dash = QTextEdit()
        self.summary_dash.setReadOnly(True)
        self.summary_dash.setStyleSheet("background: #010409; color: #d1d5da;")
        self.tabs.addTab(self.summary_dash, "Analysis Summary")

        self.pha_report = QTextEdit()
        self.pha_report.setReadOnly(True)
        self.pha_report.setStyleSheet("background: #010409; color: #d1d5da;")
        self.tabs.addTab(self.pha_report, "Risk Patterns")

        self.perm_table = QTableWidget()
        self.perm_table.setColumnCount(4)
        self.perm_table.setHorizontalHeaderLabels(["Permission", "BNL", "Level", "Risk"])
        self.perm_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 4):
            self.perm_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.tabs.addTab(self.perm_table, "Permissions")

        self.service_tree = QTreeWidget()
        self.service_tree.setHeaderLabels(["Component Structure", "Value / Action"])
        self.service_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.service_tree.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.tabs.addTab(self.service_tree, "Component Tree")

        self.url_list = QTableWidget()
        self.url_list.setColumnCount(2)
        self.url_list.setHorizontalHeaderLabels(["Scheme", "Host / Data"])
        self.url_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.url_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.tabs.addTab(self.url_list, "Deep Links & URLs")

        body.addWidget(self.tabs, 2)
        main_layout.addLayout(body, 1)

    def load_manifest_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open AndroidManifest.xml", "", "XML Files (*.xml);;All Files (*)")
        if path:
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    self.xml_input.setPlainText(f.read())
                self.run_analysis()
            except Exception as e:
                QMessageBox.critical(self, "Load Error", str(e))

    def run_analysis(self):
        raw_xml = self.xml_input.toPlainText()
        if not raw_xml.strip():
            QMessageBox.information(self, "Manifest", "Paste or load AndroidManifest.xml first.")
            return
        try:
            root = ET.fromstring(raw_xml)
            ns = {'android': 'http://schemas.android.com/apk/res/android'}
            self.populate_permissions(root)
            self.populate_pha_report(root, ns)
            self.populate_service_tree(root, ns)
            self.populate_urls(root, ns)
            self.generate_dashboard_summary(root, ns)
            self.tabs.setCurrentIndex(0)
        except Exception as e:
            QMessageBox.critical(self, "Parse Error", f"Invalid XML: {str(e)}")

    def get_protection_level(self, name):
        dangerous = ["SMS", "CONTACTS", "LOCATION", "CAMERA", "RECORD", "STORAGE", "CALL", "LOGS"]
        if any(d in str(name).upper() for d in dangerous):
            return "Dangerous", "#d32f2f"
        if "SIGNATURE" in str(name).upper():
            return "Signature", "#7b1fa2"
        return "Normal", "#2e7d32"

    def populate_permissions(self, root):
        self.perm_table.setRowCount(0)
        perms = root.findall('uses-permission')
        for p in perms:
            name = p.attrib.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
            row = self.perm_table.rowCount()
            self.perm_table.insertRow(row)
            self.perm_table.setItem(row, 0, QTableWidgetItem(name))
            is_bnl = name in self.bnl
            bnl_item = QTableWidgetItem("Yes" if is_bnl else "NO")
            if not is_bnl:
                bnl_item.setForeground(QColor("#d32f2f"))
            self.perm_table.setItem(row, 1, bnl_item)
            level_str, color = self.get_protection_level(name)
            level_item = QTableWidgetItem(level_str)
            level_item.setForeground(QColor(color))
            self.perm_table.setItem(row, 2, level_item)
            risk = "High" if level_str == "Dangerous" and not is_bnl else "Low"
            risk_item = QTableWidgetItem(risk)
            if risk == "High":
                risk_item.setForeground(QColor("#f85149"))
            self.perm_table.setItem(row, 3, risk_item)
        self.perm_table.resizeColumnsToContents()
        self.perm_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)

    def populate_pha_report(self, root, ns):
        self.pha_report.clear()
        perms = [p.attrib.get('{http://schemas.android.com/apk/res/android}name', '') for p in root.findall('uses-permission')]
        pha_map = {
            "SMS/Toll Fraud": ["SEND_SMS", "RECEIVE_SMS", "WRITE_SMS"],
            "Spyware/Audio": ["RECORD_AUDIO", "READ_LOGS", "PROCESS_OUTGOING_CALLS"],
            "Hostile Downloader": ["INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "DELETE_PACKAGES"],
            "Ransomware/Privilege": ["BIND_DEVICE_ADMIN", "DISABLE_KEYGUARD"],
            "Click Fraud": ["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
            "Rooting/Backdoor": ["android.permission.FACTORY_TEST", "android.permission.BRICK"],
        }
        self.pha_report.append("<h2>PHA Risk Pattern Matcher</h2>")
        found = False
        for cat, triggers in pha_map.items():
            matches = [p for p in perms if any(t in p for t in triggers)]
            if matches:
                found = True
                self.pha_report.append(f"<b style='color:red;'>[MATCH] {html.escape(cat)}</b>")
                for m in matches:
                    self.pha_report.append(f"&nbsp;&nbsp;• {html.escape(m)}")
        if not found:
            self.pha_report.append("<p style='color:green;'>No PHA pattern permission matches found.</p>")

    def populate_service_tree(self, root, ns):
        self.service_tree.clear()
        for tag, label in [('service', 'Services'), ('receiver', 'Receivers'), ('activity', 'Activities')]:
            comp_root = QTreeWidgetItem(self.service_tree, [label, ""])
            for comp in root.findall(f'.//{tag}', ns):
                name = comp.attrib.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                item = QTreeWidgetItem(comp_root, [f"{tag.capitalize()}: {name}", ""])
                exp = comp.attrib.get('{http://schemas.android.com/apk/res/android}exported', 'false')
                exported_item = QTreeWidgetItem(item, ["Exported", exp])
                if str(exp).lower() == "true":
                    exported_item.setForeground(1, QColor("#ffa657"))
                    exported_item.setFont(1, QFont("Arial", 10, QFont.Bold))
                for intent in comp.findall('intent-filter', ns):
                    f_item = QTreeWidgetItem(item, ["Intent Filter", ""])
                    for action in intent.findall('action', ns):
                        act_name = action.attrib.get('{http://schemas.android.com/apk/res/android}name', '')
                        act_item = QTreeWidgetItem(f_item, ["Action", act_name])
                        if any(flag in act_name for flag in self.red_flag_intents):
                            act_item.setForeground(0, QColor("red"))
                            act_item.setForeground(1, QColor("red"))
                            act_item.setFont(0, QFont("Arial", 10, QFont.Bold))
                            act_item.setFont(1, QFont("Arial", 10, QFont.Bold))
        self.service_tree.expandAll()

    def populate_urls(self, root, ns):
        self.url_list.setRowCount(0)
        for data in root.findall('.//data', ns):
            scheme = data.attrib.get('{http://schemas.android.com/apk/res/android}scheme', '')
            host = data.attrib.get('{http://schemas.android.com/apk/res/android}host', '')
            if scheme or host:
                row = self.url_list.rowCount()
                self.url_list.insertRow(row)
                self.url_list.setItem(row, 0, QTableWidgetItem(scheme))
                self.url_list.setItem(row, 1, QTableWidgetItem(host))
        self.url_list.resizeColumnsToContents()
        self.url_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)

    def generate_dashboard_summary(self, root, ns):
        self.summary_dash.clear()
        acts = len(root.findall('.//activity', ns))
        svcs = len(root.findall('.//service', ns))
        rcvs = len(root.findall('.//receiver', ns))
        perm_count = len(root.findall('uses-permission'))
        self.summary_dash.append("<h1>Executive Triage Dashboard</h1>")
        self.summary_dash.append(f"<b>Component Counts:</b> Activities ({acts}), Services ({svcs}), Receivers ({rcvs})<br>")
        self.summary_dash.append(f"<b>Permission Count:</b> {perm_count}<br>")
        if acts == 0 and (svcs > 0 or rcvs > 0):
            self.summary_dash.append("<p style='color:red;'><b>⚠️ ANOMALY:</b> Headless App detected (0 Activities). Typical of background malware.</p>")
        persistence = any(self.service_tree.findItems(f, Qt.MatchContains | Qt.MatchRecursive) for f in self.red_flag_intents)
        if persistence:
            self.summary_dash.append("<p style='color:red;'><b>⚠️ PERSISTENCE:</b> App requests high-risk boot/event triggers.</p>")
        else:
            self.summary_dash.append("<p style='color:green;'><b>✓</b> No automated persistence triggers found.</p>")

    def copy_executive_summary(self):
        summary = "--- PHA TRIAGE REPORT ---\n"
        summary += f"Perms to Review: {self.perm_table.rowCount()}\n"
        summary += f"Deep Links Found: {self.url_list.rowCount()}\n"
        summary += self.summary_dash.toPlainText()
        QApplication.clipboard().setText(summary)
        QMessageBox.information(self, "Copied", "Executive summary copied to clipboard.")

class ApkExtractorWorkspace(QWidget):
    """Embedded APK Extractor workspace adapted from the standalone ArchiveExplorer."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.temp_dir = None
        self.loaded_archives = []
        self.current_selected_path = None
        self.preview_search_results = []
        self.current_preview_search_idx = -1
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        top_bar = QHBoxLayout()
        self.merge_radio = QRadioButton("Merge All")
        self.split_radio = QRadioButton("Separate Folders")
        self.merge_radio.setChecked(True)
        self.merge_radio.toggled.connect(self.reprocess_if_loaded)
        self.btn_open = QPushButton("Load Archives")
        self.btn_open.clicked.connect(self.load_initial_files)
        self.btn_export_files = QPushButton("Export Files")
        self.btn_export_files.clicked.connect(self.export_to_disk)
        self.btn_export_files.setEnabled(False)
        top_bar.addWidget(QLabel("<b>Mode:</b>"))
        top_bar.addWidget(self.merge_radio)
        top_bar.addWidget(self.split_radio)
        top_bar.addStretch()
        top_bar.addWidget(self.btn_open)
        top_bar.addWidget(self.btn_export_files)
        main_layout.addLayout(top_bar)

        global_search_layout = QHBoxLayout()
        self.global_search_input = QLineEdit()
        self.global_search_input.setPlaceholderText("Global Regex Search (All Files)...")
        self.btn_global_search = QPushButton("Search All Files")
        self.btn_global_search.clicked.connect(self.run_global_search)
        self.btn_export_csv = QPushButton("Export Results (CSV)")
        self.btn_export_csv.clicked.connect(self.export_search_to_csv)
        self.btn_export_csv.setEnabled(False)
        global_search_layout.addWidget(QLabel("<b>Global Search:</b>"))
        global_search_layout.addWidget(self.global_search_input, 1)
        global_search_layout.addWidget(self.btn_global_search)
        global_search_layout.addWidget(self.btn_export_csv)
        main_layout.addLayout(global_search_layout)

        self.mid_splitter = QSplitter(Qt.Horizontal)
        explorer_widget = QWidget()
        exp_lay = QVBoxLayout(explorer_widget)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter Tree...")
        self.filter_input.textChanged.connect(self.apply_tree_filter)
        exp_lay.addWidget(self.filter_input)

        self.tree = QTreeView()
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_explorer_context_menu)
        self.model = QFileSystemModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.tree.setModel(self.proxy_model)
        self.tree.clicked.connect(self.on_tree_click)
        exp_lay.addWidget(self.tree)

        preview_container = QWidget()
        pre_lay = QVBoxLayout(preview_container)
        preview_top_layout = QHBoxLayout()
        self.mode_group = QButtonGroup(self)
        self.btn_mode_smart = QRadioButton("Smart")
        self.btn_mode_raw = QRadioButton("Raw")
        self.btn_mode_hex = QRadioButton("Hex")
        self.btn_mode_smart.setChecked(True)
        for b in [self.btn_mode_smart, self.btn_mode_raw, self.btn_mode_hex]:
            self.mode_group.addButton(b)
            preview_top_layout.addWidget(b)
            b.toggled.connect(self.refresh_preview)
        preview_top_layout.addSpacing(20)
        self.preview_find_input = QLineEdit()
        self.preview_find_input.setPlaceholderText("Find in preview...")
        self.preview_find_input.textChanged.connect(self.run_preview_search)
        preview_top_layout.addWidget(self.preview_find_input, 1)
        self.btn_prev_match = QPushButton("<")
        self.btn_prev_match.setFixedWidth(30)
        self.btn_prev_match.clicked.connect(lambda: self.navigate_preview_search(-1))
        self.btn_next_match = QPushButton(">")
        self.btn_next_match.setFixedWidth(30)
        self.btn_next_match.clicked.connect(lambda: self.navigate_preview_search(1))
        self.match_count_label = QLabel("0/0")
        preview_top_layout.addWidget(self.btn_prev_match)
        preview_top_layout.addWidget(self.btn_next_match)
        preview_top_layout.addWidget(self.match_count_label)
        pre_lay.addLayout(preview_top_layout)

        self.preview_pane = QTextEdit()
        self.preview_pane.setReadOnly(True)
        self.preview_pane.setLineWrapMode(QTextEdit.NoWrap)
        self.preview_pane.setContextMenuPolicy(Qt.CustomContextMenu)
        self.preview_pane.customContextMenuRequested.connect(self.show_preview_context_menu)
        self.preview_pane.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
                font-size: 13px;
            }
        """)
        pre_lay.addWidget(self.preview_pane)

        self.mid_splitter.addWidget(explorer_widget)
        self.mid_splitter.addWidget(preview_container)
        self.mid_splitter.setStretchFactor(1, 2)

        self.v_splitter = QSplitter(Qt.Vertical)
        self.v_splitter.addWidget(self.mid_splitter)
        self.results_table = QTableWidget(0, 3)
        self.results_table.setHorizontalHeaderLabels(["File", "Line", "Content"])
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.itemDoubleClicked.connect(self.on_result_row_clicked)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_table_context_menu)
        self.results_table.setStyleSheet("background-color: #252526; color: #cccccc;")
        self.v_splitter.addWidget(self.results_table)
        main_layout.addWidget(self.v_splitter, 1)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        main_layout.addWidget(self.progress)

    def run_preview_search(self):
        query = self.preview_find_input.text()
        self.preview_search_results = []
        self.current_preview_search_idx = -1
        cursor = self.preview_pane.textCursor()
        cursor.select(QTextCursor.Document)
        cursor.setCharFormat(QTextCharFormat())
        if not query:
            self.match_count_label.setText("0/0")
            return
        fmt = QTextCharFormat()
        fmt.setBackground(QColor("#4b4b00"))
        fmt.setForeground(Qt.white)
        text = self.preview_pane.toPlainText()
        try:
            matches = list(re.finditer(re.escape(query), text, re.IGNORECASE))
            for match in matches:
                start, end = match.span()
                self.preview_search_results.append((start, end))
                cursor.setPosition(start)
                cursor.setPosition(end, QTextCursor.KeepAnchor)
                cursor.setCharFormat(fmt)
            if self.preview_search_results:
                self.current_preview_search_idx = 0
                self.update_preview_search_ui()
            else:
                self.match_count_label.setText("0/0")
        except Exception:
            pass

    def navigate_preview_search(self, delta):
        if not self.preview_search_results:
            return
        self.current_preview_search_idx = (self.current_preview_search_idx + delta) % len(self.preview_search_results)
        self.update_preview_search_ui()

    def update_preview_search_ui(self):
        count = len(self.preview_search_results)
        self.match_count_label.setText(f"{self.current_preview_search_idx + 1}/{count}")
        start, end = self.preview_search_results[self.current_preview_search_idx]
        cursor = self.preview_pane.textCursor()
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        self.preview_pane.setTextCursor(cursor)
        self.preview_pane.ensureCursorVisible()

    def beautify_content(self):
        text = self.preview_pane.toPlainText().strip()
        if not text:
            return
        opts = jsbeautifier.default_options()
        opts.indent_size = 4
        try:
            if text.startswith(('{', '[')):
                self.preview_pane.setPlainText(json.dumps(json.loads(text), indent=4))
            elif text.startswith('<?xml') or (text.startswith('<') and not text.lower().startswith('<html')):
                dom = xml.dom.minidom.parseString(text)
                self.preview_pane.setPlainText(os.linesep.join([s for s in dom.toprettyxml(indent="    ").splitlines() if s.strip()]))
            else:
                self.preview_pane.setPlainText(jsbeautifier.beautify(text, opts))
            self.run_preview_search()
        except Exception as e:
            QMessageBox.warning(self, "Beautifier Error", str(e))

    def open_ext(self, p):
        if not p or not os.path.exists(p):
            return
        try:
            if sys.platform == 'darwin':
                subprocess.call(('open', p))
            elif sys.platform == 'win32':
                os.startfile(p)
            else:
                subprocess.call(('xdg-open', p))
        except Exception:
            pass

    def show_preview_context_menu(self, pos):
        menu = QMenu()
        menu.addAction("Copy Selected").triggered.connect(self.preview_pane.copy)
        menu.addAction("Copy All").triggered.connect(lambda: QApplication.clipboard().setText(self.preview_pane.toPlainText()))
        menu.addSeparator()
        b_action = menu.addAction("Beautify (JS/HTML/XML/JSON)")
        b_action.setEnabled(self.btn_mode_raw.isChecked())
        b_action.triggered.connect(self.beautify_content)
        menu.addSeparator()
        menu.addAction("Open Externally").triggered.connect(lambda: self.open_ext(self.current_selected_path))
        menu.exec_(self.preview_pane.viewport().mapToGlobal(pos))

    def show_explorer_context_menu(self, pos):
        idx = self.tree.indexAt(pos)
        if not idx.isValid():
            return
        path = self.model.filePath(self.proxy_model.mapToSource(idx))
        menu = QMenu()
        menu.addAction("Copy Path").triggered.connect(lambda: QApplication.clipboard().setText(path))
        menu.addAction("Open Externally").triggered.connect(lambda: self.open_ext(path))
        menu.exec_(self.tree.viewport().mapToGlobal(pos))

    def show_table_context_menu(self, pos):
        item = self.results_table.itemAt(pos)
        if not item:
            return
        menu = QMenu()
        menu.addAction("Copy Cell").triggered.connect(lambda: QApplication.clipboard().setText(item.text()))
        menu.exec_(self.results_table.viewport().mapToGlobal(pos))

    def load_initial_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Archives", "", "Archives (*.apk *.zip *.apks)")
        if paths:
            self.loaded_archives = paths
            self.process_files(paths)
            self.btn_export_files.setEnabled(True)

    def reprocess_if_loaded(self):
        if self.loaded_archives:
            self.process_files(self.loaded_archives)

    def process_files(self, paths):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = tempfile.mkdtemp(prefix="apk_ext_")
        for p in paths:
            self.extract_logic(p, self.temp_dir)
        self.model.setRootPath(self.temp_dir)
        self.tree.setRootIndex(self.proxy_model.mapFromSource(self.model.index(self.temp_dir)))

    def extract_logic(self, file_path, target_root):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                current_path = os.path.join(target_root, os.path.splitext(os.path.basename(file_path))[0]) if self.split_radio.isChecked() else target_root
                if not os.path.exists(current_path):
                    os.makedirs(current_path)
                for member in z.namelist():
                    if member.endswith('/'):
                        continue
                    z.extract(member, current_path)
                    full_p = os.path.join(current_path, member)
                    if member.lower().endswith(('.zip', '.apk', '.apks')):
                        self.extract_logic(full_p, os.path.dirname(full_p))
                        if os.path.exists(full_p):
                            os.remove(full_p)
        except Exception:
            pass

    def run_global_search(self):
        pattern = self.global_search_input.text()
        if not pattern or not self.temp_dir:
            return
        self.results_table.setRowCount(0)
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for root, _, files in os.walk(self.temp_dir):
                for file in files:
                    full_p = os.path.join(root, file)
                    try:
                        with open(full_p, 'r', encoding='utf-8', errors='replace') as f:
                            for i, line in enumerate(f, 1):
                                if regex.search(line):
                                    row = self.results_table.rowCount()
                                    self.results_table.insertRow(row)
                                    item = QTableWidgetItem(os.path.relpath(full_p, self.temp_dir))
                                    item.setData(Qt.UserRole, full_p)
                                    self.results_table.setItem(row, 0, item)
                                    self.results_table.setItem(row, 1, QTableWidgetItem(str(i)))
                                    self.results_table.setItem(row, 2, QTableWidgetItem(line.strip()))
                    except Exception:
                        continue
            self.btn_export_csv.setEnabled(self.results_table.rowCount() > 0)
        except Exception:
            pass

    def on_tree_click(self, index):
        self.current_selected_path = self.model.filePath(self.proxy_model.mapToSource(index))
        self.refresh_preview()

    def refresh_preview(self):
        if not self.current_selected_path or os.path.isdir(self.current_selected_path):
            self.preview_pane.clear()
            self.match_count_label.setText("0/0")
            return
        try:
            if self.btn_mode_hex.isChecked():
                self.preview_pane.setPlainText(self.get_hex_view(self.current_selected_path))
            else:
                with open(self.current_selected_path, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                    if self.btn_mode_smart.isChecked():
                        self.preview_pane.setHtml(content)
                    else:
                        self.preview_pane.setPlainText(content)
            self.run_preview_search()
        except Exception:
            pass

    def on_result_row_clicked(self, item):
        row = item.row()
        full_path = self.results_table.item(row, 0).data(Qt.UserRole)
        line_no = int(self.results_table.item(row, 1).text())
        if os.path.exists(full_path):
            self.current_selected_path = full_path
            self.btn_mode_raw.setChecked(True)
            self.refresh_preview()
            cursor = self.preview_pane.textCursor()
            cursor.movePosition(QTextCursor.Start)
            for _ in range(line_no - 1):
                cursor.movePosition(QTextCursor.Down)
            cursor.movePosition(QTextCursor.EndOfLine, QTextCursor.KeepAnchor)
            self.preview_pane.setTextCursor(cursor)
            self.preview_pane.ensureCursorVisible()

    def get_hex_view(self, p):
        try:
            with open(p, 'rb') as f:
                chunk = f.read(16384)
                lines = []
                for i in range(0, len(chunk), 16):
                    sub = chunk[i:i + 16]
                    hex_v = ' '.join(f'{b:02x}' for b in sub)
                    asc_v = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in sub)
                    lines.append(f"{i:08x}  {hex_v:<47}  |{asc_v}|")
                return "\n".join(lines)
        except Exception:
            return "Hex error"

    def export_search_to_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["File", "Line", "Content"])
                for r in range(self.results_table.rowCount()):
                    writer.writerow([self.results_table.item(r, 0).text(), self.results_table.item(r, 1).text(), self.results_table.item(r, 2).text()])

    def apply_tree_filter(self, text):
        self.proxy_model.setFilterRegExp(text)

    def export_to_disk(self):
        dest = QFileDialog.getExistingDirectory(self, "Export Directory")
        if dest and self.temp_dir:
            shutil.copytree(self.temp_dir, dest, dirs_exist_ok=True)

    def cleanup_temp(self):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None




# --- STATIC DECRYPTER WORKSPACE ---
STATIC_DECRYPTER_BASE_PATH = os.path.expanduser("~/.jpeixoto/StaticDecrypter/")
STATIC_DECRYPTER_CACHE_DIR = os.path.join(STATIC_DECRYPTER_BASE_PATH, "dex_cache")
os.makedirs(STATIC_DECRYPTER_CACHE_DIR, exist_ok=True)


class StaticDecompileWorker(QThread):
    finished = pyqtSignal(str)

    def __init__(self, data):
        super().__init__()
        self.data = data

    def run(self):
        h = hashlib.md5(self.data).hexdigest()
        cp = os.path.join(STATIC_DECRYPTER_CACHE_DIR, f"{h}.java")
        if os.path.exists(cp):
            with open(cp, "r", encoding="utf-8", errors="replace") as f:
                self.finished.emit(f.read())
            return
        try:
            from androguard.core.dex import DEX
            from androguard.core.analysis.analysis import Analysis
            from androguard.decompiler.decompile import DvMethod
            df = DEX(self.data)
            dx = Analysis(df)
            out = []
            for cls in df.get_classes()[:20]:
                for m in cls.get_methods():
                    src = None
                    mx = dx.get_method(m)
                    if mx:
                        d = DvMethod(mx)
                        d.process()
                        src = d.get_source()
                    if src:
                        out.append(src)
            code = "\n".join(out)
            with open(cp, "w", encoding="utf-8") as f:
                f.write(code)
            self.finished.emit(code)
        except Exception as e:
            self.finished.emit(f"// Error: {e}\n// Install optional dependency with: pip install androguard")


class StaticDecoderWorker(QThread):
    finished = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, script, target_content, pattern, lang):
        super().__init__()
        self.script = script or ""
        self.target_content = target_content or ""
        self.pattern = pattern or ""
        self.lang = lang or "Python"

    def run(self):
        try:
            results = []
            matches = list(re.finditer(self.pattern, self.target_content))
            total = len(matches)
            if total == 0:
                self.finished.emit([])
                return
            for i, match in enumerate(matches):
                groups = match.groups()
                p1 = groups[0] if len(groups) > 0 else ""
                p2 = groups[1] if len(groups) > 1 else ""
                p1_c = p1.replace('\\n', '').replace('\\"', '"').replace('\n', '').strip()
                p2_c = p2.replace('\\n', '').replace('\\"', '"').replace('\n', '').strip()
                decrypted = self.execute_decryption(p1_c, p2_c)
                results.append([p1_c, p2_c, str(decrypted)])
                if i % 10 == 0:
                    self.progress.emit(int((i / total) * 100))
            self.progress.emit(100)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))

    def execute_decryption(self, p1, p2):
        try:
            if self.lang == "Python":
                local_scope = {}
                exec(self.script, {"base64": base64, "re": re, "json": json}, local_scope)
                decrypt_func = local_scope.get('decrypt')
                if not decrypt_func:
                    return "[ERR: No decrypt(p1, p2) found]"
                return decrypt_func(p1, p2)
            elif self.lang == "C#":
                temp_dir = tempfile.mkdtemp(prefix="uft_static_cs_")
                try:
                    temp_cs = os.path.join(temp_dir, "temp_logic.cs")
                    temp_exe = os.path.join(temp_dir, "temp_logic.exe")
                    with open(temp_cs, "w", encoding='utf-8') as f:
                        f.write(self.script)
                    subprocess.run(f"mcs '{temp_cs}'", shell=True, check=True, capture_output=True)
                    cmd = f"mono '{temp_exe}' \"{p1}\" \"{p2}\""
                    return subprocess.check_output(cmd, shell=True).decode(errors='replace').strip()
                finally:
                    shutil.rmtree(temp_dir, ignore_errors=True)
            elif self.lang == "JavaScript":
                try:
                    import quickjs
                except Exception:
                    return "[ERR: quickjs missing. pip install quickjs]"
                context = quickjs.Context()
                context.eval(self.script)
                f = context.get("decrypt")
                return str(f(p1, p2)) if f else "[ERR: No decrypt() found]"
            return "[ERR: Unsupported Lang]"
        except Exception as e:
            return f"[ERR: {type(e).__name__}: {e}]"


class StaticDecrypterWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.toolbox_parent = parent
        self.scripts_dir = os.path.join(STATIC_DECRYPTER_BASE_PATH, "saved_scripts_StaticDecrypter")
        self.projects_dir = os.path.join(STATIC_DECRYPTER_BASE_PATH, "projects_StaticDecrypter")
        self.session_file = os.path.join(STATIC_DECRYPTER_BASE_PATH, "session_config.json")
        for d in [STATIC_DECRYPTER_BASE_PATH, self.scripts_dir, self.projects_dir, STATIC_DECRYPTER_CACHE_DIR]:
            os.makedirs(d, exist_ok=True)
        self.worker = None
        self.dw = None
        self.init_ui()
        self.load_session()

    def init_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("🔐 Static Decrypter")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #58a6ff; padding: 4px;")
        layout.addWidget(title)

        p_row = QHBoxLayout()
        self.proj_cb = QComboBox()
        self.refresh_projs()
        p_row.addWidget(QLabel("<b>Project:</b>"))
        p_row.addWidget(self.proj_cb, 1)
        btn_load_p = QPushButton("Load Project")
        btn_load_p.clicked.connect(self.load_project_file)
        btn_save_p = QPushButton("Save Project")
        btn_save_p.clicked.connect(self.save_project_explorer)
        btn_del_p = QPushButton("Delete Project")
        btn_del_p.clicked.connect(self.del_project)
        p_row.addWidget(btn_load_p)
        p_row.addWidget(btn_save_p)
        p_row.addWidget(btn_del_p)
        layout.addLayout(p_row)

        s_row = QHBoxLayout()
        self.lang_cb = QComboBox()
        self.lang_cb.addItems(["Python", "C#", "JavaScript"])
        self.script_cb = QComboBox()
        self.refresh_scripts()
        self.script_cb.currentIndexChanged.connect(self.load_script_file)
        s_row.addWidget(QLabel("<b>Lang:</b>"))
        s_row.addWidget(self.lang_cb)
        s_row.addWidget(QLabel("<b>Script:</b>"))
        s_row.addWidget(self.script_cb, 1)
        btn_new_s = QPushButton("New")
        btn_new_s.clicked.connect(self.new_script)
        btn_up_s = QPushButton("Update Current")
        btn_up_s.clicked.connect(self.update_script)
        btn_as_s = QPushButton("Save As")
        btn_as_s.clicked.connect(self.save_script_explorer)
        s_row.addWidget(btn_new_s)
        s_row.addWidget(btn_up_s)
        s_row.addWidget(btn_as_s)
        layout.addLayout(s_row)

        ed_row = QHBoxLayout()
        self.code_edit = QTextEdit()
        self.code_edit.setPlaceholderText("Write decrypt(p1, p2) here. Python example:\n\ndef decrypt(p1, p2):\n    return p1 + ':' + p2")
        self.src_edit = QTextEdit()
        self.src_edit.setPlaceholderText("Load/decompile target source, XML, DEX, or paste code here...")
        self.code_edit.setFont(QFont("Menlo" if sys.platform == "darwin" else "Consolas", 11))
        self.src_edit.setFont(QFont("Menlo" if sys.platform == "darwin" else "Consolas", 11))
        ed_row.addWidget(self.code_edit, 1)
        ed_row.addWidget(self.src_edit, 1)
        layout.addLayout(ed_row, 3)

        src_tools = QHBoxLayout()
        btn_load_any = QPushButton("ApkExplorer: LOAD ANY FILE")
        btn_load_any.clicked.connect(self.handle_load)
        btn_clear_c = QPushButton("Clear .dex_cache")
        btn_clear_c.clicked.connect(self.clear_cache)
        btn_send_to_beautifier = QPushButton("Send Source to Beautifier")
        btn_send_to_beautifier.clicked.connect(self.send_source_to_beautifier)
        src_tools.addWidget(btn_load_any, 2)
        src_tools.addWidget(btn_clear_c, 1)
        src_tools.addWidget(btn_send_to_beautifier, 1)
        layout.addLayout(src_tools)

        reg_row = QHBoxLayout()
        self.reg_cb = QComboBox()
        self.reg_cb.setEditable(True)
        self.reg_cb.setInsertPolicy(QComboBox.InsertAtTop)
        btn_clear_reg = QPushButton("Clear Hist")
        btn_clear_reg.clicked.connect(lambda: self.reg_cb.clear())
        self.run_btn = QPushButton("RUN DECODER")
        self.run_btn.setFixedHeight(45)
        self.run_btn.setStyleSheet("background: #d32f2f; color: white; font-weight: bold;")
        self.run_btn.clicked.connect(self.run_logic)
        reg_row.addWidget(QLabel("<b>Regex:</b>"))
        reg_row.addWidget(self.reg_cb, 1)
        reg_row.addWidget(btn_clear_reg)
        reg_row.addWidget(self.run_btn)
        layout.addLayout(reg_row)

        self.pbar = QProgressBar()
        layout.addWidget(self.pbar)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["P1", "P2", "Result"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 2)

        ex_row = QHBoxLayout()
        btn_copy = QPushButton("Copy Grid CSV (Clipboard)")
        btn_copy.clicked.connect(self.copy_csv)
        btn_excel = QPushButton("Export to Excel (.xlsx)")
        btn_excel.clicked.connect(self.export_excel)
        ex_row.addWidget(btn_copy)
        ex_row.addWidget(btn_excel)
        ex_row.addStretch(1)
        layout.addLayout(ex_row)

    def copy_csv(self):
        rows = ["Param 1,Param 2,Result"]
        for r in range(self.table.rowCount()):
            row_data = []
            for c in range(3):
                item = self.table.item(r, c)
                row_data.append('"' + (item.text().replace('"', '""') if item else "") + '"')
            rows.append(",".join(row_data))
        QApplication.clipboard().setText("\n".join(rows))
        QMessageBox.information(self, "Success", "Grid copied to clipboard as CSV.")

    def export_excel(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Excel", "", "Excel Files (*.xlsx)")
        if not p:
            return
        if not p.lower().endswith(".xlsx"):
            p += ".xlsx"
        data = []
        for r in range(self.table.rowCount()):
            data.append([(self.table.item(r, c).text() if self.table.item(r, c) else "") for c in range(3)])
        try:
            import pandas as pd
        except Exception:
            QMessageBox.warning(self, "Missing Dependency", "Excel export requires pandas/openpyxl. Install with: pip install pandas openpyxl")
            return
        pd.DataFrame(data, columns=["P1", "P2", "Result"]).to_excel(p, index=False)
        QMessageBox.information(self, "Success", f"Exported to {os.path.basename(p)}")

    def load_script_file(self):
        name = self.script_cb.currentText()
        path = os.path.join(self.scripts_dir, name)
        if name and os.path.isfile(path):
            with open(path, 'r', encoding='utf-8') as f:
                d = json.load(f)
                self.lang_cb.setCurrentText(d.get("lang", "Python"))
                self.code_edit.setPlainText(d.get("script", ""))
                self.reg_cb.setEditText(d.get("regex", ""))

    def update_script(self):
        n = self.script_cb.currentText()
        if n:
            d = {"lang": self.lang_cb.currentText(), "regex": self.reg_cb.currentText(), "script": self.code_edit.toPlainText()}
            with open(os.path.join(self.scripts_dir, n), 'w', encoding='utf-8') as f:
                json.dump(d, f, indent=4)
            QMessageBox.information(self, "Success", f"Updated {n}")

    def save_script_explorer(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Script", self.scripts_dir, "JSON Files (*.json)")
        if p:
            if not p.lower().endswith(".json"):
                p += ".json"
            d = {"lang": self.lang_cb.currentText(), "regex": self.reg_cb.currentText(), "script": self.code_edit.toPlainText()}
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(d, f, indent=4)
            self.refresh_scripts()
            self.script_cb.setCurrentText(os.path.basename(p))

    def load_project_file(self):
        n = self.proj_cb.currentText()
        if n and os.path.isfile(os.path.join(self.projects_dir, f"{n}.json")):
            with open(os.path.join(self.projects_dir, f"{n}.json"), 'r', encoding='utf-8') as f:
                self.apply_state(json.load(f))

    def save_project_explorer(self):
        p, _ = QFileDialog.getSaveFileName(self, "Save Project", self.projects_dir, "JSON Files (*.json)")
        if p:
            if not p.lower().endswith(".json"):
                p += ".json"
            with open(p, 'w', encoding='utf-8') as f:
                json.dump(self.get_full_state(), f, indent=4)
            self.refresh_projs()

    def del_project(self):
        n = self.proj_cb.currentText()
        if n and QMessageBox.question(self, "Delete", f"Delete project '{n}'?") == QMessageBox.Yes:
            os.remove(os.path.join(self.projects_dir, f"{n}.json"))
            self.refresh_projs()

    def handle_load(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*.*)")
        if not p:
            return
        if p.lower().endswith(".dex"):
            with open(p, 'rb') as f:
                data = f.read()
            self.set_busy(True, "Androguard Decompiling...")
            self.dw = StaticDecompileWorker(data)
            self.dw.finished.connect(self.on_dec_done)
            self.dw.start()
        elif p.lower().endswith(".xml"):
            with open(p, 'rb') as f:
                decoded = AXMLDecoder(f.read()).decode() if 'AXMLDecoder' in globals() else None
                self.src_edit.setPlainText(decoded or f.read().decode('utf-8', errors='replace'))
        else:
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                self.src_edit.setPlainText(f.read())

    def on_dec_done(self, code):
        self.src_edit.setPlainText(code)
        self.set_busy(False)

    def set_busy(self, busy, message=""):
        self.run_btn.setEnabled(not busy)
        self.pbar.setRange(0, 0 if busy else 100)
        if not busy:
            self.pbar.setValue(0)

    def clear_cache(self):
        shutil.rmtree(STATIC_DECRYPTER_CACHE_DIR, ignore_errors=True)
        os.makedirs(STATIC_DECRYPTER_CACHE_DIR, exist_ok=True)
        QMessageBox.information(self, "Cache", "Static Decrypter dex cache cleared.")

    def refresh_scripts(self):
        self.script_cb.blockSignals(True)
        self.script_cb.clear()
        self.script_cb.addItems([f for f in os.listdir(self.scripts_dir) if f.endswith(".json")])
        self.script_cb.blockSignals(False)

    def refresh_projs(self):
        self.proj_cb.blockSignals(True)
        self.proj_cb.clear()
        self.proj_cb.addItems([f.replace(".json", "") for f in os.listdir(self.projects_dir) if f.endswith(".json")])
        self.proj_cb.blockSignals(False)

    def new_script(self):
        self.script_cb.setCurrentIndex(-1)
        self.code_edit.clear()
        self.reg_cb.setEditText("")

    def get_full_state(self):
        return {
            "lang": self.lang_cb.currentText(),
            "code": self.code_edit.toPlainText(),
            "src": self.src_edit.toPlainText(),
            "reg_current": self.reg_cb.currentText(),
            "reg_history": [self.reg_cb.itemText(i) for i in range(self.reg_cb.count())]
        }

    def apply_state(self, d):
        self.lang_cb.setCurrentText(d.get("lang", "Python"))
        self.code_edit.setPlainText(d.get("code", ""))
        self.src_edit.setPlainText(d.get("src", ""))
        self.reg_cb.clear()
        self.reg_cb.addItems(d.get("reg_history", []))
        self.reg_cb.setEditText(d.get("reg_current", ""))

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    self.apply_state(json.load(f))
            except Exception:
                pass

    def save_session(self):
        with open(self.session_file, 'w', encoding='utf-8') as f:
            json.dump(self.get_full_state(), f, indent=2)

    def run_logic(self):
        self.table.setRowCount(0)
        reg = self.reg_cb.currentText()
        if not reg:
            QMessageBox.warning(self, "Regex Required", "Enter a regex pattern with one or two capture groups.")
            return
        if reg and self.reg_cb.findText(reg) == -1:
            self.reg_cb.insertItem(0, reg)
        self.run_btn.setEnabled(False)
        self.worker = StaticDecoderWorker(self.code_edit.toPlainText(), self.src_edit.toPlainText(), reg, self.lang_cb.currentText())
        self.worker.finished.connect(self.on_done)
        self.worker.progress.connect(self.pbar.setValue)
        self.worker.error.connect(lambda e: QMessageBox.critical(self, "Decoder Error", e))
        self.worker.start()

    def on_done(self, results):
        self.run_btn.setEnabled(True)
        self.pbar.setRange(0, 100)
        self.pbar.setValue(100)
        self.table.setRowCount(len(results))
        for i, row in enumerate(results):
            for j, value in enumerate(row):
                self.table.setItem(i, j, QTableWidgetItem(value))
        self.save_session()

    def send_source_to_beautifier(self):
        parent = self.toolbox_parent
        if parent and hasattr(parent, "beautifier_workspace"):
            parent.beautifier_workspace.editor.setPlainText(self.src_edit.toPlainText())
            parent.switch_to_tab_containing("Beautifier")
        else:
            QMessageBox.information(self, "Beautifier", "Beautifier workspace is not available.")



class RiskwareRubiksWorkspace(QWidget):
    """Embedded Riskware Rubiks Signal Tracker workspace."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.profiles = {
            'Corporate': {'Weak': 2, 'Medium': 4, 'Strong': 8},
            'Personal': {'Weak': 1, 'Medium': 2, 'Strong': 5},
            'Government': {'Weak': 5, 'Medium': 10, 'Strong': 20},
        }
        self.current_profile = 'Corporate'
        self.points_map = self.profiles[self.current_profile]
        self.base_dir = os.path.expanduser('~/.jpeixoto/Rubiks')
        self.template_dir = os.path.join(self.base_dir, 'templates_Rubiks')
        self.draft_dir = os.path.join(self.base_dir, 'drafts_Rubiks')
        self.is_dark_mode = True
        self.df = None
        self.df_new = None
        for folder in [self.base_dir, self.template_dir, self.draft_dir]:
            os.makedirs(folder, exist_ok=True)
        self.init_ui()
        self.autosave_timer = QTimer(self)
        self.autosave_timer.timeout.connect(self.perform_autosave)
        self.autosave_timer.start(300000)

    def _pd(self):
        try:
            import pandas as pd
            return pd
        except Exception as e:
            QMessageBox.critical(self, 'Missing Dependency', 'Riskware Rubiks requires pandas. Install it with:\n\n    pip install pandas openpyxl\n\n' + str(e))
            return None

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel('Template:'))
        self.template_dropdown = QComboBox()
        self.refresh_templates()
        self.template_dropdown.currentIndexChanged.connect(self.load_template_from_dropdown)
        controls_layout.addWidget(self.template_dropdown, 1)

        btn_refresh = QPushButton('🔄')
        btn_refresh.setFixedWidth(40)
        btn_refresh.clicked.connect(self.refresh_templates)
        controls_layout.addWidget(btn_refresh)

        btn_open_templates = QPushButton('📁 Templates')
        btn_open_templates.clicked.connect(lambda: self.open_folder(self.template_dir))
        controls_layout.addWidget(btn_open_templates)

        controls_layout.addWidget(QLabel('Profile:'))
        self.profile_dropdown = QComboBox()
        self.profile_dropdown.addItems(list(self.profiles.keys()))
        self.profile_dropdown.currentTextChanged.connect(self.change_profile)
        controls_layout.addWidget(self.profile_dropdown)

        self.score_label = QLabel('Total Score: 0')
        self.score_label.setStyleSheet('font-size: 18px; font-weight: bold; color: #ff9f43; margin-left: 15px;')
        controls_layout.addWidget(self.score_label)

        btn_export = QPushButton('Export Report')
        btn_export.clicked.connect(self.export_report)
        controls_layout.addWidget(btn_export)

        btn_save = QPushButton('Save Draft')
        btn_save.clicked.connect(self.save_draft)
        btn_load = QPushButton('Load Draft')
        btn_load.clicked.connect(self.load_draft)
        controls_layout.addWidget(btn_save)
        controls_layout.addWidget(btn_load)
        main_layout.addLayout(controls_layout)

        util_layout = QHBoxLayout()
        util_layout.addWidget(QLabel('Category:'))
        self.category_dropdown = QComboBox()
        self.category_dropdown.addItem('All Categories')
        self.category_dropdown.currentIndexChanged.connect(self.apply_filters)
        util_layout.addWidget(self.category_dropdown)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText('Search signals, notes, or evidence...')
        self.search_input.textChanged.connect(self.apply_filters)
        util_layout.addWidget(self.search_input, 1)

        btn_merge = QPushButton('Merge Template')
        btn_merge.clicked.connect(self.merge_template)
        util_layout.addWidget(btn_merge)

        btn_analytics = QPushButton('Analytics Summary')
        btn_analytics.clicked.connect(self.show_analytics)
        util_layout.addWidget(btn_analytics)

        self.btn_theme = QPushButton('☀️ Light Mode' if self.is_dark_mode else '🌙 Dark Mode')
        self.btn_theme.clicked.connect(self.toggle_theme)
        util_layout.addWidget(self.btn_theme)
        main_layout.addLayout(util_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(['Discovered', 'Category', 'Definition', 'Signal Description', 'Strength', 'Links', 'Investigator Notes', 'Evidence Path'])
        self.table.cellDoubleClicked.connect(self.handle_double_click)
        self.table.itemClicked.connect(self.handle_item_click)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        main_layout.addWidget(self.table)

        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel('Risk Level:'))
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        status_layout.addWidget(self.progress_bar)
        main_layout.addLayout(status_layout)

        self.apply_theme()
        if self.template_dropdown.count() > 0:
            self.load_template_from_dropdown()

    def open_folder(self, path):
        os.makedirs(path, exist_ok=True)
        try:
            if sys.platform == 'darwin':
                subprocess.Popen(['open', path])
            elif sys.platform == 'win32':
                os.startfile(path)
            else:
                subprocess.Popen(['xdg-open', path])
        except Exception as e:
            QMessageBox.warning(self, 'Open Folder', str(e))

    def apply_theme(self):
        if self.is_dark_mode:
            self.setStyleSheet('background-color: #1e1e1e; color: white;')
            style = "QTableWidget { background-color: #252526; color: white; gridline-color: #333; } QHeaderView::section { background-color: #333; color: white; border: 1px solid #444; } QPushButton { background-color: #444; color: white; border-radius: 4px; padding: 5px; } QLineEdit, QComboBox { background-color: #333; color: white; border: 1px solid #555; }"
        else:
            self.setStyleSheet('background-color: #f0f0f0; color: black;')
            style = "QTableWidget { background-color: white; color: black; gridline-color: #ccc; } QHeaderView::section { background-color: #e0e0e0; color: black; border: 1px solid #ccc; } QPushButton { background-color: #ddd; color: black; border-radius: 4px; padding: 5px; } QLineEdit, QComboBox { background-color: white; color: black; border: 1px solid #ccc; }"
        self.table.setStyleSheet(style)
        self.update_score()

    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        self.btn_theme.setText('☀️ Light Mode' if self.is_dark_mode else '🌙 Dark Mode')
        self.apply_theme()

    def change_profile(self, profile_name):
        if not profile_name:
            return
        self.current_profile = profile_name
        self.points_map = self.profiles[profile_name]
        self.update_score()

    def setup_table(self, append=False):
        if not append:
            self.table.setRowCount(0)
        start_row = self.table.rowCount()
        target_df = self.df if not append else self.df_new
        if target_df is None:
            return
        rows = target_df.reset_index(drop=True)
        self.table.setRowCount(start_row + len(rows))

        for offset, row in rows.iterrows():
            current_row = start_row + offset
            chk_widget = QWidget()
            chk_layout = QHBoxLayout(chk_widget)
            checkbox = QCheckBox()
            strength = str(row.get('Signal strength', 'Weak')).strip().capitalize()
            checkbox.setProperty('strength', strength)
            checkbox.stateChanged.connect(self.update_score)
            if 'Discovered' in row and str(row['Discovered']) in ['1', '1.0', 'True', 'true']:
                checkbox.setCheckState(Qt.Checked)
            chk_layout.addWidget(checkbox)
            chk_layout.setAlignment(Qt.AlignCenter)
            chk_layout.setContentsMargins(0, 0, 0, 0)
            self.table.setCellWidget(current_row, 0, chk_widget)

            cols = ['Catagory', 'Definition', 'Signal', 'Signal strength', 'SS Links']
            for col_idx, col_name in enumerate(cols, start=1):
                val = str(row.get(col_name, ''))
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                if col_name == 'SS Links' and val.startswith('http'):
                    item.setForeground(QBrush(QColor('#4dabf7')))
                self.table.setItem(current_row, col_idx, item)

            self.table.setItem(current_row, 6, QTableWidgetItem(str(row.get('Notes', ''))))
            self.table.setItem(current_row, 7, QTableWidgetItem(str(row.get('Evidence', 'Double-click to attach'))))

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        for col, width in [(0,80),(1,160),(2,260),(3,360),(4,120),(5,240),(6,240),(7,180)]:
            self.table.setColumnWidth(col, width)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)

    def handle_double_click(self, row, column):
        if column == 0:
            cb = self.table.cellWidget(row, 0).findChild(QCheckBox)
            cb.setCheckState(Qt.Unchecked if cb.isChecked() else Qt.Checked)
        elif column == 7:
            path, _ = QFileDialog.getOpenFileName(self, 'Attach Evidence File')
            if path:
                self.table.item(row, 7).setText(path)

    def handle_item_click(self, item):
        if item.column() == 5 and item.text().startswith('http'):
            QDesktopServices.openUrl(QUrl(item.text()))
        elif item.column() == 7 and os.path.exists(item.text()):
            QDesktopServices.openUrl(QUrl.fromLocalFile(item.text()))

    def merge_template(self):
        pd = self._pd()
        if pd is None:
            return
        fname, _ = QFileDialog.getOpenFileName(self, 'Select Template to Merge', self.template_dir, 'CSV Files (*.csv)')
        if fname:
            self.df_new = pd.read_csv(fname).fillna('')
            self.setup_table(append=True)
            self.update_category_list()

    def update_category_list(self):
        cats = set()
        for i in range(self.table.rowCount()):
            item = self.table.item(i, 1)
            if item:
                cats.add(item.text())
        self.category_dropdown.blockSignals(True)
        self.category_dropdown.clear()
        self.category_dropdown.addItem('All Categories')
        self.category_dropdown.addItems(sorted(list(cats)))
        self.category_dropdown.blockSignals(False)

    def show_analytics(self):
        stats = {}
        for i in range(self.table.rowCount()):
            cb_widget = self.table.cellWidget(i, 0)
            cb = cb_widget.findChild(QCheckBox) if cb_widget else None
            if cb and cb.isChecked():
                cat_item = self.table.item(i, 1)
                cat = cat_item.text() if cat_item else 'Unknown'
                strength = cb.property('strength')
                pts = self.points_map.get(strength, 0)
                stats[cat] = stats.get(cat, 0) + pts
        msg = 'Risk Breakdown by Category:\n\n'
        for cat, score in stats.items():
            bar = '█' * min(score, 20)
            msg += f'{cat:.<20} {score} pts {bar}\n'
        dialog = QDialog(self)
        dialog.setWindowTitle('Analytics Summary')
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setText(msg)
        text.setFontFamily('Courier')
        layout.addWidget(text)
        dialog.resize(520, 340)
        dialog.exec_()

    def apply_filters(self):
        search = self.search_input.text().lower()
        cat_filter = self.category_dropdown.currentText()
        for i in range(self.table.rowCount()):
            cat_item = self.table.item(i, 1)
            match_cat = (cat_filter == 'All Categories' or (cat_item and cat_item.text() == cat_filter))
            match_search = any(search in (self.table.item(i, j).text().lower() if self.table.item(i, j) else '') for j in range(1, 8))
            self.table.setRowHidden(i, not (match_cat and match_search))

    def update_score(self):
        total = 0
        h_bg = '#2d4a3e' if self.is_dark_mode else '#d4edda'
        d_bg = '#252526' if self.is_dark_mode else 'white'
        for i in range(self.table.rowCount()):
            cb_widget = self.table.cellWidget(i, 0)
            cb = cb_widget.findChild(QCheckBox) if cb_widget else None
            if cb:
                is_checked = cb.isChecked()
                bg = h_bg if is_checked else d_bg
                if is_checked:
                    total += self.points_map.get(cb.property('strength'), 0)
                cb_widget.setStyleSheet(f'background-color: {bg};')
                for j in range(1, 8):
                    if self.table.item(i, j):
                        self.table.item(i, j).setBackground(QBrush(QColor(bg)))
        self.score_label.setText(f'Total Score: {total}')
        self.progress_bar.setValue(min(total, 100))

    def export_report(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Report', '', 'Text Files (*.txt)')
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(f'RISK REPORT - Profile: {self.current_profile}\n')
                f.write(f'Final Score: {self.score_label.text()}\n' + '=' * 40 + '\n')
                for i in range(self.table.rowCount()):
                    cb_widget = self.table.cellWidget(i, 0)
                    cb = cb_widget.findChild(QCheckBox) if cb_widget else None
                    if cb and cb.isChecked():
                        f.write(f'SIGNAL: {self.table.item(i, 3).text()}\n')
                        f.write(f'NOTES: {self.table.item(i, 6).text()}\n')
                        f.write(f'EVIDENCE: {self.table.item(i, 7).text()}\n' + '-' * 20 + '\n')
            QMessageBox.information(self, 'Success', 'Report Exported.')

    def save_draft(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save Draft', self.draft_dir, 'CSV Files (*.csv)')
        if path:
            self._save_logic(path)

    def perform_autosave(self):
        if self.table.rowCount() > 0:
            self._save_logic(os.path.join(self.draft_dir, 'autosave_latest.csv'))

    def _save_logic(self, path):
        pd = self._pd()
        if pd is None:
            return
        data = []
        for i in range(self.table.rowCount()):
            cb_widget = self.table.cellWidget(i, 0)
            cb = cb_widget.findChild(QCheckBox) if cb_widget else None
            data.append({
                'Discovered': 1 if cb and cb.isChecked() else 0,
                'Catagory': self.table.item(i, 1).text() if self.table.item(i, 1) else '',
                'Definition': self.table.item(i, 2).text() if self.table.item(i, 2) else '',
                'Signal': self.table.item(i, 3).text() if self.table.item(i, 3) else '',
                'Signal strength': self.table.item(i, 4).text() if self.table.item(i, 4) else '',
                'SS Links': self.table.item(i, 5).text() if self.table.item(i, 5) else '',
                'Notes': self.table.item(i, 6).text() if self.table.item(i, 6) else '',
                'Evidence': self.table.item(i, 7).text() if self.table.item(i, 7) else '',
            })
        pd.DataFrame(data).to_csv(path, index=False)

    def load_draft(self):
        pd = self._pd()
        if pd is None:
            return
        fname, _ = QFileDialog.getOpenFileName(self, 'Open Draft', self.draft_dir, 'CSV Files (*.csv)')
        if fname:
            self.df = pd.read_csv(fname).fillna('')
            self.setup_table()
            self.update_category_list()
            self.update_score()

    def refresh_templates(self):
        self.template_dropdown.blockSignals(True)
        self.template_dropdown.clear()
        if os.path.exists(self.template_dir):
            self.template_dropdown.addItems(sorted([f for f in os.listdir(self.template_dir) if f.endswith('.csv')]))
        self.template_dropdown.blockSignals(False)

    def load_template_from_dropdown(self):
        pd = self._pd()
        if pd is None:
            return
        filename = self.template_dropdown.currentText()
        if filename:
            self.df = pd.read_csv(os.path.join(self.template_dir, filename)).fillna('')
            self.setup_table()
            self.update_category_list()
            self.update_score()


# --- SECURITY REVIEW WORKSTATION ---

TAG_DATA = [
    ("{app_name}", "App Name"), ("{package_name}", "Package Name"),
    ("{version_code}", "Version Code"), ("{artifact_id}", "Artifact ID"),
    ("{pha_category}", "PHA Category"), ("{mokka_link}", "Mokka URL"),
    ("{buganizer_link}", "Buganizer URL"), ("{stage_3_link}", "Review Stage 3 URL"),
    ("{cloaked_url}", "Cloaked URL"), ("{uncloaked_url}", "Uncloaked URL"),
    ("{uncloak_steps}", "List: Steps to Uncloak"),
    ("{notes}", "Internal Notes"),
    ("{summary}", "Summary Box"), ("{verdict}", "Verdict/Hashtags"),
    ("{static_analysis_points}", "List: Static Analysis"),
    ("{dynamic_analysis_points}", "List: Dynamic Analysis"),
    ("{bread_points}", "List: Bread Indicators + Pts"),
    ("{risk_points}", "List: Risks + Pts"), ("{nsr_summary}", "NSR Box"),
    ("{app_permissions}", "Permissions Box"), ("{scorers}", "Scorers Box"),
    ("{acc_status}", "Play: Account Status"), ("{total_apps}", "Play: Total Apps"),
    ("{total_installs}", "Play: Total Installs"), ("{app_status}", "Play: App Status"),
    ("{user_feedback}", "Play: User Feedback"), ("{app_icon}", "Play: App Icon"),
    ("{app_desc}", "Play: Description"), ("{main_sites}", "Play: Main Websites"),
    ("{priv_sites}", "Play: Privacy Websites"), ("{app_install}", "Play: App Install"),
    ("{framework}", "Play: App Framework"), ("{handling}", "Handling Box")
]

SECURITY_REVIEW_BASE_PATH = os.path.expanduser("~/.jpeixoto/GenReport")

# --- Spellcheck Engine ---

class SpellCheckHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.dict = enchant.Dict("en_US") if HAS_ENCHANT else None
        self.err_format = QTextCharFormat()
        self.err_format.setUnderlineColor(Qt.red)
        self.err_format.setUnderlineStyle(QTextCharFormat.SpellCheckUnderline)

    def highlightBlock(self, text):
        if not self.dict:
            return
        for match in re.finditer(r'\b[A-Za-z\']+\b', text):
            word = match.group()
            if not self.dict.check(word):
                self.setFormat(match.start(), match.end() - match.start(), self.err_format)


class SpellCheckEdit(QTextEdit):
    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        if HAS_ENCHANT:
            cursor = self.cursorForPosition(event.pos())
            cursor.select(QTextCursor.WordUnderCursor)
            word = cursor.selectedText()
            d = enchant.Dict("en_US")
            if word and not d.check(word):
                suggestions = d.suggest(word)[:5]
                if suggestions:
                    first_action = menu.actions()[0] if menu.actions() else None
                    menu.insertSeparator(first_action)
                    for s in reversed(suggestions):
                        new_act = QAction(s, menu)
                        new_act.triggered.connect(lambda checked, sel=s, c=cursor: self.replace_word(c, sel))
                        menu.insertAction(first_action, new_act)
        menu.exec_(event.globalPos())

    def replace_word(self, cursor, new_word):
        if not self.isReadOnly():
            cursor.insertText(new_word)


class SpellCheckBrowser(QTextBrowser):
    def contextMenuEvent(self, event):
        menu = self.createStandardContextMenu()
        if HAS_ENCHANT:
            cursor = self.cursorForPosition(event.pos())
            cursor.select(QTextCursor.WordUnderCursor)
            word = cursor.selectedText()
            d = enchant.Dict("en_US")
            if word and not d.check(word):
                suggestions = d.suggest(word)[:5]
                if suggestions:
                    first_action = menu.actions()[0] if menu.actions() else None
                    menu.insertSeparator(first_action)
                    for s in reversed(suggestions):
                        new_act = QAction(s, menu)
                        menu.insertAction(first_action, new_act)
        menu.exec_(event.globalPos())


# --- App Components ---

class MiniPreviewPopup(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.ToolTip | Qt.FramelessWindowHint)
        self.setFixedSize(500, 120)
        layout = QVBoxLayout(self)
        self.browser = QTextBrowser()
        self.browser.setStyleSheet("background-color: #1e1e1e; color: #8ab4f8; border: none;")
        self.browser.setFont(QFont("Arial", 10))
        layout.addWidget(self.browser)
        self.setStyleSheet("border: 2px solid #4CAF50; background-color: #1e1e1e;")

    def show_preview(self, url):
        html = f"""
        <div style='font-family: Arial, sans-serif;'>
            <b style='color: #4CAF50;'>Link Preview</b><br>
            <p style='color: #eee; margin-top: 5px;'>{url}</p>
            <i style='color: #888;'>Click link to open in system browser</i>
        </div>
        """
        self.browser.setHtml(html)


class TemplateEditor(QDialog):
    def __init__(self, templates_dir, current_template=None, parent=None):
        super().__init__(parent)
        self.templates_dir = templates_dir
        self.setWindowTitle("Template Editor")
        self.setMinimumSize(950, 650)
        main_layout = QHBoxLayout(self)
        sidebar = QVBoxLayout()
        sidebar.addWidget(QLabel("<b>Tags (Click to Insert):</b>"))
        self.tag_list = QListWidget()
        sorted_tags = sorted(TAG_DATA, key=lambda x: x[0].lower())
        for tag, desc in sorted_tags:
            self.tag_list.addItem(f"{tag} ({desc})")
        self.tag_list.itemClicked.connect(self.insert_tag)
        sidebar.addWidget(self.tag_list)
        main_layout.addLayout(sidebar, 1)
        editor_layout = QVBoxLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("filename.md")
        self.content_editor = SpellCheckEdit()
        if HAS_ENCHANT: self.highlighter = SpellCheckHighlighter(self.content_editor.document())
        self.content_editor.setFont(QFont("Courier", 10))
        if current_template and current_template != "None":
            self.name_input.setText(current_template)
            try:
                with open(os.path.join(templates_dir, current_template), 'r', encoding='utf-8') as f:
                    self.content_editor.setPlainText(f.read())
            except:
                pass
        editor_layout.addWidget(QLabel("Filename:"))
        editor_layout.addWidget(self.name_input)
        editor_layout.addWidget(QLabel("Markdown Content:"))
        editor_layout.addWidget(self.content_editor)
        btn_row = QHBoxLayout()
        save_btn = QPushButton("💾 Save Template")
        save_btn.clicked.connect(self.save_template)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(close_btn)
        editor_layout.addLayout(btn_row)
        main_layout.addLayout(editor_layout, 3)

    def insert_tag(self, item):
        tag = item.text().split(" ")[0]
        self.content_editor.insertPlainText(tag)
        self.content_editor.setFocus()

    def save_template(self):
        name = self.name_input.text().strip()
        if not name: return
        if not name.endswith(".md"): name += ".md"
        path = os.path.join(self.templates_dir, name)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self.content_editor.toPlainText())
        self.accept()


class SecurityReviewWorkspace(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_file_path = None
        self.base_dir = SECURITY_REVIEW_BASE_PATH

        self.reports_dir = os.path.join(SECURITY_REVIEW_BASE_PATH, "reports_GenReport")
        self.templates_dir = os.path.join(SECURITY_REVIEW_BASE_PATH, "templates_GenReport")
        for d in [SECURITY_REVIEW_BASE_PATH, self.reports_dir, self.templates_dir]:
            if not os.path.exists(d): os.makedirs(d)

        self.preview_popup = MiniPreviewPopup(self)
        self.preview_popup.hide()

        self.preview_timer = QTimer()
        self.preview_timer.setSingleShot(True)
        self.preview_timer.timeout.connect(self.update_preview)
        self.initUI()
        self.refresh_templates()
        self.refresh_draft_gallery()

    def initUI(self):
        self.setWindowTitle('Security Review Workstation')
        self.setGeometry(100, 100, 1650, 950)
        self.main_vbox = QVBoxLayout(self)
        self.main_vbox.setContentsMargins(5, 5, 5, 5)

        top_bar = QHBoxLayout()
        self.toggle_gallery_btn = QPushButton("...")
        self.toggle_gallery_btn.setFixedWidth(30)
        self.toggle_gallery_btn.setCheckable(True)
        self.toggle_gallery_btn.clicked.connect(self.toggle_gallery)
        top_bar.addWidget(self.toggle_gallery_btn)

        self.template_combo = QComboBox()
        self.template_combo.currentIndexChanged.connect(self.trigger_preview)
        btn_edit = QPushButton("📝 Edit/New Template")
        btn_edit.clicked.connect(self.open_template_editor)
        self.new_review_btn = QPushButton("🆕 New Review")
        self.new_review_btn.clicked.connect(self.confirm_new_review)
        self.save_btn = QPushButton("💾 Save")
        self.save_btn.clicked.connect(self.save_logic)
        self.save_as_btn = QPushButton("💾 Save As...")
        self.save_as_btn.clicked.connect(self.save_as_logic)
        self.load_btn = QPushButton("📂 Load Draft")
        self.load_btn.clicked.connect(self.load_from_json)
        self.export_btn = QPushButton("📄 Export MD")
        self.export_btn.clicked.connect(self.export_report)

        # ADDED: Export HTML Button
        self.export_html_btn = QPushButton("🌐 Export HTML")
        self.export_html_btn.clicked.connect(self.export_html_report)

        self.create_bug_btn = QPushButton("🐛 Create Bug")
        self.create_bug_btn.setStyleSheet("background: #d32f2f; color: white; font-weight: bold;")
        self.create_bug_btn.clicked.connect(lambda: webbrowser.open("http://go/accio-qc"))

        top_bar.addWidget(QLabel("Template:"))
        top_bar.addWidget(self.template_combo)
        top_bar.addWidget(btn_edit)
        top_bar.addStretch()
        for w in [self.new_review_btn, self.save_btn, self.save_as_btn, self.load_btn,
                  self.export_btn, self.export_html_btn, self.create_bug_btn]: top_bar.addWidget(w)
        self.main_vbox.addLayout(top_bar, 0)

        self.main_splitter = QSplitter(Qt.Horizontal)
        self.gallery_container = QWidget()
        gal_lay = QVBoxLayout(self.gallery_container)
        gal_lay.addWidget(QLabel("<b>Draft Gallery</b>"))

        self.draft_tree = QTreeWidget()
        self.draft_tree.setHeaderHidden(True)
        self.draft_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.draft_tree.customContextMenuRequested.connect(self.show_gallery_context_menu)
        self.draft_tree.itemClicked.connect(self.load_gallery_item)
        gal_lay.addWidget(self.draft_tree)

        self.gallery_container.setVisible(False)
        self.main_splitter.addWidget(self.gallery_container)

        self.work_splitter = QSplitter(Qt.Horizontal)
        self.input_container = QWidget()
        input_layout = QVBoxLayout(self.input_container)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        self.form_layout = QVBoxLayout(scroll_content)

        meta_group = QGroupBox("App Metadata")
        mv = QFormLayout()
        mv.setLabelAlignment(Qt.AlignLeft)
        mv.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.app_name, self.artifact_id, self.package_name, self.version_code, self.pha_category, self.mokka_link, self.buganizer_link, self.stage_3_link = [
            QLineEdit() for _ in range(8)]
        self.pha_category.setText("warn_toll_fraud")

        def add_link_row(l, ew):
            r = QHBoxLayout()
            r.addWidget(ew)
            b = QPushButton("🌐 Open")
            b.setFixedWidth(60)
            b.clicked.connect(lambda: webbrowser.open(ew.text()) if ew.text() else None)
            r.addWidget(b)
            mv.addRow(l, r)

        mv.addRow("App Name:", self.app_name)
        mv.addRow("Artifact ID:", self.artifact_id)
        mv.addRow("Package Name:", self.package_name)
        mv.addRow("Version code:", self.version_code)
        mv.addRow("PHA Category:", self.pha_category)
        add_link_row("Mokka Link:", self.mokka_link)
        add_link_row("Buganizer Link:", self.buganizer_link)
        add_link_row("Review Stage 3:", self.stage_3_link)

        for e in [self.app_name, self.artifact_id, self.package_name, self.version_code, self.pha_category,
                  self.mokka_link, self.buganizer_link, self.stage_3_link]:
            e.textChanged.connect(self.trigger_preview)
            e.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        meta_group.setLayout(mv)
        self.form_layout.addWidget(meta_group)

        self.signals_toggle_btn = QPushButton("🔽 Show App and Dev Signals")
        self.signals_toggle_btn.setCheckable(True)
        self.signals_toggle_btn.setFixedWidth(250)
        self.signals_toggle_btn.clicked.connect(self.toggle_signals_section)
        self.form_layout.addWidget(self.signals_toggle_btn)

        self.signals_container_widget = QWidget()
        self.signals_layout = QVBoxLayout(self.signals_container_widget)
        self.signals_container_widget.setVisible(False)
        self.app_permissions, self.scorers = QTextEdit(), QTextEdit()
        self.app_permissions.setFixedHeight(80)
        self.scorers.setFixedHeight(80)
        for t, w in [("App Permissions:", self.app_permissions),
                     ("Scorers:", self.scorers)]:
            self.signals_layout.addWidget(QLabel(t))
            self.signals_layout.addWidget(w)
            w.textChanged.connect(self.trigger_preview)

        play_group = QGroupBox("Play Store Details")
        pl_lay = QFormLayout()
        pl_lay.setLabelAlignment(Qt.AlignLeft)
        pl_lay.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.acc_status, self.total_apps, self.total_installs, self.app_status, self.user_feedback, self.app_icon, self.app_desc, self.main_sites, self.priv_sites, self.app_install_field, self.app_framework = [
            QLineEdit() for _ in range(11)]
        play_f = [("Account Status:", self.acc_status), ("Total Apps:", self.total_apps),
                  ("Total Installs:", self.total_installs), ("App Status:", self.app_status),
                  ("User Feedback:", self.user_feedback), ("App Icon:", self.app_icon),
                  ("App Description:", self.app_desc), ("Main Websites:", self.main_sites),
                  ("Privacy Websites:", self.priv_sites), ("App Install:", self.app_install_field),
                  ("App Framework:", self.app_framework)]
        for l, e in play_f:
            e.textChanged.connect(self.trigger_preview)
            e.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            pl_lay.addRow(l, e)
        play_group.setLayout(pl_lay)
        self.signals_layout.addWidget(play_group)
        self.form_layout.addWidget(self.signals_container_widget)

        self.static_analysis_container, self.dynamic_analysis_container = QVBoxLayout(), QVBoxLayout()
        ana_group = QGroupBox("Analysis Points")
        am_lay = QVBoxLayout()
        self.setup_sub_section("Static Analysis", self.static_analysis_container, self.add_static_row, am_lay)
        self.setup_sub_section("Dynamic Analysis", self.dynamic_analysis_container, self.add_dynamic_row, am_lay)
        ana_group.setLayout(am_lay)
        self.form_layout.addWidget(ana_group)

        self.bread_container, self.risk_container = QVBoxLayout(), QVBoxLayout()
        self.setup_section("Bread Indicators / Potential Evasion", self.bread_container,
                           lambda: self.add_indicator_row(self.bread_container))
        self.setup_section("Risks", self.risk_container, lambda: self.add_indicator_row(self.risk_container))

        cloak_group = QGroupBox("Cloaked | Uncloaked")
        cl_lay = QVBoxLayout()
        cl_form = QFormLayout()
        cl_form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        self.cloaked_url, self.uncloaked_url = QLineEdit(), QLineEdit()
        for u in [self.cloaked_url, self.uncloaked_url]:
            u.textChanged.connect(self.trigger_preview)
            u.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        cl_form.addRow("Cloaked URL:", self.cloaked_url)
        cl_form.addRow("Uncloaked URL:", self.uncloaked_url)
        cl_lay.addLayout(cl_form)
        cl_lay.addWidget(QLabel("<b>Steps to Uncloak</b>"))
        self.uncloak_steps_container = QVBoxLayout()
        cl_lay.addLayout(self.uncloak_steps_container)
        ab = QPushButton("+ Add Uncloak Step Point")
        ab.clicked.connect(self.add_uncloak_row)
        cl_lay.addWidget(ab)
        cloak_group.setLayout(cl_lay)
        self.form_layout.addWidget(cloak_group)

        self.nsr_box, self.hand_box = SpellCheckEdit(), QTextEdit()
        self.nsr_box.setFixedHeight(80)
        self.hand_box.setFixedHeight(60)
        self.hand_box.setPlainText("#nesting")
        for w in [self.nsr_box, self.hand_box]: w.textChanged.connect(self.trigger_preview)
        self.form_layout.addWidget(QLabel("NSR Subsection:"))
        self.form_layout.addWidget(self.nsr_box)
        self.form_layout.addWidget(QLabel("Handling Context:"))
        self.form_layout.addWidget(self.hand_box)

        sum_group = QGroupBox("Summary, Verdict & Internal Notes")
        sl = QVBoxLayout()
        self.summary_text, self.verdict_input, self.notes_box = SpellCheckEdit(), QLineEdit(), SpellCheckEdit()
        self.notes_include_chk = QCheckBox("Include Notes in MD Export")
        self.summary_text.setFixedHeight(80)
        self.notes_box.setFixedHeight(120)
        self.summary_text.textChanged.connect(self.trigger_preview)
        self.verdict_input.textChanged.connect(self.trigger_preview)
        self.notes_box.textChanged.connect(self.trigger_preview)
        self.notes_include_chk.stateChanged.connect(self.trigger_preview)
        self.verdict_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sl.addWidget(QLabel("Summary:"))
        sl.addWidget(self.summary_text)
        sl.addWidget(QLabel("Verdict:"))
        sl.addWidget(self.verdict_input)
        notes_hdr = QHBoxLayout()
        notes_hdr.addWidget(QLabel("Internal Notes:"))
        notes_hdr.addStretch()
        notes_hdr.addWidget(self.notes_include_chk)
        sl.addLayout(notes_hdr)
        sl.addWidget(self.notes_box)
        sum_group.setLayout(sl)
        self.form_layout.addWidget(sum_group)

        if HAS_ENCHANT:
            self.sum_high = SpellCheckHighlighter(self.summary_text.document())
            self.nsr_high = SpellCheckHighlighter(self.nsr_box.document())
            self.note_high = SpellCheckHighlighter(self.notes_box.document())

        scroll.setWidget(scroll_content)
        input_layout.addWidget(scroll)
        self.preview_pane = QWidget()
        pv = QVBoxLayout(self.preview_pane)
        self.tabs = QTabWidget()
        self.render_view = SpellCheckBrowser()
        self.render_view.setOpenExternalLinks(True)
        self.render_view.setMouseTracking(True)
        self.render_view.viewport().installEventFilter(self)
        self.raw_view = SpellCheckEdit()
        if HAS_ENCHANT: self.raw_high = SpellCheckHighlighter(self.raw_view.document())
        self.render_view.setReadOnly(True)
        self.raw_view.setReadOnly(True)
        self.raw_view.setFont(QFont("Courier", 10))
        self.tabs.addTab(self.render_view, "✨ Rendered")
        self.tabs.addTab(self.raw_view, "📝 Raw MD")
        btn_copy = QPushButton("COPY RAW MARKDOWN")
        btn_copy.setFixedHeight(45)
        btn_copy.setStyleSheet("background: #4CAF50; color: white; font-weight: bold;")
        btn_copy.clicked.connect(self.copy_to_clipboard)
        pv.addWidget(self.tabs)
        pv.addWidget(btn_copy)
        self.work_splitter.addWidget(self.input_container)
        self.work_splitter.addWidget(self.preview_pane)
        self.work_splitter.setStretchFactor(0, 1)
        self.work_splitter.setStretchFactor(1, 1)
        self.main_splitter.addWidget(self.work_splitter)
        self.main_vbox.addWidget(self.main_splitter)
        self.status_bar = QStatusBar()
        self.status_bar.setFixedHeight(22)
        self.main_vbox.addWidget(self.status_bar, 0)
        self.work_splitter.setSizes([775, 775])

        self.add_static_row();
        self.add_dynamic_row()
        self.add_indicator_row(self.bread_container)
        self.add_indicator_row(self.risk_container)
        self.add_uncloak_row()

    def show_gallery_context_menu(self, position):
        item = self.draft_tree.itemAt(position)
        if not item or not item.data(0, Qt.UserRole): return

        rel_path = item.data(0, Qt.UserRole)
        menu = QMenu()
        move_root = menu.addAction("Move to Root")
        move_completed = menu.addAction("Move to Completed")
        move_old = menu.addAction("Move to OldReports")
        menu.addSeparator()
        delete_act = menu.addAction("🗑 Delete File")
        action = menu.exec_(self.draft_tree.viewport().mapToGlobal(position))

        if action == move_root:
            self.move_draft_file(rel_path, "")
        elif action == move_completed:
            self.move_draft_file(rel_path, "Completed")
        elif action == move_old:
            self.move_draft_file(rel_path, "OldReports")
        elif action == delete_act:
            if QMessageBox.question(self, "Delete", f"Delete {rel_path}?") == QMessageBox.Yes:
                os.remove(os.path.join(self.reports_dir, rel_path))
                self.refresh_draft_gallery()

    def move_draft_file(self, rel_path, target_subfolder):
        old_path = os.path.normpath(os.path.join(self.reports_dir, rel_path))
        file_name = os.path.basename(rel_path)
        target_dir = os.path.join(self.reports_dir, target_subfolder)
        if not os.path.exists(target_dir): os.makedirs(target_dir)
        new_path = os.path.normpath(os.path.join(target_dir, file_name))
        if old_path == new_path: return
        try:
            os.rename(old_path, new_path)
            if self.current_file_path and os.path.normpath(self.current_file_path) == old_path:
                self.current_file_path = new_path
            self.status_bar.showMessage(f"Moved to {target_subfolder or 'Root'}", 3000)
            self.refresh_draft_gallery()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Move failed: {e}")

    def eventFilter(self, obj, event):
        if obj == self.render_view.viewport():
            if event.type() == QEvent.MouseMove:
                anchor = self.render_view.anchorAt(event.pos())
                if anchor:
                    self.preview_popup.show_preview(anchor)
                    pos = self.render_view.mapToGlobal(event.pos()) + QPoint(15, 15)
                    self.preview_popup.move(pos)
                    self.preview_popup.show()
                else:
                    self.preview_popup.hide()
            elif event.type() == QEvent.Leave:
                self.preview_popup.hide()
        return super().eventFilter(obj, event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape: self.preview_popup.hide()
        super().keyPressEvent(event)

    def refresh_draft_gallery(self):
        self.draft_tree.clear()
        categories = {
            "": QTreeWidgetItem(self.draft_tree, ["Root"]),
            "Completed": QTreeWidgetItem(self.draft_tree, ["Completed"]),
            "OldReports": QTreeWidgetItem(self.draft_tree, ["OldReports"]),
            "Other": QTreeWidgetItem(self.draft_tree, ["Other Folders"])
        }
        for cat in categories.values():
            cat.setFlags(cat.flags() & ~Qt.ItemIsSelectable)
            cat.setFont(0, QFont("Arial", 10, QFont.Bold))

        file_entries = []
        for root, dirs, files in os.walk(self.reports_dir):
            for file in files:
                if file.endswith(".json"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, self.reports_dir)
                    mtime = os.path.getmtime(full_path)
                    verd = ""
                    try:
                        with open(full_path, 'r', encoding='utf-8') as f:
                            verd = json.load(f).get('verd', '').upper().strip()
                    except:
                        pass
                    dirname = os.path.dirname(rel_path)
                    cat_key = "Other"
                    if dirname == "":
                        cat_key = ""
                    elif "Completed" in rel_path:
                        cat_key = "Completed"
                    elif "OldReports" in rel_path:
                        cat_key = "OldReports"
                    file_entries.append((rel_path, verd, mtime, cat_key))

        file_entries.sort(key=lambda x: x[2], reverse=True)
        for path, v, m, cat_key in file_entries:
            parent = categories[cat_key]
            item = QTreeWidgetItem(parent, [os.path.basename(path)])
            item.setData(0, Qt.UserRole, path)
            if not v:
                item.setBackground(0, QColor("#fbc02d"));
                item.setForeground(0, QColor("black"))
            elif "FP" in v:
                item.setBackground(0, QColor("#2e7d32"))
            elif "TP" in v:
                item.setBackground(0, QColor("#c62828"))
            else:
                item.setBackground(0, QColor("#fbc02d"));
                item.setForeground(0, QColor("black"))
        self.draft_tree.expandAll()

    def toggle_gallery(self):
        v = self.toggle_gallery_btn.isChecked()
        self.gallery_container.setVisible(v)
        if v: self.refresh_draft_gallery(); self.main_splitter.setSizes([300, 1350])

    def load_gallery_item(self, item):
        path = item.data(0, Qt.UserRole)
        if not path: return
        p = os.path.join(self.reports_dir, path)
        self.current_file_path = p
        self.restore_from_file(p)
        self.status_bar.showMessage(f"Loaded: {os.path.basename(path)}", 3000)

    def setup_section(self, title, container, add_func):
        group = QGroupBox(title)
        lay = QVBoxLayout();
        lay.addLayout(container)
        ab = QPushButton(f"+ Add {title}");
        ab.clicked.connect(add_func)
        lay.addWidget(ab);
        group.setLayout(lay)
        self.form_layout.addWidget(group)

    def setup_sub_section(self, title, container, add_func, parent):
        parent.addWidget(QLabel(f"<b>{title}</b>"))
        parent.addLayout(container)
        ab = QPushButton(f"+ Add {title} Point");
        ab.clicked.connect(add_func)
        parent.addWidget(ab)

    def toggle_signals_section(self):
        v = self.signals_toggle_btn.isChecked()
        self.signals_container_widget.setVisible(v)
        self.signals_toggle_btn.setText("🔼 Hide Signals" if v else "🔽 Show App and Dev Signals")

    def open_template_editor(self):
        curr = self.template_combo.currentText()
        if TemplateEditor(self.templates_dir, curr, self).exec_(): self.refresh_templates()

    def md_to_html(self, text):
        lines = text.split('\n');
        out = [];
        in_list = False
        for line in lines:
            line_str = line.strip()
            line = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
            line = re.sub(r'\[ss\]\((https?://\S+?)\)',
                          r'<a href="\1" style="color:#8ab4f8; text-decoration:none;">[ss]</a>', line)
            if line.startswith('## ['):
                line = re.sub(r'## \[(.*?)\]\((.*?)\)',
                              r'<h2 style="border-bottom:1px solid #555; margin:0;"><a href="\2" style="color:#4CAF50; text-decoration:none;">\1</a></h2>',
                              line)
            elif line.startswith('## '):
                line = f'<h2 style="border-bottom:1px solid #555; margin:0;">{line[3:]}</h2>'
            elif line.startswith('### '):
                line = f'<h3 style="color:#8ab4f8; margin:0;">{line[4:]}</h3>'
            if line_str.startswith('* '):
                if not in_list: out.append(
                    '<ul style="margin-left:20px; list-style-type:disc; color:#eee;">'); in_list = True
                content = re.sub(r'\[ss\]\((https?://\S+?)\)',
                                 r'<a href="\1" style="color:#8ab4f8; text-decoration:none;">[ss]</a>', line_str[2:])
                out.append(f'<li>{content}</li>')
            else:
                if in_list: out.append('</ul>'); in_list = False
                out.append(line + '<br>')
        return f"<html><body style='background:#2b2b2b; color:#eee; font-family:Arial, sans-serif; font-size:12px;'>{''.join(out)}</body></html>"

    def process_dynamic_markdown(self, container, is_ind=False):
        lines, pts = [], 0
        for i in range(container.count()):
            w = container.itemAt(i).widget()
            if w and w.layout().itemAt(0).widget().isChecked():
                l_main = w.layout();
                l = l_main.itemAt(1).widget().layout()
                if is_ind:
                    desc, h = l.itemAt(0).widget().text(), l.itemAt(1).layout()
                    u, s, p = h.itemAt(0).widget().text(), h.itemAt(1).widget().text(), h.itemAt(2).widget().text()
                    try:
                        pts += int(p) if p else 0
                    except:
                        pass
                    ss = ' '.join([f'[ss]({v.strip()})' for v in u.split(',') if v.strip().startswith('http')])
                    if desc: lines.append(f"* {desc} **({s})** {ss}")
                else:
                    t, u = l.itemAt(0).widget().text(), l.itemAt(1).widget().text()
                    ss = ' '.join([f'[ss]({v.strip()})' for v in u.split(',') if v.strip().startswith('http')])
                    if t: lines.append(f"* {t} {ss}")
        return "\n".join(lines), pts

    def build_markdown(self):
        sel = self.template_combo.currentText()
        if sel == "None": return f"## [{self.package_name.text()} (Version {self.version_code.text()})]({self.mokka_link.text()})\n\n{self.summary_text.toPlainText()}"
        try:
            with open(os.path.join(self.templates_dir, sel), 'r', encoding='utf-8') as f:
                tpl = f.read()
            s_ana, d_ana, uncl = [self.process_dynamic_markdown(c)[0] for c in
                                  [self.static_analysis_container, self.dynamic_analysis_container,
                                   self.uncloak_steps_container]]
            brd, bp = self.process_dynamic_markdown(self.bread_container, True)
            rsk, rp = self.process_dynamic_markdown(self.risk_container, True)
            nsr_v, hand_v, notes_v = self.nsr_box.toPlainText().strip(), self.hand_box.toPlainText().strip(), (
                self.notes_box.toPlainText().strip() if self.notes_include_chk.isChecked() else "")
            cloak_v, uncloak_v = self.cloaked_url.text().strip(), self.uncloaked_url.text().strip()
            if not nsr_v: tpl = re.sub(r'#+ NSR.*?\{nsr_summary\}', '', tpl, flags=re.DOTALL | re.IGNORECASE)
            if not hand_v or hand_v.lower() == "#nesting": tpl = re.sub(r'#+ Handling.*?\{handling\}', '', tpl,
                                                                        flags=re.DOTALL | re.IGNORECASE)
            if not notes_v: tpl = re.sub(r'#+ Notes.*?\{notes\}', '', tpl, flags=re.DOTALL | re.IGNORECASE)
            if not cloak_v and not uncloak_v: tpl = re.sub(r'\|Cloaked\|Uncloaked\|.*?\{uncloaked_url\}\)', '', tpl,
                                                           flags=re.DOTALL | re.IGNORECASE)
            if not uncl: tpl = re.sub(r'#+ Steps to Uncloak.*?\{uncloak_steps\}', '', tpl,
                                      flags=re.DOTALL | re.IGNORECASE)
            mapping = {"{app_name}": self.app_name.text(), "{package_name}": self.package_name.text(),
                       "{version_code}": self.version_code.text(), "{artifact_id}": self.artifact_id.text(),
                       "{pha_category}": self.pha_category.text(), "{mokka_link}": self.mokka_link.text(),
                       "{buganizer_link}": self.buganizer_link.text(), "{stage_3_link}": self.stage_3_link.text(),
                       "{cloaked_url}": cloak_v, "{uncloaked_url}": uncloak_v, "{uncloak_steps}": uncl,
                       "{notes}": notes_v, "{summary}": self.summary_text.toPlainText(),
                       "{verdict}": self.verdict_input.text(), "{static_analysis_points}": s_ana,
                       "{dynamic_analysis_points}": d_ana, "{bread_points}": f"({bp} pts)\n{brd}",
                       "{risk_points}": f"({rp} pts)\n{rsk}", "{nsr_summary}": nsr_v, "{handling}": hand_v,
                       "{app_permissions}": self.app_permissions.toPlainText(), "{scorers}": self.scorers.toPlainText(),
                       "{acc_status}": self.acc_status.text(), "{total_apps}": self.total_apps.text(),
                       "{total_installs}": self.total_installs.text(), "{app_status}": self.app_status.text(),
                       "{user_feedback}": self.user_feedback.text(), "{app_icon}": self.app_icon.text(),
                       "{app_desc}": self.app_desc.text(), "{main_sites}": self.main_sites.text(),
                       "{priv_sites}": self.priv_sites.text(), "{app_install}": self.app_install_field.text(),
                       "{framework}": self.app_framework.text()}
            for k, v in mapping.items(): tpl = tpl.replace(k, str(v) if v else "")
            return re.sub(r'\n{3,}', '\n\n', tpl).strip()
        except Exception as e:
            return f"Error: {e}"

    def trigger_preview(self):
        self.preview_timer.start(300)

    def update_preview(self):
        rs, raw_s = self.render_view.verticalScrollBar().value(), self.raw_view.verticalScrollBar().value()
        md = self.build_markdown()
        self.raw_view.setPlainText(md);
        self.render_view.setHtml(self.md_to_html(md))
        self.render_view.verticalScrollBar().setValue(rs);
        self.raw_view.verticalScrollBar().setValue(raw_s)

    def refresh_templates(self):
        self.template_combo.clear()
        self.template_combo.addItem("None")
        if os.path.exists(self.templates_dir):
            templates = [f for f in os.listdir(self.templates_dir) if f.endswith(".md")]
            templates.sort(key=lambda x: x.lower())
            self.template_combo.addItems(templates)

    def save_logic(self):
        if self.current_file_path:
            with open(self.current_file_path, 'w', encoding='utf-8') as f:
                json.dump(self.get_form_data(), f, indent=4)
            self.status_bar.showMessage(f"Saved to {self.current_file_path}", 3000);
            self.refresh_draft_gallery()
        else:
            self.save_as_logic()



    def save_as_logic(self):
        # Get metadata values
        app = self.app_name.text().strip().replace(" ", "")
        art = self.artifact_id.text().strip().replace(" ", "")

        # Combine them with an underscore
        combined_name = f"{app}_{art}"

        # Replace spaces and any non-alphanumeric characters (except _ or -) with an underscore
        # This handles symbols like :, /, \, *, ?, ", <, >, | etc.
        sanitized_name = re.sub(r'[^a-zA-Z0-9_-]', '_', combined_name)

        # Collapse multiple underscores into one for a cleaner filename
        sanitized_name = re.sub(r'_+', '_', sanitized_name).strip('_')

        prefill = f"{sanitized_name}.json" if sanitized_name else ""

        p, _ = QFileDialog.getSaveFileName(
            self,
            "Save Draft As",
            os.path.join(self.reports_dir, prefill),
            "JSON (*.json)"
        )
        if p:
            self.current_file_path = p
            self.save_logic()

    def load_from_json(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open Draft", self.reports_dir, "JSON (*.json)")
        if p: self.current_file_path = p; self.restore_from_file(p)

    def get_form_data(self):
        def scan(c, is_ind=False):
            res = []
            for i in range(c.count()):
                w = c.itemAt(i).widget()
                if w:
                    chk = w.layout().itemAt(0).widget().isChecked();
                    l = w.layout().itemAt(1).widget().layout()
                    if is_ind:
                        h = l.itemAt(1).layout()
                        res.append({"inc": chk, "t": l.itemAt(0).widget().text(), "s": h.itemAt(0).widget().text(),
                                    "st": h.itemAt(1).widget().text(), "p": h.itemAt(2).widget().text()})
                    else:
                        res.append({"inc": chk, "t": l.itemAt(0).widget().text(), "s": l.itemAt(1).widget().text()})
            return res

        return {
            "meta": [self.app_name.text(), self.artifact_id.text(), self.package_name.text(), self.pha_category.text(),
                     self.version_code.text(), self.mokka_link.text(), self.buganizer_link.text(),
                     self.stage_3_link.text()],
            "cloak": [self.cloaked_url.text(), self.uncloaked_url.text()],
            "signals": [self.app_permissions.toPlainText(), self.scorers.toPlainText()],
            "play": [self.acc_status.text(), self.total_apps.text(), self.total_installs.text(), self.app_status.text(),
                     self.user_feedback.text(), self.app_icon.text(), self.app_desc.text(), self.main_sites.text(),
                     self.priv_sites.text(), self.app_install_field.text(), self.app_framework.text()],
            "sum": self.summary_text.toPlainText(), "verd": self.verdict_input.text(),
            "notes": self.notes_box.toPlainText(), "notes_inc": self.notes_include_chk.isChecked(),
            "nsr": self.nsr_box.toPlainText(), "hand": self.hand_box.toPlainText(),
            "s_ana": scan(self.static_analysis_container), "d_ana": scan(self.dynamic_analysis_container),
            "brd": scan(self.bread_container, True), "rsk": scan(self.risk_container, True),
            "uncl": scan(self.uncloak_steps_container)}

    def restore_from_file(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            m = data.get('meta', []);
            f_m = [self.app_name, self.artifact_id, self.package_name, self.pha_category, self.version_code,
                   self.mokka_link, self.buganizer_link, self.stage_3_link]
            for i, fl in enumerate(f_m): (fl.setText(m[i]) if i < len(m) else None)
            c = data.get('cloak', ["", ""]);
            self.cloaked_url.setText(c[0]);
            self.uncloaked_url.setText(c[1])
            s = data.get('signals', ["", ""]);
            self.app_permissions.setPlainText(s[0]);
            self.scorers.setPlainText(s[1])
            p = data.get('play', [""] * 11);
            pl_f = [self.acc_status, self.total_apps, self.total_installs, self.app_status, self.user_feedback,
                    self.app_icon, self.app_desc, self.main_sites, self.priv_sites, self.app_install_field,
                    self.app_framework]
            for i, fl in enumerate(pl_f): (fl.setText(p[i]) if i < len(p) else None)
            self.summary_text.setPlainText(data.get('sum', ''));
            self.verdict_input.setText(data.get('verd', ''))
            self.notes_box.setPlainText(data.get('notes', ''));
            self.notes_include_chk.setChecked(data.get('notes_inc', False))
            self.nsr_box.setPlainText(data.get('nsr', ''));
            self.hand_box.setPlainText(data.get('hand', ''))
            map_c = [(self.static_analysis_container, 's_ana', self.add_static_row),
                     (self.dynamic_analysis_container, 'd_ana', self.add_dynamic_row),
                     (self.bread_container, 'brd', self.add_indicator_row),
                     (self.risk_container, 'rsk', self.add_indicator_row),
                     (self.uncloak_steps_container, 'uncl', self.add_uncloak_row)]
            for c, k, func in map_c:
                for i in reversed(range(c.count())): (
                    c.itemAt(i).widget().setParent(None) if c.itemAt(i).widget() else None)
                for rd in data.get(k, []): (func(rd) if 'ana' in k or k == 'uncl' else func(c, rd))
            self.trigger_preview()
        except:
            pass

    def export_report(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export MD", self.reports_dir, "Markdown (*.md)")
        if p: open(p, 'w', encoding='utf-8').write(self.build_markdown())

    # ADDED: Export HTML logic
    def export_html_report(self):
        p, _ = QFileDialog.getSaveFileName(self, "Export HTML", self.reports_dir, "HTML (*.html)")
        if p:
            md = self.build_markdown()
            html = self.md_to_html(md)
            with open(p, 'w', encoding='utf-8') as f:
                f.write(html)
            self.status_bar.showMessage(f"HTML Exported: {os.path.basename(p)}", 3000)

    def confirm_new_review(self):
        if QMessageBox.question(self, 'New', "Clear all data?") == QMessageBox.Yes:
            self.current_file_path = None
            for w in self.findChildren(QLineEdit): w.clear()
            for w in self.findChildren(QTextEdit): w.clear()
            self.pha_category.setText("warn_toll_fraud");
            self.hand_box.setPlainText("#nesting");
            self.notes_include_chk.setChecked(False)
            for c in [self.static_analysis_container, self.dynamic_analysis_container, self.bread_container,
                      self.risk_container, self.uncloak_steps_container]:
                for i in reversed(range(c.count())): (
                    c.itemAt(i).widget().setParent(None) if c.itemAt(i).widget() else None)
            self.add_static_row();
            self.add_dynamic_row();
            self.add_uncloak_row()

    def copy_to_clipboard(self):
        QApplication.clipboard().setText(self.build_markdown())
        self.status_bar.showMessage("Copied!", 2000)

    def _move_row(self, container, widget, delta):
        idx = container.indexOf(widget)
        new_idx = idx + delta
        if 0 <= new_idx < container.count():
            container.insertWidget(new_idx, widget);
            self.trigger_preview()

    def add_static_row(self, d=None):
        self._add_ana(self.static_analysis_container, d)

    def add_dynamic_row(self, d=None):
        self._add_ana(self.dynamic_analysis_container, d)

    def add_uncloak_row(self, d=None):
        self._add_ana(self.uncloak_steps_container, d)

    def _add_ana(self, c, d):
        f = QFrame();
        o = QHBoxLayout(f);
        cw = QWidget();
        l = QVBoxLayout(cw)
        t, s = QLineEdit(), QLineEdit()
        t.setPlaceholderText("Finding...");
        s.setPlaceholderText("SS URLs")
        t.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed);
        s.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if d: t.setText(d.get('t', '')); s.setText(d.get('s', ''))
        t.textChanged.connect(self.trigger_preview);
        s.textChanged.connect(self.trigger_preview)
        l.addWidget(t);
        l.addWidget(s)
        chk = QCheckBox();
        chk.setChecked(d.get('inc', True) if d else True);
        chk.stateChanged.connect(self.trigger_preview)
        up_b = QPushButton("↑");
        up_b.setFixedWidth(25);
        up_b.clicked.connect(lambda: self._move_row(c, f, -1))
        dn_b = QPushButton("↓");
        dn_b.setFixedWidth(25);
        dn_b.clicked.connect(lambda: self._move_row(c, f, 1))
        db = QPushButton("🗑️");
        db.setFixedWidth(30);
        db.clicked.connect(lambda: f.deleteLater() or self.trigger_preview())
        o.addWidget(chk);
        o.addWidget(cw);
        o.addWidget(up_b);
        o.addWidget(dn_b);
        o.addWidget(db);
        c.addWidget(f);
        self.trigger_preview()

    def add_indicator_row(self, c, d=None):
        f = QFrame();
        o = QHBoxLayout(f);
        cw = QWidget();
        l = QVBoxLayout(cw)
        t, h = QLineEdit(), QHBoxLayout()
        ss, st, p = QLineEdit(), QLineEdit(), QLineEdit();
        p.setFixedWidth(40)
        t.setPlaceholderText("Signal...");
        t.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        ss.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed);
        st.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if d: t.setText(d.get('t', '')); ss.setText(d.get('s', '')); st.setText(d.get('st', '')); p.setText(
            d.get('p', ''))
        for w in [t, ss, st, p]: w.textChanged.connect(self.trigger_preview)
        h.addWidget(ss);
        h.addWidget(st);
        h.addWidget(p);
        l.addWidget(t);
        l.addLayout(h)
        chk = QCheckBox();
        chk.setChecked(d.get('inc', True) if d else True);
        chk.stateChanged.connect(self.trigger_preview)
        up_b = QPushButton("↑");
        up_b.setFixedWidth(25);
        up_b.clicked.connect(lambda: self._move_row(c, f, -1))
        dn_b = QPushButton("↓");
        dn_b.setFixedWidth(25);
        dn_b.clicked.connect(lambda: self._move_row(c, f, 1))
        db = QPushButton("🗑️");
        db.setFixedWidth(30);
        db.clicked.connect(lambda: f.deleteLater() or self.trigger_preview())
        o.addWidget(chk);
        o.addWidget(cw);
        o.addWidget(up_b);
        o.addWidget(dn_b);
        o.addWidget(db);
        c.addWidget(f);
        self.trigger_preview()

# --- FORENSICS MASTER APPLICATION ---

class Forensics(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ultimate Forensics Toolbox V1.11 - Jason Peixoto.")
        self.resize(1750, 1000)
        self.setStyle(DepressStyle())
        self.setStyleSheet(self.get_theme())

        self.current_file_path, self.captured_images, self.current_image_index = None, [], -1
        self.log_paused, self.frida_paused, self.current_remote_dir, self.worker = False, False, "/", None
        self.frida_log_entries = []  # Buffered tuples: (level, message). Used by Frida log filters/search.
        self.frida_log_max_entries = 5000
        self.path_history = ["/", "/sdcard", "/sdcard/Download", "/data/local/tmp"]

        if not os.path.exists(FRIDA_TEMPLATE_FILE):
            default_template = """Java.perform(function () {
    console.log('
[+] [FRIDA ENGINE] Java Property Proxy Hook Active!');
    console.log('[+] Target Tunnel Pipeline Route: {protocol}://{ip}:{port}
');

    var System = Java.use('java.lang.System');
    var proxy_host = "{ip}";
    var proxy_port = "{port}";
    var proxy_type = String("{protocol}" || "http").toLowerCase().trim();
    var is_socks = (proxy_type === "socks" || proxy_type === "socks4" || proxy_type === "socks5");

    console.log("[+] Proxy type detected: " + proxy_type + " | socks=" + is_socks);

    function hostProp(prop) { return is_socks ? prop === "socksProxyHost" : (prop === "http.proxyHost" || prop === "https.proxyHost"); }
    function portProp(prop) { return is_socks ? prop === "socksProxyPort" : (prop === "http.proxyPort" || prop === "https.proxyPort"); }

    System.getProperty.overload('java.lang.String').implementation = function (prop) {
        prop = String(prop);
        if (hostProp(prop)) { console.log('[~] Intercepted getProperty(' + prop + ') -> ' + proxy_host); return proxy_host; }
        if (portProp(prop)) { console.log('[~] Intercepted getProperty(' + prop + ') -> ' + proxy_port); return proxy_port; }
        return this.getProperty(prop);
    };

    try {
        if (is_socks) {
            System.setProperty("socksProxyHost", proxy_host);
            System.setProperty("socksProxyPort", proxy_port);
            System.clearProperty("http.proxyHost");
            System.clearProperty("http.proxyPort");
            System.clearProperty("https.proxyHost");
            System.clearProperty("https.proxyPort");
        } else {
            System.setProperty("http.proxyHost", proxy_host);
            System.setProperty("http.proxyPort", proxy_port);
            System.setProperty("https.proxyHost", proxy_host);
            System.setProperty("https.proxyPort", proxy_port);
            System.clearProperty("socksProxyHost");
            System.clearProperty("socksProxyPort");
        }
    } catch (e) { console.log("[!] Failed to seed Java proxy properties: " + e); }

    console.log("[+] Java property proxy hook is installed.");
});
"""
            with open(FRIDA_TEMPLATE_FILE, 'w', encoding="utf-8") as f: f.write(default_template)

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

        self.tabs = SideNavigationTabs()
        # Left-side navigation uses a real list menu so labels stay horizontal.
        self.setCentralWidget(self.tabs)

        self.setup_device_status_tab()
        self.setup_processes_tab()
        self.setup_frida_manager_tab()
        self.setup_frida_logs_tab()
        self.setup_logcat_tab()
        self.setup_file_explorer_tab()
        self.setup_gallery_tab()
        self.setup_proxy_tab()
        self.setup_network_tab()
        self.setup_adb_tab()
        self.setup_remote_tab()
        self.setup_console_tab()
        self.setup_future_disabled_tools()
        self.setup_settings_tab()
        self.setup_navigation_hotkeys()
        if hasattr(self.tabs, "ensure_settings_label_visible"):
            self.tabs.ensure_settings_label_visible()

        self.load_settings()
        if hasattr(self.tabs, "ensure_settings_label_visible"):
            self.tabs.ensure_settings_label_visible()
        self.load_image_history()
        self.update_viewer_ui()
        self.start_logcat_stream()
        self.load_manual_proxies_to_ui()
        QTimer.singleShot(800, self.refresh_device_status)

    def setup_navigation_hotkeys(self):
        """Quick jump shortcuts for the left navigation menu."""
        if not hasattr(self, "tabs"):
            return
        for index in range(min(self.tabs.count(), 19)):
            if index < 9:
                shortcut = f"Ctrl+{index + 1}"
            elif index == 9:
                shortcut = "Ctrl+0"
            else:
                shortcut = f"Ctrl+Shift+{index - 9}"
            action = QAction(self)
            action.setShortcut(shortcut)
            action.triggered.connect(lambda checked=False, i=index: self.tabs.setCurrentIndex(i))
            self.addAction(action)

    def switch_to_tab_containing(self, title_text):
        if hasattr(self.tabs, "indexOfTitleContains"):
            idx = self.tabs.indexOfTitleContains(title_text)
            if idx >= 0:
                self.tabs.setCurrentIndex(idx)
                return True
        return False

    def go_to_page_title(self, title_text):
        # Backward-compatible alias used by newer workspace actions/snippets.
        return self.switch_to_tab_containing(title_text)

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
                  QTabBar::tab:west { min-width: 155px; min-height: 34px; padding: 8px 12px; text-align: left; }
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
        out_raw = self.adb_process.readAllStandardOutput().data().decode("utf-8", errors="replace");
        err_raw = self.adb_process.readAllStandardError().data().decode("utf-8", errors="replace")
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


    def setup_device_status_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        summary_box = QGroupBox("Device / Frida Health Check")
        summary_layout = QVBoxLayout(summary_box)

        top_row = QHBoxLayout()
        btn_refresh = QPushButton("🔄 Refresh Status")
        btn_refresh.setObjectName("runBtn")
        btn_refresh.clicked.connect(self.refresh_device_status)

        btn_copy = QPushButton("📋 Copy Report")
        btn_copy.clicked.connect(self.copy_device_status_report)

        btn_versions = QPushButton("🧪 Frida Versions")
        btn_versions.clicked.connect(self.show_frida_versions)

        btn_start = QPushButton("🚀 Start Frida Server")
        btn_start.setObjectName("runBtn")
        btn_start.clicked.connect(self.start_frida_server)

        btn_stop = QPushButton("🛑 Stop Frida Server")
        btn_stop.setObjectName("killBtn")
        btn_stop.clicked.connect(self.stop_frida_server)

        btn_clear_proxy = QPushButton("🧹 Clear Android Proxy")
        btn_clear_proxy.clicked.connect(self.clear_android_proxy_from_status)

        self.chk_device_status_auto = QCheckBox("Auto refresh")
        self.chk_device_status_auto.setStyleSheet("color: white;")
        self.chk_device_status_auto.toggled.connect(self.toggle_device_status_autorefresh)

        self.device_status_interval_spin = QSpinBox()
        self.device_status_interval_spin.setRange(5, 300)
        self.device_status_interval_spin.setValue(30)
        self.device_status_interval_spin.setSuffix(" sec")
        self.device_status_interval_spin.valueChanged.connect(self.update_device_status_timer_interval)

        top_row.addWidget(btn_refresh)
        top_row.addWidget(btn_copy)
        top_row.addWidget(btn_versions)
        top_row.addSpacing(16)
        top_row.addWidget(btn_start)
        top_row.addWidget(btn_stop)
        top_row.addWidget(btn_clear_proxy)
        top_row.addStretch(1)
        top_row.addWidget(self.chk_device_status_auto)
        top_row.addWidget(self.device_status_interval_spin)
        summary_layout.addLayout(top_row)

        self.device_status_banner = QLabel("Status has not been refreshed yet.")
        self.device_status_banner.setStyleSheet("color: #8b949e; padding: 6px;")
        summary_layout.addWidget(self.device_status_banner)

        self.device_status_table = QTableWidget(0, 4)
        self.device_status_table.setHorizontalHeaderLabels(["Check", "State", "Details", "Time"])
        self.device_status_table.verticalHeader().setVisible(False)
        self.device_status_table.setAlternatingRowColors(True)
        self.device_status_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_status_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.device_status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.device_status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.device_status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.device_status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        summary_layout.addWidget(self.device_status_table, 1)

        layout.addWidget(summary_box, 3)

        log_box = QGroupBox("Health Check Log")
        log_layout = QVBoxLayout(log_box)
        self.device_status_log = QTextEdit()
        self.device_status_log.setReadOnly(True)
        self.device_status_log.setFont(QFont("Monospace", 10))
        self.device_status_log.setStyleSheet("background: #010409; color: #d1d5da;")
        log_layout.addWidget(self.device_status_log)
        layout.addWidget(log_box, 1)

        self.device_status_records = []
        self.device_status_timer = QTimer(self)
        self.device_status_timer.timeout.connect(self.refresh_device_status)

        self.tabs.addTab(tab, "🩺 Device Status")

    def refresh_device_status(self):
        if hasattr(self, "device_status_worker") and self.device_status_worker.isRunning():
            self.append_device_status_log("Refresh already running; ignoring duplicate request.", "#ffa657")
            return

        self.device_status_records = []
        self.device_status_table.setRowCount(0)
        self.device_status_banner.setText("Refreshing device status...")
        self.device_status_banner.setStyleSheet("color: #58a6ff; padding: 6px;")

        target_pkg = ""
        try:
            if hasattr(self, "target_pkg"):
                target_pkg = self.target_pkg.currentText().strip()
            if not target_pkg and hasattr(self, "app_selector"):
                target_pkg = self.app_selector.currentText().strip()
        except Exception:
            target_pkg = ""

        cli_path = FRIDA_CLI_PATH
        try:
            if hasattr(self, "frida_cli_path"):
                cli_path = self.frida_cli_path.text().strip() or FRIDA_CLI_PATH
        except Exception:
            pass

        self.device_status_worker = DeviceStatusWorker(target_pkg=target_pkg, frida_cli_path=cli_path)
        self.device_status_worker.row_signal.connect(self.add_device_status_row)
        self.device_status_worker.log_signal.connect(self.append_device_status_log)
        self.device_status_worker.done_signal.connect(self.device_status_refresh_done)
        self.device_status_worker.start()

    def add_device_status_row(self, check, state, detail, color):
        ts = time.strftime("%H:%M:%S")
        self.device_status_records.append((check, state, detail, ts))

        row = self.device_status_table.rowCount()
        self.device_status_table.insertRow(row)
        values = [check, state, detail, ts]
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setForeground(QColor(color))
            if col in (0, 1):
                item.setFont(QFont("Arial", weight=QFont.Bold))
            self.device_status_table.setItem(row, col, item)
        self.device_status_table.scrollToBottom()

    def append_device_status_log(self, message, color="#c9d1d9"):
        safe_message = html.escape(str(message), quote=False)
        line = f"<font color='{color}'>[{time.strftime('%H:%M:%S')}] {safe_message}</font>"
        try:
            self.device_status_log.append(line)
            self.device_status_log.moveCursor(QTextCursor.End)
        except Exception:
            pass

    def device_status_refresh_done(self):
        ok_count = sum(1 for _, state, _, _ in getattr(self, "device_status_records", []) if str(state).upper() == "OK")
        warn_count = sum(1 for _, state, _, _ in getattr(self, "device_status_records", []) if str(state).upper() == "WARN")
        fail_count = sum(1 for _, state, _, _ in getattr(self, "device_status_records", []) if str(state).upper() == "FAIL")
        info_count = sum(1 for _, state, _, _ in getattr(self, "device_status_records", []) if str(state).upper() == "INFO")

        if fail_count:
            color = "#ff7b72"
        elif warn_count:
            color = "#ffa657"
        else:
            color = "#7ee787"

        self.device_status_banner.setText(f"Last refresh complete: OK={ok_count}, WARN={warn_count}, FAIL={fail_count}, INFO={info_count}")
        self.device_status_banner.setStyleSheet(f"color: {color}; padding: 6px;")

    def toggle_device_status_autorefresh(self, enabled):
        if enabled:
            self.device_status_timer.start(self.device_status_interval_spin.value() * 1000)
            self.append_device_status_log("Auto refresh enabled.", "#58a6ff")
        else:
            self.device_status_timer.stop()
            self.append_device_status_log("Auto refresh disabled.", "#8b949e")

    def update_device_status_timer_interval(self):
        if hasattr(self, "device_status_timer") and self.device_status_timer.isActive():
            self.device_status_timer.start(self.device_status_interval_spin.value() * 1000)

    def copy_device_status_report(self):
        records = getattr(self, "device_status_records", [])
        if not records:
            QApplication.clipboard().setText("No device status report available yet.")
            return
        lines = ["Ultimate Forensics Toolbox Device Status Report", time.strftime("Generated: %Y-%m-%d %H:%M:%S"), ""]
        for check, state, detail, ts in records:
            lines.append(f"[{ts}] {check}: {state} - {detail}")
        QApplication.clipboard().setText("\n".join(lines))
        self.append_device_status_log("Copied device status report to clipboard.", "#7ee787")

    def clear_android_proxy_from_status(self):
        self.append_device_status_log("Clearing Android global http_proxy...", "#58a6ff")
        self.run_adb_cmd(f"{ADB_PATH} shell settings put global http_proxy :0")
        QTimer.singleShot(700, lambda: self.run_adb_cmd(f"{ADB_PATH} shell settings delete global http_proxy"))
        QTimer.singleShot(1500, self.refresh_device_status)

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
        self.frida_manager_splitter = QSplitter(Qt.Horizontal)
        self.frida_manager_splitter.setChildrenCollapsible(False)
        self.frida_manager_splitter.setHandleWidth(7)
        layout.addWidget(self.frida_manager_splitter)
        self.f_model = QFileSystemModel();
        self.f_model.setRootPath(FRIDA_SCRIPTS_DIR);
        self.f_model.setReadOnly(False)
        # Keep the Frida Manager isolated to ~/.jpeixoto/UltimateForensicsToolbox/FridaScripts.
        # This shows folders plus JavaScript files only; other toolbox folders/files stay hidden.
        self.f_model.setFilter(QDir.AllDirs | QDir.NoDotAndDotDot | QDir.Files)
        self.f_model.setNameFilters(["*.js"]);
        self.f_model.setNameFilterDisables(False)
        self.f_tree = QTreeView();
        self.f_tree.setModel(self.f_model);
        self.f_tree.setRootIndex(self.f_model.index(FRIDA_SCRIPTS_DIR))
        self.f_tree.setHeaderHidden(False);
        self.f_tree.header().setSectionResizeMode(0, QHeaderView.Interactive)
        self.f_tree.setMinimumWidth(420)
        try:
            self.f_tree.setColumnWidth(0, 420)
        except Exception:
            pass
        for i in range(1, 4): self.f_tree.setColumnHidden(i, True)
        self.f_tree.clicked.connect(self.on_file_clicked);
        self.f_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.f_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        self.frida_manager_splitter.addWidget(self.f_tree)

        self.frida_editor_panel = QWidget()
        r_box = QVBoxLayout(self.frida_editor_panel);
        tools = QHBoxLayout()
        btn_new_script = QPushButton("📄 New Script")
        btn_new_script.setToolTip("Create a new unsaved Frida script. Use Save or Save As when ready.")
        btn_new_script.clicked.connect(self.create_new_script)
        btn_proj = QPushButton("📁 Folder");
        btn_proj.clicked.connect(self.create_new_project)
        btn_s = QPushButton("💾 Save");
        btn_s.clicked.connect(self.save_script)
        btn_save_as = QPushButton("💾 Save As");
        btn_save_as.clicked.connect(self.save_script_as)
        btn_reload = QPushButton("↻ Reload");
        btn_reload.clicked.connect(self.reload_current_script)
        btn_b = QPushButton("✨ Beautify");
        btn_b.clicked.connect(self.beautify_code)
        btn_validate = QPushButton("✅ Validate")
        btn_validate.setToolTip("Check JavaScript syntax, Frida 17 compatibility, and Python API compile/bundle issues before injection — Cmd/Ctrl+Shift+K")
        btn_validate.clicked.connect(self.validate_current_script)
        btn_snippets = QPushButton("🧩 Snippets")
        btn_snippets.setToolTip("Insert common Frida hook templates at the cursor")
        btn_snippets.clicked.connect(self.show_frida_snippet_menu)

        self.editor_font_spin = QSpinBox()
        self.editor_font_spin.setRange(8, 40)
        self.editor_font_spin.setValue(12)
        self.editor_font_spin.setSuffix(" pt")
        self.editor_font_spin.setToolTip("Editor font size. You can also use Cmd/Ctrl + mouse wheel or trackpad pinch.")

        btn_font_down = QPushButton("A−")
        btn_font_down.setToolTip("Decrease editor font size — Cmd/Ctrl -")
        btn_font_down.clicked.connect(self.editor_zoom_out)

        btn_font_up = QPushButton("A+")
        btn_font_up.setToolTip("Increase editor font size — Cmd/Ctrl +")
        btn_font_up.clicked.connect(self.editor_zoom_in)

        btn_font_reset = QPushButton("A0")
        btn_font_reset.setToolTip("Reset editor font size — Cmd/Ctrl 0")
        btn_font_reset.clicked.connect(self.editor_zoom_reset)
        btn_editor_text_settings = QPushButton("⚙")
        btn_editor_text_settings.setFixedWidth(38)
        btn_editor_text_settings.setToolTip("Frida editor text/font settings")
        btn_editor_text_settings.clicked.connect(lambda: self.show_text_settings_dialog("editor"))

        tools.addWidget(btn_new_script);
        tools.addWidget(btn_proj);
        tools.addWidget(btn_s);
        tools.addWidget(btn_save_as);
        tools.addWidget(btn_reload);
        tools.addWidget(btn_b);
        tools.addWidget(btn_validate);
        tools.addWidget(btn_snippets);
        tools.addStretch()
        tools.addWidget(btn_editor_text_settings)
        r_box.addLayout(tools)

        editor_search_row = QHBoxLayout()
        self.editor_find_input = QLineEdit()
        self.editor_find_input.setPlaceholderText("Find in script...  Ctrl+F")
        self.editor_find_input.textChanged.connect(lambda _=None: self.refresh_editor_search_highlights(reset=True))
        self.editor_replace_input = QLineEdit()
        self.editor_replace_input.setPlaceholderText("Replace with...  Ctrl+H")
        self.editor_case_chk = QCheckBox("Case")
        self.editor_regex_chk = QCheckBox("Regex")
        self.editor_word_chk = QCheckBox("Whole word")
        self.editor_highlight_chk = QCheckBox("Highlight all")
        self.editor_highlight_chk.setChecked(True)
        for chk in [self.editor_case_chk, self.editor_regex_chk, self.editor_word_chk, self.editor_highlight_chk]:
            chk.setStyleSheet("color: #c9d1d9;")
            chk.toggled.connect(lambda _=None: self.refresh_editor_search_highlights(reset=True))

        btn_find_prev = QPushButton("↑ Prev")
        btn_find_prev.clicked.connect(lambda: self.editor_find_next(backward=True))
        btn_find_next = QPushButton("↓ Next")
        btn_find_next.clicked.connect(lambda: self.editor_find_next(backward=False))
        btn_replace = QPushButton("Replace")
        btn_replace.clicked.connect(self.editor_replace_one)
        btn_replace_all = QPushButton("Replace All")
        btn_replace_all.clicked.connect(self.editor_replace_all)
        btn_go_line = QPushButton("Go Line")
        btn_go_line.clicked.connect(self.editor_go_to_line)

        editor_search_row.addWidget(QLabel("Find:"))
        editor_search_row.addWidget(self.editor_find_input, 2)
        editor_search_row.addWidget(QLabel("Replace:"))
        editor_search_row.addWidget(self.editor_replace_input, 2)
        editor_search_row.addWidget(btn_find_prev)
        editor_search_row.addWidget(btn_find_next)
        editor_search_row.addWidget(btn_replace)
        editor_search_row.addWidget(btn_replace_all)
        editor_search_row.addWidget(btn_go_line)
        editor_search_row.addWidget(self.editor_case_chk)
        editor_search_row.addWidget(self.editor_regex_chk)
        editor_search_row.addWidget(self.editor_word_chk)
        editor_search_row.addWidget(self.editor_highlight_chk)
        r_box.addLayout(editor_search_row)

        self.editor = FridaScriptEditor();
        self.editor.set_script_font_size(self.editor_font_spin.value(), emit_signal=False)
        self.editor.fontSizeChanged.connect(self.on_editor_font_size_changed)
        self.editor_font_spin.valueChanged.connect(self.on_editor_font_spin_changed)
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.editor.cursorPositionChanged.connect(self.update_editor_status)
        self.editor.textChanged.connect(lambda: self.refresh_editor_search_highlights(reset=False, quiet=True))
        self.editor.document().modificationChanged.connect(lambda _=None: self.update_editor_status())
        self.highlighter = JSHighlighter(self.editor.document());
        r_box.addWidget(self.editor)

        self.editor_status = QLabel("Line 1, Col 1 | Ready")
        self.editor_status.setStyleSheet("color: #8b949e; padding: 3px;")
        r_box.addWidget(self.editor_status)
        self.setup_frida_editor_shortcuts()

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
        self.frida_manager_splitter.addWidget(self.frida_editor_panel)
        self.frida_manager_splitter.setStretchFactor(0, 0)
        self.frida_manager_splitter.setStretchFactor(1, 1)
        self.frida_manager_splitter.setSizes([420, 1100])
        self.frida_manager_splitter.splitterMoved.connect(lambda _pos, _idx: self.on_frida_manager_splitter_moved())
        QTimer.singleShot(0, lambda: self.apply_frida_tree_width(getattr(self, '_pending_frida_tree_width', 420)))
        self.frida_manager_tab = tab
        self.tabs.addTab(tab, "🛠️ Frida Manager")

    def frida_tree_width(self):
        try:
            if hasattr(self, 'frida_manager_splitter'):
                sizes = self.frida_manager_splitter.sizes()
                if sizes:
                    return max(220, int(sizes[0]))
        except Exception:
            pass
        return int(getattr(self, '_pending_frida_tree_width', 420))

    def apply_frida_tree_width(self, width):
        try:
            width = max(220, min(900, int(width)))
        except Exception:
            width = 420
        self._pending_frida_tree_width = width
        try:
            if hasattr(self, 'frida_manager_splitter'):
                total = max(sum(self.frida_manager_splitter.sizes()) or self.width() or 1500, width + 600)
                self.frida_manager_splitter.setSizes([width, max(600, total - width)])
            if hasattr(self, 'f_tree'):
                self.f_tree.setMinimumWidth(220)
                self.f_tree.setColumnWidth(0, max(200, width - 30))
        except Exception:
            pass

    def on_frida_manager_splitter_moved(self):
        try:
            width = self.frida_tree_width()
            self._pending_frida_tree_width = width
            if hasattr(self, 'f_tree'):
                self.f_tree.setColumnWidth(0, max(200, width - 30))
            QTimer.singleShot(300, self.save_settings)
        except Exception:
            pass

    def setup_frida_editor_shortcuts(self):
        shortcuts = [
            ("Ctrl+F", lambda: self.editor_find_input.setFocus() if hasattr(self, "editor_find_input") else None),
            ("Ctrl+H", lambda: self.editor_replace_input.setFocus() if hasattr(self, "editor_replace_input") else None),
            ("F3", lambda: self.editor_find_next(backward=False)),
            ("Shift+F3", lambda: self.editor_find_next(backward=True)),
            ("Ctrl+G", self.editor_go_to_line),
            ("Ctrl+S", self.save_script),
            ("Ctrl+Shift+K", self.validate_current_script),
            ("Meta+Shift+K", self.validate_current_script),
            ("Ctrl++", self.editor_zoom_in),
            ("Ctrl+=", self.editor_zoom_in),
            ("Ctrl+-", self.editor_zoom_out),
            ("Ctrl+0", self.editor_zoom_reset),
            ("Meta++", self.editor_zoom_in),
            ("Meta+=", self.editor_zoom_in),
            ("Meta+-", self.editor_zoom_out),
            ("Meta+0", self.editor_zoom_reset),
        ]
        for key, callback in shortcuts:
            action = QAction(self)
            action.setShortcut(key)
            action.triggered.connect(callback)
            self.addAction(action)

    def on_editor_font_spin_changed(self, size):
        if hasattr(self, "editor"):
            self.editor.set_script_font_size(size)
        self.save_settings()
        self.update_editor_status()

    def on_editor_font_size_changed(self, size):
        if hasattr(self, "editor_font_spin") and self.editor_font_spin.value() != size:
            self.editor_font_spin.blockSignals(True)
            self.editor_font_spin.setValue(size)
            self.editor_font_spin.blockSignals(False)
        self.save_settings()
        self.update_editor_status()

    def editor_zoom_in(self):
        if hasattr(self, "editor"):
            self.editor.zoom_in_font()

    def editor_zoom_out(self):
        if hasattr(self, "editor"):
            self.editor.zoom_out_font()

    def editor_zoom_reset(self):
        if hasattr(self, "editor"):
            self.editor.reset_font_zoom()

    def show_text_settings_dialog(self, view_name):
        """Compact gear-popup for editor/log text settings so top toolbars stay narrow."""
        configs = {
            "editor": {
                "title": "Frida Editor Text Settings",
                "spin_attr": "editor_font_spin",
                "current": lambda: self.editor.current_font_size() if hasattr(self, "editor") else 12,
                "set": lambda value: self.editor.set_script_font_size(value) if hasattr(self, "editor") else None,
                "minus": self.editor_zoom_out,
                "plus": self.editor_zoom_in,
                "reset": self.editor_zoom_reset,
            },
            "frida": {
                "title": "Frida Log Text Settings",
                "spin_attr": "frida_log_font_spin",
                "current": lambda: self.frida_display.current_font_size() if hasattr(self, "frida_display") else 10,
                "set": lambda value: self.set_log_view_font_size("frida", value),
                "minus": lambda: self.frida_display.zoom_out_font() if hasattr(self, "frida_display") else None,
                "plus": lambda: self.frida_display.zoom_in_font() if hasattr(self, "frida_display") else None,
                "reset": lambda: self.frida_display.reset_font_zoom() if hasattr(self, "frida_display") else None,
            },
            "logcat": {
                "title": "LogCat Text Settings",
                "spin_attr": "logcat_font_spin",
                "current": lambda: self.log_display.current_font_size() if hasattr(self, "log_display") else 10,
                "set": lambda value: self.set_log_view_font_size("logcat", value),
                "minus": lambda: self.log_display.zoom_out_font() if hasattr(self, "log_display") else None,
                "plus": lambda: self.log_display.zoom_in_font() if hasattr(self, "log_display") else None,
                "reset": lambda: self.log_display.reset_font_zoom() if hasattr(self, "log_display") else None,
            },
            "adb_console": {
                "title": "ADB Console Text Settings",
                "spin_attr": "adb_console_font_spin",
                "current": lambda: self.console.current_font_size() if hasattr(self, "console") else 10,
                "set": lambda value: self.set_log_view_font_size("adb_console", value),
                "minus": lambda: self.console.zoom_out_font() if hasattr(self, "console") else None,
                "plus": lambda: self.console.zoom_in_font() if hasattr(self, "console") else None,
                "reset": lambda: self.console.reset_font_zoom() if hasattr(self, "console") else None,
            },
        }
        cfg = configs.get(view_name)
        if not cfg:
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(cfg["title"])
        dlg.resize(360, 140)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel(cfg["title"]))

        row = QHBoxLayout()
        btn_minus = QPushButton("A−")
        btn_plus = QPushButton("A+")
        btn_reset = QPushButton("A0")
        local_spin = QSpinBox()
        local_spin.setRange(8, 40)
        try:
            current_size = int(cfg["current"]())
        except Exception:
            current_size = 10
        local_spin.setValue(current_size)
        local_spin.setSuffix(" pt")

        def apply_size(value):
            try:
                value = int(value)
                cfg["set"](value)
                master = getattr(self, cfg["spin_attr"], None)
                if master and master.value() != value:
                    master.blockSignals(True)
                    master.setValue(value)
                    master.blockSignals(False)
                self.save_settings()
            except Exception:
                pass

        def sync_after(fn):
            try:
                fn()
            finally:
                try:
                    local_spin.setValue(int(cfg["current"]()))
                except Exception:
                    pass

        btn_minus.clicked.connect(lambda: sync_after(cfg["minus"]))
        btn_plus.clicked.connect(lambda: sync_after(cfg["plus"]))
        btn_reset.clicked.connect(lambda: sync_after(cfg["reset"]))
        local_spin.valueChanged.connect(apply_size)

        row.addWidget(QLabel("Font:"))
        row.addWidget(btn_minus)
        row.addWidget(local_spin)
        row.addWidget(btn_plus)
        row.addWidget(btn_reset)
        layout.addLayout(row)

        hint = QLabel("Tip: Cmd/Ctrl + mouse wheel or trackpad zoom still works in supported text views.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #8b949e;")
        layout.addWidget(hint)
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        layout.addWidget(btn_close)
        dlg.exec_()

    def set_log_view_font_size(self, view_name, size):
        """Apply and persist font size for Frida Logs, LogCat, or ADB Console."""
        widget_map = {
            "frida": "frida_display",
            "logcat": "log_display",
            "adb_console": "console",
        }
        attr = widget_map.get(view_name)
        widget = getattr(self, attr, None) if attr else None
        if widget and hasattr(widget, "set_log_font_size"):
            widget.set_log_font_size(size)
        self.save_settings()

    def _sync_log_font_spin(self, spin_attr, size):
        spin = getattr(self, spin_attr, None)
        if spin and spin.value() != size:
            spin.blockSignals(True)
            spin.setValue(size)
            spin.blockSignals(False)
        self.save_settings()

    def on_frida_log_font_size_changed(self, size):
        self._sync_log_font_spin("frida_log_font_spin", size)

    def on_logcat_font_size_changed(self, size):
        self._sync_log_font_spin("logcat_font_spin", size)

    def on_adb_console_font_size_changed(self, size):
        self._sync_log_font_spin("adb_console_font_spin", size)

    def editor_search_pattern(self):
        if not hasattr(self, "editor_find_input"):
            return None, ""
        needle = self.editor_find_input.text()
        if not needle:
            return None, ""

        pattern = needle if self.editor_regex_chk.isChecked() else re.escape(needle)
        if self.editor_word_chk.isChecked():
            pattern = r"\b(?:" + pattern + r")\b"
        flags = 0 if self.editor_case_chk.isChecked() else re.IGNORECASE

        try:
            return re.compile(pattern, flags), ""
        except re.error as e:
            return None, f"Regex error: {e}"

    def editor_search_matches(self):
        regex, error = self.editor_search_pattern()
        if error:
            return [], error
        if regex is None:
            return [], ""
        text = self.editor.toPlainText()
        matches = []
        for match in regex.finditer(text):
            # Avoid zero-length regex loops/highlights that make replacement unsafe.
            if match.end() > match.start():
                matches.append(match)
        return matches, ""

    def refresh_editor_search_highlights(self, reset=False, quiet=False):
        if not hasattr(self, "editor") or not hasattr(self, "editor_find_input"):
            return

        matches, error = self.editor_search_matches()
        selections = []

        if error:
            self.editor.setExtraSelections([])
            if hasattr(self.editor, "set_search_match_lines"):
                self.editor.set_search_match_lines(set(), None)
            if not quiet:
                self.update_editor_status(error)
            return

        active_match_line = None
        match_lines = set()
        if self.editor_find_input.text():
            doc = self.editor.document()
            for match in matches:
                block = doc.findBlock(match.start())
                if block.isValid():
                    match_lines.add(block.blockNumber())

            cursor_now = self.editor.textCursor()
            active_idx = self.editor_current_match_index(
                matches,
                cursor_now.selectionStart(),
                cursor_now.selectionEnd()
            )
            if active_idx >= 0:
                active_block = doc.findBlock(matches[active_idx].start())
                if active_block.isValid():
                    active_match_line = active_block.blockNumber()

        if hasattr(self.editor, "set_search_match_lines"):
            self.editor.set_search_match_lines(match_lines, active_match_line)

        if self.editor_find_input.text() and self.editor_highlight_chk.isChecked():
            fmt = QTextCharFormat()
            fmt.setBackground(QColor("#3a3f4b"))
            fmt.setForeground(QColor("#ffffff"))

            # Keep highlighting responsive even on very large scripts.
            for match in matches[:1000]:
                cursor = QTextCursor(self.editor.document())
                cursor.setPosition(match.start())
                cursor.setPosition(match.end(), QTextCursor.KeepAnchor)
                sel = QTextEdit.ExtraSelection()
                sel.cursor = cursor
                sel.format = fmt
                selections.append(sel)

        self.editor.setExtraSelections(selections)
        self.update_editor_status()

    def update_editor_status(self, message=None):
        if not hasattr(self, "editor_status") or not hasattr(self, "editor"):
            return
        cursor = self.editor.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.positionInBlock() + 1
        total_lines = self.editor.document().blockCount()
        modified = "*" if self.editor.document().isModified() else ""

        if message is None:
            matches, error = self.editor_search_matches() if hasattr(self, "editor_find_input") else ([], "")
            if error:
                message = error
            elif hasattr(self, "editor_find_input") and self.editor_find_input.text():
                current = self.editor_current_match_index(matches, cursor.selectionStart(), cursor.selectionEnd())
                if current >= 0:
                    message = f"Match {current + 1}/{len(matches)}"
                else:
                    message = f"{len(matches)} match(es)"
            else:
                message = "Ready"

        path = os.path.basename(self.current_file_path) if self.current_file_path else "Unsaved script"
        font_size = self.editor.current_font_size() if hasattr(self.editor, "current_font_size") else self.editor.font().pointSize()
        self.editor_status.setText(f"{path}{modified} | Line {line}/{total_lines}, Col {col} | Font {font_size} pt | {message}")

    def editor_current_match_index(self, matches, start, end):
        for idx, match in enumerate(matches):
            if match.start() == start and match.end() == end:
                return idx
        return -1

    def select_editor_range(self, start, end):
        cursor = QTextCursor(self.editor.document())
        cursor.setPosition(start)
        cursor.setPosition(end, QTextCursor.KeepAnchor)
        self.editor.setTextCursor(cursor)
        self.editor.ensureCursorVisible()
        self.refresh_editor_search_highlights(reset=False)

    def editor_find_next(self, backward=False):
        if not hasattr(self, "editor"):
            return
        if not self.editor_find_input.text():
            self.editor_find_input.setFocus()
            return

        matches, error = self.editor_search_matches()
        if error:
            self.update_editor_status(error)
            return
        if not matches:
            self.update_editor_status("No matches")
            return

        cursor = self.editor.textCursor()
        if backward:
            pos = cursor.selectionStart() if cursor.hasSelection() else cursor.position()
            prior = [m for m in matches if m.start() < pos]
            match = prior[-1] if prior else matches[-1]
        else:
            pos = cursor.selectionEnd() if cursor.hasSelection() else cursor.position()
            later = [m for m in matches if m.start() >= pos]
            match = later[0] if later else matches[0]

        self.select_editor_range(match.start(), match.end())

    def editor_replace_one(self):
        if not hasattr(self, "editor"):
            return
        matches, error = self.editor_search_matches()
        if error:
            self.update_editor_status(error)
            return
        if not matches:
            self.editor_find_next(backward=False)
            return

        cursor = self.editor.textCursor()
        idx = self.editor_current_match_index(matches, cursor.selectionStart(), cursor.selectionEnd())
        if idx < 0:
            self.editor_find_next(backward=False)
            return

        match = matches[idx]
        replacement_raw = self.editor_replace_input.text()
        try:
            replacement = match.expand(replacement_raw) if self.editor_regex_chk.isChecked() else replacement_raw
        except re.error as e:
            self.update_editor_status(f"Replacement error: {e}")
            return

        cursor.beginEditBlock()
        cursor.insertText(replacement)
        cursor.endEditBlock()
        self.refresh_editor_search_highlights(reset=False)
        self.editor_find_next(backward=False)

    def editor_replace_all(self):
        if not hasattr(self, "editor"):
            return
        regex, error = self.editor_search_pattern()
        if error:
            self.update_editor_status(error)
            return
        if regex is None:
            self.editor_find_input.setFocus()
            return

        text = self.editor.toPlainText()
        replacement = self.editor_replace_input.text()
        try:
            new_text, count = regex.subn(replacement, text)
        except re.error as e:
            self.update_editor_status(f"Replacement error: {e}")
            return

        if count == 0:
            self.update_editor_status("No matches to replace")
            return

        cursor_pos = self.editor.textCursor().position()
        self.editor.blockSignals(True)
        self.editor.setPlainText(new_text)
        self.editor.blockSignals(False)
        cursor = QTextCursor(self.editor.document())
        cursor.setPosition(min(cursor_pos, len(new_text)))
        self.editor.setTextCursor(cursor)
        self.editor.document().setModified(True)
        self.refresh_editor_search_highlights(reset=True)
        self.update_editor_status(f"Replaced {count} occurrence(s)")
        self.route_frida_log("SYSTEM", f"Editor Replace All completed: {count} occurrence(s) replaced.")

    def editor_go_to_line(self):
        if not hasattr(self, "editor"):
            return
        max_line = max(1, self.editor.document().blockCount())
        current_line = self.editor.textCursor().blockNumber() + 1
        line, ok = QInputDialog.getInt(self, "Go To Line", "Line number:", current_line, 1, max_line)
        if not ok:
            return
        self.jump_editor_to_line(line, 1)

    def jump_editor_to_line(self, line, col=1, status_message=None):
        if not hasattr(self, "editor"):
            return False

        max_line = max(1, self.editor.document().blockCount())
        line = max(1, min(int(line), max_line))
        col = max(1, int(col or 1))

        block = self.editor.document().findBlockByNumber(line - 1)
        if not block.isValid():
            return False

        max_col_offset = max(0, block.length() - 1)
        pos = block.position() + min(col - 1, max_col_offset)
        cursor = QTextCursor(block)
        cursor.setPosition(pos)
        self.editor.setTextCursor(cursor)
        self.editor.ensureCursorVisible()
        self.editor.setFocus()

        if hasattr(self, "tabs") and hasattr(self, "frida_manager_tab"):
            self.tabs.setCurrentWidget(self.frida_manager_tab)

        self.update_editor_status(status_message or f"Jumped to line {line}, col {col}")
        return True

    def editor_line_col_from_position(self, position):
        """Return 1-based line/column for a document character offset."""
        if not hasattr(self, "editor"):
            return 1, 1
        block = self.editor.document().findBlock(int(max(0, position)))
        if not block.isValid():
            return 1, 1
        return block.blockNumber() + 1, int(max(0, position - block.position())) + 1

    def find_node_binary(self):
        """Find node for JavaScript syntax checking."""
        candidates = [
            shutil.which("node"),
            "/opt/homebrew/bin/node",
            "/usr/local/bin/node",
            "/usr/bin/node",
        ]
        for c in candidates:
            if c and os.path.exists(c):
                return c
        return None

    def run_node_syntax_check(self, code):
        """
        Run a syntax-only JavaScript parse through Node.
        This does not execute Frida APIs; it only catches JS parse errors.
        """
        node = self.find_node_binary()
        if not node:
            return {
                "ok": None,
                "message": "Node.js was not found. Install with: brew install node. Skipping syntax-only parse check.",
                "line": None,
                "col": None,
            }

        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(prefix="uft_frida_syntax_", suffix=".mjs")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code or "")

            result = subprocess.run(
                [node, "--check", tmp_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
            )
            output = (result.stdout or "").strip()
            if result.returncode == 0:
                return {"ok": True, "message": f"JavaScript syntax OK using {node}.", "line": None, "col": None}

            # Node commonly prints: /tmp/file.mjs:12
            line = None
            col = None
            m = re.search(re.escape(tmp_path) + r":(?P<line>\d+)(?::(?P<col>\d+))?", output)
            if not m:
                m = re.search(r"\.mjs:(?P<line>\d+)(?::(?P<col>\d+))?", output)
            if m:
                line = int(m.group("line"))
                col = int(m.group("col") or 1)
            else:
                # Fallback: estimate column from caret line if present.
                lines = output.splitlines()
                for i, out_line in enumerate(lines):
                    if tmp_path in out_line and i + 2 < len(lines) and "^" in lines[i + 2]:
                        line_match = re.search(r":(\d+)", out_line)
                        if line_match:
                            line = int(line_match.group(1))
                            col = lines[i + 2].find("^") + 1
                            break

            return {"ok": False, "message": output or "Node syntax check failed.", "line": line, "col": col or 1}
        except subprocess.TimeoutExpired:
            return {"ok": False, "message": "Node syntax check timed out.", "line": None, "col": None}
        except Exception as e:
            return {"ok": None, "message": f"Node syntax check could not run: {str(e)}", "line": None, "col": None}
        finally:
            if tmp_path:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    def frida17_static_checks(self, code):
        """Return warnings/errors for common Frida 16 -> 17 script breakages."""
        checks = []
        patterns = [
            (
                r"\bModule\.findExportByName\s*\(",
                "WARN",
                "Frida 17 removed static Module.findExportByName(). Use Module.findGlobalExportByName(name) for global/null exports, or Process.findModuleByName(lib).findExportByName(name).",
            ),
            (
                r"\bModule\.getExportByName\s*\(",
                "WARN",
                "Frida 17 removed static Module.getExportByName(). Use Module.getGlobalExportByName(name) or Process.getModuleByName(lib).getExportByName(name).",
            ),
            (
                r"\bModule\.enumerateSymbolsSync\s*\(",
                "WARN",
                "Frida 17 removed old static symbol enumeration. Use Process.findModuleByName(lib).enumerateSymbols().",
            ),
            (
                r"\bModule\.enumerateExportsSync\s*\(",
                "WARN",
                "Frida 17 removed old static export enumeration. Use Process.findModuleByName(lib).enumerateExports().",
            ),
            (
                r"\bMemory\.(readCString|readUtf8String|readByteArray|readU8|readU16|readU32|readPointer)\s*\(",
                "WARN",
                "Frida 17 removed old Memory.read* helpers. Use pointer methods such as args[0].readCString(), ptr.readByteArray(size), ptr.readU8(), etc.",
            ),
            (
                r"\bInterceptor\.attach\s*\(\s*null\b",
                "ERROR",
                "Interceptor.attach(null, ...) will fail. Check the export/module lookup before attaching.",
            ),
        ]

        for pattern, level, message in patterns:
            try:
                for match in re.finditer(pattern, code or ""):
                    line, col = self.editor_line_col_from_position(match.start())
                    checks.append({"level": level, "line": line, "col": col, "message": message})
            except re.error:
                pass

        if re.search(r"\bJava\b", code or ""):
            checks.append({
                "level": "INFO",
                "line": 1,
                "col": 1,
                "message": "This script references Java. Python API mode will compile/bundle frida-java-bridge; CLI mode already bundles Java compatibility.",
            })

        return checks

    def python_api_compile_check(self, code):
        """Compile the same wrapped/bundled agent that Python API mode will inject."""
        try:
            needs_java = re.search(r"\bJava\b", code or "") is not None
            if not needs_java:
                return {"ok": True, "message": "Python API compile check skipped: no Java bridge import needed for this script."}

            worker = FridaWorker("__validation__", code or "", FRIDA_INJECTION_MODE_PYTHON, self.frida_cli_path.text().strip() if hasattr(self, "frida_cli_path") else FRIDA_CLI_PATH)
            worker.log_signal.connect(self.route_frida_log)
            wrapped = worker._wrap_script_for_python_api(code or "")
            bundle = worker._build_python_api_agent_source(wrapped, needs_java)
            if bundle is None:
                return {"ok": False, "message": "Python API frida-java-bridge compile failed. See log lines above."}
            return {"ok": True, "message": "Python API frida-java-bridge bundle compiled successfully."}
        except Exception as e:
            return {"ok": False, "message": f"Python API compile check failed: {str(e)}"}

    def validate_current_script(self):
        """Validate the current Frida editor buffer before injection."""
        if not hasattr(self, "editor"):
            return

        code = self.editor.toPlainText()
        self.switch_to_tab_containing("Frida Logs")  # Frida Logs
        self.route_frida_log("SYSTEM", "Script validation started. This checks syntax/static compatibility; it does not execute hooks.")

        if not code.strip():
            self.route_frida_log("ERROR", "Validation failed: editor is empty.")
            self.update_editor_status("Validation failed: empty script")
            return

        failures = 0
        warnings = 0
        first_jump = None

        syntax = self.run_node_syntax_check(code)
        if syntax["ok"] is True:
            self.route_frida_log("SCRIPT", "✅ " + syntax["message"])
        elif syntax["ok"] is False:
            failures += 1
            location = ""
            if syntax.get("line"):
                location = f" at editor:{syntax['line']}:{syntax.get('col') or 1}"
                first_jump = first_jump or (syntax["line"], syntax.get("col") or 1)
            self.route_frida_log("ERROR", "JavaScript syntax check failed" + location + ": " + syntax["message"])
        else:
            warnings += 1
            self.route_frida_log("WARN", syntax["message"])

        for check in self.frida17_static_checks(code):
            level = check["level"]
            if level == "ERROR":
                failures += 1
                first_jump = first_jump or (check["line"], check["col"])
            elif level == "WARN":
                warnings += 1
            self.route_frida_log(level, f"Frida static check editor:{check['line']}:{check['col']} - {check['message']}")

        mode = self.frida_injection_mode.currentData() if hasattr(self, "frida_injection_mode") else FRIDA_INJECTION_MODE_CLI
        if mode == FRIDA_INJECTION_MODE_PYTHON:
            compile_result = self.python_api_compile_check(code)
            if compile_result["ok"]:
                self.route_frida_log("SCRIPT", "✅ " + compile_result["message"])
            else:
                failures += 1
                self.route_frida_log("ERROR", compile_result["message"])
        else:
            self.route_frida_log("SCRIPT", "CLI mode selected: syntax/static checks completed. CLI runtime test occurs when you inject.")

        if first_jump:
            self.jump_editor_to_line(first_jump[0], first_jump[1], "Validation issue")

        if failures == 0:
            if warnings:
                self.route_frida_log("WARN", f"Validation completed with {warnings} warning(s). Script may still fail at runtime if a module/symbol is not loaded yet.")
                self.update_editor_status(f"Validation warnings: {warnings}")
            else:
                self.route_frida_log("SYSTEM", "✅ Validation passed. Runtime-only failures are still possible if symbols/classes are unavailable in the target app.")
                self.update_editor_status("Validation passed")
        else:
            self.route_frida_log("ERROR", f"Validation failed with {failures} error(s) and {warnings} warning(s).")
            self.update_editor_status(f"Validation failed: {failures} error(s)")

    def extract_script_location_from_log_line(self, line):
        # Handles Frida locations such as:
        #   (/script1.js:58)
        #   (/script1.js:58:12)
        #   at foo (/agent/index.js:58:12)
        pattern = re.compile(r"(?P<file>/?[^()\s:]+\.js):(?P<line>\d+)(?::(?P<col>\d+))?")
        matches = list(pattern.finditer(str(line or "")))
        if not matches:
            return None

        # Prefer the first real JS frame and avoid generated/eval locations when possible.
        preferred = None
        for match in matches:
            file_name = match.group("file")
            if "eval" not in file_name.lower():
                preferred = match
                break
        if preferred is None:
            preferred = matches[0]

        return {
            "file": preferred.group("file"),
            "line": int(preferred.group("line")),
            "col": int(preferred.group("col") or 1),
        }

    def handle_frida_log_double_click(self, line):
        loc = self.extract_script_location_from_log_line(line)
        if not loc:
            self.route_frida_log("SYSTEM", "Double-clicked log line has no JavaScript file:line location.")
            return

        ok = self.jump_editor_to_line(
            loc["line"],
            loc["col"],
            f"Jumped from Frida log {loc['file']}:{loc['line']}:{loc['col']}"
        )
        if ok:
            self.route_frida_log("SYSTEM", f"Jumped to editor line {loc['line']}, col {loc['col']} from {loc['file']}.")
        else:
            self.route_frida_log("WARN", f"Could not jump to {loc['file']}:{loc['line']}:{loc['col']}.")

    def save_script_as(self):
        start_dir = os.path.dirname(self.current_file_path) if self.current_file_path and self.current_file_path.startswith(FRIDA_SCRIPTS_DIR) else FRIDA_SCRIPTS_DIR
        path, _ = QFileDialog.getSaveFileName(self, "Save Frida Script As", start_dir, "Frida JavaScript (*.js);;All Files (*)")
        if not path:
            return
        if not os.path.splitext(path)[1]:
            path += ".js"
        self.current_file_path = path
        self.save_script()
        if hasattr(self, "f_tree"):
            self.f_tree.setRootIndex(self.f_model.index(FRIDA_SCRIPTS_DIR))

    def reload_current_script(self):
        if not self.current_file_path or not os.path.exists(self.current_file_path):
            self.route_frida_log("WARN", "No saved Frida script selected to reload.")
            return
        if self.editor.document().isModified():
            answer = QMessageBox.question(self, "Reload Script", "Discard unsaved editor changes and reload from disk?")
            if answer != QMessageBox.Yes:
                return
        try:
            with open(self.current_file_path, "r", encoding="utf-8", errors="replace") as f:
                self.editor.setPlainText(f.read())
            self.editor.document().setModified(False)
            self.refresh_editor_search_highlights(reset=True)
            self.update_editor_status("Reloaded")
            self.route_frida_log("SYSTEM", f"Reloaded script: {self.current_file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Reload Error", f"Could not reload script: {str(e)}")

    def show_frida_snippet_menu(self):
        menu = QMenu(self)
        snippets = {
            "Java class hook": "Java.perform(function() {\n    var Target = Java.use('com.example.Target');\n    Target.method.implementation = function() {\n        console.log('[+] Target.method called');\n        return this.method.apply(this, arguments);\n    };\n});\n",
            "Native export hook": "var mod = Process.getModuleByName('libtarget.so');\nvar addr = mod.findExportByName('target_export');\nif (addr) {\n    Interceptor.attach(addr, {\n        onEnter: function(args) { console.log('[+] target_export called'); },\n        onLeave: function(retval) {}\n    });\n}\n",
            "dlopen watcher": "var android_dlopen_ext = Module.findGlobalExportByName('android_dlopen_ext');\nif (android_dlopen_ext) {\n    Interceptor.attach(android_dlopen_ext, {\n        onEnter: function(args) { this.path = args[0].readCString(); },\n        onLeave: function() { if (this.path) console.log('[+] Loaded: ' + this.path); }\n    });\n}\n",
            "Stack trace logger": "function printBacktrace(context) {\n    console.log(Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));\n}\n",
            "Frida 17 module lookup": "var moduleName = 'libc.so';\nvar symbolName = 'fwrite';\nvar mod = Process.findModuleByName(moduleName);\nif (mod) {\n    var addr = mod.findExportByName(symbolName);\n    console.log(moduleName + '!' + symbolName + ' = ' + addr);\n}\n"
        }
        for name, code in snippets.items():
            act = menu.addAction(name)
            act.triggered.connect(lambda _, c=code: self.insert_frida_snippet(c))
        menu.exec_(self.cursor().pos())

    def insert_frida_snippet(self, code):
        if hasattr(self, "editor"):
            self.editor.insertPlainText(code)
            self.editor.setFocus()
            self.update_editor_status("Snippet inserted")

    def apply_selected_logcat_preset(self):
        preset = self.logcat_preset_box.currentText() if hasattr(self, "logcat_preset_box") else ""
        def set_levels(levels):
            self.set_logcat_level_checks(levels)
        if preset == "App Errors":
            self.log_level_box.setCurrentText("Error")
            set_levels(["E", "F"])
            self.log_filter.setText("")
            self.log_hard_filter.setChecked(True)
        elif preset == "Frida Only":
            self.log_level_box.setCurrentText("Verbose")
            set_levels(self.logcat_order)
            self.log_filter.setText("frida")
            self.log_hard_filter.setChecked(True)
        elif preset == "Network":
            self.log_level_box.setCurrentText("Verbose")
            set_levels(self.logcat_order)
            self.log_filter.setText("network")
            self.log_hard_filter.setChecked(False)
        elif preset == "ActivityManager":
            self.log_level_box.setCurrentText("Verbose")
            set_levels(self.logcat_order)
            self.log_filter.setText("ActivityManager")
            self.log_hard_filter.setChecked(True)
        elif preset == "Current Package Only":
            pkg = ""
            if hasattr(self, "target_pkg"):
                pkg = self.target_pkg.currentText().strip()
            self.log_level_box.setCurrentText("Verbose")
            set_levels(self.logcat_order)
            self.log_filter.setText(pkg)
            self.log_hard_filter.setChecked(True)
        self.refresh_logcat_display()

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

        self.frida_log_font_spin = QSpinBox()
        self.frida_log_font_spin.setRange(8, 40)
        self.frida_log_font_spin.setValue(10)
        self.frida_log_font_spin.setSuffix(" pt")
        self.frida_log_font_spin.setToolTip("Frida Logs font size. You can also use Cmd/Ctrl + mouse wheel or trackpad pinch.")
        btn_frida_font_down = QPushButton("A−")
        btn_frida_font_down.setToolTip("Decrease Frida Logs font size")
        btn_frida_font_down.clicked.connect(lambda: self.frida_display.zoom_out_font())
        btn_frida_font_up = QPushButton("A+")
        btn_frida_font_up.setToolTip("Increase Frida Logs font size")
        btn_frida_font_up.clicked.connect(lambda: self.frida_display.zoom_in_font())
        btn_frida_font_reset = QPushButton("A0")
        btn_frida_font_reset.setToolTip("Reset Frida Logs font size")
        btn_frida_font_reset.clicked.connect(lambda: self.frida_display.reset_font_zoom())
        btn_frida_text_settings = QPushButton("⚙")
        btn_frida_text_settings.setFixedWidth(38)
        btn_frida_text_settings.setToolTip("Frida log text/font settings")
        btn_frida_text_settings.clicked.connect(lambda: self.show_text_settings_dialog("frida"))

        controls.addWidget(QLabel("Search:"));
        controls.addWidget(self.frida_filter, 1);
        controls.addWidget(self.btn_frida_pause);
        controls.addWidget(btn_c);
        controls.addWidget(btn_frida_text_settings);
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

        self.frida_display = FridaLogDisplay();
        self.frida_display.setReadOnly(True);
        self.frida_display.set_log_font_size(self.frida_log_font_spin.value(), emit_signal=False)
        self.frida_display.fontSizeChanged.connect(self.on_frida_log_font_size_changed)
        self.frida_log_font_spin.valueChanged.connect(lambda size: self.set_log_view_font_size("frida", size))
        self.frida_display.setStyleSheet("background: #010409; color: #d1d5da;");
        self.frida_display.lineDoubleClicked.connect(self.handle_frida_log_double_click)
        layout.addWidget(self.frida_display)
        self.tabs.addTab(tab, "💉 Frida Logs")

    def setup_logcat_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Buffered LogCat model: never discard lines because a level/search filter is active.
        # The UI filters only control what is visible from this buffer.
        self.logcat_entries = []
        self.logcat_order = ["V", "D", "I", "W", "E", "F"]
        self.logcat_level_names = {
            "V": "Verbose", "D": "Debug", "I": "Info", "W": "Warning", "E": "Error", "F": "Fatal"
        }
        self.logcat_colors = {
            "V": "#8b949e", "D": "#79c0ff", "I": "#aff5b4",
            "W": "#ffa657", "E": "#ff7b72", "F": "#f85149"
        }
        self.logcat_max_entries = 20000

        # Performance state: LogCat can emit thousands of rows quickly.
        # Never recompute all visible rows for every incoming line; keep a rolling visible count
        # and flush UI appends in batches on a short timer.
        self.logcat_last_visible_count = 0
        self.logcat_pending_html = []
        self.logcat_flush_timer = QTimer(self)
        self.logcat_flush_timer.setSingleShot(True)
        self.logcat_flush_timer.timeout.connect(self.flush_logcat_pending_display)
        self.logcat_status_timer = QTimer(self)
        self.logcat_status_timer.setSingleShot(True)
        self.logcat_status_timer.timeout.connect(self.update_logcat_status)

        top_row = QHBoxLayout()
        self.log_filter = QLineEdit()
        self.log_filter.setPlaceholderText("Search LogCat buffer... filters visible rows only, does not discard lines")
        self.log_filter.textChanged.connect(lambda _=None: self.refresh_logcat_display())

        self.log_level_box = QComboBox()
        self.log_levels = {"Verbose": "V", "Debug": "D", "Info": "I", "Warning": "W", "Error": "E", "Fatal": "F"}
        self.log_level_box.addItems(list(self.log_levels.keys()))
        self.log_level_box.setToolTip("Minimum visible level. Buffered rows are preserved when you change this.")
        self.log_level_box.currentIndexChanged.connect(lambda _=None: self.refresh_logcat_display())

        self.log_hard_filter = QCheckBox("Hide Non-Matching")
        self.log_hard_filter.setChecked(True)
        self.log_hard_filter.setToolTip("When off, search text is highlighted but non-matching rows remain visible.")
        self.log_hard_filter.setStyleSheet("color: white;")
        self.log_hard_filter.toggled.connect(lambda _=None: self.refresh_logcat_display())

        self.log_auto_scroll = QCheckBox("Auto-scroll")
        self.log_auto_scroll.setChecked(True)
        self.log_auto_scroll.setStyleSheet("color: white;")

        self.btn_log_pause = QPushButton("⏸ Pause Display")
        self.btn_log_pause.setToolTip("Pause live drawing only. Incoming LogCat lines still stay in the buffer.")
        self.btn_log_pause.clicked.connect(self.toggle_log_pause)

        btn_clear = QPushButton("🧹 Clear Buffer")
        btn_clear.setToolTip("Clear the stored LogCat buffer and visible output.")
        btn_clear.clicked.connect(self.clear_logcat_buffer)

        btn_export = QPushButton("💾 Export Visible")
        btn_export.setToolTip("Export currently visible/filtered LogCat rows to a .txt file.")
        btn_export.clicked.connect(self.export_visible_logcat)

        self.logcat_font_spin = QSpinBox()
        self.logcat_font_spin.setRange(8, 40)
        self.logcat_font_spin.setValue(10)
        self.logcat_font_spin.setSuffix(" pt")
        self.logcat_font_spin.setToolTip("LogCat font size. You can also use Cmd/Ctrl + mouse wheel or trackpad pinch.")
        btn_logcat_font_down = QPushButton("A−")
        btn_logcat_font_down.setToolTip("Decrease LogCat font size")
        btn_logcat_font_down.clicked.connect(lambda: self.log_display.zoom_out_font())
        btn_logcat_font_up = QPushButton("A+")
        btn_logcat_font_up.setToolTip("Increase LogCat font size")
        btn_logcat_font_up.clicked.connect(lambda: self.log_display.zoom_in_font())
        btn_logcat_font_reset = QPushButton("A0")
        btn_logcat_font_reset.setToolTip("Reset LogCat font size")
        btn_logcat_font_reset.clicked.connect(lambda: self.log_display.reset_font_zoom())
        btn_logcat_text_settings = QPushButton("⚙")
        btn_logcat_text_settings.setFixedWidth(38)
        btn_logcat_text_settings.setToolTip("LogCat text/font settings")
        btn_logcat_text_settings.clicked.connect(lambda: self.show_text_settings_dialog("logcat"))

        self.logcat_preset_box = QComboBox()
        self.logcat_preset_box.addItems(["App Errors", "Frida Only", "Network", "ActivityManager", "Current Package Only"])
        btn_apply_logcat_preset = QPushButton("Apply Preset")
        btn_apply_logcat_preset.clicked.connect(self.apply_selected_logcat_preset)

        top_row.addWidget(QLabel("Min Level:"))
        top_row.addWidget(self.log_level_box)
        top_row.addWidget(QLabel("Preset:"))
        top_row.addWidget(self.logcat_preset_box)
        top_row.addWidget(btn_apply_logcat_preset)
        top_row.addWidget(self.log_filter, 1)
        top_row.addWidget(self.log_hard_filter)
        top_row.addWidget(self.log_auto_scroll)
        top_row.addWidget(self.btn_log_pause)
        top_row.addWidget(btn_clear)
        top_row.addWidget(btn_export)
        top_row.addWidget(btn_logcat_text_settings)
        layout.addLayout(top_row)

        level_row = QHBoxLayout()
        level_row.addWidget(QLabel("Show Levels:"))
        self.logcat_level_checks = {}
        for code in self.logcat_order:
            chk = QCheckBox(code)
            chk.setChecked(True)
            chk.setToolTip(self.logcat_level_names.get(code, code))
            chk.setStyleSheet(f"color: {self.logcat_colors.get(code, '#c9d1d9')}; font-weight: bold;")
            chk.toggled.connect(lambda _=None: self.refresh_logcat_display())
            self.logcat_level_checks[code] = chk
            level_row.addWidget(chk)

        btn_levels_all = QPushButton("All")
        btn_levels_all.clicked.connect(lambda: self.set_logcat_level_checks(self.logcat_order))
        btn_levels_none = QPushButton("None")
        btn_levels_none.clicked.connect(lambda: self.set_logcat_level_checks([]))
        btn_levels_errors = QPushButton("Errors+")
        btn_levels_errors.setToolTip("Show Error and Fatal only")
        btn_levels_errors.clicked.connect(lambda: self.set_logcat_level_checks(["E", "F"]))

        self.logcat_buffer_spin = QSpinBox()
        self.logcat_buffer_spin.setRange(1000, 200000)
        self.logcat_buffer_spin.setSingleStep(1000)
        self.logcat_buffer_spin.setValue(self.logcat_max_entries)
        self.logcat_buffer_spin.setSuffix(" rows")
        self.logcat_buffer_spin.setToolTip("Maximum stored LogCat rows kept in memory.")
        self.logcat_buffer_spin.valueChanged.connect(self.set_logcat_max_entries)

        self.logcat_count_label = QLabel("Buffered: 0 | Visible: 0")
        self.logcat_count_label.setStyleSheet("color: #8b949e;")

        level_row.addWidget(btn_levels_all)
        level_row.addWidget(btn_levels_none)
        level_row.addWidget(btn_levels_errors)
        level_row.addSpacing(20)
        level_row.addWidget(QLabel("Buffer:"))
        level_row.addWidget(self.logcat_buffer_spin)
        level_row.addWidget(self.logcat_count_label)
        level_row.addStretch()
        layout.addLayout(level_row)

        self.log_display = ZoomableLogTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.set_log_font_size(self.logcat_font_spin.value(), emit_signal=False)
        self.log_display.fontSizeChanged.connect(self.on_logcat_font_size_changed)
        self.logcat_font_spin.valueChanged.connect(lambda size: self.set_log_view_font_size("logcat", size))
        self.log_display.setStyleSheet("background: #010409; color: #d1d5da;")
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
        self.remote_table.horizontalHeader().setStretchLastSection(False)
        self.remote_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.remote_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.remote_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.remote_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.remote_table.verticalHeader().setVisible(False)
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
        QTimer.singleShot(0, self.auto_size_remote_columns)

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
        QTimer.singleShot(250, self.update_viewer_ui)

    def setup_proxy_tab(self):
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

        global_px_box = QGroupBox("Proxy Router / Validator");
        global_px_layout = QVBoxLayout(global_px_box)

        self.country_selector = QComboBox()
        self.country_selector.setMinimumWidth(280)

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

        self.proxy_priority_countries = priority_countries
        self.proxy_standard_countries = standard_countries
        self.populate_proxy_country_selector(default_code="IN")
        self.country_selector.currentIndexChanged.connect(self.load_manual_proxies_to_ui)

        self.chk_auto_fallback = QCheckBox("Auto-Fallback On Noise/Fail");
        self.chk_auto_fallback.setChecked(True);
        self.chk_auto_fallback.setStyleSheet("color: white;")

        self.chk_include_socks_proxy = QCheckBox("Include SOCKS proxies")
        self.chk_include_socks_proxy.setChecked(False)
        self.chk_include_socks_proxy.setStyleSheet("color: white;")
        self.chk_include_socks_proxy.setToolTip(
            "HTTP/HTTPS proxy records are always shown and tested. Enable this to also include socks/socks4/socks5 records. "
            "SOCKS validation through Python requests requires PySocks: pip install PySocks"
        )
        self.chk_include_socks_proxy.toggled.connect(self.on_include_socks_proxy_toggled)

        self.proxy_timeout_spin = QSpinBox()
        self.proxy_timeout_spin.setRange(3, 60)
        self.proxy_timeout_spin.setValue(10)
        self.proxy_timeout_spin.setSuffix(" sec")
        self.proxy_timeout_spin.setToolTip(
            "Timeout for each proxy validation request. Use a higher value for slow country proxies."
        )
        self.proxy_timeout_spin.valueChanged.connect(self.save_settings)

        self.chk_clear_device_proxy_before_route = QCheckBox("Clear Android global proxy before Frida route")
        self.chk_clear_device_proxy_before_route.setChecked(True)
        self.chk_clear_device_proxy_before_route.setStyleSheet("color: white;")
        self.chk_clear_device_proxy_before_route.setToolTip(
            "Prevents stale Android global http_proxy settings from interfering with the per-app Frida proxy hook. "
            "This does not change your macOS network proxy settings."
        )

        self.chk_apply_android_global_proxy_after_validation = QCheckBox("Set Android global proxy after validation")
        self.chk_apply_android_global_proxy_after_validation.setChecked(False)
        self.chk_apply_android_global_proxy_after_validation.setStyleSheet("color: white;")
        self.chk_apply_android_global_proxy_after_validation.setToolTip(
            "After a proxy validates, set Android Settings.Global http_proxy to host:port for device-wide proxy testing. "
            "Android global http_proxy supports HTTP-style proxies only, not SOCKS."
        )

        self.chk_android_global_proxy_only = QCheckBox("Android global only, no Frida inject")
        self.chk_android_global_proxy_only.setChecked(False)
        self.chk_android_global_proxy_only.setStyleSheet("color: white;")
        self.chk_android_global_proxy_only.setToolTip(
            "Use this when you want Android global proxy mode only. It validates the proxy, sets Android global http_proxy, "
            "and skips the per-app Java System.getProperty Frida hook."
        )

        btn_edit_frida_script = QPushButton("📜 Frida Proxy Script")
        btn_edit_frida_script.setObjectName("editFridaScriptBtn")
        btn_edit_frida_script.clicked.connect(self.open_frida_template_editor_modal)

        btn_edit_list = QPushButton("📝 Edit Proxy File")
        btn_edit_list.setObjectName("editListBtn")
        btn_edit_list.clicked.connect(self.open_proxy_file_in_system_editor)

        btn_fetch_proxifly = QPushButton("⬇ Import Sources")
        btn_fetch_proxifly.setToolTip(
            "Download the checked proxy source selections, merge new records into manual_proxies.json, "
            "create a backup first, and refresh country counts."
        )
        btn_fetch_proxifly.clicked.connect(lambda: self.start_proxy_source_import(replace_existing=False, all_sources=False))

        btn_route_proxy = QPushButton("🚀 Validate / Route Proxy");
        btn_route_proxy.setObjectName("runBtn");
        btn_route_proxy.clicked.connect(self.start_global_proxy_routing)

        btn_remove_proxy = QPushButton("🛑 Remove Proxy");
        btn_remove_proxy.setObjectName("killBtn");
        btn_remove_proxy.clicked.connect(self.remove_global_proxy)

        self.global_proxy_status = QLabel("Validated proxy: none")
        self.global_proxy_status.setStyleSheet("color: #8b949e; padding-left: 8px;")

        router_main_row = QHBoxLayout()
        router_main_row.addWidget(QLabel("Target Country:"))
        router_main_row.addWidget(self.country_selector, 1)
        router_main_row.addWidget(QLabel("Timeout:"))
        router_main_row.addWidget(self.proxy_timeout_spin)
        router_main_row.addSpacing(12)
        router_main_row.addWidget(btn_route_proxy)
        router_main_row.addWidget(btn_remove_proxy)
        global_px_layout.addLayout(router_main_row)

        router_options_box = QGroupBox("Validation / Routing Options")
        router_options_grid = QGridLayout(router_options_box)
        router_options_grid.addWidget(self.chk_auto_fallback, 0, 0)
        router_options_grid.addWidget(self.chk_include_socks_proxy, 0, 1)
        router_options_grid.addWidget(self.chk_clear_device_proxy_before_route, 0, 2)
        router_options_grid.addWidget(self.chk_apply_android_global_proxy_after_validation, 1, 0)
        router_options_grid.addWidget(self.chk_android_global_proxy_only, 1, 1)
        router_options_grid.setColumnStretch(2, 1)
        global_px_layout.addWidget(router_options_box)

        router_tools_row = QHBoxLayout()
        router_tools_row.addWidget(btn_edit_frida_script)
        router_tools_row.addWidget(btn_edit_list)
        router_tools_row.addWidget(btn_fetch_proxifly)
        router_tools_row.addStretch(1)
        router_tools_row.addWidget(self.global_proxy_status, 2)
        global_px_layout.addLayout(router_tools_row)

        android_proxy_row = QHBoxLayout()
        btn_apply_android_proxy = QPushButton("🌐 Apply Validated to Android")
        btn_apply_android_proxy.setToolTip("Set Android global http_proxy using the last validated HTTP/HTTPS proxy.")
        btn_apply_android_proxy.clicked.connect(self.apply_current_validated_proxy_to_android_global)

        btn_check_android_proxy = QPushButton("🔎 Check Android Proxy")
        btn_check_android_proxy.setToolTip("Run adb shell settings get global http_proxy.")
        btn_check_android_proxy.clicked.connect(self.check_android_global_proxy)

        btn_clear_android_proxy = QPushButton("🧹 Clear Android Proxy")
        btn_clear_android_proxy.setObjectName("killBtn")
        btn_clear_android_proxy.setToolTip("Clear Android global http_proxy. This does not change your Mac proxy settings.")
        btn_clear_android_proxy.clicked.connect(self.clear_android_global_proxy)

        self.android_global_proxy_status = QLabel("Android global proxy: unknown")
        self.android_global_proxy_status.setStyleSheet("color: #8b949e; padding-left: 8px;")

        android_proxy_row.addWidget(btn_apply_android_proxy)
        android_proxy_row.addWidget(btn_check_android_proxy)
        android_proxy_row.addWidget(btn_clear_android_proxy)
        android_proxy_row.addWidget(self.android_global_proxy_status, 1)
        global_px_layout.addLayout(android_proxy_row)

        manual_row = QHBoxLayout()
        self.manual_proxy_input = QLineEdit()
        self.manual_proxy_input.setPlaceholderText(
            "HTTP proxies always included, e.g. http://1.2.3.4:8080 or 1.2.3.4:8080. Enable SOCKS to use socks5://1.2.3.4:1080")
        self.manual_proxy_input.setToolTip(
            "This is the editable proxy candidate pool for the selected country. HTTP/HTTPS proxies are always included. "
            "SOCKS/SOCKS4/SOCKS5 proxies are shown/tested only when Include SOCKS proxies is enabled. "
            "Plain host:port entries save as http://host:port. It does not set macOS proxy settings. "
            "Safety: empty saves are blocked so clearing this box cannot delete a country pool."
        )
        btn_save_manual = QPushButton("💾 Save Country Pool")
        btn_save_manual.setToolTip("Save the visible proxy list for the selected country. Creates an automatic backup first. Empty saves are blocked.")
        btn_save_manual.clicked.connect(self.save_manual_proxies_from_ui)
        btn_reload_pool = QPushButton("↻ Reload Pool")
        btn_reload_pool.setToolTip("Reload this country pool from manual_proxies.json, discarding unsaved edits in the text box.")
        btn_reload_pool.clicked.connect(self.load_manual_proxies_to_ui)
        btn_backup_proxy = QPushButton("🧷 Backup")
        btn_backup_proxy.setToolTip("Create a timestamped backup of manual_proxies.json now.")
        btn_backup_proxy.clicked.connect(lambda: self.backup_manual_proxy_file(user_visible=True))
        btn_restore_proxy = QPushButton("↩ Restore Backup")
        btn_restore_proxy.setToolTip("Restore manual_proxies.json from a timestamped backup file.")
        btn_restore_proxy.clicked.connect(self.restore_manual_proxy_backup)
        btn_recover_cache = QPushButton("🛟 Recover Cache")
        btn_recover_cache.setToolTip("Best-effort recovery: rebuild selected country entries from proxy_cache.json if available.")
        btn_recover_cache.clicked.connect(self.recover_selected_proxy_pool_from_cache)
        btn_refresh_counts = QPushButton("🔄 Counts")
        btn_refresh_counts.clicked.connect(lambda: self.refresh_proxy_country_counts())

        manual_row.addWidget(QLabel("Proxy Pool for Selected Country: "))
        manual_row.addWidget(self.manual_proxy_input, 1)
        global_px_layout.addLayout(manual_row)

        manual_actions_row = QHBoxLayout()
        manual_actions_row.addWidget(btn_save_manual)
        manual_actions_row.addWidget(btn_reload_pool)
        manual_actions_row.addWidget(btn_backup_proxy)
        manual_actions_row.addWidget(btn_restore_proxy)
        manual_actions_row.addWidget(btn_recover_cache)
        manual_actions_row.addWidget(btn_refresh_counts)
        manual_actions_row.addStretch(1)
        global_px_layout.addLayout(manual_actions_row)

        layout.addWidget(global_px_box)

        dashboard_box = QGroupBox("Proxy Health Dashboard / Profiles")
        dashboard_layout = QVBoxLayout(dashboard_box)
        dash_queue_row = QHBoxLayout()
        dash_profile_row = QHBoxLayout()
        btn_refresh_health = QPushButton("📊 Refresh Health")
        btn_refresh_health.clicked.connect(self.refresh_proxy_health_dashboard)
        btn_validate_selected = QPushButton("✅ Validate Selected Country")
        btn_validate_selected.clicked.connect(self.start_global_proxy_routing)
        btn_validate_all = QPushButton("🧪 Validate All")
        btn_validate_all.setToolTip("Bulk validate all proxies without routing/injecting")
        btn_validate_all.clicked.connect(lambda: self.start_proxy_bulk_validation("all"))
        btn_validate_imported = QPushButton("🧪 Validate Imported")
        btn_validate_imported.setToolTip("Bulk validate imported/source-tagged proxies only")
        btn_validate_imported.clicked.connect(lambda: self.start_proxy_bulk_validation("imported"))
        btn_stop_queue = QPushButton("⏹ Stop Queue")
        btn_stop_queue.setObjectName("killBtn")
        btn_stop_queue.clicked.connect(self.stop_proxy_bulk_validation)
        self.proxy_dead_rank_spin = QSpinBox()
        self.proxy_dead_rank_spin.setRange(-1000, 0)
        self.proxy_dead_rank_spin.setValue(-25)
        self.proxy_dead_rank_spin.setToolTip("Remove proxies with cached rank less than or equal to this value")
        btn_remove_dead = QPushButton("🧹 Remove Dead <= Rank")
        btn_remove_dead.clicked.connect(self.remove_dead_proxies_by_rank)
        self.proxy_profile_combo = QComboBox()
        self.refresh_proxy_profile_combo()
        btn_save_profile = QPushButton("💾 Save Profile")
        btn_save_profile.clicked.connect(self.save_current_proxy_profile)
        btn_apply_profile = QPushButton("▶ Apply Profile")
        btn_apply_profile.clicked.connect(self.apply_selected_proxy_profile)
        btn_delete_profile = QPushButton("🗑 Delete Profile")
        btn_delete_profile.clicked.connect(self.delete_selected_proxy_profile)
        dash_queue_row.addWidget(btn_refresh_health)
        dash_queue_row.addWidget(btn_validate_selected)
        dash_queue_row.addWidget(btn_validate_all)
        dash_queue_row.addWidget(btn_validate_imported)
        dash_queue_row.addWidget(btn_stop_queue)
        dash_queue_row.addStretch(1)
        dash_profile_row.addWidget(QLabel("Dead Rank:"))
        dash_profile_row.addWidget(self.proxy_dead_rank_spin)
        dash_profile_row.addWidget(btn_remove_dead)
        dash_profile_row.addSpacing(20)
        dash_profile_row.addWidget(QLabel("Profile:"))
        dash_profile_row.addWidget(self.proxy_profile_combo, 1)
        dash_profile_row.addWidget(btn_save_profile)
        dash_profile_row.addWidget(btn_apply_profile)
        dash_profile_row.addWidget(btn_delete_profile)
        dashboard_layout.addLayout(dash_queue_row)
        dashboard_layout.addLayout(dash_profile_row)
        self.proxy_health_table = QTableWidget(0, 8)
        self.proxy_health_table.setHorizontalHeaderLabels(["Country", "HTTP", "SOCKS", "Good", "Bad", "Timeout", "Last Checked", "Avg Rank"])
        self.proxy_health_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 8):
            self.proxy_health_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.proxy_health_table.setMinimumHeight(150)
        dashboard_layout.addWidget(self.proxy_health_table)
        layout.addWidget(dashboard_box)

        import_box = QGroupBox("Proxy Source Import")
        import_layout = QHBoxLayout(import_box)

        source_left = QVBoxLayout()
        source_left.addWidget(QLabel("Select one or more sources:"))
        self.proxy_source_list = QListWidget()
        self.proxy_source_list.setMinimumHeight(190)
        self.populate_proxy_source_list()
        source_left.addWidget(self.proxy_source_list)

        source_buttons = QHBoxLayout()
        btn_sources_all = QPushButton("All")
        btn_sources_all.clicked.connect(lambda: self.set_proxy_source_checks(True))
        btn_sources_none = QPushButton("None")
        btn_sources_none.clicked.connect(lambda: self.set_proxy_source_checks(False))
        btn_sources_http = QPushButton("HTTP Only")
        btn_sources_http.clicked.connect(lambda: self.select_proxy_sources_by_family("http"))
        btn_sources_socks = QPushButton("SOCKS Only")
        btn_sources_socks.clicked.connect(lambda: self.select_proxy_sources_by_family("socks"))
        source_buttons.addWidget(btn_sources_all)
        source_buttons.addWidget(btn_sources_none)
        source_buttons.addWidget(btn_sources_http)
        source_buttons.addWidget(btn_sources_socks)
        source_left.addLayout(source_buttons)

        import_actions = QVBoxLayout()
        btn_import_selected = QPushButton("⬇ Import Selected / Merge")
        btn_import_selected.setObjectName("runBtn")
        btn_import_selected.setToolTip("Download selected proxy sources, normalize to manual_proxies.json format, and merge only new protocol/ip/port records.")
        btn_import_selected.clicked.connect(lambda: self.start_proxy_source_import(replace_existing=False, all_sources=False))

        btn_import_all = QPushButton("⬇ Import All / Merge")
        btn_import_all.setToolTip("Download all configured proxy sources and merge new records into manual_proxies.json.")
        btn_import_all.clicked.connect(lambda: self.start_proxy_source_import(replace_existing=False, all_sources=True))

        btn_clear_import_all = QPushButton("🧨 Clear List + Import All")
        btn_clear_import_all.setObjectName("killBtn")
        btn_clear_import_all.setToolTip("Back up current manual_proxies.json, clear it, then rebuild it from all configured sources.")
        btn_clear_import_all.clicked.connect(lambda: self.start_proxy_source_import(replace_existing=True, all_sources=True))

        btn_open_proxy_file = QPushButton("📝 Open Proxy JSON")
        btn_open_proxy_file.clicked.connect(self.open_proxy_file_in_system_editor)

        import_actions.addWidget(btn_import_selected)
        import_actions.addWidget(btn_import_all)
        import_actions.addWidget(btn_clear_import_all)
        import_actions.addWidget(btn_open_proxy_file)
        import_actions.addStretch()

        source_right = QVBoxLayout()
        source_right.addWidget(QLabel("Import status:"))
        self.proxy_import_table = QTableWidget(0, 6)
        self.proxy_import_table.setHorizontalHeaderLabels(["Source", "Status", "Raw", "Normalized", "Unique", "Skipped/Error"])
        self.proxy_import_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 6):
            self.proxy_import_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.proxy_import_table.setMinimumHeight(160)
        source_right.addWidget(self.proxy_import_table)

        import_layout.addLayout(source_left, 2)
        import_layout.addLayout(import_actions, 1)
        import_layout.addLayout(source_right, 3)
        layout.addWidget(import_box)

        log_box = QGroupBox("Proxy Status Log")
        log_layout = QVBoxLayout(log_box)
        self.proxy_log = QTextEdit()
        self.proxy_log.setReadOnly(True)
        self.proxy_log.setFont(QFont("Monospace", 10))
        self.proxy_log.setStyleSheet("background: #010409; color: #d1d5da;")
        self.proxy_log.setMinimumHeight(160)
        log_layout.addWidget(self.proxy_log)
        layout.addWidget(log_box)

        self.tabs.addTab(tab, "🌐 Proxy")

    def setup_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info = QLabel(
            "Android Network workspace: socket snapshots and tcpdump/PCAP are captured from the Android device. "
            "The grid shows sockets/connections, not payload bytes. To see request/response bodies or socket data, insert the Frida snippets below; payload view can be Text, JSON, Hex, or Hex+ASCII."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #8b949e; padding: 6px;")
        layout.addWidget(info)

        controls = QHBoxLayout()
        btn_refresh_net = QPushButton("🔄 Refresh Connections")
        btn_refresh_net.setObjectName("runBtn")
        btn_refresh_net.clicked.connect(self.refresh_network_connections)
        self.btn_network_monitor = QPushButton("▶ Monitor")
        self.btn_network_monitor.setCheckable(True)
        self.btn_network_monitor.toggled.connect(self.toggle_network_monitor)
        self.network_interval_spin = QSpinBox()
        self.network_interval_spin.setRange(1, 30)
        self.network_interval_spin.setValue(3)
        self.network_interval_spin.setSuffix(" sec")
        controls.addWidget(btn_refresh_net)
        controls.addWidget(self.btn_network_monitor)
        controls.addWidget(QLabel("Every:"))
        controls.addWidget(self.network_interval_spin)
        controls.addStretch(1)
        layout.addLayout(controls)

        filter_box = QGroupBox("Network Filters")
        filter_grid = QGridLayout(filter_box)
        self.network_proto_filter = QComboBox()
        self.network_proto_filter.addItems(["Any Protocol", "TCP only", "UDP only"])
        self.network_proto_filter.setMinimumWidth(170)
        self.network_proto_filter.currentIndexChanged.connect(lambda _=None: self.apply_network_filters())
        self.network_state_filter = QComboBox()
        self.network_state_filter.addItems(["Any State", "ESTABLISHED", "LISTEN", "TIME-WAIT", "CLOSE-WAIT", "SYN-SENT", "UNCONN"])
        self.network_state_filter.setMinimumWidth(190)
        self.network_state_filter.currentIndexChanged.connect(lambda _=None: self.apply_network_filters())
        self.network_filter_input = QLineEdit()
        self.network_filter_input.setPlaceholderText("Search all fields...")
        self.network_filter_input.textChanged.connect(lambda _=None: self.apply_network_filters())
        self.network_host_filter = QLineEdit()
        self.network_host_filter.setPlaceholderText("Remote/local IP or host...")
        self.network_host_filter.textChanged.connect(lambda _=None: self.apply_network_filters())
        self.network_process_filter = QLineEdit()
        self.network_process_filter.setPlaceholderText("Process/package...")
        self.network_process_filter.textChanged.connect(lambda _=None: self.apply_network_filters())
        self.network_port_filter = QLineEdit()
        self.network_port_filter.setPlaceholderText("Ports/ranges: 80,443,8000-9000")
        self.network_port_filter.textChanged.connect(lambda _=None: self.apply_network_filters())
        btn_clear_filters = QPushButton("Clear Filters")
        btn_clear_filters.clicked.connect(self.clear_network_filters)
        filter_grid.addWidget(QLabel("Protocol:"), 0, 0)
        filter_grid.addWidget(self.network_proto_filter, 0, 1)
        filter_grid.addWidget(QLabel("State:"), 0, 2)
        filter_grid.addWidget(self.network_state_filter, 0, 3)
        filter_grid.addWidget(QLabel("Search:"), 0, 4)
        filter_grid.addWidget(self.network_filter_input, 0, 5)
        filter_grid.addWidget(QLabel("Host/IP:"), 1, 0)
        filter_grid.addWidget(self.network_host_filter, 1, 1)
        filter_grid.addWidget(QLabel("Process:"), 1, 2)
        filter_grid.addWidget(self.network_process_filter, 1, 3)
        filter_grid.addWidget(QLabel("Ports:"), 1, 4)
        filter_grid.addWidget(self.network_port_filter, 1, 5)
        filter_grid.addWidget(btn_clear_filters, 1, 6)
        filter_grid.setColumnStretch(5, 1)
        layout.addWidget(filter_box)

        self.network_table = QTableWidget(0, 6)
        self.network_table.setHorizontalHeaderLabels(["Proto", "Local", "Remote", "State", "Process", "Raw"])
        self.network_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.network_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.network_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.network_table.setMouseTracking(True)
        self.network_table.setToolTipDuration(30000)
        self.network_table.itemDoubleClicked.connect(self.show_network_row_details)
        self.network_all_rows = []
        layout.addWidget(self.network_table, 2)

        capture_box = QGroupBox("Packet Capture / PCAP")
        capture_layout = QHBoxLayout(capture_box)
        btn_start_cap = QPushButton("● Start tcpdump")
        btn_start_cap.setObjectName("runBtn")
        btn_start_cap.clicked.connect(self.start_network_capture)
        btn_stop_cap = QPushButton("■ Stop + Pull PCAP")
        btn_stop_cap.setObjectName("killBtn")
        btn_stop_cap.clicked.connect(self.stop_network_capture)
        btn_open_cap = QPushButton("📁 Open Capture Folder")
        btn_open_cap.clicked.connect(self.open_network_capture_folder)
        self.network_capture_label = QLabel("Capture: idle")
        self.network_capture_label.setStyleSheet("color: #8b949e;")
        capture_layout.addWidget(btn_start_cap)
        capture_layout.addWidget(btn_stop_cap)
        capture_layout.addWidget(btn_open_cap)
        capture_layout.addWidget(self.network_capture_label, 1)
        layout.addWidget(capture_box)

        snippets_box = QGroupBox("App-Layer / Socket Data Frida Snippets")
        snippets_layout = QHBoxLayout(snippets_box)
        self.network_payload_format = QComboBox()
        self.network_payload_format.addItems(["Auto Text", "Text", "JSON Pretty", "Hex", "Hex + ASCII"])
        self.network_payload_format.setMinimumWidth(150)
        snippets_layout.addWidget(QLabel("Payload View:"))
        snippets_layout.addWidget(self.network_payload_format)
        for label, key in [
            ("REST/OkHttp Req+Resp", "rest"),
            ("HTTP/URLConnection", "http"),
            ("Chrome/Cronet Java", "cronet"),
            ("Native TLS SSL_read/write", "tls"),
            ("OkHttp/WebSocket", "websocket"),
            ("MQTT/Paho", "mqtt"),
            ("Native socket data", "native"),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked=False, k=key: self.insert_network_snippet(k))
            snippets_layout.addWidget(btn)
        snippets_layout.addStretch()
        layout.addWidget(snippets_box)

        self.network_log = QTextEdit()
        self.network_log.setReadOnly(True)
        self.network_log.setFont(QFont("Menlo" if sys.platform == "darwin" else "Monospace", 10))
        self.network_log.setStyleSheet("background: #010409; color: #d1d5da;")
        self.network_log.setMinimumHeight(130)
        layout.addWidget(self.network_log, 1)

        self.network_timer = QTimer(self)
        self.network_timer.timeout.connect(self.refresh_network_connections)
        self.tabs.addTab(tab, "🌐 Network")

    def append_network_log(self, message, color="#c9d1d9"):
        if hasattr(self, "network_log"):
            self.network_log.append(f"<font color='{color}'>[{time.strftime('%H:%M:%S')}] {html.escape(str(message))}</font>")
            self.network_log.moveCursor(QTextCursor.End)

    def refresh_network_connections(self):
        if hasattr(self, "network_worker") and self.network_worker.isRunning():
            return
        # Capture all socket rows, then apply UI filters without discarding data.
        self.network_worker = NetworkSnapshotWorker("")
        self.network_worker.rows_signal.connect(self.populate_network_rows)
        self.network_worker.log_signal.connect(self.append_network_log)
        self.network_worker.start()

    def clear_network_filters(self):
        if hasattr(self, "network_proto_filter"):
            self.network_proto_filter.setCurrentIndex(0)
        if hasattr(self, "network_state_filter"):
            self.network_state_filter.setCurrentIndex(0)
        for attr in ["network_filter_input", "network_host_filter", "network_process_filter", "network_port_filter"]:
            w = getattr(self, attr, None)
            if w:
                w.clear()
        self.apply_network_filters()

    def network_row_key(self, row_data):
        normalized = list(row_data[:6]) + [""] * max(0, 6 - len(row_data))
        return "|".join(str(x) for x in normalized[:6])

    def selected_network_row_key(self):
        try:
            row = self.network_table.currentRow()
            if row >= 0:
                item = self.network_table.item(row, 0)
                data = item.data(Qt.UserRole) if item else None
                if data:
                    return self.network_row_key(data)
        except Exception:
            pass
        return None

    def parse_network_port_ranges(self, text_value):
        ranges = []
        for token in re.split(r"[,\s]+", str(text_value or "").strip()):
            if not token:
                continue
            if "-" in token:
                a, b = token.split("-", 1)
                if a.strip().isdigit() and b.strip().isdigit():
                    lo, hi = int(a), int(b)
                    if lo > hi:
                        lo, hi = hi, lo
                    ranges.append((lo, hi))
            elif token.isdigit():
                p = int(token)
                ranges.append((p, p))
        return ranges

    def network_extract_port(self, addr):
        text_value = str(addr or "")
        m = re.search(r":(\d+)$", text_value)
        if m:
            return int(m.group(1))
        m = re.search(r"\]:(\d+)$", text_value)
        if m:
            return int(m.group(1))
        return None

    def network_row_matches_filters(self, row_data):
        row = list(row_data[:6]) + [""] * max(0, 6 - len(row_data))
        proto, local, remote, state, proc, raw = [str(x or "") for x in row[:6]]
        joined = " ".join(row).lower()
        proto_filter = self.network_proto_filter.currentText().lower() if hasattr(self, "network_proto_filter") else "any"
        state_filter = self.network_state_filter.currentText().lower() if hasattr(self, "network_state_filter") else "any"
        search = self.network_filter_input.text().lower().strip() if hasattr(self, "network_filter_input") else ""
        host = self.network_host_filter.text().lower().strip() if hasattr(self, "network_host_filter") else ""
        proc_filter = self.network_process_filter.text().lower().strip() if hasattr(self, "network_process_filter") else ""
        port_ranges = self.parse_network_port_ranges(self.network_port_filter.text() if hasattr(self, "network_port_filter") else "")
        if proto_filter.startswith("tcp") and "tcp" not in proto.lower():
            return False
        if proto_filter.startswith("udp") and "udp" not in proto.lower():
            return False
        if not state_filter.startswith("any") and state_filter not in state.lower() and state_filter not in raw.lower():
            return False
        if search and search not in joined:
            return False
        if host and host not in local.lower() and host not in remote.lower() and host not in raw.lower():
            return False
        if proc_filter and proc_filter not in proc.lower() and proc_filter not in raw.lower():
            return False
        if port_ranges:
            local_port = self.network_extract_port(local)
            remote_port = self.network_extract_port(remote)
            ports = [p for p in [local_port, remote_port] if p is not None]
            if not any(lo <= p <= hi for p in ports for lo, hi in port_ranges):
                return False
        return True

    def apply_network_filters(self):
        rows = getattr(self, "network_all_rows", []) or []
        filtered = [r for r in rows if self.network_row_matches_filters(r)]
        self.update_network_table(filtered)

    def network_row_tooltip(self, row_data):
        fields = ["Protocol", "Local", "Remote", "State", "Process", "Raw"]
        parts = []
        for name, value in zip(fields, list(row_data or [])[:6]):
            parts.append(f"<b>{html.escape(name)}:</b> {html.escape(str(value))}")
        return "<br>".join(parts)

    def network_row_plain_details(self, row_data):
        fields = ["Protocol", "Local", "Remote", "State", "Process", "Raw"]
        lines = []
        for name, value in zip(fields, list(row_data or [])[:6]):
            lines.append(f"{name}: {value}")
        return "\n".join(lines)

    def populate_network_rows(self, rows):
        self.network_all_rows = [list(r[:6]) + [""] * max(0, 6 - len(r)) for r in (rows or [])]
        self.apply_network_filters()

    def update_network_table(self, rows):
        selected_key = self.selected_network_row_key()
        try:
            vscroll = self.network_table.verticalScrollBar().value()
        except Exception:
            vscroll = 0
        self.network_table.setSortingEnabled(False)
        needed = len(rows or [])
        while self.network_table.rowCount() < needed:
            self.network_table.insertRow(self.network_table.rowCount())
        while self.network_table.rowCount() > needed:
            self.network_table.removeRow(self.network_table.rowCount() - 1)
        reselect_row = -1
        for r, row_data in enumerate(rows or []):
            normalized = list(row_data[:6]) + [""] * max(0, 6 - len(row_data))
            tooltip = self.network_row_tooltip(normalized)
            key = self.network_row_key(normalized)
            if key == selected_key:
                reselect_row = r
            for c, val in enumerate(normalized[:6]):
                item = self.network_table.item(r, c)
                if item is None:
                    item = QTableWidgetItem()
                    self.network_table.setItem(r, c, item)
                item.setText(str(val))
                item.setToolTip(tooltip)
                item.setData(Qt.UserRole, normalized)
                if c == 0:
                    item.setForeground(QColor("#79c0ff"))
                elif c == 2:
                    item.setForeground(QColor("#7ee787"))
                else:
                    item.setForeground(QColor("#c9d1d9"))
        self.network_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        if reselect_row >= 0:
            self.network_table.selectRow(reselect_row)
        try:
            self.network_table.verticalScrollBar().setValue(vscroll)
        except Exception:
            pass

    def show_network_row_details(self, item):
        if item is None:
            return
        row = item.row()
        first = self.network_table.item(row, 0)
        row_data = first.data(Qt.UserRole) if first else None
        if not row_data:
            row_data = []
            for c in range(self.network_table.columnCount()):
                cell = self.network_table.item(row, c)
                row_data.append(cell.text() if cell else "")
        detail_text = self.network_row_plain_details(row_data)
        dlg = QDialog(self)
        dlg.setWindowTitle("Network Connection Details")
        dlg.resize(900, 520)
        dlg_layout = QVBoxLayout(dlg)
        header = QLabel("Full Android network connection row details")
        header.setStyleSheet("color: #58a6ff; font-weight: bold; padding: 4px;")
        dlg_layout.addWidget(header)
        details = QTextEdit()
        details.setReadOnly(True)
        details.setFont(QFont("Menlo" if sys.platform == "darwin" else "Monospace", 10))
        details.setStyleSheet("background: #010409; color: #d1d5da;")
        details.setPlainText(detail_text)
        dlg_layout.addWidget(details, 1)
        btn_row = QHBoxLayout()
        btn_copy = QPushButton("📋 Copy")
        btn_copy.clicked.connect(lambda: QApplication.clipboard().setText(detail_text))
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        btn_row.addStretch(1)
        btn_row.addWidget(btn_copy)
        btn_row.addWidget(btn_close)
        dlg_layout.addLayout(btn_row)
        dlg.exec_()

    def toggle_network_monitor(self, enabled):
        if enabled:
            self.btn_network_monitor.setText("🛑 Stop Monitor")
            self.network_timer.start(self.network_interval_spin.value() * 1000)
            self.refresh_network_connections()
            self.append_network_log("Network monitor started.", "#58a6ff")
        else:
            self.btn_network_monitor.setText("▶ Monitor")
            self.network_timer.stop()
            self.append_network_log("Network monitor stopped.", "#8b949e")

    def start_network_capture(self):
        ts = int(time.time())
        self.network_remote_pcap = f"/data/local/tmp/uft_capture_{ts}.pcap"
        cmd = f"{ADB_PATH} shell \"su -c 'pkill -2 tcpdump 2>/dev/null; tcpdump -i any -s 0 -w {self.network_remote_pcap} >/dev/null 2>&1 &'\""
        self.run_adb_cmd(cmd)
        if hasattr(self, "network_capture_label"):
            self.network_capture_label.setText(f"Capture running: {self.network_remote_pcap}")
            self.network_capture_label.setStyleSheet("color: #7ee787;")
        self.append_network_log("Started tcpdump capture. Requires tcpdump on device/root.", "#7ee787")

    def stop_network_capture(self):
        remote = getattr(self, "network_remote_pcap", "")
        self.run_adb_cmd(f"{ADB_PATH} shell \"su -c 'pkill -2 tcpdump 2>/dev/null'\"")
        if remote:
            local = os.path.join(NETWORK_CAPTURE_DIR, os.path.basename(remote))
            QTimer.singleShot(900, lambda: self.run_adb_cmd(f"{ADB_PATH} pull '{remote}' '{local}'"))
            QTimer.singleShot(1500, lambda: self.run_adb_cmd(f"{ADB_PATH} shell \"su -c 'rm -f {remote}'\""))
            if hasattr(self, "network_capture_label"):
                self.network_capture_label.setText(f"Pulled capture to: {local}")
                self.network_capture_label.setStyleSheet("color: #58a6ff;")
            self.append_network_log(f"Stopped capture and requested pull to {local}", "#58a6ff")
        else:
            self.append_network_log("No active capture path recorded.", "#ffa657")

    def open_network_capture_folder(self):
        os.makedirs(NETWORK_CAPTURE_DIR, exist_ok=True)
        try:
            if sys.platform == "darwin":
                subprocess.Popen(["open", NETWORK_CAPTURE_DIR])
            elif sys.platform == "win32":
                os.startfile(NETWORK_CAPTURE_DIR)
            else:
                subprocess.Popen(["xdg-open", NETWORK_CAPTURE_DIR])
        except Exception as e:
            self.append_network_log(f"Could not open capture folder: {e}", "#ff7b72")

    def insert_network_snippet(self, kind):
        snippets = {
            "rest": r"""// REST/HTTP inspector for OkHttp + HttpURLConnection - Frida 17 compatible
// Logs request method/url/headers and response code/body preview where available.
Java.perform(function() {
    console.log('[REST] Android app-layer REST/HTTP inspector loaded');

    function safeString(v) {
        try { return (v === null || v === undefined) ? '<null>' : String(v); }
        catch (e) { return '<string-error:' + e + '>'; }
    }

    function logBlock(title, body) {
        console.log('\n========== ' + title + ' ==========' );
        console.log(body);
        console.log('========== END ' + title + ' ==========\n');
    }

    // OkHttp request/response visibility.
    try {
        var RealCall = Java.use('okhttp3.RealCall');
        var Buffer = null;
        try { Buffer = Java.use('okio.Buffer'); } catch (_) {}

        function dumpRequest(req) {
            try {
                var out = [];
                out.push('METHOD: ' + req.method());
                out.push('URL: ' + req.url().toString());
                out.push('HEADERS:\n' + req.headers().toString());
                try {
                    var body = req.body();
                    if (body !== null && Buffer !== null) {
                        var buffer = Buffer.$new();
                        body.writeTo(buffer);
                        out.push('BODY:\n' + buffer.readUtf8());
                    }
                } catch (bodyErr) {
                    out.push('BODY: <unreadable: ' + bodyErr + '>');
                }
                logBlock('OkHttp REQUEST', out.join('\n'));
            } catch (e) {
                console.log('[REST] dumpRequest error: ' + e);
            }
        }

        function dumpResponse(resp) {
            try {
                var out = [];
                out.push('CODE: ' + resp.code());
                out.push('MESSAGE: ' + resp.message());
                out.push('URL: ' + resp.request().url().toString());
                out.push('HEADERS:\n' + resp.headers().toString());
                try {
                    var peek = resp.peekBody(1024 * 1024);
                    out.push('BODY PREVIEW:\n' + peek.string());
                } catch (bodyErr) {
                    out.push('BODY PREVIEW: <unreadable: ' + bodyErr + '>');
                }
                logBlock('OkHttp RESPONSE', out.join('\n'));
            } catch (e) {
                console.log('[REST] dumpResponse error: ' + e);
            }
        }

        RealCall.execute.implementation = function() {
            dumpRequest(this.request());
            var response = this.execute();
            dumpResponse(response);
            return response;
        };

        RealCall.enqueue.implementation = function(callback) {
            dumpRequest(this.request());
            return this.enqueue(callback);
        };

        console.log('[REST] OkHttp RealCall hooks installed');
    } catch (e) {
        console.log('[REST] OkHttp not hooked: ' + e);
    }

    // Basic HttpURLConnection visibility. Good for older Java networking stacks.
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overloads.forEach(function(ov) {
            ov.implementation = function() {
                console.log('[URLConnection] openConnection -> ' + this.toString());
                return ov.apply(this, arguments);
            };
        });

        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getResponseCode.implementation = function() {
            var code = this.getResponseCode();
            try {
                console.log('[HttpURLConnection] ' + this.getRequestMethod() + ' ' + this.getURL().toString() + ' -> ' + code);
            } catch (_) {}
            return code;
        };
        console.log('[REST] HttpURLConnection hooks installed');
    } catch (e) {
        console.log('[REST] HttpURLConnection not hooked: ' + e);
    }
});
""",
            "http": r"""// HTTP/URLConnection visibility helper - Frida 17 compatible
Java.perform(function() {
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overloads.forEach(function(ov) {
            ov.implementation = function() {
                console.log('[HTTP] openConnection -> ' + this.toString());
                return ov.apply(this, arguments);
            };
        });
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getResponseCode.implementation = function() {
            var code = this.getResponseCode();
            try { console.log('[HTTP] ' + this.getRequestMethod() + ' ' + this.getURL().toString() + ' -> ' + code); } catch (_) {}
            return code;
        };
        console.log('[HTTP] URLConnection hooks active');
    } catch (e) { console.log('[HTTP] URLConnection hook failed: ' + e); }
});
""",
            "cronet": r"""// Chrome/Cronet Java visibility helper - Frida 17 compatible
// For apps using the public org.chromium.net Cronet API. Chrome itself often uses internal/native paths,
// so this may show class-not-found or builder activity only. Pair with TLS/native hooks for Chrome.
Java.perform(function() {
    console.log('[Cronet] Chrome/Cronet Java hook starting');

    function tryHook(name, fn) {
        try { fn(); console.log('[Cronet] Hooked ' + name); }
        catch (e) { console.log('[Cronet] ' + name + ' not hooked: ' + e); }
    }

    tryHook('org.chromium.net.CronetEngine$Builder.build', function() {
        var Builder = Java.use('org.chromium.net.CronetEngine$Builder');
        Builder.build.implementation = function() {
            console.log('[Cronet] CronetEngine.Builder.build()');
            return this.build();
        };
    });

    tryHook('org.chromium.net.CronetEngine.newUrlRequestBuilder', function() {
        var Engine = Java.use('org.chromium.net.CronetEngine');
        Engine.newUrlRequestBuilder.overload('java.lang.String', 'org.chromium.net.UrlRequest$Callback', 'java.util.concurrent.Executor').implementation = function(url, cb, executor) {
            console.log('[Cronet] newUrlRequestBuilder URL=' + url);
            return this.newUrlRequestBuilder(url, cb, executor);
        };
    });

    tryHook('org.chromium.net.UrlRequest$Builder methods', function() {
        var ReqBuilder = Java.use('org.chromium.net.UrlRequest$Builder');
        ReqBuilder.setHttpMethod.implementation = function(method) {
            console.log('[Cronet] setHttpMethod ' + method);
            return this.setHttpMethod(method);
        };
        ReqBuilder.addHeader.implementation = function(name, value) {
            console.log('[Cronet] addHeader ' + name + ': ' + value);
            return this.addHeader(name, value);
        };
        ReqBuilder.build.implementation = function() {
            console.log('[Cronet] UrlRequest.Builder.build()');
            return this.build();
        };
    });

    tryHook('org.chromium.net.UrlRequest.start', function() {
        var UrlRequest = Java.use('org.chromium.net.UrlRequest');
        UrlRequest.start.implementation = function() {
            console.log('[Cronet] UrlRequest.start()');
            return this.start();
        };
    });

    console.log('[Cronet] Java hooks installed where classes exist');
});
""",
            "tls": r"""// Native TLS plaintext visibility helper - Frida 17 compatible
// Attempts to hook SSL_read/SSL_write exports. Works when BoringSSL/OpenSSL symbols are exported.
// Chrome/Cronet may statically link or hide these symbols, so this is best-effort.
(function() {
    console.log('[TLS] Native SSL_read/SSL_write hook starting');

    function preview(ptrValue, lenValue) {
        try {
            var len = parseInt(lenValue);
            if (!ptrValue || ptrValue.isNull() || len <= 0) return '<empty>';
            var max = Math.min(len, 4096);
            var bytes = ptrValue.readByteArray(max);
            var u8 = new Uint8Array(bytes);
            var ascii = '';
            for (var i = 0; i < u8.length; i++) {
                var c = u8[i];
                ascii += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '.';
            }
            return ascii;
        } catch (e) { return '<preview error: ' + e + '>'; }
    }

    function findSymbolEverywhere(names) {
        var found = [];
        names.forEach(function(name) {
            try {
                var g = Module.findGlobalExportByName(name);
                if (g) found.push({ name: name, address: g, module: 'global' });
            } catch (_) {}
        });
        try {
            Process.enumerateModules().forEach(function(m) {
                try {
                    var syms = m.enumerateSymbols();
                    syms.forEach(function(s) {
                        names.forEach(function(name) {
                            if (s.name === name || s.name.indexOf(name) !== -1) {
                                found.push({ name: s.name, address: s.address, module: m.name });
                            }
                        });
                    });
                } catch (_) {}
            });
        } catch (_) {}
        return found;
    }

    var hooked = {};
    var candidates = findSymbolEverywhere(['SSL_write', 'SSL_read']);
    candidates.forEach(function(c) {
        var key = c.module + ':' + c.name + ':' + c.address;
        if (hooked[key]) return;
        hooked[key] = true;
        try {
            if (c.name.indexOf('SSL_write') !== -1) {
                Interceptor.attach(c.address, {
                    onEnter: function(args) {
                        var len = args[2].toInt32();
                        console.log('\n[TLS WRITE] ' + c.module + '!' + c.name + ' len=' + len + '\n' + preview(args[1], len));
                    }
                });
                console.log('[TLS] Hooked WRITE ' + c.module + '!' + c.name + ' @ ' + c.address);
            } else if (c.name.indexOf('SSL_read') !== -1) {
                Interceptor.attach(c.address, {
                    onEnter: function(args) { this.buf = args[1]; },
                    onLeave: function(retval) {
                        var len = retval.toInt32();
                        if (len > 0) console.log('\n[TLS READ] ' + c.module + '!' + c.name + ' len=' + len + '\n' + preview(this.buf, len));
                    }
                });
                console.log('[TLS] Hooked READ ' + c.module + '!' + c.name + ' @ ' + c.address);
            }
        } catch (e) { console.log('[TLS] Failed hook ' + c.module + '!' + c.name + ': ' + e); }
    });
    console.log('[TLS] Hook count=' + Object.keys(hooked).length + '. If zero, symbols are hidden/static; use Android global proxy + trusted CA or deeper native tracing.');
})();
""",
            "websocket": r"""// OkHttp WebSocket visibility helper - Frida 17 compatible
Java.perform(function() {
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newWebSocket.implementation = function(request, listener) {
            try { console.log('[WebSocket] newWebSocket -> ' + request.url().toString()); } catch (_) {}
            return this.newWebSocket(request, listener);
        };
        try {
            var RealWebSocket = Java.use('okhttp3.internal.ws.RealWebSocket');
            RealWebSocket.send.overload('java.lang.String').implementation = function(text) {
                console.log('[WebSocket] send text -> ' + text);
                return this.send(text);
            };
            RealWebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
                console.log('[WebSocket] send bytes -> ' + bytes.hex());
                return this.send(bytes);
            };
        } catch (inner) { console.log('[WebSocket] RealWebSocket send hooks unavailable: ' + inner); }
        console.log('[WebSocket] OkHttp WebSocket hooks active');
    } catch (e) { console.log('[WebSocket] OkHttp classes not found: ' + e); }
});
""",
            "mqtt": r"""// MQTT/Paho visibility helper - Frida 17 compatible
Java.perform(function() {
    function dumpMqttMessage(msg) {
        try {
            var payload = msg.getPayload();
            var JString = Java.use('java.lang.String');
            return JString.$new(payload);
        } catch (e) { return '<payload unreadable: ' + e + '>'; }
    }
    try {
        var Client = Java.use('org.eclipse.paho.client.mqttv3.MqttAsyncClient');
        Client.publish.overloads.forEach(function(ov) {
            ov.implementation = function() {
                try {
                    var topic = arguments[0];
                    var detail = '[MQTT] publish topic=' + topic;
                    if (arguments.length > 1) detail += ' payload=' + dumpMqttMessage(arguments[1]);
                    console.log(detail);
                } catch (e) { console.log('[MQTT] publish log error: ' + e); }
                return ov.apply(this, arguments);
            };
        });
        console.log('[MQTT] Paho publish hooks active');
    } catch (e) { console.log('[MQTT] Paho classes not found: ' + e); }
});
""",
            "native": r"""// Native socket send/recv/connect visibility helper - Frida 17
// Payload view mode is selected in the Network tab before inserting this snippet.
var UFT_SOCKET_DATA_MODE = "__UFT_PAYLOAD_MODE__";
function uftFormatBytes(ptrValue, lenValue) {
    try {
        var len = parseInt(lenValue);
        if (!ptrValue || ptrValue.isNull() || len <= 0) return '<empty>';
        var max = Math.min(len, 8192);
        var bytes = ptrValue.readByteArray(max);
        var u8 = new Uint8Array(bytes);
        var text = '';
        for (var i = 0; i < u8.length; i++) {
            var c = u8[i];
            text += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : '.';
        }
        if (UFT_SOCKET_DATA_MODE.indexOf('json') !== -1) {
            try { return JSON.stringify(JSON.parse(text), null, 2); } catch (_) { return text; }
        }
        if (UFT_SOCKET_DATA_MODE === 'text' || UFT_SOCKET_DATA_MODE.indexOf('auto') !== -1) return text;
        if (UFT_SOCKET_DATA_MODE.indexOf('hex + ascii') !== -1) return hexdump(ptrValue, { length: max, ansi: false });
        if (UFT_SOCKET_DATA_MODE.indexOf('hex') !== -1) {
            var hex = [];
            for (var j = 0; j < u8.length; j++) hex.push(('0' + u8[j].toString(16)).slice(-2));
            return hex.join(' ');
        }
        return text;
    } catch (e) { return '<format error: ' + e + '>'; }
}
['connect','send','recv','sendto','recvfrom'].forEach(function(name) {
    var addr = Module.findGlobalExportByName(name);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function(args) {
                this.name = name;
                if (name === 'send' || name === 'sendto') {
                    try {
                        var len = args[2].toInt32();
                        if (len > 0) console.log('
[NATIVE ' + name.toUpperCase() + '] len=' + len + ' mode=' + UFT_SOCKET_DATA_MODE + '
' + uftFormatBytes(args[1], len));
                    } catch (e) { console.log('[NATIVE NET] send format error: ' + e); }
                } else if (name === 'recv' || name === 'recvfrom') {
                    this.buf = args[1];
                } else {
                    console.log('[NATIVE NET] ' + name + ' called');
                }
            },
            onLeave: function(retval) {
                if (this.name === 'recv' || this.name === 'recvfrom') {
                    try {
                        var len = retval.toInt32();
                        if (len > 0) console.log('
[NATIVE ' + this.name.toUpperCase() + '] len=' + len + ' mode=' + UFT_SOCKET_DATA_MODE + '
' + uftFormatBytes(this.buf, len));
                    } catch (e) { console.log('[NATIVE NET] recv format error: ' + e); }
                }
            }
        });
    }
});
""",
        }
        snippet = snippets.get(kind, "")
        if not snippet:
            return
        payload_mode = "auto text"
        if hasattr(self, "network_payload_format"):
            payload_mode = self.network_payload_format.currentText().lower().strip()
        snippet = snippet.replace("__UFT_PAYLOAD_MODE__", payload_mode)
        if hasattr(self, "editor"):
            self.editor.appendPlainText("\n" + snippet)
            self.switch_to_tab_containing("Frida Manager")
            self.append_network_log(f"Inserted {kind} Frida snippet into editor. Inject into the target app to see request/response logs in Frida Logs.", "#7ee787")
        else:
            self.append_network_log("Frida editor not available yet.", "#ff7b72")

    def setup_adb_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab)
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

    def setup_future_disabled_tools(self):
        """Reserve left-side menu entries for planned workspaces.

        These are intentionally disabled placeholders for now so the menu structure can grow
        without exposing unfinished functionality.
        """
        future_items = [
            ("📦 Apk Explorer", "APK Explorer workspace reserved for future implementation."),
            ("📤 Apk Extractor", "APK Extractor workspace reserved for future implementation."),
            ("✨ Beautifier", "Beautifier workspace reserved for future implementation."),
            ("🧊 Decrypt Cocoas", "Decrypt Cocoas workspace reserved for future implementation."),
            ("📝 PHA Notes", "PHA Notes workspace reserved for future implementation."),
            ("🧩 Rubiks", "Rubiks workspace reserved for future implementation."),
            ("🛡️ Security Review Workstation", "Security Review Workstation workspace reserved for future implementation."),
            ("🔐 Static Decrypter", "Static Decrypter workspace reserved for future implementation."),
            ("🧾 Strip Manifest", "Strip Manifest workspace reserved for future implementation."),
            ("🎮 Unity App Prepare", "Unity App Prepare workspace reserved for future implementation."),
        ]
        for title, message in future_items:
            if title.startswith("📦 Apk Explorer"):
                self.setup_apk_explorer_tab()
                continue
            if title.startswith("📤 Apk Extractor"):
                self.setup_apk_extractor_tab()
                continue
            if title.startswith("✨ Beautifier"):
                self.setup_beautifier_tab()
                continue
            if title.startswith("🧊 Decrypt Cocoas"):
                self.setup_decrypt_cocoas_tab()
                continue
            if title.startswith("🔐 Static Decrypter"):
                self.setup_static_decrypter_tab()
                continue
            if title.startswith("🧾 Strip Manifest"):
                self.setup_strip_manifest_tab()
                continue
            if title.startswith("🎮 Unity App Prepare"):
                self.setup_unity_app_prepare_tab()
                continue
            if title.startswith("📝 PHA Notes"):
                self.setup_pha_notes_tab()
                continue
            if title.startswith("🧩 Rubiks"):
                self.setup_rubiks_tab()
                continue
            if title.startswith("🛡️ Security Review Workstation"):
                self.setup_security_review_tab()
                continue
            if hasattr(self.tabs, 'addDisabledTab'):
                self.tabs.addDisabledTab(title, message)
            else:
                tab = QWidget()
                layout = QVBoxLayout(tab)
                lbl = QLabel(message)
                lbl.setAlignment(Qt.AlignCenter)
                lbl.setStyleSheet("color: #8b949e; font-size: 18px;")
                layout.addWidget(lbl)
                tab.setEnabled(False)
                self.tabs.addTab(tab, title)

    def setup_apk_explorer_tab(self):
        tab = ApkExplorerWorkspace(self)
        self.apk_explorer_workspace = tab
        self.tabs.addTab(tab, "📦 Apk Explorer")

    def setup_apk_extractor_tab(self):
        tab = ApkExtractorWorkspace(self)
        self.apk_extractor_workspace = tab
        self.tabs.addTab(tab, "📤 Apk Extractor")

    def setup_beautifier_tab(self):
        tab = JSBeautifierWorkspace(self)
        self.beautifier_workspace = tab
        self.tabs.addTab(tab, "✨ Beautifier")

    def setup_decrypt_cocoas_tab(self):
        tab = DecryptCocoasWorkspace(self)
        self.decrypt_cocoas_workspace = tab
        self.tabs.addTab(tab, "🧊 Decrypt Cocoas")

    def setup_unity_app_prepare_tab(self):
        tab = UnityAppPrepWorkspace(self)
        self.unity_app_prep_workspace = tab
        self.tabs.addTab(tab, "🎮 Unity App Prepare")

    def setup_static_decrypter_tab(self):
        tab = StaticDecrypterWorkspace(self)
        self.static_decrypter_workspace = tab
        self.tabs.addTab(tab, "🔐 Static Decrypter")

    def setup_strip_manifest_tab(self):
        tab = StripManifestWorkspace(self)
        self.strip_manifest_workspace = tab
        self.tabs.addTab(tab, "🧾 Strip Manifest")

    def setup_rubiks_tab(self):
        tab = RiskwareRubiksWorkspace(self)
        self.rubiks_workspace = tab
        self.tabs.addTab(tab, "🧩 Rubiks")

    def setup_security_review_tab(self):
        tab = SecurityReviewWorkspace(self)
        self.security_review_workspace = tab
        self.tabs.addTab(tab, "🛡️ Security Review Workstation")

    def setup_pha_notes_tab(self):
        tab = PhaNotesWorkspace(self)
        self.tabs.addTab(tab, "📝 PHA Notes")

    def add_settings_file_row(self, grid, row, label, line_attr, browse_title, file_filter="All Files (*)"):
        grid.addWidget(QLabel(label), row, 0)
        edit = QLineEdit()
        edit.setPlaceholderText(browse_title)
        setattr(self, line_attr, edit)
        grid.addWidget(edit, row, 1)
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda _=False, e=edit, t=browse_title, f=file_filter: self.browse_settings_file(e, t, f))
        grid.addWidget(btn, row, 2)
        return edit

    def add_settings_folder_row(self, grid, row, label, line_attr, browse_title):
        grid.addWidget(QLabel(label), row, 0)
        edit = QLineEdit()
        edit.setPlaceholderText(browse_title)
        setattr(self, line_attr, edit)
        grid.addWidget(edit, row, 1)
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda _=False, e=edit, t=browse_title: self.browse_settings_folder(e, t))
        grid.addWidget(btn, row, 2)
        return edit

    def browse_settings_file(self, edit, title, file_filter="All Files (*)"):
        path, _ = QFileDialog.getOpenFileName(self, title, "", file_filter)
        if path:
            edit.setText(path)

    def browse_settings_folder(self, edit, title):
        path = QFileDialog.getExistingDirectory(self, title, "")
        if path:
            edit.setText(path)

    def load_decrypt_cocoas_settings_into_settings(self):
        data = {"at": "", "rv": "", "pt": ""}
        try:
            if os.path.exists(DECRYPT_COCOAS_CONFIG_FILE):
                with open(DECRYPT_COCOAS_CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        data.update(loaded)
        except Exception as e:
            try:
                self.console.append(f"<font color='#ff7b72'>[SETTINGS] Failed to read Decrypt Cocoas settings: {html.escape(str(e))}</font>")
            except Exception:
                pass
        for attr, key in [
            ("settings_cocos_apktool_path", "at"),
            ("settings_cocos_reverse_path", "rv"),
            ("settings_cocos_prettier_path", "pt"),
        ]:
            if hasattr(self, attr):
                getattr(self, attr).setText(str(data.get(key, "") or ""))

    def save_decrypt_cocoas_settings_from_settings(self):
        data = {
            "at": self.settings_cocos_apktool_path.text().strip() if hasattr(self, "settings_cocos_apktool_path") else "",
            "rv": self.settings_cocos_reverse_path.text().strip() if hasattr(self, "settings_cocos_reverse_path") else "",
            "pt": self.settings_cocos_prettier_path.text().strip() if hasattr(self, "settings_cocos_prettier_path") else "",
        }
        os.makedirs(DECRYPT_COCOAS_BASE_PATH, exist_ok=True)
        with open(DECRYPT_COCOAS_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        # Keep the embedded Decrypt Cocoas workspace immediately in sync.
        if hasattr(self, "decrypt_cocoas_workspace"):
            self.decrypt_cocoas_workspace.binaries = dict(data)
        QMessageBox.information(self, "Decrypt Cocoas Settings", "Decrypt Cocoas binary paths saved.")

    def load_unity_app_prep_settings_into_settings(self):
        data = {"dumper": "", "output": "", "dotnet": "/usr/local/share/dotnet/dotnet" if os.path.exists("/usr/local/share/dotnet/dotnet") else "dotnet"}
        try:
            if os.path.exists(UNITY_APP_PREP_CONFIG_FILE):
                with open(UNITY_APP_PREP_CONFIG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict):
                        data.update(loaded)
        except Exception as e:
            try:
                self.console.append(f"<font color='#ff7b72'>[SETTINGS] Failed to read Unity App Prep settings: {html.escape(str(e))}</font>")
            except Exception:
                pass
        for attr, key in [
            ("settings_unity_dumper_path", "dumper"),
            ("settings_unity_output_path", "output"),
            ("settings_unity_dotnet_path", "dotnet"),
        ]:
            if hasattr(self, attr):
                getattr(self, attr).setText(str(data.get(key, "") or ""))

    def save_unity_app_prep_settings_from_settings(self):
        data = {
            "dumper": self.settings_unity_dumper_path.text().strip() if hasattr(self, "settings_unity_dumper_path") else "",
            "output": self.settings_unity_output_path.text().strip() if hasattr(self, "settings_unity_output_path") else "",
            "dotnet": self.settings_unity_dotnet_path.text().strip() if hasattr(self, "settings_unity_dotnet_path") else "",
        }
        os.makedirs(UNITY_APP_PREP_BASE_PATH, exist_ok=True)
        with open(UNITY_APP_PREP_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        if hasattr(self, "unity_app_prep_workspace"):
            self.unity_app_prep_workspace.dumper_path.setText(data.get("dumper", ""))
            self.unity_app_prep_workspace.out_path.setText(data.get("output", ""))
            self.unity_app_prep_workspace.dotnet_path.setText(data.get("dotnet", ""))
        QMessageBox.information(self, "Unity App Prepare Settings", "Unity App Prepare paths saved.")

    def sync_grouped_settings_from_live_widgets(self):
        # Mirrors current live widget values into the grouped settings page, if those duplicate controls exist.
        if hasattr(self, "settings_sidebar_width_spin") and hasattr(self, "tabs") and hasattr(self.tabs, "sidebar_width"):
            self.settings_sidebar_width_spin.setValue(int(self.tabs.sidebar_width()))
        if hasattr(self, "settings_frida_tree_width_spin") and hasattr(self, "frida_tree_width"):
            self.settings_frida_tree_width_spin.setValue(int(self.frida_tree_width()))
        if hasattr(self, "settings_frida_cli_path") and hasattr(self, "frida_cli_path"):
            self.settings_frida_cli_path.setText(self.frida_cli_path.text())
        if hasattr(self, "settings_frida_engine") and hasattr(self, "frida_injection_mode"):
            self.settings_frida_engine.setCurrentIndex(self.frida_injection_mode.currentIndex())
        self.load_decrypt_cocoas_settings_into_settings()
        self.load_unity_app_prep_settings_into_settings()

    def setup_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        title = QLabel("⚙ Settings grouped by workspace")
        title.setStyleSheet("color: #58a6ff; font-size: 18px; font-weight: bold; padding: 4px;")
        layout.addWidget(title)

        # General / Gallery
        general_box = QGroupBox("General / Gallery")
        general_grid = QGridLayout(general_box)
        general_grid.addWidget(QLabel("Screenshot / clipboard scale %:"), 0, 0)
        self.scale_spin = QSpinBox()
        self.scale_spin.setRange(10, 100)
        self.scale_spin.setValue(100)
        self.scale_spin.valueChanged.connect(self.save_settings)
        general_grid.addWidget(self.scale_spin, 0, 1)
        general_grid.setColumnStretch(2, 1)
        layout.addWidget(general_box)

        # Navigation / Layout
        nav_box = QGroupBox("Navigation / Layout")
        nav_grid = QGridLayout(nav_box)
        nav_grid.addWidget(QLabel("Sidebar width:"), 0, 0)
        self.settings_sidebar_width_spin = QSpinBox()
        self.settings_sidebar_width_spin.setRange(160, 520)
        self.settings_sidebar_width_spin.setValue(self.tabs.sidebar_width() if hasattr(self.tabs, "sidebar_width") else 245)
        self.settings_sidebar_width_spin.setSuffix(" px")
        self.settings_sidebar_width_spin.valueChanged.connect(lambda v: self.tabs.set_sidebar_width(v) if hasattr(self.tabs, "set_sidebar_width") else None)
        self.settings_sidebar_width_spin.valueChanged.connect(self.save_settings)
        nav_grid.addWidget(self.settings_sidebar_width_spin, 0, 1)
        nav_grid.addWidget(QLabel("Frida Manager file tree width:"), 1, 0)
        self.settings_frida_tree_width_spin = QSpinBox()
        self.settings_frida_tree_width_spin.setRange(180, 900)
        self.settings_frida_tree_width_spin.setValue(self.frida_tree_width() if hasattr(self, "frida_tree_width") else 420)
        self.settings_frida_tree_width_spin.setSuffix(" px")
        self.settings_frida_tree_width_spin.valueChanged.connect(lambda v: self.apply_frida_tree_width(v) if hasattr(self, "apply_frida_tree_width") else None)
        self.settings_frida_tree_width_spin.valueChanged.connect(self.save_settings)
        nav_grid.addWidget(self.settings_frida_tree_width_spin, 1, 1)
        nav_grid.setColumnStretch(2, 1)
        layout.addWidget(nav_box)

        # Frida Manager
        frida_box = QGroupBox("Frida Manager")
        frida_grid = QGridLayout(frida_box)
        frida_grid.addWidget(QLabel("Frida engine:"), 0, 0)
        self.settings_frida_engine = QComboBox()
        if hasattr(self, "frida_injection_mode"):
            for i in range(self.frida_injection_mode.count()):
                self.settings_frida_engine.addItem(self.frida_injection_mode.itemText(i), self.frida_injection_mode.itemData(i))
            self.settings_frida_engine.setCurrentIndex(self.frida_injection_mode.currentIndex())
        else:
            self.settings_frida_engine.addItem("Command Line / frida-tools", FRIDA_INJECTION_MODE_CLI)
            self.settings_frida_engine.addItem("Python API / frida module", FRIDA_INJECTION_MODE_PYTHON)
        self.settings_frida_engine.currentIndexChanged.connect(lambda idx: self.frida_injection_mode.setCurrentIndex(idx) if hasattr(self, "frida_injection_mode") else None)
        self.settings_frida_engine.currentIndexChanged.connect(self.save_settings)
        frida_grid.addWidget(self.settings_frida_engine, 0, 1)
        frida_grid.addWidget(QLabel("Frida CLI path:"), 1, 0)
        self.settings_frida_cli_path = QLineEdit(self.frida_cli_path.text() if hasattr(self, "frida_cli_path") else FRIDA_CLI_PATH)
        self.settings_frida_cli_path.textChanged.connect(lambda value: self.frida_cli_path.setText(value) if hasattr(self, "frida_cli_path") else None)
        self.settings_frida_cli_path.textChanged.connect(self.save_settings)
        frida_grid.addWidget(self.settings_frida_cli_path, 1, 1)
        btn_detect = QPushButton("Auto Detect")
        btn_detect.clicked.connect(self.detect_frida_cli_path)
        btn_detect.clicked.connect(lambda: self.settings_frida_cli_path.setText(self.frida_cli_path.text()) if hasattr(self, "frida_cli_path") else None)
        frida_grid.addWidget(btn_detect, 1, 2)
        frida_grid.addWidget(QLabel("Editor font size:"), 2, 0)
        if hasattr(self, "editor_font_spin"):
            frida_grid.addWidget(self.editor_font_spin, 2, 1)
        frida_grid.setColumnStretch(1, 1)
        layout.addWidget(frida_box)

        # Logs / Console text settings
        log_box = QGroupBox("Logs / Console Text")
        log_grid = QGridLayout(log_box)
        row = 0
        for label, attr in [
            ("Frida Logs font size:", "frida_log_font_spin"),
            ("LogCat font size:", "logcat_font_spin"),
            ("ADB Console font size:", "adb_console_font_spin"),
        ]:
            log_grid.addWidget(QLabel(label), row, 0)
            if hasattr(self, attr):
                log_grid.addWidget(getattr(self, attr), row, 1)
            row += 1
        if hasattr(self, "logcat_buffer_spin"):
            log_grid.addWidget(QLabel("LogCat buffer rows:"), row, 0)
            log_grid.addWidget(self.logcat_buffer_spin, row, 1)
            row += 1
        log_grid.setColumnStretch(2, 1)
        layout.addWidget(log_box)

        # Proxy
        proxy_box = QGroupBox("Proxy")
        proxy_grid = QGridLayout(proxy_box)
        if hasattr(self, "chk_include_socks_proxy"):
            proxy_grid.addWidget(self.chk_include_socks_proxy, 0, 0)
        proxy_grid.addWidget(QLabel("Validation timeout:"), 1, 0)
        if hasattr(self, "proxy_timeout_spin"):
            proxy_grid.addWidget(self.proxy_timeout_spin, 1, 1)
        if hasattr(self, "chk_clear_device_proxy_before_route"):
            proxy_grid.addWidget(self.chk_clear_device_proxy_before_route, 2, 0, 1, 2)
        if hasattr(self, "chk_apply_android_global_proxy_after_validation"):
            proxy_grid.addWidget(self.chk_apply_android_global_proxy_after_validation, 3, 0, 1, 2)
        if hasattr(self, "chk_android_global_proxy_only"):
            proxy_grid.addWidget(self.chk_android_global_proxy_only, 4, 0, 1, 2)
        proxy_grid.setColumnStretch(2, 1)
        layout.addWidget(proxy_box)

        # Decrypt Cocoas
        cocos_box = QGroupBox("Decrypt Cocoas")
        cocos_grid = QGridLayout(cocos_box)
        self.add_settings_file_row(cocos_grid, 0, "Apktool path:", "settings_cocos_apktool_path", "Select apktool", "All Files (*)")
        self.add_settings_file_row(cocos_grid, 1, "Reverse path:", "settings_cocos_reverse_path", "Select reverse tool", "All Files (*)")
        self.add_settings_file_row(cocos_grid, 2, "Prettier path:", "settings_cocos_prettier_path", "Select prettier", "All Files (*)")
        btn_save_cocos = QPushButton("💾 Save Decrypt Cocoas Settings")
        btn_save_cocos.clicked.connect(self.save_decrypt_cocoas_settings_from_settings)
        cocos_grid.addWidget(btn_save_cocos, 3, 0, 1, 3)
        cocos_grid.setColumnStretch(1, 1)
        layout.addWidget(cocos_box)

        # Unity App Prepare
        unity_box = QGroupBox("Unity App Prepare")
        unity_grid = QGridLayout(unity_box)
        self.add_settings_file_row(unity_grid, 0, "Il2CppDumper.dll:", "settings_unity_dumper_path", "Select Il2CppDumper.dll", "DLL (*.dll);;All Files (*)")
        self.add_settings_folder_row(unity_grid, 1, "Default output folder:", "settings_unity_output_path", "Select Unity prep output folder")
        self.add_settings_file_row(unity_grid, 2, "dotnet path:", "settings_unity_dotnet_path", "Select dotnet executable", "All Files (*)")
        btn_save_unity = QPushButton("💾 Save Unity App Prepare Settings")
        btn_save_unity.clicked.connect(self.save_unity_app_prep_settings_from_settings)
        unity_grid.addWidget(btn_save_unity, 3, 0, 1, 3)
        unity_grid.setColumnStretch(1, 1)
        layout.addWidget(unity_box)

        # Investigation Sessions
        session_box = QGroupBox("Investigation Session")
        session_layout = QHBoxLayout(session_box)
        btn_save_session = QPushButton("💾 Save Session")
        btn_save_session.clicked.connect(self.save_investigation_session)
        btn_load_session = QPushButton("📂 Load Session")
        btn_load_session.clicked.connect(self.load_investigation_session)
        session_layout.addWidget(btn_save_session)
        session_layout.addWidget(btn_load_session)
        session_layout.addStretch(1)
        layout.addWidget(session_box)

        self.load_decrypt_cocoas_settings_into_settings()
        self.load_unity_app_prep_settings_into_settings()
        layout.addStretch()
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

        self.adb_console_font_spin = QSpinBox()
        self.adb_console_font_spin.setRange(8, 40)
        self.adb_console_font_spin.setValue(10)
        self.adb_console_font_spin.setSuffix(" pt")
        self.adb_console_font_spin.setToolTip("ADB Console font size. You can also use Cmd/Ctrl + mouse wheel or trackpad pinch.")
        btn_adb_font_down = QPushButton("A−")
        btn_adb_font_down.setToolTip("Decrease ADB Console font size")
        btn_adb_font_down.clicked.connect(lambda: self.console.zoom_out_font())
        btn_adb_font_up = QPushButton("A+")
        btn_adb_font_up.setToolTip("Increase ADB Console font size")
        btn_adb_font_up.clicked.connect(lambda: self.console.zoom_in_font())
        btn_adb_font_reset = QPushButton("A0")
        btn_adb_font_reset.setToolTip("Reset ADB Console font size")
        btn_adb_font_reset.clicked.connect(lambda: self.console.reset_font_zoom())
        btn_adb_text_settings = QPushButton("⚙")
        btn_adb_text_settings.setFixedWidth(38)
        btn_adb_text_settings.setToolTip("ADB Console text/font settings")
        btn_adb_text_settings.clicked.connect(lambda: self.show_text_settings_dialog("adb_console"))

        h_layout.addWidget(QLabel("ADB:"), 0);
        h_layout.addWidget(self.cmd_input, 1);
        h_layout.addWidget(btn_send, 0);
        h_layout.addWidget(btn_adb_text_settings, 0);
        layout.addLayout(h_layout)
        self.console = ZoomableLogTextEdit();
        self.console.setReadOnly(True);
        self.console.set_log_font_size(self.adb_console_font_spin.value(), emit_signal=False)
        self.console.fontSizeChanged.connect(self.on_adb_console_font_size_changed)
        self.adb_console_font_spin.valueChanged.connect(lambda size: self.set_log_view_font_size("adb_console", size))
        self.console.setStyleSheet("background: #010409; color: #d1d5da;");
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

            QTimer.singleShot(1500, self.refresh_proxy_country_counts)
        except Exception as e:
            QMessageBox.warning(self, "Editor Error", f"Could not launch system editor: {str(e)}")

    def load_proxy_file_records(self):
        if not os.path.exists(MANUAL_PROXY_FILE):
            return []
        try:
            with open(MANUAL_PROXY_FILE, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception as e:
            if hasattr(self, "adb_out"):
                self.adb_out.append(
                    f"<font color='#ff7b72'>[PROXY EDITOR] Failed to read proxy file for counts: {str(e)}</font>")
            return []

    def proxy_record_country_value(self, record):
        if not isinstance(record, dict):
            return ""
        geo = record.get("geolocation", {})
        country = geo.get("country", "") if isinstance(geo, dict) else ""
        if not country:
            country = record.get("country", "")
        return str(country).upper().strip()

    def proxy_record_matches_country(self, record, country_code):
        country_code = str(country_code).upper().strip()
        country_value = self.proxy_record_country_value(record)
        target_full_name = GLOBAL_COUNTRY_MAP.get(country_code, "").upper().strip()
        return country_value == country_code or bool(target_full_name and target_full_name in country_value)

    def normalize_proxy_protocol_value(self, proto):
        proto = str(proto or "http").lower().strip()
        if proto in ("socks", "socks4", "socks5"):
            return proto
        if proto in ("http", "https"):
            return proto
        return "http"

    def proxy_protocol_from_record(self, record):
        if not isinstance(record, dict):
            return "http"
        proto = str(record.get("protocol", "") or "").lower().strip()
        if not proto:
            proxy_url = str(record.get("proxy", "") or "").lower().strip()
            m = re.match(r'^([a-zA-Z0-9+.-]+)://', proxy_url)
            proto = m.group(1).lower() if m else "http"
        return self.normalize_proxy_protocol_value(proto)

    def proxy_protocol_family(self, proto):
        proto = self.normalize_proxy_protocol_value(proto)
        return "socks" if proto.startswith("socks") else "http"

    def include_socks_proxies(self):
        return bool(hasattr(self, "chk_include_socks_proxy") and self.chk_include_socks_proxy.isChecked())

    def proxy_protocol_allowed(self, proto, include_socks=None):
        if include_socks is None:
            include_socks = self.include_socks_proxies()
        family = self.proxy_protocol_family(proto)
        return family == "http" or bool(include_socks)

    def proxy_record_allowed_by_protocol(self, record, include_socks=None):
        return self.proxy_protocol_allowed(self.proxy_protocol_from_record(record), include_socks=include_socks)

    def proxy_country_protocol_counts(self, data=None):
        data = self.load_proxy_file_records() if data is None else data
        counts = {}
        known_codes = set()
        if hasattr(self, "proxy_priority_countries"):
            known_codes.update(self.proxy_priority_countries.values())
        if hasattr(self, "proxy_standard_countries"):
            known_codes.update(self.proxy_standard_countries.values())
        known_codes.update(GLOBAL_COUNTRY_MAP.keys())

        for code in known_codes:
            counts[code] = {"http": 0, "socks": 0}

        for record in data:
            if not isinstance(record, dict) or not record.get("ip") or not record.get("port"):
                continue
            proto = self.proxy_protocol_from_record(record)
            family = self.proxy_protocol_family(proto)
            matched = False
            for code in known_codes:
                if self.proxy_record_matches_country(record, code):
                    counts.setdefault(code, {"http": 0, "socks": 0})
                    counts[code][family] = counts[code].get(family, 0) + 1
                    matched = True
            if not matched:
                country_value = self.proxy_record_country_value(record)
                if country_value:
                    counts.setdefault(country_value, {"http": 0, "socks": 0})
                    counts[country_value][family] = counts[country_value].get(family, 0) + 1
        return counts

    def append_proxy_status(self, category, message, color=None):
        colors = {"INFO": "#58a6ff", "TESTING": "#8b949e", "WARN": "#ffa657", "SUCCESS": "#7ee787", "ERROR": "#ff7b72", "CRITICAL": "#f85149"}
        use_color = color or colors.get(str(category).upper(), "#c9d1d9")
        safe_msg = html.escape(str(message))
        line = f"<font color='{use_color}'>[PROXY] {safe_msg}</font>"
        if hasattr(self, "proxy_log"):
            self.proxy_log.append(line)
            self.proxy_log.moveCursor(QTextCursor.End)
        if hasattr(self, "adb_out"):
            self.adb_out.append(line.replace("[PROXY]", "[PROXY ROTATOR]"))

    def get_proxy_import_sources(self):
        return list(PROXY_IMPORT_SOURCES)

    def populate_proxy_source_list(self):
        if not hasattr(self, "proxy_source_list"):
            return
        self.proxy_source_list.clear()
        for src in self.get_proxy_import_sources():
            item = QListWidgetItem(src.get("name", src.get("id", "proxy-source")))
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            # Default to Proxifly + HTTP text lists, leave SOCKS opt-in so imports stay manageable.
            proto = str(src.get("protocol", "auto")).lower()
            checked = src.get("id") in ("proxifly_all_json", "thespeedx_http", "monosans_http", "jetkai_http")
            item.setCheckState(Qt.Checked if checked else Qt.Unchecked)
            item.setData(Qt.UserRole, src)
            item.setToolTip(src.get("url", ""))
            self.proxy_source_list.addItem(item)

    def set_proxy_source_checks(self, checked):
        if not hasattr(self, "proxy_source_list"):
            return
        for i in range(self.proxy_source_list.count()):
            self.proxy_source_list.item(i).setCheckState(Qt.Checked if checked else Qt.Unchecked)

    def select_proxy_sources_by_family(self, family):
        if not hasattr(self, "proxy_source_list"):
            return
        family = str(family or "").lower()
        for i in range(self.proxy_source_list.count()):
            item = self.proxy_source_list.item(i)
            src = item.data(Qt.UserRole) or {}
            proto = str(src.get("protocol", "auto")).lower()
            if family == "http":
                checked = proto in ("auto", "http", "https")
            elif family == "socks":
                checked = proto in ("socks", "socks4", "socks5")
            else:
                checked = False
            item.setCheckState(Qt.Checked if checked else Qt.Unchecked)

    def selected_proxy_import_sources(self, all_sources=False):
        sources = []
        if all_sources or not hasattr(self, "proxy_source_list"):
            return self.get_proxy_import_sources()
        for i in range(self.proxy_source_list.count()):
            item = self.proxy_source_list.item(i)
            if item.checkState() == Qt.Checked:
                src = item.data(Qt.UserRole)
                if isinstance(src, dict):
                    sources.append(src)
        return sources

    def start_proxy_source_import(self, replace_existing=False, all_sources=False):
        if hasattr(self, "proxy_source_import_worker") and self.proxy_source_import_worker.isRunning():
            QMessageBox.information(self, "Import Already Running", "A proxy source import is already running.")
            return

        sources = self.selected_proxy_import_sources(all_sources=all_sources)
        if not sources:
            QMessageBox.warning(self, "No Sources Selected", "Select at least one proxy source to import.")
            return

        if replace_existing:
            if QMessageBox.question(
                self,
                "Clear List and Reimport",
                f"This will back up manual_proxies.json, clear the current list, and rebuild it from all {len(sources)} configured source(s).\n\nContinue?",
            ) != QMessageBox.Yes:
                return
        else:
            if QMessageBox.question(
                self,
                "Import Proxy Sources",
                f"Download and merge {len(sources)} selected proxy source(s) into manual_proxies.json?\n\nA backup is created before writing. Existing protocol/ip/port entries are skipped.",
            ) != QMessageBox.Yes:
                return

        timeout = 30
        if hasattr(self, "proxy_timeout_spin"):
            timeout = max(30, int(self.proxy_timeout_spin.value()))
        self.proxy_import_replace_existing = bool(replace_existing)
        self.proxy_import_table.setRowCount(0) if hasattr(self, "proxy_import_table") else None
        self.append_proxy_status("INFO", f"Starting proxy source import: sources={len(sources)}, replace_existing={replace_existing}, timeout={timeout}s")

        self.proxy_source_import_worker = ProxySourceImportWorker(sources=sources, timeout_seconds=timeout)
        self.proxy_source_import_worker.status_signal.connect(self.handle_proxy_worker_status)
        self.proxy_source_import_worker.result_signal.connect(self.handle_proxy_source_import_result)
        self.proxy_source_import_worker.start()

    def update_proxy_import_table(self, stats):
        if not hasattr(self, "proxy_import_table"):
            return
        rows = (stats or {}).get("sources", []) if isinstance(stats, dict) else []
        self.proxy_import_table.setRowCount(0)
        for row in rows:
            r = self.proxy_import_table.rowCount()
            self.proxy_import_table.insertRow(r)
            vals = [
                row.get("name", ""),
                row.get("status", ""),
                str(row.get("raw", 0)),
                str(row.get("normalized", 0)),
                str(row.get("deduped", 0)),
                row.get("error") or str(row.get("skipped", 0)),
            ]
            for c, val in enumerate(vals):
                item = QTableWidgetItem(str(val))
                if c == 1:
                    if str(val).upper() == "OK":
                        item.setForeground(QColor("#7ee787"))
                    else:
                        item.setForeground(QColor("#ff7b72"))
                self.proxy_import_table.setItem(r, c, item)
        self.proxy_import_table.resizeColumnsToContents()
        self.proxy_import_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)

    def write_proxy_records_replacing_existing(self, imported_records):
        clean = []
        seen = set()
        for rec in imported_records or []:
            if not isinstance(rec, dict):
                continue
            ip = str(rec.get("ip", "")).strip()
            port = str(rec.get("port", "")).strip()
            proto = self.normalize_proxy_protocol_value(rec.get("protocol", "http"))
            if not ip or not port:
                continue
            key = (proto, ip, port)
            if key in seen:
                continue
            seen.add(key)
            rec["protocol"] = proto
            rec["proxy"] = f"{proto}://{ip}:{port}"
            if "geolocation" not in rec or not isinstance(rec.get("geolocation"), dict):
                rec["geolocation"] = {"country": str(rec.get("country", "UNKNOWN")).upper().strip() or "UNKNOWN", "city": "Unknown"}
            clean.append(rec)
        self.backup_manual_proxy_file(user_visible=True)
        with open(MANUAL_PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=4)
        return len(clean)

    def handle_proxy_source_import_result(self, imported_records, stats, error):
        self.update_proxy_import_table(stats)
        if error:
            self.append_proxy_status("ERROR", f"Proxy source import failed: {error}")
            QMessageBox.critical(self, "Proxy Import Failed", str(error))
            return
        try:
            replace_existing = bool(getattr(self, "proxy_import_replace_existing", False))
            if replace_existing:
                written = self.write_proxy_records_replacing_existing(imported_records)
                duplicates = 0
                added = written
            else:
                added, duplicates = self.merge_imported_proxy_records(imported_records)
            self.refresh_proxy_country_counts()
            total_raw = stats.get("total_raw", 0) if isinstance(stats, dict) else 0
            total_norm = stats.get("total_normalized", len(imported_records or [])) if isinstance(stats, dict) else len(imported_records or [])
            total_skipped = stats.get("total_skipped", 0) if isinstance(stats, dict) else 0
            mode = "cleared and rebuilt" if replace_existing else "merged"
            self.append_proxy_status("SUCCESS", f"Proxy import complete: mode={mode}, raw={total_raw}, normalized={total_norm}, added/written={added}, duplicates skipped={duplicates}, invalid/source skipped={total_skipped}")
            QMessageBox.information(
                self,
                "Proxy Import Complete",
                f"Proxy import complete.\n\nMode: {mode}\nRaw records: {total_raw}\nNormalized unique batch: {total_norm}\nAdded/Written: {added}\nDuplicates skipped: {duplicates}\nInvalid/source skipped: {total_skipped}",
            )
        except Exception as e:
            self.append_proxy_status("ERROR", f"Proxy import merge/write failed: {e}")
            QMessageBox.critical(self, "Proxy Import Merge Failed", str(e))

    def count_proxy_records_by_country(self, data=None):
        # Backward-compatible helper: returns visible/eligible count based on Include SOCKS setting.
        family_counts = self.proxy_country_protocol_counts(data=data)
        include_socks = self.include_socks_proxies()
        out = {}
        for code, c in family_counts.items():
            out[code] = int(c.get("http", 0)) + (int(c.get("socks", 0)) if include_socks else 0)
        return out

    def proxy_count_label_for_country(self, country_code, family_counts):
        c = family_counts.get(country_code, {"http": 0, "socks": 0})
        http_count = int(c.get("http", 0))
        socks_count = int(c.get("socks", 0))
        if self.include_socks_proxies():
            total = http_count + socks_count
            return f"H:{http_count} S:{socks_count} T:{total}"
        return str(http_count)

    def populate_proxy_country_selector(self, default_code=None):
        if not hasattr(self, "country_selector"):
            return
        current_code = default_code or self.get_resolved_country_code()
        counts = self.proxy_country_protocol_counts()

        self.country_selector.blockSignals(True)
        self.country_selector.clear()
        self.country_selector.addItem("--- ⭐ Priority Targets ---", None)
        for name, code in self.proxy_priority_countries.items():
            self.country_selector.addItem(f"{name} [{self.proxy_count_label_for_country(code, counts)}]", code)
        self.country_selector.addItem("--- 🌐 Global Regions ---", None)
        for name, code in sorted(self.proxy_standard_countries.items()):
            self.country_selector.addItem(f"{name} [{self.proxy_count_label_for_country(code, counts)}]", code)

        if current_code:
            for i in range(self.country_selector.count()):
                if self.country_selector.itemData(i) == current_code:
                    self.country_selector.setCurrentIndex(i)
                    break
        self.country_selector.blockSignals(False)

    def on_include_socks_proxy_toggled(self, checked):
        self.refresh_proxy_country_counts()
        self.save_settings()
        mode = "HTTP/HTTPS + SOCKS" if checked else "HTTP/HTTPS only"
        if hasattr(self, "adb_out"):
            self.adb_out.append(f"<font color='#8b949e'>[PROXY EDITOR] Proxy pool mode changed to: {mode}</font>")

    def refresh_proxy_country_counts(self):
        keep_code = self.get_resolved_country_code() if hasattr(self, "country_selector") else "IN"
        self.populate_proxy_country_selector(default_code=keep_code)
        self.load_manual_proxies_to_ui()
        if hasattr(self, "adb_out"):
            mode = "HTTP/HTTPS + SOCKS" if self.include_socks_proxies() else "HTTP/HTTPS only"
            self.adb_out.append(f"<font color='#8b949e'>[PROXY EDITOR] Country proxy counts refreshed ({mode}).</font>")

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

        data = self.load_proxy_file_records()
        matches = []
        include_socks = self.include_socks_proxies()
        for x in data:
            if (self.proxy_record_matches_country(x, country_code) and x.get("ip") and x.get("port")
                    and self.proxy_record_allowed_by_protocol(x, include_socks=include_socks)):
                proto = self.proxy_protocol_from_record(x)
                matches.append(f"{proto}://{x['ip']}:{x['port']}")

        self.manual_proxy_input.setText(", ".join(matches))

    def get_proxy_backup_dir(self):
        backup_dir = os.path.join(BASE_DIR, "proxy_backups")
        os.makedirs(backup_dir, exist_ok=True)
        return backup_dir

    def backup_manual_proxy_file(self, user_visible=False):
        if not os.path.exists(MANUAL_PROXY_FILE):
            if user_visible and hasattr(self, "adb_out"):
                self.adb_out.append("<font color='#ffa657'>[PROXY BACKUP] No manual_proxies.json exists yet; nothing to backup.</font>")
            return None

        try:
            if os.path.getsize(MANUAL_PROXY_FILE) <= 0:
                if user_visible and hasattr(self, "adb_out"):
                    self.adb_out.append("<font color='#ffa657'>[PROXY BACKUP] manual_proxies.json is empty; backup skipped.</font>")
                return None
        except Exception:
            pass

        try:
            backup_dir = self.get_proxy_backup_dir()
            stamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(backup_dir, f"manual_proxies_backup_{stamp}.json")
            shutil.copy2(MANUAL_PROXY_FILE, backup_path)

            # Keep the newest 75 backups to avoid unbounded growth.
            try:
                backups = sorted(
                    [os.path.join(backup_dir, f) for f in os.listdir(backup_dir) if f.startswith("manual_proxies_backup_") and f.endswith(".json")],
                    key=os.path.getmtime,
                    reverse=True,
                )
                for old_backup in backups[75:]:
                    try:
                        os.remove(old_backup)
                    except Exception:
                        pass
            except Exception:
                pass

            if user_visible and hasattr(self, "adb_out"):
                self.adb_out.append(
                    f"<font color='#7ee787'>[PROXY BACKUP] Saved backup: {backup_path}</font>")
            return backup_path
        except Exception as e:
            if hasattr(self, "adb_out"):
                self.adb_out.append(
                    f"<font color='#ff7b72'>[PROXY BACKUP] Backup failed: {str(e)}</font>")
            return None

    def merge_imported_proxy_records(self, imported_records):
        if not imported_records:
            return 0, 0

        existing_data = self.load_proxy_file_records()
        existing_keys = set()
        for rec in existing_data:
            if not isinstance(rec, dict):
                continue
            ip = str(rec.get("ip", "")).strip()
            port = str(rec.get("port", "")).strip()
            proto = self.normalize_proxy_protocol_value(self.proxy_protocol_from_record(rec))
            if ip and port:
                existing_keys.add((proto, ip, port))

        added = 0
        duplicates = 0
        for rec in imported_records:
            if not isinstance(rec, dict):
                continue
            ip = str(rec.get("ip", "")).strip()
            port = str(rec.get("port", "")).strip()
            proto = self.normalize_proxy_protocol_value(rec.get("protocol", "http"))
            if not ip or not port:
                continue
            key = (proto, ip, port)
            if key in existing_keys:
                duplicates += 1
                continue
            rec["protocol"] = proto
            rec["proxy"] = f"{proto}://{ip}:{port}"
            if "geolocation" not in rec or not isinstance(rec.get("geolocation"), dict):
                rec["geolocation"] = {"country": str(rec.get("country", "UNKNOWN")).upper().strip() or "UNKNOWN", "city": "Unknown"}
            rec.setdefault("source", "proxifly/free-proxy-list")
            rec.setdefault("anonymity", "proxifly-import")
            rec.setdefault("score", 1)
            existing_data.append(rec)
            existing_keys.add(key)
            added += 1

        if added > 0:
            self.backup_manual_proxy_file(user_visible=True)
            with open(MANUAL_PROXY_FILE, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=4)

        return added, duplicates

    def fetch_free_proxy_list_from_proxifly(self):
        if hasattr(self, "proxifly_import_worker") and self.proxifly_import_worker.isRunning():
            QMessageBox.information(self, "Import Already Running", "A free proxy list import is already running.")
            return

        if QMessageBox.question(
            self,
            "Fetch Free Proxy List",
            "Download and merge the Proxifly free proxy list into manual_proxies.json?\n\n"
            "A backup is created before writing. Existing ip/port/protocol entries are skipped."
        ) != QMessageBox.Yes:
            return

        timeout = 30
        if hasattr(self, "proxy_timeout_spin"):
            timeout = max(30, int(self.proxy_timeout_spin.value()))

        self.proxifly_import_worker = ProxiflyImportWorker(timeout_seconds=timeout)
        self.proxifly_import_worker.status_signal.connect(self.handle_proxy_worker_status)
        self.proxifly_import_worker.result_signal.connect(self.handle_proxifly_import_result)
        self.proxifly_import_worker.start()

    def handle_proxifly_import_result(self, imported_records, total_items, skipped, normalized_count, error):
        if error:
            self.adb_out.append(
                f"<font color='#ff7b72'>[PROXY IMPORT] Proxifly import failed: {html.escape(str(error))}</font>")
            QMessageBox.critical(self, "Proxy Import Failed", f"Could not import Proxifly proxy list:\n{str(error)}")
            return

        try:
            added, duplicates = self.merge_imported_proxy_records(imported_records)
            self.refresh_proxy_country_counts()
            self.adb_out.append(
                f"<font color='#7ee787'>[PROXY IMPORT] Proxifly import complete. Raw: {total_items}, normalized: {normalized_count}, added: {added}, duplicates skipped: {duplicates}, invalid skipped: {skipped}.</font>")
            QMessageBox.information(
                self,
                "Proxy Import Complete",
                f"Proxifly import complete.\n\n"
                f"Raw records: {total_items}\n"
                f"Normalized: {normalized_count}\n"
                f"Added: {added}\n"
                f"Duplicates skipped: {duplicates}\n"
                f"Invalid skipped: {skipped}"
            )
        except Exception as e:
            self.adb_out.append(
                f"<font color='#ff7b72'>[PROXY IMPORT] Failed to merge Proxifly proxies: {html.escape(str(e))}</font>")
            QMessageBox.critical(self, "Proxy Import Merge Failed", str(e))

    def restore_manual_proxy_backup(self):
        backup_dir = self.get_proxy_backup_dir()
        backup_path, _ = QFileDialog.getOpenFileName(
            self,
            "Restore manual_proxies.json Backup",
            backup_dir,
            "JSON Files (*.json);;All Files (*)",
        )
        if not backup_path:
            return

        if QMessageBox.question(
            self,
            "Restore Proxy Backup",
            "Restore this backup over the current manual_proxies.json?\n\n"
            "The current file will be backed up first.",
        ) != QMessageBox.Yes:
            return

        try:
            self.backup_manual_proxy_file(user_visible=True)
            shutil.copy2(backup_path, MANUAL_PROXY_FILE)
            self.refresh_proxy_country_counts()
            self.adb_out.append(
                f"<font color='#7ee787'>[PROXY BACKUP] Restored proxy file from: {backup_path}</font>")
        except Exception as e:
            QMessageBox.critical(self, "Restore Failed", f"Could not restore backup:\n{str(e)}")
            if hasattr(self, "adb_out"):
                self.adb_out.append(
                    f"<font color='#ff7b72'>[PROXY BACKUP] Restore failed: {str(e)}</font>")

    def parse_proxy_pool_tokens(self, raw_text):
        tokens = [t.strip() for t in re.split(r'[,\s;]+', raw_text or "") if t.strip()]
        parsed = []
        seen = set()
        for token in tokens:
            # Accept protocol://host:port and plain host:port.
            proto = "http"
            proto_match = re.match(r'^([a-zA-Z0-9+.-]+)://(.+)$', token)
            if proto_match:
                proto = self.normalize_proxy_protocol_value(proto_match.group(1))
                cleaned = proto_match.group(2)
            else:
                cleaned = token

            if cleaned.count(":") < 1:
                continue
            ip, port = cleaned.rsplit(":", 1)
            ip = ip.strip().strip("[]")
            port = port.strip()
            if not ip or not port:
                continue
            if not port.isdigit():
                continue
            port_int = int(port)
            key = (self.normalize_proxy_protocol_value(proto), ip, str(port_int))
            if key in seen:
                continue
            seen.add(key)
            parsed.append({"ip": ip, "port": port_int, "protocol": self.normalize_proxy_protocol_value(proto)})
        return parsed

    def recover_selected_proxy_pool_from_cache(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            QMessageBox.warning(self, "Selection Error", "Please select a valid target country.")
            return

        cache_file = os.path.join(BASE_DIR, "proxy_cache.json")
        if not os.path.exists(cache_file):
            QMessageBox.warning(self, "No Cache", f"No proxy cache file found:\n{cache_file}")
            return

        try:
            with open(cache_file, "r", encoding="utf-8", errors="replace") as f:
                cache = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Cache Read Error", f"Could not read proxy cache:\n{str(e)}")
            return

        cached_nodes = cache.get(country_code, [])
        if not cached_nodes:
            QMessageBox.warning(self, "No Cached Entries", f"No cached proxy entries found for [{country_code}].")
            return

        target_full_name = GLOBAL_COUNTRY_MAP.get(country_code, "")
        existing_data = self.load_proxy_file_records()
        existing_keys = set()
        for rec in existing_data:
            if isinstance(rec, dict) and rec.get("ip") and rec.get("port"):
                existing_keys.add((str(rec.get("ip")), str(rec.get("port"))))

        recovered = []
        for node in cached_nodes:
            ip = str(node.get("ip", "")).strip()
            port = str(node.get("port", "")).strip()
            if not ip or not port:
                continue
            key = (ip, port)
            if key in existing_keys:
                continue
            recovered.append({
                "proxy": f"{self.normalize_proxy_protocol_value(node.get('protocol', 'http'))}://{ip}:{port}",
                "protocol": self.normalize_proxy_protocol_value(node.get("protocol", "http")),
                "ip": ip,
                "port": int(port) if port.isdigit() else port,
                "https": False,
                "anonymity": "recovered-from-cache",
                "score": node.get("rank", 1),
                "geolocation": {
                    "country": target_full_name if target_full_name else country_code,
                    "city": "Recovered from proxy_cache.json"
                }
            })
            existing_keys.add(key)

        if not recovered:
            self.adb_out.append(
                f"<font color='#ffa657'>[PROXY RECOVERY] Cache had entries for [{country_code}], but they already exist in manual_proxies.json.</font>")
            return

        if QMessageBox.question(
            self,
            "Recover Proxy Pool From Cache",
            f"Recover {len(recovered)} cached proxy record(s) for [{country_code}] into manual_proxies.json?\n\n"
            "A backup of the current file will be created first."
        ) != QMessageBox.Yes:
            return

        try:
            self.backup_manual_proxy_file(user_visible=True)
            existing_data.extend(recovered)
            with open(MANUAL_PROXY_FILE, "w", encoding="utf-8") as f:
                json.dump(existing_data, f, indent=4)
            self.refresh_proxy_country_counts()
            self.adb_out.append(
                f"<font color='#7ee787'>[PROXY RECOVERY] Recovered {len(recovered)} cached proxy record(s) for [{country_code}].</font>")
        except Exception as e:
            self.adb_out.append(
                f"<font color='#ff7b72'>[PROXY RECOVERY] Failed to recover from cache: {str(e)}</font>")
            QMessageBox.critical(self, "Recovery Failed", str(e))

    def save_manual_proxies_from_ui(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            QMessageBox.warning(self, "Selection Error", "Please select a valid target country.")
            return

        target_full_name = GLOBAL_COUNTRY_MAP.get(country_code, "")
        raw_text = self.manual_proxy_input.text().strip()
        existing_data = self.load_proxy_file_records()
        include_socks = self.include_socks_proxies()
        mode_label = "HTTP/HTTPS + SOCKS" if include_socks else "HTTP/HTTPS only"

        existing_count_for_country = sum(
            1 for x in existing_data
            if self.proxy_record_matches_country(x, country_code)
            and self.proxy_record_allowed_by_protocol(x, include_socks=include_socks)
        )

        # Safety fix: never treat an empty text box as a destructive delete operation.
        # Clearing this QLineEdit should only clear the visible editor field, not wipe JSON records.
        if not raw_text:
            QMessageBox.warning(
                self,
                "Empty Save Blocked",
                f"The proxy pool field for [{country_code}] is empty.\n\n"
                f"Saving this would remove {existing_count_for_country} visible {mode_label} record(s), so it was blocked.\n\n"
                "Use ↻ Reload Pool to restore the visible list from manual_proxies.json, "
                "or edit the JSON file directly if you intentionally need to delete records."
            )
            self.adb_out.append(
                f"<font color='#ffa657'>[PROXY SAFETY] Empty save blocked for [{country_code}] to prevent deleting {existing_count_for_country} record(s).</font>")
            return

        parsed = self.parse_proxy_pool_tokens(raw_text)
        if not parsed:
            QMessageBox.warning(
                self,
                "No Valid Proxies",
                "No valid proxy entries were found. Use host:port, http://host:port, https://host:port, or enable SOCKS for socks5://host:port."
            )
            self.adb_out.append(
                f"<font color='#ffa657'>[PROXY SAFETY] Save blocked for [{country_code}] because no valid proxy entries were parsed.</font>")
            return

        socks_entries = [p for p in parsed if self.proxy_protocol_family(p.get("protocol")) == "socks"]
        if socks_entries and not include_socks:
            QMessageBox.warning(
                self,
                "SOCKS Not Enabled",
                f"This list contains {len(socks_entries)} SOCKS proxy entr{'y' if len(socks_entries) == 1 else 'ies'}, "
                "but Include SOCKS proxies is not checked.\n\n"
                "Check Include SOCKS proxies before saving/testing SOCKS records."
            )
            self.adb_out.append(
                f"<font color='#ffa657'>[PROXY SAFETY] Save blocked for [{country_code}] because SOCKS records were present while Include SOCKS proxies was off.</font>")
            return

        purged_data = []
        for x in existing_data:
            # Only replace the visible/eligible family. This prevents HTTP-only editing from deleting SOCKS records.
            if self.proxy_record_matches_country(x, country_code) and self.proxy_record_allowed_by_protocol(x, include_socks=include_socks):
                continue
            purged_data.append(x)

        for node in parsed:
            proto = self.normalize_proxy_protocol_value(node.get("protocol", "http"))
            purged_data.append({
                "proxy": f"{proto}://{node['ip']}:{node['port']}",
                "protocol": proto,
                "ip": node["ip"],
                "port": node["port"],
                "https": proto in ("http", "https"),
                "anonymity": "manual-ui",
                "score": 1,
                "geolocation": {
                    "country": target_full_name if target_full_name else country_code,
                    "city": "Unknown"
                }
            })

        try:
            backup_path = self.backup_manual_proxy_file(user_visible=True)
            with open(MANUAL_PROXY_FILE, "w", encoding="utf-8") as f:
                json.dump(purged_data, f, indent=4)
            self.refresh_proxy_country_counts()
            self.adb_out.append(
                f"<font color='#7ee787'>[PROXY EDITOR] Saved {len(parsed)} {mode_label} proxy record(s) for [{country_code}]. Backup: {backup_path or 'none'}</font>")
        except Exception as e:
            self.adb_out.append(
                f"<font color='#ff7b72'>[PROXY EDITOR] Failed to write proxy file: {str(e)}</font>")

    def start_proxy_bulk_validation(self, mode="all"):
        if hasattr(self, "proxy_bulk_worker") and self.proxy_bulk_worker.isRunning():
            QMessageBox.information(self, "Validation Running", "A proxy validation queue is already running.")
            return
        include_socks = self.include_socks_proxies() if hasattr(self, "chk_include_socks_proxy") else False
        timeout = self.proxy_timeout_spin.value() if hasattr(self, "proxy_timeout_spin") else 10
        if mode == "all":
            msg = "Validate all eligible proxies now? This updates proxy_cache.json ranks but does not route/inject."
        else:
            msg = "Validate imported/source-tagged proxies now? This updates proxy_cache.json ranks but does not route/inject."
        if QMessageBox.question(self, "Start Proxy Validation Queue", msg) != QMessageBox.Yes:
            return
        self.proxy_bulk_worker = ProxyBulkValidatorWorker(mode=mode, include_socks=include_socks, timeout_seconds=timeout)
        self.proxy_bulk_worker.status_signal.connect(self.handle_proxy_worker_status)
        self.proxy_bulk_worker.done_signal.connect(self.handle_proxy_bulk_done)
        self.append_proxy_status("INFO", f"Started proxy validation queue: mode={mode}, include_socks={include_socks}, timeout={timeout}s")
        self.proxy_bulk_worker.start()

    def stop_proxy_bulk_validation(self):
        if hasattr(self, "proxy_bulk_worker") and self.proxy_bulk_worker.isRunning():
            self.proxy_bulk_worker.stop()
            self.append_proxy_status("WARN", "Stopping proxy validation queue after current request completes...")
        else:
            self.append_proxy_status("INFO", "No proxy validation queue is running.")

    def handle_proxy_bulk_done(self, total, good, bad, skipped):
        self.append_proxy_status("SUCCESS", f"Proxy validation queue finished: total={total}, good={good}, bad={bad}, skipped={skipped}")
        self.refresh_proxy_health_dashboard()
        self.refresh_proxy_country_counts()

    def load_proxy_cache_records(self):
        cache_file = os.path.join(BASE_DIR, "proxy_cache.json")
        if not os.path.exists(cache_file):
            return []
        try:
            with open(cache_file, "r", encoding="utf-8", errors="replace") as f:
                cache = json.load(f)
            rows = []
            if isinstance(cache, dict):
                for country, items in cache.items():
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                row = dict(item)
                                row["country_code"] = country
                                rows.append(row)
            return rows
        except Exception:
            return []

    def refresh_proxy_health_dashboard(self):
        if not hasattr(self, "proxy_health_table"):
            return
        records = self.load_proxy_file_records()
        cache_rows = self.load_proxy_cache_records()
        cache_by_key = {}
        for c in cache_rows:
            key = (self.normalize_proxy_protocol_value(c.get("protocol", "http")), str(c.get("ip", "")), str(c.get("port", "")))
            cache_by_key[key] = c
        agg = {}
        for rec in records:
            if not isinstance(rec, dict) or not rec.get("ip") or not rec.get("port"):
                continue
            country = self.proxy_record_country_value(rec) or "UNKNOWN"
            proto = self.proxy_protocol_family(self.proxy_protocol_from_record(rec))
            bucket = agg.setdefault(country, {"http": 0, "socks": 0, "good": 0, "bad": 0, "timeout": 0, "last": 0, "rank_sum": 0, "rank_count": 0})
            bucket[proto] += 1
            key = (self.normalize_proxy_protocol_value(self.proxy_protocol_from_record(rec)), str(rec.get("ip")), str(rec.get("port")))
            c = cache_by_key.get(key, {})
            rank = int(c.get("rank", 0) or 0)
            status = str(c.get("last_status", "")).upper()
            last = int(c.get("last_checked", 0) or 0)
            if rank > 0:
                bucket["good"] += 1
            elif rank < 0:
                bucket["bad"] += 1
            if "TIMEOUT" in status:
                bucket["timeout"] += 1
            if last > bucket["last"]:
                bucket["last"] = last
            bucket["rank_sum"] += rank
            bucket["rank_count"] += 1
        self.proxy_health_table.setRowCount(0)
        for country, b in sorted(agg.items(), key=lambda x: x[0]):
            row = self.proxy_health_table.rowCount()
            self.proxy_health_table.insertRow(row)
            avg = (b["rank_sum"] / b["rank_count"]) if b["rank_count"] else 0
            last = time.strftime("%Y-%m-%d %H:%M", time.localtime(b["last"])) if b["last"] else "never"
            vals = [country, str(b["http"]), str(b["socks"]), str(b["good"]), str(b["bad"]), str(b["timeout"]), last, f"{avg:.1f}"]
            for col, val in enumerate(vals):
                item = QTableWidgetItem(val)
                if col == 3 and int(b["good"]): item.setForeground(QColor("#7ee787"))
                if col in (4,5) and int(vals[col]): item.setForeground(QColor("#ff7b72"))
                self.proxy_health_table.setItem(row, col, item)
        self.append_proxy_status("INFO", f"Proxy health dashboard refreshed: {len(agg)} country bucket(s).")

    def remove_dead_proxies_by_rank(self):
        threshold = self.proxy_dead_rank_spin.value() if hasattr(self, "proxy_dead_rank_spin") else -25
        records = self.load_proxy_file_records()
        cache_rows = self.load_proxy_cache_records()
        cache_by_key = {}
        for c in cache_rows:
            key = (self.normalize_proxy_protocol_value(c.get("protocol", "http")), str(c.get("ip", "")), str(c.get("port", "")))
            cache_by_key[key] = int(c.get("rank", 0) or 0)
        keep, removed = [], 0
        for rec in records:
            key = (self.normalize_proxy_protocol_value(self.proxy_protocol_from_record(rec)), str(rec.get("ip", "")), str(rec.get("port", "")))
            rank = cache_by_key.get(key, 0)
            if rank <= threshold and key in cache_by_key:
                removed += 1
            else:
                keep.append(rec)
        if removed == 0:
            self.append_proxy_status("INFO", f"No proxies found with cached rank <= {threshold}.")
            return
        if QMessageBox.question(self, "Remove Dead Proxies", f"Remove {removed} proxy record(s) with cached rank <= {threshold}? A backup will be created first.") != QMessageBox.Yes:
            return
        self.backup_manual_proxy_file(user_visible=True)
        with open(MANUAL_PROXY_FILE, "w", encoding="utf-8") as f:
            json.dump(keep, f, indent=4)
        self.refresh_proxy_country_counts()
        self.refresh_proxy_health_dashboard()
        self.append_proxy_status("SUCCESS", f"Removed {removed} dead proxy record(s).")

    def load_proxy_profiles(self):
        if not os.path.exists(PROXY_PROFILES_FILE):
            return {}
        try:
            with open(PROXY_PROFILES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save_proxy_profiles(self, profiles):
        with open(PROXY_PROFILES_FILE, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=4)

    def refresh_proxy_profile_combo(self):
        if not hasattr(self, "proxy_profile_combo"):
            return
        current = self.proxy_profile_combo.currentText()
        self.proxy_profile_combo.clear()
        self.proxy_profile_combo.addItems(sorted(self.load_proxy_profiles().keys()))
        if current:
            idx = self.proxy_profile_combo.findText(current)
            if idx >= 0:
                self.proxy_profile_combo.setCurrentIndex(idx)

    def save_current_proxy_profile(self):
        name, ok = QInputDialog.getText(self, "Save Proxy Profile", "Profile name:", text=self.proxy_profile_combo.currentText() if hasattr(self, "proxy_profile_combo") else "")
        if not ok or not name.strip():
            return
        profiles = self.load_proxy_profiles()
        profiles[name.strip()] = {
            "country_code": self.get_resolved_country_code(),
            "include_socks": self.include_socks_proxies(),
            "timeout": self.proxy_timeout_spin.value() if hasattr(self, "proxy_timeout_spin") else 10,
            "auto_fallback": self.chk_auto_fallback.isChecked() if hasattr(self, "chk_auto_fallback") else True,
            "clear_android_proxy": self.chk_clear_device_proxy_before_route.isChecked() if hasattr(self, "chk_clear_device_proxy_before_route") else True,
            "apply_android_global": self.chk_apply_android_global_proxy_after_validation.isChecked() if hasattr(self, "chk_apply_android_global_proxy_after_validation") else False,
            "android_global_only": self.chk_android_global_proxy_only.isChecked() if hasattr(self, "chk_android_global_proxy_only") else False,
        }
        self.save_proxy_profiles(profiles)
        self.refresh_proxy_profile_combo()
        self.proxy_profile_combo.setCurrentText(name.strip())
        self.append_proxy_status("SUCCESS", f"Saved proxy profile: {name.strip()}")

    def apply_selected_proxy_profile(self):
        name = self.proxy_profile_combo.currentText() if hasattr(self, "proxy_profile_combo") else ""
        profile = self.load_proxy_profiles().get(name)
        if not profile:
            return
        code = profile.get("country_code")
        if code:
            self.populate_proxy_country_selector(default_code=code)
        if hasattr(self, "chk_include_socks_proxy"): self.chk_include_socks_proxy.setChecked(bool(profile.get("include_socks", False)))
        if hasattr(self, "proxy_timeout_spin"): self.proxy_timeout_spin.setValue(int(profile.get("timeout", 10)))
        if hasattr(self, "chk_auto_fallback"): self.chk_auto_fallback.setChecked(bool(profile.get("auto_fallback", True)))
        if hasattr(self, "chk_clear_device_proxy_before_route"): self.chk_clear_device_proxy_before_route.setChecked(bool(profile.get("clear_android_proxy", True)))
        if hasattr(self, "chk_apply_android_global_proxy_after_validation"): self.chk_apply_android_global_proxy_after_validation.setChecked(bool(profile.get("apply_android_global", False)))
        if hasattr(self, "chk_android_global_proxy_only"): self.chk_android_global_proxy_only.setChecked(bool(profile.get("android_global_only", False)))
        self.load_manual_proxies_to_ui()
        self.append_proxy_status("SUCCESS", f"Applied proxy profile: {name}")

    def delete_selected_proxy_profile(self):
        name = self.proxy_profile_combo.currentText() if hasattr(self, "proxy_profile_combo") else ""
        profiles = self.load_proxy_profiles()
        if name in profiles and QMessageBox.question(self, "Delete Proxy Profile", f"Delete profile {name}?") == QMessageBox.Yes:
            profiles.pop(name, None)
            self.save_proxy_profiles(profiles)
            self.refresh_proxy_profile_combo()
            self.append_proxy_status("WARN", f"Deleted proxy profile: {name}")

    def save_investigation_session(self):
        os.makedirs(SESSIONS_DIR, exist_ok=True)
        default_path = os.path.join(SESSIONS_DIR, f"session_{time.strftime('%Y%m%d_%H%M%S')}.json")
        path, _ = QFileDialog.getSaveFileName(self, "Save Investigation Session", default_path, "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        data = {
            "saved_at": int(time.time()),
            "target_pkg": self.target_pkg.currentText() if hasattr(self, "target_pkg") else "",
            "script_path": self.current_file_path,
            "script_text": self.editor.toPlainText() if hasattr(self, "editor") else "",
            "proxy_country": self.get_resolved_country_code() if hasattr(self, "country_selector") else "",
            "include_socks": self.include_socks_proxies() if hasattr(self, "chk_include_socks_proxy") else False,
            "logcat_filter": self.log_filter.text() if hasattr(self, "log_filter") else "",
            "logcat_level": self.log_level_box.currentText() if hasattr(self, "log_level_box") else "Verbose",
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        QMessageBox.information(self, "Session Saved", f"Saved session:\n{path}")

    def load_investigation_session(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load Investigation Session", SESSIONS_DIR, "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if hasattr(self, "target_pkg"):
                self.target_pkg.setCurrentText(data.get("target_pkg", ""))
            if hasattr(self, "editor"):
                self.editor.setPlainText(data.get("script_text", ""))
                self.current_file_path = data.get("script_path")
            if data.get("proxy_country"):
                self.populate_proxy_country_selector(default_code=data.get("proxy_country"))
            if hasattr(self, "chk_include_socks_proxy"):
                self.chk_include_socks_proxy.setChecked(bool(data.get("include_socks", False)))
            if hasattr(self, "log_filter"):
                self.log_filter.setText(data.get("logcat_filter", ""))
            if hasattr(self, "log_level_box"):
                self.log_level_box.setCurrentText(data.get("logcat_level", "Verbose"))
            QMessageBox.information(self, "Session Loaded", f"Loaded session:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Load Session Failed", str(e))

    def start_global_proxy_routing(self):
        country_code = self.get_resolved_country_code()
        if not country_code:
            self.adb_out.append(
                "<font color='#f85149'>[ERROR] Invalid region selector option placeholder targeted.</font>")
            return

        auto_fallback = self.chk_auto_fallback.isChecked()
        include_socks = self.include_socks_proxies()
        proxy_timeout = self.proxy_timeout_spin.value() if hasattr(self, 'proxy_timeout_spin') else 10
        if hasattr(self, 'chk_clear_device_proxy_before_route') and self.chk_clear_device_proxy_before_route.isChecked():
            self.run_adb_cmd(f"{ADB_PATH} shell settings put global http_proxy :0")
            self.adb_out.append(
                "<font color='#8b949e'>[PROXY ROTATOR] Cleared Android global http_proxy before Frida per-app routing. macOS proxy settings were not changed.</font>")
        if hasattr(self, 'proxy_tester_worker') and self.proxy_tester_worker.isRunning():
            self.proxy_tester_worker.stop();
            self.proxy_tester_worker.wait()

        self.proxy_tester_worker = ProxyTesterWorker(country_code, auto_fallback, include_socks=include_socks, proxy_timeout_seconds=proxy_timeout)
        self.proxy_tester_worker.status_signal.connect(self.handle_proxy_worker_status)
        self.proxy_tester_worker.proxy_found_signal.connect(self.inject_validated_proxy)
        self.proxy_tester_worker.start()

    def handle_proxy_worker_status(self, status_type, message):
        self.append_proxy_status(status_type, message)

    def inject_validated_proxy(self, ip, port, protocol="http"):
        # Do not copy this remote proxy into the Burp/Android global proxy field.
        # Proxy routing can be either a per-app Frida hook or Android global http_proxy mode, depending on UI options.
        protocol = str(protocol or "http").lower().strip()
        if protocol in ("socks", "socks4", "socks5"):
            normalized_protocol = protocol
        elif protocol in ("http", "https"):
            normalized_protocol = protocol
        else:
            normalized_protocol = "http"

        self.current_validated_global_proxy = f"{normalized_protocol}://{ip}:{port}"
        self.current_validated_global_proxy_tuple = (str(ip), str(port), normalized_protocol)
        if hasattr(self, "global_proxy_status"):
            self.global_proxy_status.setText(f"Validated proxy: {normalized_protocol}://{ip}:{port}")
            self.global_proxy_status.setStyleSheet("color: #7ee787; padding-left: 8px;")

        if hasattr(self, "chk_apply_android_global_proxy_after_validation") and self.chk_apply_android_global_proxy_after_validation.isChecked():
            self.apply_android_global_proxy(ip, port, normalized_protocol)

        if hasattr(self, "chk_android_global_proxy_only") and self.chk_android_global_proxy_only.isChecked():
            self.adb_out.append(
                "<font color='#58a6ff'>[PROXY ROTATOR] Android global-only mode enabled. Skipping Frida injection.</font>")
            return

        raw_template = ""
        try:
            with open(FRIDA_TEMPLATE_FILE, 'r', encoding="utf-8") as f:
                raw_template = f.read()
        except:
            raw_template = (
                "Java.perform(function() { "
                "console.log('Proxy connection: {protocol}://{ip}:{port}'); "
                "});"
            )

        full_payload = (
            raw_template
            .replace("{ip}", str(ip))
            .replace("{port}", str(port))
            .replace("{protocol}", normalized_protocol)
        )

        self.editor.setPlainText(full_payload)
        self.adb_out.append(
            f"<font color='#7ee787'>[+] Protocol-aware proxy script compiled for {normalized_protocol}://{ip}:{port}. Launching injection...</font>")
        self.start_forge()


    def apply_android_global_proxy(self, ip, port, protocol="http"):
        protocol = str(protocol or "http").lower().strip()
        if protocol.startswith("socks"):
            self.adb_out.append(
                f"<font color='#ffa657'>[ANDROID PROXY] Android global http_proxy does not support SOCKS directly. "
                f"Not applying {protocol}://{ip}:{port}. Use an HTTP/HTTPS proxy for Android global proxy mode.</font>")
            return False

        host_port = f"{ip}:{port}"
        self.run_adb_cmd(f"{ADB_PATH} shell settings put global http_proxy {host_port}")
        if hasattr(self, "android_global_proxy_status"):
            self.android_global_proxy_status.setText(f"Android global proxy: {host_port}")
            self.android_global_proxy_status.setStyleSheet("color: #7ee787; padding-left: 8px;")

        self.adb_out.append(
            f"<font color='#7ee787'>[ANDROID PROXY] Set Android global http_proxy to {host_port}. "
            f"Restart the target app so it picks up the Android global proxy.</font>")
        return True

    def apply_current_validated_proxy_to_android_global(self):
        if not hasattr(self, "current_validated_global_proxy_tuple"):
            self.adb_out.append(
                "<font color='#ffa657'>[ANDROID PROXY] No validated proxy yet. Click Validate / Route Proxy first.</font>")
            return

        ip, port, protocol = self.current_validated_global_proxy_tuple
        self.apply_android_global_proxy(ip, port, protocol)

    def clear_android_global_proxy(self):
        self.run_adb_cmd(f"{ADB_PATH} shell \"settings put global http_proxy :0; settings delete global http_proxy\"")
        if hasattr(self, "android_global_proxy_status"):
            self.android_global_proxy_status.setText("Android global proxy: cleared")
            self.android_global_proxy_status.setStyleSheet("color: #8b949e; padding-left: 8px;")
        self.adb_out.append(
            "<font color='#ff7b72'>[ANDROID PROXY] Cleared Android global http_proxy. macOS proxy settings were not changed.</font>")

    def check_android_global_proxy(self):
        self.run_adb_cmd(f"{ADB_PATH} shell settings get global http_proxy")
        self.adb_out.append("<font color='#58a6ff'>[ANDROID PROXY] Checking Android global http_proxy...</font>")

    def remove_global_proxy(self):
        if hasattr(self,
                   'proxy_tester_worker') and self.proxy_tester_worker.isRunning(): self.proxy_tester_worker.stop()
        self.clear_burp_proxy();
        self.stop_frida_worker()
        if hasattr(self, "current_validated_global_proxy_tuple"):
            delattr(self, "current_validated_global_proxy_tuple")
        if hasattr(self, "global_proxy_status"):
            self.global_proxy_status.setText("Validated proxy: none")
            self.global_proxy_status.setStyleSheet("color: #8b949e; padding-left: 8px;")
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
        editor_font_size = 12
        if hasattr(self, 'editor_font_spin'):
            editor_font_size = self.editor_font_spin.value()
        elif hasattr(self, 'editor'):
            editor_font_size = self.editor.current_font_size()

        frida_log_font_size = self.frida_log_font_spin.value() if hasattr(self, 'frida_log_font_spin') else 10
        logcat_font_size = self.logcat_font_spin.value() if hasattr(self, 'logcat_font_spin') else 10
        adb_console_font_size = self.adb_console_font_spin.value() if hasattr(self, 'adb_console_font_spin') else 10

        logcat_visible_levels = []
        if hasattr(self, 'logcat_level_checks'):
            logcat_visible_levels = [code for code, chk in self.logcat_level_checks.items() if chk.isChecked()]
        logcat_min_level = self.log_level_box.currentText() if hasattr(self, 'log_level_box') else "Verbose"
        logcat_hide_nonmatching = self.log_hard_filter.isChecked() if hasattr(self, 'log_hard_filter') else True
        logcat_auto_scroll = self.log_auto_scroll.isChecked() if hasattr(self, 'log_auto_scroll') else True
        logcat_buffer_rows = self.logcat_buffer_spin.value() if hasattr(self, 'logcat_buffer_spin') else 20000
        include_socks_proxy = self.chk_include_socks_proxy.isChecked() if hasattr(self, 'chk_include_socks_proxy') else False
        proxy_timeout_seconds = self.proxy_timeout_spin.value() if hasattr(self, 'proxy_timeout_spin') else 10
        sidebar_width = self.tabs.sidebar_width() if hasattr(self, 'tabs') and hasattr(self.tabs, 'sidebar_width') else 245
        frida_tree_width = self.frida_tree_width() if hasattr(self, 'frida_tree_width') else 420

        d = {"scale": self.scale_spin.value(), "last_pkg": self.target_pkg.currentText(),
             "path_history": self.path_history, "console_history": console_history,
             "frida_injection_mode": frida_mode, "frida_cli_path": frida_cli_path,
             "editor_font_size": editor_font_size,
             "frida_log_font_size": frida_log_font_size,
             "logcat_font_size": logcat_font_size,
             "adb_console_font_size": adb_console_font_size,
             "logcat_min_level": logcat_min_level,
             "logcat_visible_levels": logcat_visible_levels,
             "logcat_hide_nonmatching": logcat_hide_nonmatching,
             "logcat_auto_scroll": logcat_auto_scroll,
             "logcat_buffer_rows": logcat_buffer_rows,
             "include_socks_proxy": include_socks_proxy,
             "proxy_timeout_seconds": proxy_timeout_seconds,
             "sidebar_width": sidebar_width,
             "frida_tree_width": frida_tree_width}
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

                    editor_font_size = int(d.get("editor_font_size", 12))
                    if hasattr(self, 'editor_font_spin'):
                        self.editor_font_spin.setValue(editor_font_size)
                    if hasattr(self, 'editor'):
                        self.editor.set_script_font_size(editor_font_size, emit_signal=False)

                    frida_log_font_size = int(d.get("frida_log_font_size", 10))
                    if hasattr(self, 'frida_log_font_spin'):
                        self.frida_log_font_spin.setValue(frida_log_font_size)
                    if hasattr(self, 'frida_display'):
                        self.frida_display.set_log_font_size(frida_log_font_size, emit_signal=False)

                    logcat_font_size = int(d.get("logcat_font_size", 10))
                    if hasattr(self, 'logcat_font_spin'):
                        self.logcat_font_spin.setValue(logcat_font_size)
                    if hasattr(self, 'log_display'):
                        self.log_display.set_log_font_size(logcat_font_size, emit_signal=False)

                    adb_console_font_size = int(d.get("adb_console_font_size", 10))
                    if hasattr(self, 'adb_console_font_spin'):
                        self.adb_console_font_spin.setValue(adb_console_font_size)
                    if hasattr(self, 'console'):
                        self.console.set_log_font_size(adb_console_font_size, emit_signal=False)

                    if hasattr(self, 'log_level_box'):
                        idx = self.log_level_box.findText(d.get("logcat_min_level", "Verbose"))
                        if idx >= 0:
                            self.log_level_box.setCurrentIndex(idx)
                    if hasattr(self, 'log_hard_filter'):
                        self.log_hard_filter.setChecked(bool(d.get("logcat_hide_nonmatching", True)))
                    if hasattr(self, 'log_auto_scroll'):
                        self.log_auto_scroll.setChecked(bool(d.get("logcat_auto_scroll", True)))
                    if hasattr(self, 'logcat_buffer_spin'):
                        buffer_rows = int(d.get("logcat_buffer_rows", 20000))
                        self.logcat_buffer_spin.setValue(max(self.logcat_buffer_spin.minimum(), min(self.logcat_buffer_spin.maximum(), buffer_rows)))
                    if hasattr(self, 'logcat_level_checks'):
                        visible_levels = d.get("logcat_visible_levels", ["V", "D", "I", "W", "E", "F"])
                        self.set_logcat_level_checks(visible_levels)
                    if hasattr(self, 'chk_include_socks_proxy'):
                        self.chk_include_socks_proxy.setChecked(bool(d.get("include_socks_proxy", False)))
                    if hasattr(self, 'proxy_timeout_spin'):
                        timeout_seconds = int(d.get("proxy_timeout_seconds", 10))
                        self.proxy_timeout_spin.setValue(max(self.proxy_timeout_spin.minimum(), min(self.proxy_timeout_spin.maximum(), timeout_seconds)))
                    if hasattr(self, 'tabs') and hasattr(self.tabs, 'set_sidebar_width'):
                        self.tabs.set_sidebar_width(int(d.get("sidebar_width", 245)))
                        self.tabs.ensure_settings_label_visible()
                    self._pending_frida_tree_width = int(d.get("frida_tree_width", 420))
                    if hasattr(self, 'apply_frida_tree_width'):
                        self.apply_frida_tree_width(self._pending_frida_tree_width)
                    if hasattr(self, 'chk_include_socks_proxy'):
                        self.refresh_proxy_country_counts()
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
            res = subprocess.check_output(f"{ADB_PATH} shell pm list packages -3", shell=True, text=True, encoding="utf-8", errors="replace").splitlines()
            pkgs = [l.replace("package:", "").strip() for l in res if l.startswith("package:")]
            self.app_selector.clear();
            self.app_selector.addItems(sorted(pkgs))
        except:
            pass

    def fetch_running_apps(self):
        try:
            res = subprocess.check_output(f"{ADB_PATH} shell ps -A", shell=True, text=True, encoding="utf-8", errors="replace").splitlines();
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

    def auto_size_remote_columns(self):
        """Keep File Explorer columns readable after startup and every refresh."""
        if not hasattr(self, "remote_table"):
            return
        try:
            header = self.remote_table.horizontalHeader()
            header.setStretchLastSection(False)
            header.setSectionResizeMode(0, QHeaderView.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
            for col in range(1, self.remote_table.columnCount()):
                self.remote_table.resizeColumnToContents(col)
            self.remote_table.setColumnWidth(1, max(self.remote_table.columnWidth(1), 90))
            self.remote_table.setColumnWidth(2, max(self.remote_table.columnWidth(2), 150))
            self.remote_table.setColumnWidth(3, max(self.remote_table.columnWidth(3), 95))
        except Exception:
            pass

    def refresh_remote_fs(self):
        self.remote_table.setRowCount(0);
        self.remote_table.setSortingEnabled(False)
        try:
            res = subprocess.check_output(f"{ADB_PATH} shell ls -al '{self.current_remote_dir}'", shell=True,
                                          text=True, encoding="utf-8", errors="replace").splitlines()
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
        self.auto_size_remote_columns()

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

    def confirm_editor_transition(self, action_text="continue"):
        if not hasattr(self, "editor") or not self.editor.document().isModified():
            return True
        reply = QMessageBox.question(
            self,
            "Unsaved Script Changes",
            f"The current Frida script has unsaved changes. Save before you {action_text}?",
            QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
            QMessageBox.Cancel
        )
        if reply == QMessageBox.Cancel:
            return False
        if reply == QMessageBox.Save:
            self.save_script()
            return not self.editor.document().isModified()
        return True

    def on_file_clicked(self, i):
        p = self.f_model.filePath(i)
        if not os.path.isfile(p):
            return
        if not self.confirm_editor_transition("open another script"):
            return
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                self.editor.setPlainText(f.read())
            self.current_file_path = p
            self.editor.document().setModified(False)
            self.refresh_editor_search_highlights(reset=True)
            self.update_editor_status("Loaded")
        except Exception as e:
            QMessageBox.warning(self, "Open Error", f"Could not open script: {str(e)}")

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
        self.switch_to_tab_containing("Frida Logs")
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

    def parse_logcat_level(self, line):
        """Best-effort Android logcat level parser that supports threadtime and brief/tag forms."""
        order = getattr(self, "logcat_order", ["V", "D", "I", "W", "E", "F"])
        # Common threadtime: 05-18 15:00:00.000  1234  5678 D Tag: message
        # Common brief: D/Tag(1234): message
        for code in reversed(order):
            if f" {code} " in line or f" {code}/" in line or line.startswith(f"{code}/"):
                return code
        return "V"

    def set_logcat_max_entries(self, value):
        self.logcat_max_entries = int(value)
        if hasattr(self, "logcat_entries") and len(self.logcat_entries) > self.logcat_max_entries:
            self.logcat_entries = self.logcat_entries[-self.logcat_max_entries:]
            self.refresh_logcat_display()
        else:
            self.update_logcat_status()
        self.save_settings()

    def set_logcat_level_checks(self, visible_levels):
        visible = set(visible_levels or [])
        if not hasattr(self, "logcat_level_checks"):
            return
        for code, chk in self.logcat_level_checks.items():
            chk.blockSignals(True)
            chk.setChecked(code in visible)
            chk.blockSignals(False)
        self.refresh_logcat_display()

    def clear_logcat_buffer(self):
        self.logcat_entries = []
        self.logcat_pending_html = []
        self.logcat_last_visible_count = 0
        if hasattr(self, "log_display"):
            self.log_display.clear()
        self.update_logcat_status(visible_count=0)

    def get_visible_logcat_entries(self):
        if not hasattr(self, "logcat_entries"):
            return []
        return [entry for entry in self.logcat_entries if self.logcat_entry_matches_filters(entry)]

    def logcat_entry_matches_filters(self, entry):
        level = entry.get("level", "V")
        order = getattr(self, "logcat_order", ["V", "D", "I", "W", "E", "F"])

        # Minimum visible severity dropdown: hide below this level without discarding from buffer.
        try:
            min_level = self.log_levels[self.log_level_box.currentText()]
            if order.index(level) < order.index(min_level):
                return False
        except Exception:
            pass

        # Per-level checkboxes.
        checks = getattr(self, "logcat_level_checks", {})
        if checks and level in checks and not checks[level].isChecked():
            return False

        query = self.log_filter.text().strip() if hasattr(self, "log_filter") else ""
        if query and hasattr(self, "log_hard_filter") and self.log_hard_filter.isChecked():
            return query.lower() in entry.get("line", "").lower()

        return True

    def highlight_logcat_search_html(self, escaped_text, raw_text):
        query = self.log_filter.text().strip() if hasattr(self, "log_filter") else ""
        if not query:
            return escaped_text
        # Highlight only when Hide Non-Matching is off; when on, the visible rows are already matches.
        if hasattr(self, "log_hard_filter") and self.log_hard_filter.isChecked():
            return escaped_text
        try:
            pattern = re.escape(query)
            return re.sub(
                pattern,
                lambda m: f"<span style='background-color:#d29922; color:#010409;'>{html.escape(m.group(0), quote=False)}</span>",
                escaped_text,
                flags=re.IGNORECASE,
            )
        except Exception:
            return escaped_text

    def format_logcat_entry_html(self, entry):
        level = entry.get("level", "V")
        color = getattr(self, "logcat_colors", {}).get(level, "#d1d5da")
        raw_line = entry.get("line", "")
        escaped = html.escape(raw_line, quote=False)
        escaped = self.highlight_logcat_search_html(escaped, raw_line)
        return f'<font color="{color}">{escaped}</font>'

    def update_logcat_status(self, visible_count=None):
        if not hasattr(self, "logcat_count_label"):
            return
        buffered = len(getattr(self, "logcat_entries", []))
        # Important: do NOT call get_visible_logcat_entries() here. This function is called
        # frequently while logcat is streaming, and rescanning the whole buffer on every line
        # will freeze the UI. refresh_logcat_display() computes an exact count when filters change.
        if visible_count is None:
            visible_count = int(getattr(self, "logcat_last_visible_count", 0))
        paused = " | Display Paused" if getattr(self, "log_paused", False) else ""
        pending = len(getattr(self, "logcat_pending_html", []))
        pending_text = f" | Pending Draw: {pending}" if pending else ""
        self.logcat_count_label.setText(f"Buffered: {buffered} | Visible: {visible_count}{paused}{pending_text}")

    def schedule_logcat_status_update(self):
        timer = getattr(self, "logcat_status_timer", None)
        if timer is not None and not timer.isActive():
            timer.start(500)

    def schedule_logcat_flush(self):
        timer = getattr(self, "logcat_flush_timer", None)
        if timer is not None and not timer.isActive():
            timer.start(150)

    def flush_logcat_pending_display(self):
        if not hasattr(self, "log_display"):
            return
        pending = getattr(self, "logcat_pending_html", [])
        if not pending:
            self.update_logcat_status()
            return
        # If display is paused, do not draw stale queued lines. They remain in the buffer
        # and will be redrawn by refresh_logcat_display() when resumed.
        if getattr(self, "log_paused", False):
            self.logcat_pending_html = []
            self.update_logcat_status()
            return
        self.logcat_pending_html = []
        self.log_display.append("<br>".join(pending))
        if hasattr(self, "log_auto_scroll") and self.log_auto_scroll.isChecked():
            self.log_display.moveCursor(QTextCursor.End)
        self.update_logcat_status()

    def refresh_logcat_display(self):
        if not hasattr(self, "log_display"):
            return
        # Filter changes are user-driven, so this is the one place where we intentionally
        # rescan the buffer and compute the exact visible set/count.
        self.logcat_pending_html = []
        visible = self.get_visible_logcat_entries()
        self.logcat_last_visible_count = len(visible)
        self.log_display.clear()
        # Append in one HTML batch instead of thousands of QTextEdit.append() calls.
        if visible:
            self.log_display.setHtml("<br>".join(self.format_logcat_entry_html(entry) for entry in visible))
            if hasattr(self, "log_auto_scroll") and self.log_auto_scroll.isChecked():
                self.log_display.moveCursor(QTextCursor.End)
        self.update_logcat_status(visible_count=len(visible))

    def export_visible_logcat(self):
        visible = self.get_visible_logcat_entries()
        if not visible:
            QMessageBox.information(self, "Export LogCat", "No visible LogCat rows to export.")
            return
        default_name = os.path.join(BASE_DIR, f"logcat_visible_{int(time.time())}.txt")
        path, _ = QFileDialog.getSaveFileName(self, "Export Visible LogCat", default_name, "Text Files (*.txt);;All Files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                for entry in visible:
                    f.write(entry.get("line", "") + "\n")
            self.console.append(f"<font color='#7ee787'>[LOGCAT] Exported {len(visible)} visible rows to {html.escape(path)}</font>")
        except Exception as e:
            QMessageBox.warning(self, "Export Failed", f"Could not export LogCat rows:\n{str(e)}")

    def process_new_log(self, line):
        # Always buffer incoming rows first. Filters only affect visibility, so changing level/search later
        # never loses earlier rows. Keep this method O(1); do not rescan the full buffer here.
        if not hasattr(self, "logcat_entries"):
            self.logcat_entries = []
        level = self.parse_logcat_level(line)
        entry = {"line": line, "level": level, "time": time.time()}
        self.logcat_entries.append(entry)

        max_entries = int(getattr(self, "logcat_max_entries", 20000))
        if len(self.logcat_entries) > max_entries:
            overflow = len(self.logcat_entries) - max_entries
            removed = self.logcat_entries[:overflow]
            self.logcat_entries = self.logcat_entries[overflow:]
            # Keep the visible count approximately correct without scanning the whole buffer.
            try:
                removed_visible = sum(1 for old_entry in removed if self.logcat_entry_matches_filters(old_entry))
                self.logcat_last_visible_count = max(0, int(getattr(self, "logcat_last_visible_count", 0)) - removed_visible)
            except Exception:
                pass

        try:
            entry_visible = self.logcat_entry_matches_filters(entry)
        except Exception:
            entry_visible = True

        if entry_visible:
            self.logcat_last_visible_count = int(getattr(self, "logcat_last_visible_count", 0)) + 1
            if not getattr(self, "log_paused", False):
                self.logcat_pending_html.append(self.format_logcat_entry_html(entry))
                # Avoid unbounded pending growth if the UI is busy. If the queue gets too large,
                # force a full redraw soon instead of trying to append every line individually.
                if len(self.logcat_pending_html) > 1000:
                    self.logcat_pending_html = []
                    QTimer.singleShot(0, self.refresh_logcat_display)
                else:
                    self.schedule_logcat_flush()

        self.schedule_logcat_status_update()

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
                encoding="utf-8",
                errors="replace",
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
        name, ok = QInputDialog.getText(self, "Frida Script Folder", "Folder name:")
        if ok and name.strip():
            safe_name = os.path.basename(name.strip())
            os.makedirs(os.path.join(FRIDA_SCRIPTS_DIR, safe_name), exist_ok=True)
            if hasattr(self, "f_tree"):
                self.f_tree.setRootIndex(self.f_model.index(FRIDA_SCRIPTS_DIR))

    def create_new_script(self, p=None):
        if not self.confirm_editor_transition("create a new script"):
            return
        default_code = "// New unsaved Frida script\nJava.perform(function() {\n    console.log('Frida script loaded');\n});\n"
        self.current_file_path = None
        if hasattr(self, "editor"):
            self.editor.setPlainText(default_code)
            self.editor.document().setModified(True)
            self.editor.setFocus()
        self.refresh_editor_search_highlights(reset=True)
        self.update_editor_status("New unsaved script — use Save or Save As")
        self.route_frida_log("SYSTEM", "Created new unsaved Frida script. Use Save or Save As when ready.")

    def create_new_folder(self, p):
        if not os.path.abspath(p).startswith(os.path.abspath(FRIDA_SCRIPTS_DIR)):
            p = FRIDA_SCRIPTS_DIR
        name, ok = QInputDialog.getText(self, "Folder", "Name:")
        if ok and name.strip():
            safe_name = os.path.basename(name.strip())
            os.makedirs(os.path.join(p, safe_name), exist_ok=True)

    def beautify_code(self):
        try:
            raw_code = self.editor.toPlainText()
            if not raw_code.strip(): return
            cursor_pos = self.editor.textCursor().position()
            opts = jsbeautifier.default_options();
            opts.indent_size = 4;
            opts.space_in_empty_paren = True
            self.editor.setPlainText(jsbeautifier.beautify(raw_code, opts));
            cursor = QTextCursor(self.editor.document())
            cursor.setPosition(min(cursor_pos, len(self.editor.toPlainText())))
            self.editor.setTextCursor(cursor)
            self.editor.document().setModified(True)
            self.refresh_editor_search_highlights(reset=False)
            self.adb_out.append("[SYSTEM] Code beautified successfully.")
            self.update_editor_status("Beautified")
        except Exception as e:
            QMessageBox.warning(self, "Beautify Error", f"Could not beautify: {str(e)}")

    def save_script(self):
        if not self.current_file_path:
            self.save_script_as()
            return
        try:
            os.makedirs(os.path.dirname(self.current_file_path), exist_ok=True)
            with open(self.current_file_path, 'w', encoding='utf-8', errors='replace') as f:
                f.write(self.editor.toPlainText())
            self.editor.document().setModified(False)
            self.update_editor_status("Saved")
            self.route_frida_log("SYSTEM", f"Saved script: {self.current_file_path}")
        except Exception as e:
            QMessageBox.warning(self, "Save Error", f"Could not save script: {str(e)}")

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
        if hasattr(self, "btn_log_pause"):
            self.btn_log_pause.setText("▶ Resume Display" if self.log_paused else "⏸ Pause Display")
        if self.log_paused:
            self.logcat_pending_html = []
            self.update_logcat_status()
        else:
            self.refresh_logcat_display()

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
                if hasattr(self.viewer, "set_image_path"):
                    self.viewer.set_image_path(path)
                else:
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
