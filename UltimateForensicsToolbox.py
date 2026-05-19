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
                             QPushButton, QTextEdit, QPlainTextEdit, QListWidget, QLabel,
                             QTabWidget, QHeaderView, QFrame, QLineEdit,
                             QMessageBox, QListWidgetItem, QGridLayout, QGroupBox,
                             QInputDialog, QTreeView, QFileSystemModel, QProxyStyle,
                             QStyle, QComboBox, QCompleter, QSpinBox, QMenu, QCheckBox,
                             QFileDialog, QSplitter, QSystemTrayIcon, QAction,
                             QSizePolicy, QDialog)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRegExp, QProcess, QDir, QSize, QModelIndex, QTimer, QRect, QEvent
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QPixmap, QImage, QTextCursor, QIcon, QPainter

# --- SYSTEM SETTINGS ---
BASE_DIR = os.path.expanduser("~/.jpeixoto/UltimateForensicsToolbox")
VAULT_DIR, PROJECTS_DIR, SCRAP_DIR = [os.path.join(BASE_DIR, x) for x in ["Global_Vault", "Projects", "Scrap"]]
CMD_FILE = os.path.join(BASE_DIR, "commands.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config_DecryptCocoas.json")
MANUAL_PROXY_FILE = os.path.join(BASE_DIR, "manual_proxies.json")
FRIDA_TEMPLATE_FILE = os.path.join(BASE_DIR, "frida_proxy_template.js")
FRIDA_SCRIPTS_DIR = os.path.join(BASE_DIR, "FridaScripts")
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

for d in [BASE_DIR, VAULT_DIR, PROJECTS_DIR, SCRAP_DIR, FRIDA_SCRIPTS_DIR]:
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

    def mark_proxy_failure(self, cache, node, proto, ip, port):
        node["rank"] = node.get("rank", 0) - 5
        if self.country_code not in cache:
            cache[self.country_code] = []
        existing = next((x for x in cache[self.country_code] if x.get("ip") == ip and str(x.get("port")) == str(port)), None)
        if existing:
            existing["rank"] = node["rank"]
            existing["protocol"] = proto
        else:
            cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"], "protocol": proto})
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
                    else:
                        cache[self.country_code].append({"ip": ip, "port": port, "rank": node["rank"], "protocol": proto})

                    self.save_cache(cache)
                    self.proxy_found_signal.emit(ip, port, proto)
                    return

                self.mark_proxy_failure(cache, node, proto, ip, port)
                self.status_signal.emit("WARN", f"Bad response from node: HTTP {test_res.status_code} after {elapsed:.1f}s. Moving to next baseline option...")
                if self.auto_fallback:
                    continue
                return

            except Exception as e:
                elapsed = time.monotonic() - start_time
                if "socks" in str(proto).lower() and ("SOCKS" in str(e) or "Missing dependencies" in str(e)):
                    self.status_signal.emit("ERROR", "SOCKS proxy validation requires PySocks. Install it with: pip install PySocks")

                failure_type, failure_reason = self.describe_proxy_failure(e, elapsed)
                self.mark_proxy_failure(cache, node, proto, ip, port)

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
        self.setWindowTitle("Ultimate Forensics Toolbox V1.10 - Jason Peixoto.")
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

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.setup_device_status_tab()
        self.setup_processes_tab()
        self.setup_frida_manager_tab()
        self.setup_frida_logs_tab()
        self.setup_logcat_tab()
        self.setup_file_explorer_tab()
        self.setup_gallery_tab()
        self.setup_proxy_tab()
        self.setup_adb_tab()
        self.setup_remote_tab()
        self.setup_console_tab()
        self.setup_settings_tab()

        self.load_settings()
        self.load_image_history()
        self.update_viewer_ui()
        self.start_logcat_stream()
        self.load_manual_proxies_to_ui()
        QTimer.singleShot(800, self.refresh_device_status)

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
        for i in range(1, 4): self.f_tree.setColumnHidden(i, True)
        self.f_tree.clicked.connect(self.on_file_clicked);
        self.f_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.f_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.f_tree, 1)

        r_box = QVBoxLayout();
        tools = QHBoxLayout()
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

        tools.addWidget(btn_proj);
        tools.addWidget(btn_s);
        tools.addWidget(btn_save_as);
        tools.addWidget(btn_reload);
        tools.addWidget(btn_b);
        tools.addWidget(btn_validate);
        tools.addStretch()
        tools.addWidget(QLabel("Font:"))
        tools.addWidget(btn_font_down)
        tools.addWidget(self.editor_font_spin)
        tools.addWidget(btn_font_up)
        tools.addWidget(btn_font_reset)
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
        layout.addLayout(r_box, 3)
        self.frida_manager_tab = tab
        self.tabs.addTab(tab, "🛠️ Frida Manager")

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
        self.tabs.setCurrentIndex(2)  # Frida Logs
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

        controls.addWidget(QLabel("Search:"));
        controls.addWidget(self.frida_filter, 1);
        controls.addWidget(QLabel("Font:"));
        controls.addWidget(btn_frida_font_down);
        controls.addWidget(self.frida_log_font_spin);
        controls.addWidget(btn_frida_font_up);
        controls.addWidget(btn_frida_font_reset);
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

        top_row.addWidget(QLabel("Min Level:"))
        top_row.addWidget(self.log_level_box)
        top_row.addWidget(self.log_filter, 1)
        top_row.addWidget(self.log_hard_filter)
        top_row.addWidget(self.log_auto_scroll)
        top_row.addWidget(QLabel("Font:"))
        top_row.addWidget(btn_logcat_font_down)
        top_row.addWidget(self.logcat_font_spin)
        top_row.addWidget(btn_logcat_font_up)
        top_row.addWidget(btn_logcat_font_reset)
        top_row.addWidget(self.btn_log_pause)
        top_row.addWidget(btn_clear)
        top_row.addWidget(btn_export)
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

        h_layout.addWidget(QLabel("ADB:"), 0);
        h_layout.addWidget(self.cmd_input, 1);
        h_layout.addWidget(btn_send, 0);
        h_layout.addWidget(QLabel("Font:"), 0);
        h_layout.addWidget(btn_adb_font_down, 0);
        h_layout.addWidget(self.adb_console_font_spin, 0);
        h_layout.addWidget(btn_adb_font_up, 0);
        h_layout.addWidget(btn_adb_font_reset, 0);
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
             "proxy_timeout_seconds": proxy_timeout_seconds}
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

    def on_file_clicked(self, i):
        p = self.f_model.filePath(i)
        if not os.path.isfile(p):
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

    def create_new_script(self, p):
        if not os.path.abspath(p).startswith(os.path.abspath(FRIDA_SCRIPTS_DIR)):
            p = FRIDA_SCRIPTS_DIR
        name, ok = QInputDialog.getText(self, "Script", "Name:")
        if ok and name.strip():
            safe_name = os.path.basename(name.strip())
            if not safe_name.lower().endswith(".js"):
                safe_name += ".js"
            script_path = os.path.join(p, safe_name)
            with open(script_path, 'w', encoding="utf-8") as f:
                f.write("// Frida\nJava.perform(function() {\n    console.log('Frida script loaded');\n});\n")
            self.current_file_path = script_path
            self.on_file_clicked(self.f_model.index(script_path))

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
