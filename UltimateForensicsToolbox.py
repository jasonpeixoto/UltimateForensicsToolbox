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
import zipfile
import tempfile
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QTextEdit, QListWidget, QLabel,
                             QTabWidget, QHeaderView, QFrame, QLineEdit,
                             QMessageBox, QListWidgetItem, QGridLayout, QGroupBox,
                             QInputDialog, QTreeView, QFileSystemModel, QProxyStyle,
                             QStyle, QComboBox, QCompleter, QSpinBox, QMenu, QCheckBox,
                             QFileDialog, QSplitter, QSystemTrayIcon, QAction,
                             QSizePolicy) # <--- ADD THIS
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QRegExp, QProcess, QDir, QSize, QModelIndex, QTimer # <--- ADD QTimer HERE
from PyQt5.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QPixmap, QImage, QTextCursor, QIcon

# --- SYSTEM SETTINGS ---
BASE_DIR = os.path.join(os.path.expanduser("~"), "UltimateFrida")
VAULT_DIR, PROJECTS_DIR, SCRAP_DIR = [os.path.join(BASE_DIR, x) for x in ["Global_Vault", "Projects", "Scrap"]]
CMD_FILE = os.path.join(BASE_DIR, "commands.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

for d in [VAULT_DIR, PROJECTS_DIR, SCRAP_DIR]:
    os.makedirs(d, exist_ok=True)

ADB_PATH = shutil.which("adb") or "/usr/local/bin/adb"


class DepressStyle(QProxyStyle):
    def pixelMetric(self, metric, option=None, widget=None):
        if metric in [QStyle.PM_ButtonShiftHorizontal, QStyle.PM_ButtonShiftVertical]: return 3
        return super().pixelMetric(metric, option, widget)


# --- WORKER THREADS ---

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

    def __init__(self, pkg, code):
        super().__init__()
        self.pkg, self.code, self.session = pkg, code, None

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message.get('payload')
            self.log_signal.emit("SCRIPT", str(payload))
        elif message['type'] == 'log':
            self.log_signal.emit("LOG", str(message.get('payload')))
        elif message['type'] == 'error':
            self.log_signal.emit("ERROR", f"{message.get('description')}")

    def run(self):
        try:
            dev = frida.get_usb_device()
            target_pid = None

            # 1. Check application state
            apps = dev.enumerate_applications()
            for app in apps:
                if app.identifier == self.pkg:
                    # If pid is not 0, the app is currently running
                    if app.pid != 0:
                        target_pid = app.pid
                    break

            # 2. Decision: Attach or Spawn
            if target_pid:
                self.log_signal.emit("SYSTEM", f"App is running (PID: {target_pid}). Attaching...")
                self.session = dev.attach(target_pid)
            else:
                self.log_signal.emit("SYSTEM", f"App not running. Spawning {self.pkg}...")
                pid = dev.spawn([self.pkg])
                self.session = dev.attach(pid)
                dev.resume(pid)

            # 3. Load Script
            script = self.session.create_script(self.code)
            script.on('message', self.on_message)
            script.load()

            while not self.isInterruptionRequested():
                self.sleep(1)
        except Exception as e:
            self.log_signal.emit("CRITICAL", f"Frida Error: {str(e)}")
        finally:
            if self.session:
                try: self.session.detach()
                except: pass


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
        self.rules.append((QRegExp("\\b[A-Za-z0-9_]+(?=\\()"), f1))

    def highlightBlock(self, text):
        for p, f in self.rules:
            expr = QRegExp(p)
            i = expr.indexIn(text)
            while i >= 0:
                self.setFormat(i, expr.matchedLength(), f)
                i = expr.indexIn(text, i + expr.matchedLength())


class ClickableImage(QLabel):
    doubleClicked = pyqtSignal(str)
    # Signal now sends (x, y, type) where type is 'tap' or 'drag'
    input_event = pyqtSignal(int, int, int, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.start_pos = None
        self.current_path = None  # Initialize this
        self.setMouseTracking(True)

    def setPixmap(self, pixmap):
        # Override setPixmap so we can store the path if needed
        # Or better, add a helper method:
        super().setPixmap(pixmap)

    # Add this helper to the class:
    def update_image(self, pixmap, path):
        self.current_path = path
        self.setPixmap(pixmap)

    def mousePressEvent(self, event):
        self.start_pos = event.pos()  # Record where the click started

    def mouseReleaseEvent(self, event):
        if self.start_pos:
            end_pos = event.pos()
            # Calculate distance to distinguish between a tap and a drag
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
        self.setWindowTitle("Ultimate Forensics Toolbox V1.00 - Jason Peixoto")
        self.resize(1750, 1000)
        self.setStyle(DepressStyle())
        self.setStyleSheet(self.get_theme())

        # Internal State
        self.current_file_path, self.captured_images, self.current_image_index = None, [], -1
        self.log_paused, self.frida_paused, self.current_remote_dir, self.worker = False, False, "/", None
        self.path_history = ["/", "/sdcard", "/sdcard/Download", "/data/local/tmp"]

        # Tray Configuration
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

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Initializing Tabs
        self.setup_processes_tab()
        self.setup_frida_manager_tab()
        self.setup_frida_logs_tab()
        self.setup_logcat_tab()
        self.setup_file_explorer_tab()
        self.setup_gallery_tab()
        self.setup_adb_tab()  # Will be renamed to Frida/ADB Control
        self.setup_remote_tab()
        self.setup_console_tab()  # Will be renamed to ADB Console
        self.setup_settings_tab()  # Now the last tab

        # Load Preferences
        self.load_settings()
        self.load_image_history()
        self.update_viewer_ui()
        self.start_logcat_stream()

    def send_remote_input(self, x1, y1, x2, y2, mode):
        # 1. Coordinate Mapping
        # Use 'wm size' output for your specific phone (e.g., 1080 2400)
        dev_w, dev_h = 1080, 2400

        # Correct for aspect ratio letterboxing
        pix = self.remote_viewer.pixmap()
        if not pix: return

        # Calculate the actual displayed image offsets
        # (This ensures 0,0 is the top-left of the phone screen, not the black bar)
        offset_x = (self.remote_viewer.width() - pix.width()) / 2
        offset_y = (self.remote_viewer.height() - pix.height()) / 2

        rx1 = int(((x1 - offset_x) / pix.width()) * dev_w)
        ry1 = int(((y1 - offset_y) / pix.height()) * dev_h)
        rx2 = int(((x2 - offset_x) / pix.width()) * dev_w)
        ry2 = int(((y2 - offset_y) / pix.height()) * dev_h)

        # 2. Execute ADB Command
        if mode == "tap":
            # Popen doesn't block the UI, making the mouse feel 'snappy'
            subprocess.Popen([ADB_PATH, "shell", "input", "tap", str(rx1), str(ry1)])
        elif mode == "drag":
            subprocess.Popen([ADB_PATH, "shell", "input", "swipe", str(rx1), str(ry1), str(rx2), str(ry2), "200"])

        self.console.append(f"<font color='#8b949e'>[REMOTE] {mode.upper()} at {rx1},{ry1}</font>")

    def start_frida_server(self):
        # 1. Force SELinux to Permissive (Essential for the Java Bridge)
        self.run_adb_cmd(f"{ADB_PATH} shell su -c setenforce 0")

        # 2. Start the server using the Magisk path found via 'which'
        # We use -l 0.0.0.0 to ensure it listens on all interfaces
        self.run_adb_cmd(f"{ADB_PATH} shell su -c frida-server -l 0.0.0.0 &")

        self.adb_out.append("[SYSTEM] Frida Server: Permissive mode set and start command sent.")

    def stop_frida_server(self):
        # Kill all instances of the server to ensure a clean slate
        self.run_adb_cmd(f"{ADB_PATH} shell su -c pkill -9 frida-server")
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
                  #killBtn { background: #f85149; color: white; font-weight: bold; }
                  #installBtn { background: #8957e5; color: white; font-weight: bold; }
                  #addBtn { background: #1f6feb; color: white; font-weight: bold; border-radius: 15px; min-width: 30px; }"""

    # --- UI SETUP METHODS ---
    def execute_console_command(self):
        full_cmd = self.cmd_input.currentText().strip()
        if not full_cmd: return

        # Format and display the SENT command in BLUE
        self.console.append(f"<font color='#58a6ff'><b>> {full_cmd}</b></font>")

        exec_cmd = full_cmd if full_cmd.startswith("adb") else f"{ADB_PATH} {full_cmd}"
        self.run_adb_cmd(exec_cmd)

        # Update History & Save
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
        self.f_tree.setContextMenuPolicy(Qt.CustomContextMenu);
        self.f_tree.customContextMenuRequested.connect(self.show_file_context_menu)
        layout.addWidget(self.f_tree, 1)

        r_box = QVBoxLayout();
        tools = QHBoxLayout();
        btn_proj = QPushButton("📁 Project");
        btn_proj.clicked.connect(self.create_new_project);
        btn_s = QPushButton("💾 Save");
        btn_s.clicked.connect(self.save_script);
        btn_b = QPushButton("✨ Beautify");
        btn_b.clicked.connect(self.beautify_code);
        tools.addWidget(btn_proj);
        tools.addWidget(btn_s);
        tools.addWidget(btn_b);
        r_box.addLayout(tools)
        self.editor = QTextEdit();
        self.highlighter = JSHighlighter(self.editor.document());
        r_box.addWidget(self.editor)

        self.target_pkg = QComboBox();
        self.target_pkg.setEditable(True);
        self.target_completer = QCompleter([])
        self.target_completer.setCaseSensitivity(Qt.CaseInsensitive);
        self.target_completer.setFilterMode(Qt.MatchContains)
        self.target_pkg.setCompleter(self.target_completer)
        r_box.addWidget(QLabel("Target Package ID:"));
        r_box.addWidget(self.target_pkg)

        btns = QHBoxLayout();
        fb = QPushButton("FORGE & INJECT");
        fb.setObjectName("forgeBtn");
        fb.clicked.connect(self.start_forge)
        sb = QPushButton("🛑 STOP SCRIPT");
        sb.setObjectName("stopBtn");
        sb.clicked.connect(self.stop_frida_worker)
        btns.addWidget(fb);
        btns.addWidget(sb)
        r_box.addLayout(btns);
        layout.addLayout(r_box, 3);
        self.tabs.addTab(tab, "🛠️ Frida Manager")

    def setup_frida_logs_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        controls = QHBoxLayout();
        self.frida_filter = QLineEdit();
        btn_p = QPushButton("⏸ Pause");
        btn_p.clicked.connect(self.toggle_frida_pause);
        btn_c = QPushButton("🧹 Clear");
        btn_c.clicked.connect(lambda: self.frida_display.clear());
        controls.addWidget(self.frida_filter, 1);
        controls.addWidget(btn_p);
        controls.addWidget(btn_c);
        layout.addLayout(controls)
        self.frida_display = QTextEdit();
        self.frida_display.setReadOnly(True);
        self.frida_display.setFont(QFont("Monospace", 10));
        self.frida_display.setStyleSheet("background: #010409; color: #d1d5da;");
        layout.addWidget(self.frida_display);
        self.tabs.addTab(tab, "💉 Frida Logs")

    def setup_logcat_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        h = QHBoxLayout()
        self.log_filter = QLineEdit();
        self.log_level_box = QComboBox();
        self.log_levels = {"Verbose": "V", "Debug": "D", "Info": "I", "Warning": "W", "Error": "E", "Fatal": "F"}
        self.log_level_box.addItems(list(self.log_levels.keys()));
        self.log_hard_filter = QCheckBox("Hide Non-Matching");
        self.log_hard_filter.setChecked(True);
        self.log_hard_filter.setStyleSheet("color: white;")
        self.btn_log_pause = QPushButton("⏸ Pause");
        self.btn_log_pause.clicked.connect(self.toggle_log_pause)
        btn_clear = QPushButton("🧹 Clear");
        btn_clear.clicked.connect(lambda: self.log_display.clear())
        h.addWidget(QLabel("Level:"));
        h.addWidget(self.log_level_box);
        h.addWidget(self.log_filter, 1);
        h.addWidget(self.log_hard_filter);
        h.addWidget(self.btn_log_pause);
        h.addWidget(btn_clear)
        layout.addLayout(h);
        self.log_display = QTextEdit();
        self.log_display.setReadOnly(True);
        self.log_display.setFont(QFont("Monospace", 10));
        self.log_display.setStyleSheet("background: #010409; color: #d1d5da;");
        layout.addWidget(self.log_display);
        self.tabs.addTab(tab, "🕵️ LogCat")

    def setup_file_explorer_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        nav = QHBoxLayout()
        btn_up = QPushButton("⤴ Up");
        btn_up.clicked.connect(self.remote_dir_up)
        self.path_box = QComboBox();
        self.path_box.setEditable(True);
        self.path_box.addItems(self.path_history);
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
        nav.addWidget(btn_refresh)
        layout.addLayout(nav);
        self.fs_filter = QLineEdit();
        self.fs_filter.setPlaceholderText("Filter folder...");
        self.fs_filter.textChanged.connect(self.run_fs_filter);
        layout.addWidget(self.fs_filter)
        self.fs_splitter = QSplitter(Qt.Horizontal);
        self.remote_table = QTableWidget(0, 4);
        self.remote_table.setHorizontalHeaderLabels(["Name", "Size", "Date/Time", "Perms"]);
        self.remote_table.setSortingEnabled(True);
        self.remote_table.setContextMenuPolicy(Qt.CustomContextMenu);
        self.remote_table.customContextMenuRequested.connect(self.show_remote_context_menu);
        self.remote_table.itemSelectionChanged.connect(self.preview_remote_file);
        self.remote_table.itemDoubleClicked.connect(self.on_remote_item_double_click);
        self.fs_splitter.addWidget(self.remote_table);
        self.preview_box = QTextEdit();
        self.preview_box.setReadOnly(True);
        self.preview_box.setFont(QFont("Monospace", 9));
        self.preview_box.setStyleSheet("background: #0d1117; color: #8b949e; border-left: 1px solid #30363d;");
        self.fs_splitter.addWidget(self.preview_box);
        self.fs_splitter.setStretchFactor(0, 3);
        self.fs_splitter.setStretchFactor(1, 1);
        layout.addWidget(self.fs_splitter);
        self.tabs.addTab(tab, "📁 File Explorer")
        self.refresh_remote_fs()

    def setup_gallery_tab(self):
        tab = QWidget();
        layout = QHBoxLayout(tab);
        ctrl = QVBoxLayout();
        btn_shot = QPushButton("📸 Snapshot + Portal");
        btn_shot.clicked.connect(self.take_snapshot);
        ctrl.addWidget(btn_shot);
        self.img_info = QLabel("Empty");
        self.img_info.setAlignment(Qt.AlignCenter);
        ctrl.addWidget(self.img_info);
        nav = QHBoxLayout();
        btn_p = QPushButton("<- Prev");
        btn_p.clicked.connect(lambda: self.cycle_image(-1));
        btn_n = QPushButton("Next ->");
        btn_n.clicked.connect(lambda: self.cycle_image(1));
        nav.addWidget(btn_p);
        nav.addWidget(btn_n);
        ctrl.addLayout(nav);
        mg = QHBoxLayout();
        btn_del = QPushButton("Delete");
        btn_del.clicked.connect(self.delete_current_image);
        btn_cl = QPushButton("Clear All");
        btn_cl.clicked.connect(self.clear_all_images);
        mg.addWidget(btn_del);
        mg.addWidget(btn_cl);
        ctrl.addLayout(mg);
        ctrl.addStretch();
        layout.addLayout(ctrl, 1);
        self.viewer = ClickableImage();
        self.viewer.setAlignment(Qt.AlignCenter)
        self.viewer.doubleClicked.connect(self.copy_image_to_clipboard_and_portal)
        layout.addWidget(self.viewer, 2)
        self.tabs.addTab(tab, "📸 Gallery")

    def setup_adb_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab)
        # Burp
        p_box = QGroupBox("Burp Proxy");
        px_layout = QHBoxLayout(p_box);
        self.px_in = QLineEdit(f"{self.get_ip()}:8080");
        btn_rip = QPushButton("🔄 IP");
        btn_rip.clicked.connect(self.refresh_local_ip);
        btn_set = QPushButton("Set");
        btn_set.clicked.connect(self.set_burp_proxy);
        btn_cl = QPushButton("Clear");
        btn_cl.clicked.connect(self.clear_burp_proxy);
        px_layout.addWidget(QLabel("Proxy:"));
        px_layout.addWidget(self.px_in);
        px_layout.addWidget(btn_rip);
        px_layout.addWidget(btn_set);
        px_layout.addWidget(btn_cl);
        layout.addWidget(p_box)
        # Deploy
        apk_box = QGroupBox("Deployment");
        apk_layout = QHBoxLayout(apk_box);
        self.apk_path_display = QLineEdit();
        btn_b = QPushButton("📁 Browse");
        btn_b.clicked.connect(self.browse_deployment_file);
        btn_i = QPushButton("🚀 Atomic Install");
        btn_i.setObjectName("installBtn");
        btn_i.clicked.connect(self.start_installation_process);
        apk_layout.addWidget(self.apk_path_display, 1);
        apk_layout.addWidget(btn_b);
        apk_layout.addWidget(btn_i);
        layout.addWidget(apk_box)
        # Control
        ctrl_box = QGroupBox("App Control Center");
        ctrl_layout = QVBoxLayout(ctrl_box);
        r1 = QHBoxLayout();
        self.app_selector = QComboBox();
        self.app_selector.setEditable(True);
        btn_all = QPushButton("🔄 Refresh All");
        btn_all.clicked.connect(self.fetch_all_apps);
        btn_run = QPushButton("📋 Running");
        btn_run.clicked.connect(self.fetch_running_apps);
        r1.addWidget(QLabel("ID:"));
        r1.addWidget(self.app_selector, 1);
        r1.addWidget(btn_all);
        r1.addWidget(btn_run)
        r2 = QHBoxLayout();
        btn_launch = QPushButton("▶ START APP");
        btn_launch.setObjectName("runBtn");
        btn_launch.clicked.connect(self.launch_selected_app);
        btn_kill = QPushButton("💀 KILL APP");
        btn_kill.setObjectName("killBtn");
        btn_kill.clicked.connect(self.kill_selected_app);
        r2.addStretch();
        r2.addWidget(btn_launch);
        row2_btn_kill = btn_kill;
        r2.addWidget(row2_btn_kill);
        ctrl_layout.addLayout(r1);
        ctrl_layout.addLayout(r2);
        layout.addWidget(ctrl_box)
        # Grid
        self.adb_grid_box = QGroupBox("ADB Arsenal");
        self.adb_grid_layout = QGridLayout(self.adb_grid_box)
        h = QHBoxLayout();
        h.addWidget(QLabel("Commands (4 per Row):"));
        btn_add = QPushButton("+");
        btn_add.setObjectName("addBtn");
        btn_add.clicked.connect(self.add_custom_command);
        h.addStretch();
        h.addWidget(btn_add);
        layout.addLayout(h)
        self.load_adb_buttons();
        layout.addWidget(self.adb_grid_box)
        self.adb_out = QTextEdit();
        self.adb_out.setStyleSheet("background: black; color: #00FF00; font-family: Monospace;");
        layout.addWidget(self.adb_out);
        self.tabs.addTab(tab, "🔌 Frida/ADB Control")

        # Frida Server Control Group
        frida_box = QGroupBox("Frida Server Management")
        frida_layout = QHBoxLayout(frida_box)

        btn_start = QPushButton("🚀 START SERVER")
        btn_start.setObjectName("runBtn")  # Matches your blue theme
        btn_start.clicked.connect(self.start_frida_server)

        btn_stop = QPushButton("🛑 STOP SERVER")
        btn_stop.setObjectName("killBtn")  # Matches your red theme
        btn_stop.clicked.connect(self.stop_frida_server)

        frida_layout.addWidget(btn_start)
        frida_layout.addWidget(btn_stop)
        layout.addWidget(frida_box)  # Adds it to the ADB Dashboard tab

    def setup_settings_tab(self):
        tab = QWidget();
        layout = QVBoxLayout(tab);
        group = QGroupBox("Configuration");
        glay = QGridLayout(group)
        glay.addWidget(QLabel("Scale %:"), 0, 0);
        self.scale_spin = QSpinBox();
        self.scale_spin.setRange(10, 100);
        self.scale_spin.setValue(100);
        self.scale_spin.valueChanged.connect(self.save_settings);
        glay.addWidget(self.scale_spin, 0, 1)
        layout.addWidget(group);
        layout.addStretch();
        self.tabs.addTab(tab, "⚙️ Settings")

    def setup_console_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 1. Input Area (Now at the Top)
        h_layout = QHBoxLayout()
        self.cmd_input = QComboBox()
        self.cmd_input.setEditable(True)
        self.cmd_input.setInsertPolicy(QComboBox.InsertAtTop)
        self.cmd_input.setPlaceholderText("Enter ADB command...")
        self.cmd_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # Load history from config
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f)
                    self.cmd_input.addItems(d.get("console_history", []))
            except: pass

        self.cmd_input.lineEdit().returnPressed.connect(self.execute_console_command)
        btn_send = QPushButton("SEND")
        btn_send.clicked.connect(self.execute_console_command)

        h_layout.addWidget(QLabel("ADB:"), 0)
        h_layout.addWidget(self.cmd_input, 1)
        h_layout.addWidget(btn_send, 0)
        layout.addLayout(h_layout)

        # 2. Output Area (Now below the input)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        # Deep black background with neutral gray text for general logs
        self.console.setStyleSheet("background: #010409; color: #d1d5da; font-family: 'Monospace';")
        layout.addWidget(self.console)

        self.tabs.addTab(tab, "📟 ADB Console")

    def setup_remote_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        head = QHBoxLayout()
        # Toggle for internal stream
        self.btn_live = QPushButton("▶ EMBEDDED STREAM")
        self.btn_live.setCheckable(True)
        self.btn_live.toggled.connect(self.toggle_live_stream)

        # External Button
        btn_scrcpy = QPushButton("⚡ EXTERNAL TURBO")
        btn_scrcpy.setObjectName("runBtn")
        btn_scrcpy.clicked.connect(self.launch_high_speed_mirror)

        head.addWidget(self.btn_live)
        head.addWidget(btn_scrcpy)
        head.addStretch()
        layout.addLayout(head)

        self.remote_viewer = ClickableImage()
        self.remote_viewer.setAlignment(Qt.AlignCenter)

        # THE FIX: Tell the label to NEVER grow based on the image content
        self.remote_viewer.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Ignored)  # <--- CRITICAL

        # This allows the viewer to fill the tab but not push the boundaries out
        self.remote_viewer.setMinimumSize(100, 100)

        self.remote_viewer.input_event.connect(self.send_remote_input)
        layout.addWidget(self.remote_viewer, 1)

        self.tabs.addTab(tab, "📱 Remote")


    def toggle_live_stream(self, started):
        if started:
            self.btn_live.setText("🛑 STOP STREAM")
            self.live_timer = QTimer()
            self.live_timer.timeout.connect(self.take_live_frame)
            self.live_timer.start(200) # Faster 5 FPS refresh
        else:
            self.btn_live.setText("▶ START LIVE STREAM")
            if hasattr(self, 'live_timer'):
                self.live_timer.stop()

    def launch_high_speed_mirror(self):
        scrcpy_path = "/opt/homebrew/bin/scrcpy"
        # We use the ADB_PATH variable already defined at the top of your script
        # Which you confirmed is shutil.which("adb") or "/usr/local/bin/adb"

        if hasattr(self, 'live_timer') and self.live_timer.isActive():
            self.live_timer.stop()
            self.btn_live.setChecked(False)
            self.btn_live.setText("▶ START LIVE STREAM")

        if os.path.exists(scrcpy_path):
            try:
                self.console.append(
                    f"<font color='#58a6ff'>[SYSTEM] Launching High-Speed Mirror with ADB Injection...</font>")

                # 1. Prepare the environment for scrcpy
                env = os.environ.copy()
                env["ADB"] = ADB_PATH  # Tell scrcpy exactly which adb to use

                # 2. Launch with the injected environment
                subprocess.Popen(
                    [scrcpy_path, "--max-fps", "60", "-b", "8M", "--always-on-top"],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )

            except Exception as e:
                self.console.append(f"<font color='#ff7b72'>[ERROR] Failed to start: {str(e)}</font>")
        else:
            self.console.append(f"<font color='#ff7b72'>[ERROR] Scrcpy not found at {scrcpy_path}</font>")

    def take_live_frame(self):
        try:
            # We use 'screencap -p' and pipe it to stdout
            # No files are saved on the phone or Mac disk
            process = subprocess.run(
                [ADB_PATH, "shell", "screencap", "-p"],
                capture_output=True,
                check=True
            )

            # Load the image directly from the byte-stream in memory
            pix = QPixmap()
            pix.loadFromData(process.stdout)

            if not pix.isNull():
                # Scale to the viewer's current geometry
                scaled_pix = pix.scaled(
                    self.remote_viewer.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation  # Use FastTransformation if it's still laggy
                )
                self.remote_viewer.setPixmap(scaled_pix)
        except:
            pass

    def send_remote_tap(self, x, y):
        # 1. Get Widget and Pixmap sizes
        label_w = self.remote_viewer.width()
        label_h = self.remote_viewer.height()

        # 2. Get Device Resolution (Forensic standard is 1080x1920 usually)
        # In a full build, you'd pull this via 'wm size'
        dev_w, dev_h = 1080, 1920

        # 3. Calculate Ratio and Send
        real_x = int((x / label_w) * dev_w)
        real_y = int((y / label_h) * dev_h)

        subprocess.run([ADB_PATH, "shell", "input", "tap", str(real_x), str(real_y)])
        self.console.append(f"<font color='#8b949e'>[REMOTE] Tap sent to {real_x}, {real_y}</font>")

    # --- CORE METHODS ---

    def actual_quit(self):
        self.tray_icon.hide();
        QApplication.quit()

    def closeEvent(self, event):
        if self.tray_icon.isVisible(): self.hide(); event.ignore()

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger: self.show() if not self.isVisible() else self.hide()

    def save_settings(self):
        # Gather all commands currently in the Console dropdown
        console_history = [self.cmd_input.itemText(i) for i in range(self.cmd_input.count())]

        d = {
            "scale": self.scale_spin.value(),
            "last_pkg": self.target_pkg.currentText(),
            "path_history": self.path_history,
            "console_history": console_history  # <--- Save the history here
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(d, f)

    def load_settings(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    d = json.load(f)
                    self.scale_spin.setValue(d.get("scale", 100))
                    self.target_pkg.setCurrentText(d.get("last_pkg", ""))
                    self.path_history = d.get("path_history", ["/", "/sdcard"])

                    # Restore Console History
                    self.cmd_input.clear()
                    history = d.get("console_history", [])
                    if history:
                        self.cmd_input.addItems(history)

                    # Also refresh the File Explorer path box
                    self.path_box.clear()
                    self.path_box.addItems(self.path_history)
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
            res = subprocess.check_output(f"{ADB_PATH} shell ps -A", shell=True, text=True).splitlines()
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
                    apks = [f for f in z.namelist() if f.lower().endswith('.apk')]
                    z.extractall(tmp);
                    paths = [f"'{os.path.join(tmp, a)}'" for a in apks]
                    self.run_adb_cmd(f"{ADB_PATH} install-multiple -r {' '.join(paths)}")
            finally:
                shutil.rmtree(tmp, ignore_errors=True)

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
            t = os.path.normpath(os.path.join(self.current_remote_dir, item.text()[4:]))
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
        if self.current_remote_dir != "/":
            self.current_remote_dir = os.path.dirname(self.current_remote_dir)
            self.path_box.setCurrentText(self.current_remote_dir);
            self.refresh_remote_fs()

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
            (new, ok) = QInputDialog.getText(self, "Rename", "Name:", text=n); ok and self.run_adb_cmd(
                f"{ADB_PATH} shell mv '{full}' '{os.path.join(self.current_remote_dir, new)}'"); self.refresh_remote_fs()
        elif act == dele:
            (QMessageBox.question(self, "Del", f"Delete {n}?")) == QMessageBox.Yes and self.run_adb_cmd(
                f"{ADB_PATH} shell rm -rf '{full}'"); self.refresh_remote_fs()

    def push_remote_file(self):
        loc = QFileDialog.getOpenFileName(self, "Push")[0]
        if loc: self.run_adb_cmd(f"{ADB_PATH} push '{loc}' '{self.current_remote_dir}'"); self.refresh_remote_fs()

    def preview_remote_file(self):
        sel = self.remote_table.selectedItems()
        if sel and sel[0].text().startswith("[F] "):
            try:
                self.preview_box.setText(subprocess.check_output(
                    f"{ADB_PATH} shell \"head -c 2048 '{os.path.normpath(os.path.join(self.current_remote_dir, sel[0].text()[4:]))}'\"",
                    shell=True, text=False).decode('utf-8', errors='replace'))
            except:
                self.preview_box.setText("Preview Error.")
        else:
            self.preview_box.clear()

    def refresh_procs(self):
        try:
            self.proc_table.setRowCount(0)
            self.proc_table.setSortingEnabled(False)  # Disable sorting while loading

            dev = frida.get_usb_device()
            pkgs = []

            # Use enumerate_applications to get the actual Package IDs (identifiers)
            # This is much more reliable for Android forensics than enumerate_processes
            apps = dev.enumerate_applications()

            for app in apps:
                r = self.proc_table.rowCount()
                self.proc_table.insertRow(r)

                # app.name is the Label (e.g., "Picture")
                # app.identifier is the Package ID (e.g., "com.camera.picture")
                name_item = QTableWidgetItem(app.name)
                id_item = QTableWidgetItem(app.identifier)

                self.proc_table.setItem(r, 0, name_item)
                self.proc_table.setItem(r, 1, id_item)

                pkgs.append(app.identifier)

            sorted_p = sorted(list(set(pkgs)))
            self.target_pkg.clear()
            self.target_pkg.addItems(sorted_p)
            self.target_completer.setModel(self.target_pkg.model())

            self.proc_table.setSortingEnabled(True)
        except Exception as e:
            self.adb_out.append(f"[ERROR] Failed to fetch apps: {str(e)}")

    def on_process_clicked(self, item):
        self.target_pkg.setCurrentText(self.proc_table.item(item.row(), 1).text())

    def on_file_clicked(self, i):
        p = self.f_model.filePath(i);
        (os.path.isfile(p)) and self.editor.setText(open(p).read());
        self.current_file_path = p

    def start_forge(self):
        self.stop_frida_worker();
        pkg, code = self.target_pkg.currentText(), self.editor.toPlainText()
        if pkg: self.worker = FridaWorker(pkg, code); self.worker.log_signal.connect(
            self.route_frida_log); self.worker.start(); self.tabs.setCurrentIndex(2); self.save_settings()

    def stop_frida_worker(self):
        if self.worker: self.worker.requestInterruption(); self.route_frida_log("SYSTEM",
                                                                                "Detached."); self.worker = None

    def start_logcat_stream(self):
        self.log_worker = LogcatWorker(); self.log_worker.new_log_signal.connect(
            self.process_new_log); self.log_worker.start()

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

    def load_adb_buttons(self):
        for i in reversed(range(self.adb_grid_layout.count())):
            if self.adb_grid_layout.itemAt(i).widget(): self.adb_grid_layout.itemAt(i).widget().setParent(None)
        cmds = {"🔄 Reboot": "reboot", "🚀 Boot Frida": "shell su -c /data/local/tmp/frida-server &",
                "💀 Kill Frida": "shell pkill -9 frida-server", "🔓 Unlock": "shell input keyevent 82",
                "📍 Top App": "shell dumpsys activity responses | grep -E 'mFocusedApp'",
                "📦 Apps": "shell pm list packages -3"}
        if os.path.exists(CMD_FILE):
            try:
                cmds.update(json.load(open(CMD_FILE)))
            except:
                pass
        r, c = 0, 0
        for n, cmd in cmds.items():
            btn = QPushButton(n);
            btn.clicked.connect(lambda _, x=cmd: self.run_adb_cmd(f"{ADB_PATH} {x}"))
            btn.setContextMenuPolicy(Qt.CustomContextMenu);
            btn.customContextMenuRequested.connect(lambda pos, name=n: self.show_cmd_context(name))
            self.adb_grid_layout.addWidget(btn, r, c);
            c += 1
            if c > 3: r += 1; c = 0

    def add_custom_command(self):
        n, ok1 = QInputDialog.getText(self, "New", "Title:")
        if ok1 and n:
            c, ok2 = QInputDialog.getText(self, "Cmd", "ADB Cmd:")
            if ok2 and c:
                cust = {};
                (os.path.exists(CMD_FILE)) and (cust := json.load(open(CMD_FILE)))
                cust[n] = c;
                (json.dump(cust, open(CMD_FILE, 'w')));
                self.load_adb_buttons()

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
                                             text=self.f_model.fileName(idx)); ok and self.f_model.setData(idx, new)
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
            # Get current text
            raw_code = self.editor.toPlainText()
            if not raw_code.strip():
                return

            # Configure beautifier options for better results
            opts = jsbeautifier.default_options()
            opts.indent_size = 4
            opts.space_in_empty_paren = True

            # Perform beautification
            beautified = jsbeautifier.beautify(raw_code, opts)

            # Update the editor
            self.editor.setText(beautified)
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

    def spawn_objection(self):
        (p := self.target_pkg.currentText()) and os.system(
            f"osascript -e 'tell application \"Terminal\" to do script \"objection -g {p} explore\"'")

    def route_frida_log(self, l, m):
        (not self.frida_paused) and self.frida_display.append(f"<b>[{l}]</b> {m}") or self.frida_display.moveCursor(
            QTextCursor.End)

    def toggle_frida_pause(self):
        self.frida_paused = not self.frida_paused

    def toggle_log_pause(self):
        self.log_paused = not self.log_paused

    def run_adb_cmd(self, c):
        # Log to the dashboard tab
        self.adb_out.append(f"> {c}")
        # 'sh -c' allows complex commands with su, &, and | to work correctly
        self.adb_process.start("sh", ["-c", c])

    def handle_adb_stdout(self):
        # Capture successful output in GREEN
        out_data = self.adb_process.readAllStandardOutput().data().decode().strip()
        if out_data:
            self.adb_out.append(out_data)
            self.console.append(f"<font color='#7ee787'>{out_data}</font>")

        # Capture error responses in RED
        err_data = self.adb_process.readAllStandardError().data().decode().strip()
        if err_data:
            self.console.append(f"<font color='#ff7b72'>[!] {err_data}</font>")

    def get_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); ip = s.getsockname()[
                0]; s.close(); return ip
        except:
            return "127.0.0.1"

    def take_snapshot(self):
        ts = int(time.time())
        filename = f"screen_{ts}.png"
        target_path = os.path.join(SCRAP_DIR, filename)
        temp_phone_path = "/data/local/tmp/s.png"

        try:
            self.console.append(f"<font color='#58a6ff'><b>></b> Capturing Framebuffer...</font>")
            subprocess.run([ADB_PATH, "shell", "su", "-c", f"screencap -p {temp_phone_path}"], check=True)
            subprocess.run([ADB_PATH, "pull", temp_phone_path, target_path], check=True)

            # Wait for file stability
            timeout = 10
            while not os.path.exists(target_path) and timeout > 0:
                time.sleep(0.1)
                timeout -= 1

            if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                self.load_image_history()  # Rebuilds list and sets index
                self.update_viewer_ui()
                self.copy_image_to_clipboard_and_portal(target_path)
                self.console.append(f"<font color='#7ee787'>[SUCCESS] Loaded {filename}</font>")

            subprocess.run([ADB_PATH, "shell", "su", "-c", f"rm {temp_phone_path}"])
        except Exception as e:
            self.console.append(f"<font color='#ff7b72'>[ERROR] Snapshot failed: {str(e)}</font>")

    def copy_image_to_clipboard_and_portal(self, path=None):
        # If no path is passed (like from the Snapshot button),
        # use the currently displayed image
        if not path:
            if self.current_image_index >= 0 and self.captured_images:
                path = self.captured_images[self.current_image_index]
            else:
                return

        if not os.path.exists(path):
            self.console.append(f"<font color='red'>[ERROR] File missing: {path}</font>")
            return

        # 1. Load and Scale for Clipboard
        img = QImage(path)
        if not img.isNull():
            clip = QApplication.clipboard()
            scale_val = self.scale_spin.value() / 100.0
            if scale_val != 1.0:
                img = img.scaled(img.size() * scale_val, Qt.KeepAspectRatio, Qt.SmoothTransformation)

            clip.setImage(img)
            self.console.append(f"<font color='#7ee787'>[CLIPBOARD] Copied {os.path.basename(path)}</font>")

            # 2. Trigger the Browser Portal
            portal_url = "https://screenshot.googleplex.com/"
            os.system(f"open {portal_url}")
            self.console.append(f"<font color='#58a6ff'>[PORTAL] Opening browser...</font>")

    def load_image_history(self):
        self.captured_images = sorted([os.path.join(SCRAP_DIR, f) for f in os.listdir(SCRAP_DIR) if f.endswith(".png")],
                                      key=os.path.getmtime); self.current_image_index = len(
            self.captured_images) - 1 if self.captured_images else -1

    def update_viewer_ui(self):
        if self.current_image_index >= 0 and self.captured_images:
            path = self.captured_images[self.current_image_index]
            pixmap = QPixmap(path)
            if not pixmap.isNull():
                # Maintain aspect ratio while scaling to the viewer's current size
                self.viewer.setPixmap(pixmap.scaled(
                    self.viewer.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation
                ))
                self.img_info.setText(os.path.basename(path))
            else:
                self.console.append(f"<font color='red'>Error: Pixmap is null for {path}</font>")
        else:
            self.viewer.clear()
            self.img_info.setText("Empty")

    def cycle_image(self, d):
        (self.captured_images) and (setattr(self, 'current_image_index', (self.current_image_index + d) % len(
            self.captured_images)) or self.update_viewer_ui())

    def delete_current_image(self):
        (self.current_image_index >= 0) and (os.remove(
            self.captured_images[self.current_image_index]) or self.load_image_history() or self.update_viewer_ui())

    def clear_all_images(self):
        [os.remove(f) for f in self.captured_images]; setattr(self, 'captured_images', []); setattr(self,
                                                                                                    'current_image_index',
                                                                                                    -1); self.update_viewer_ui()


if __name__ == "__main__":
    app = QApplication(sys.argv);
    app.setQuitOnLastWindowClosed(False);
    window = Forensics();
    window.show();
    sys.exit(app.exec_())
