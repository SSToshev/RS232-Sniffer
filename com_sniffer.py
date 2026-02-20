import sys
import os
import platform
import traceback
import faulthandler
import ctypes
from collections import deque
import serial
import serial.tools.list_ports
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QComboBox, QSpinBox, QLabel, QPushButton, QTextEdit,
    QFileDialog, QMessageBox, QCheckBox, QTabWidget, QGridLayout, QLineEdit,
    QPlainTextEdit
)
from PyQt5.QtCore import (
    QThread, pyqtSignal, Qt, QSettings, QTimer, qInstallMessageHandler, QtMsgType
)
from PyQt5.QtGui import QFont, QColor, QTextCursor


_diagnostics_log_file = None


def diagnostics_log(message):
    if not _diagnostics_log_file:
        return
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _diagnostics_log_file.write(f"[{timestamp}] {message}\n")
        _diagnostics_log_file.flush()
    except Exception:
        pass


def _get_process_memory_bytes():
    if sys.platform.startswith("win"):
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return int(counters.WorkingSetSize)
        return 0

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF)
        memory_kb = usage.ru_maxrss
        if sys.platform == "darwin":
            return int(memory_kb)
        return int(memory_kb * 1024)
    except Exception:
        return 0


def calculate_lrc(data):
    """Калкулация на LRC (Longitudinal Redundancy Check) - за Gilbarco"""
    lrc = 0
    for byte in data:
        lrc ^= byte
    return ((lrc ^ 0xFF) + 1) & 0xFF


def format_packet_display(hex_data, packet_bytes):
    """Форматиране на пакет с HEX за четен преглед"""
    return hex_data


def _diagnostics_dir():
    base_dir = os.path.join(os.path.expanduser("~"), "COM_Sniffer_Logs", "diagnostics")
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def setup_diagnostics():
    global _diagnostics_log_file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
    log_path = os.path.join(_diagnostics_dir(), f"diagnostics_{timestamp}.log")
    log_file = open(log_path, 'w', encoding='utf-8', buffering=1)
    _diagnostics_log_file = log_file

    log_file.write("=== COM Sniffer Diagnostics ===\n")
    log_file.write(f"Time: {datetime.now().isoformat()}\n")
    log_file.write(f"Python: {sys.version}\n")
    log_file.write(f"Platform: {platform.platform()}\n")
    log_file.write("=" * 50 + "\n\n")

    def _qt_handler(mode, context, message):
        try:
            log_file.write(f"[Qt:{int(mode)}] {message}\n")
        except Exception:
            pass

    qInstallMessageHandler(_qt_handler)

    def _excepthook(exc_type, exc, tb):
        try:
            log_file.write("\n=== Unhandled Exception ===\n")
            log_file.write(''.join(traceback.format_exception(exc_type, exc, tb)))
            log_file.write("\n")
            log_file.flush()
        except Exception:
            pass
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = _excepthook

    try:
        faulthandler.enable(file=log_file, all_threads=True)
    except Exception:
        pass

    return log_path


class SerialReaderThread(QThread):
    """Thread za čitanje iz COM porta"""
    data_received = pyqtSignal(str, str)
    status_changed = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str, str)
    
    def __init__(self, port, baudrate, bytesize, parity, stopbits, log_dir=None, timeout=0.01, source_label="RX1", buffer_enabled=False, end_marker="", start_marker=""):
        super().__init__()
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.timeout = timeout
        self.serial_conn = None
        self.is_running = True
        self.log_dir = log_dir
        self.log_file = None
        self.log_file_size = 0
        self.max_log_size = 20 * 1024 * 1024  # 20MB
        self.source_label = source_label
        self.buffer_enabled = buffer_enabled
        self.end_marker = end_marker
        self.start_marker = start_marker
        self.buffer = b''
        self.last_timestamp = None
        self.max_buffer_size = 1024 * 1024  # 1MB safety cap to avoid unbounded growth

    def _parse_marker(self, marker_str):
        if not marker_str:
            return b""
        marker_upper = marker_str.strip().upper()
        if marker_upper == "STX":
            return bytes([0x02])
        if marker_upper == "ETX":
            return bytes([0x03])
        if marker_upper.lower().startswith('0x'):
            try:
                return bytes([int(marker_upper, 16)])
            except ValueError:
                return marker_str.encode('utf-8')
        if marker_upper.isdigit():
            return bytes([int(marker_upper)])
        return marker_str.encode('utf-8')
        
    def run(self):
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                bytesize=self.bytesize,
                parity=self.parity,
                stopbits=self.stopbits,
                timeout=self.timeout
            )
            self.status_changed.emit(self.source_label, f"✓ Свързано: {self.port} @ {self.baudrate} baud")
            
            # Отварянев на лог файл ако има log_dir
            if self.log_dir:
                self.open_new_log_file()
            
            while self.is_running:
                if self.serial_conn.in_waiting:
                    data = self.serial_conn.read(self.serial_conn.in_waiting)
                    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                    self.last_timestamp = timestamp
                    
                    if self.buffer_enabled and self.end_marker:
                        # Буфериране на пакетите до маркер
                        self.buffer += data
                        if len(self.buffer) > self.max_buffer_size:
                            # Изрязване на най-старите данни ако няма край на пакет
                            self.buffer = self.buffer[-self.max_buffer_size:]

                        start_byte = self._parse_marker(self.start_marker)
                        end_byte = self._parse_marker(self.end_marker)

                        if start_byte:
                            # STX..ETX рамкиране - изкарва само реалните пакети
                            while True:
                                start_index = self.buffer.find(start_byte)
                                if start_index == -1:
                                    self.buffer = b""
                                    break
                                if start_index > 0:
                                    self.buffer = self.buffer[start_index:]
                                end_index = self.buffer.find(end_byte, len(start_byte))
                                if end_index == -1:
                                    break
                                end_index += len(end_byte)
                                packet = self.buffer[:end_index]
                                self.buffer = self.buffer[end_index:]

                                hex_data = ' '.join(f'{b:02X}' for b in packet)
                                formatted_display = format_packet_display(hex_data, packet)
                                message = f"[{self.last_timestamp}] {self.source_label} {formatted_display}\n"
                                self.data_received.emit(self.source_label, message)

                                if self.log_file:
                                    self.log_file.write(message)
                                    self.log_file.flush()
                                    self.log_file_size += len(message.encode('utf-8'))
                                    if self.log_file_size >= self.max_log_size:
                                        self.rotate_log_file()
                        else:
                            # Проверка дали буфера съдържа маркера
                            while end_byte in self.buffer:
                                packet, self.buffer = self.buffer.split(end_byte, 1)
                                packet += end_byte  # Добавяне на маркера към пакета

                                hex_data = ' '.join(f'{b:02X}' for b in packet)
                                formatted_display = format_packet_display(hex_data, packet)
                                message = f"[{self.last_timestamp}] {self.source_label} {formatted_display}\n"
                                self.data_received.emit(self.source_label, message)

                                if self.log_file:
                                    self.log_file.write(message)
                                    self.log_file.flush()
                                    self.log_file_size += len(message.encode('utf-8'))
                                    if self.log_file_size >= self.max_log_size:
                                        self.rotate_log_file()
                    else:
                        # Обикновено режим - показать всеки пакет веднага
                        hex_data = ' '.join(f'{b:02X}' for b in data)
                        formatted_display = format_packet_display(hex_data, data)
                        message = f"[{timestamp}] {self.source_label} {formatted_display}\n"
                        self.data_received.emit(self.source_label, message)
                        
                        if self.log_file:
                            self.log_file.write(message)
                            self.log_file.flush()
                            self.log_file_size += len(message.encode('utf-8'))
                            if self.log_file_size >= self.max_log_size:
                                self.rotate_log_file()
                
        except serial.SerialException as e:
            self.error_occurred.emit(self.source_label, f"Грешка при отваряне на порт: {str(e)}")
        except Exception as e:
            self.error_occurred.emit(self.source_label, f"Неочаквана грешка: {str(e)}")
        finally:
            if self.log_file:
                self.log_file.write(f"\nКрай: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self.log_file.close()
            if self.serial_conn and self.serial_conn.is_open:
                self.serial_conn.close()
            self.status_changed.emit(self.source_label, "✗ Изключено")
    
    def open_new_log_file(self):
        """Отваряне на нов лог файл"""
        if not self.log_dir:
            return
            
        if self.log_file:
            self.log_file.write(f"\nКрай: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.close()
        
        os.makedirs(self.log_dir, exist_ok=True)
        log_filename = f"com_sniffer_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
        log_path = os.path.join(self.log_dir, log_filename)
        
        self.log_file = open(log_path, 'w', encoding='utf-8', buffering=1)
        self.log_file_size = 0
        self.last_fsync_size = 0
        
        self.log_file.write(f"=== COM Sniffer Log ===\n")
        self.log_file.write(f"Начало: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_file.write(f"Източник: {self.source_label}\n")
        self.log_file.write(f"Порт: {self.port}, Скорост: {self.baudrate} baud\n")
        self.log_file.write(f"Data Bits: {self.bytesize}\n")
        self.log_file.write("="*50 + "\n\n")
        self.log_file.flush()
    
    def rotate_log_file(self):
        """Ротирани на лог файл при превишаване на размер"""
        self.open_new_log_file()
    
    def stop(self):
        self.is_running = False
        if self.serial_conn:
            try:
                self.serial_conn.cancel_read()
            except Exception:
                pass
        # Ако има остатък в буфера, го показва
        if self.buffer_enabled and self.buffer:
            hex_data = ' '.join(f'{b:02X}' for b in self.buffer)
            message = f"[{self.last_timestamp}] {self.source_label} {hex_data}\n"
            self.data_received.emit(self.source_label, message)
            if self.log_file:
                self.log_file.write(message)
                self.log_file.flush()
        if self.log_file:
            self.log_file.close()


class ComSniffer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("ComSniffer", "ComSniffer")
        self.reader_threads = []
        self.is_stopping = False
        self.log_file_path = None
        self.port_configs = {}
        self.status_labels = {}
        self.log_file = None
        self.log_file_size = 0
        self.last_fsync_size = 0
        self.fsync_interval = 8 * 1024
        self.max_log_size = 20 * 1024 * 1024  # 20MB
        self.pending_display = deque()
        self.pending_log = deque()
        self.pending_log_bytes = 0
        self.max_display_lines = 5000
        self.max_pending_display = 20000
        self.max_pending_log_bytes = 5 * 1024 * 1024
        self.memory_log_interval_ms = 10 * 60 * 1000
        self.init_ui()
        self.init_flush_timer()
        self.init_memory_logger()

    def init_flush_timer(self):
        self.flush_timer = QTimer(self)
        self.flush_timer.setInterval(50)
        self.flush_timer.timeout.connect(self.flush_pending)
        self.flush_timer.start()

    def init_memory_logger(self):
        self.memory_timer = QTimer(self)
        self.memory_timer.setInterval(self.memory_log_interval_ms)
        self.memory_timer.timeout.connect(self.log_memory_usage)
        self.memory_timer.start()

    def log_memory_usage(self):
        memory_bytes = _get_process_memory_bytes()
        if memory_bytes <= 0:
            diagnostics_log("Memory usage: unavailable")
            return
        memory_mb = memory_bytes / (1024 * 1024)
        diagnostics_log(f"Memory usage: {memory_mb:.1f} MB (working set)")
        
    def init_ui(self):
        """Инициализиране на GUI"""
        self.setWindowTitle("COM Sniffer - Monitor na COM portove")
        self.setGeometry(100, 100, 900, 700)
        
        # Главен widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # === КОНФИГУРАЦИОННА СЕКЦИЯ ===
        config_group = QGroupBox("Конфигурация")
        config_layout = QVBoxLayout()

        self.port_configs["RX1"] = self.create_port_config("RX1")
        self.port_configs["RX2"] = self.create_port_config("RX2")
        config_layout.addWidget(self.port_configs["RX1"]["group"])
        config_layout.addWidget(self.port_configs["RX2"]["group"])

        self.refresh_ports()
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # === УПРАВЛЕНИЕ И ЛОГВАНЕ ===
        control_group = QGroupBox("Управление")
        control_layout = QHBoxLayout()
        
        # Start Button
        self.start_btn = QPushButton("СТАРТ")
        self.start_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 5px;")
        self.start_btn.clicked.connect(self.start_monitoring)
        control_layout.addWidget(self.start_btn)
        
        # Stop Button
        self.stop_btn = QPushButton("СТОП")
        self.stop_btn.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 5px;")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        # Clear Button
        self.clear_btn = QPushButton("Изчистване")
        self.clear_btn.clicked.connect(self.clear_display)
        control_layout.addWidget(self.clear_btn)
        
        # Log File Checkbox
        self.log_checkbox = QCheckBox("Логване във файл")
        self.log_checkbox.setChecked(True)
        control_layout.addWidget(self.log_checkbox)
        
        # Log File Button
        self.log_file_btn = QPushButton("Избор на папка за log")
        self.log_file_btn.clicked.connect(self.choose_log_directory)
        control_layout.addWidget(self.log_file_btn)
        
        # Status Label
        self.status_labels["RX1"] = QLabel("RX1: ✗ Изключено")
        self.status_labels["RX1"].setStyleSheet("color: red; font-weight: bold;")
        control_layout.addWidget(self.status_labels["RX1"])

        self.status_labels["RX2"] = QLabel("RX2: ✗ Изключено")
        self.status_labels["RX2"].setStyleSheet("color: red; font-weight: bold;")
        control_layout.addWidget(self.status_labels["RX2"])
        
        control_group.setLayout(control_layout)
        main_layout.addWidget(control_group)

        self.load_settings()
        
        # === ДАННИ СЕКЦИЯ ===
        data_group = QGroupBox("Получени Данни")
        data_layout = QVBoxLayout()
        
        # Tabs for Display and Log
        self.tabs = QTabWidget()
        
        # Display Tab
        self.display_text = QPlainTextEdit()
        self.display_text.setReadOnly(True)
        self.display_text.setUndoRedoEnabled(False)
        font = QFont("Courier")
        font.setPointSize(9)
        self.display_text.setFont(font)
        # Премахване на разстоянията между редовете
        doc = self.display_text.document()
        doc.setDocumentMargin(0)
        doc.setMaximumBlockCount(self.max_display_lines)
        # Забрана на обвиване на текста - всеки пакет остава на един ред
        self.display_text.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.tabs.addTab(self.display_text, "Монитор")
        
        # Info Tab
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setFont(font)
        self.update_info()
        self.tabs.addTab(self.info_text, "Информация")
        
        data_layout.addWidget(self.tabs)
        data_group.setLayout(data_layout)
        main_layout.addWidget(data_group)
        
    def create_port_config(self, title):
        group = QGroupBox(title)
        layout = QVBoxLayout()

        # Главен хоризонтален контейнер с чекбокс
        main_h_layout = QHBoxLayout()

        # Чекбокс за избор на порта
        enable_checkbox = QCheckBox("Активен")
        enable_checkbox.setChecked(True)
        main_h_layout.addWidget(enable_checkbox)

        # Хоризонтален layout за параметрите
        params_layout = QHBoxLayout()

        # Режим на протокол
        protocol_label = QLabel("Протокол:")
        protocol_combo = QComboBox()
        protocol_combo.addItems(["Обичайна", "Gilbarco 2Wire"])
        protocol_combo.setMaximumWidth(130)
        params_layout.addWidget(protocol_label)
        params_layout.addWidget(protocol_combo)

        port_label = QLabel("COM Порт:")
        port_combo = QComboBox()
        params_layout.addWidget(port_label)
        params_layout.addWidget(port_combo)

        baud_label = QLabel("Скорост (baud):")
        baud_combo = QComboBox()
        baud_combo.addItems([
            "300", "600", "1200", "2400", "4800", "9600", "14400", "19200",
            "28800", "38400", "57600", "115200", "230400", "460800", "921600"
        ])
        baud_combo.setCurrentText("9600")
        params_layout.addWidget(baud_label)
        params_layout.addWidget(baud_combo)

        databits_label = QLabel("Data Bits:")
        databits_combo = QComboBox()
        databits_combo.addItems(["5", "6", "7", "8"])
        databits_combo.setCurrentText("8")
        params_layout.addWidget(databits_label)
        params_layout.addWidget(databits_combo)

        parity_label = QLabel("Parity:")
        parity_combo = QComboBox()
        parity_combo.addItems(["NONE", "EVEN", "ODD"])
        params_layout.addWidget(parity_label)
        params_layout.addWidget(parity_combo)

        stopbits_label = QLabel("Stop Bits:")
        stopbits_combo = QComboBox()
        stopbits_combo.addItems(["1", "1.5", "2"])
        params_layout.addWidget(stopbits_label)
        params_layout.addWidget(stopbits_combo)

        timeout_label = QLabel("Timeout (ms):")
        timeout_spin = QSpinBox()
        timeout_spin.setMinimum(1)
        timeout_spin.setMaximum(1000)
        timeout_spin.setValue(10)
        timeout_spin.setSuffix(" ms")
        params_layout.addWidget(timeout_label)
        params_layout.addWidget(timeout_spin)

        refresh_btn = QPushButton("Обновяване")
        refresh_btn.clicked.connect(self.refresh_ports)
        params_layout.addWidget(refresh_btn)

        params_layout.addStretch()

        main_h_layout.addLayout(params_layout)

        # Втора линия за буфериране на пакети
        buffer_layout = QHBoxLayout()
        
        buffer_checkbox = QCheckBox("Буфериране пакет")
        buffer_checkbox.setChecked(False)
        buffer_layout.addWidget(buffer_checkbox)
        
        start_marker_label = QLabel("Маркер начало (STX/0x02):")
        start_marker_input = QLineEdit()
        start_marker_input.setPlaceholderText("например: 0x02 или 2 или STX")
        start_marker_input.setMaximumWidth(120)
        buffer_layout.addWidget(start_marker_label)
        buffer_layout.addWidget(start_marker_input)

        marker_label = QLabel("Маркер край (ETX/0x03):")
        marker_input = QLineEdit()
        marker_input.setPlaceholderText("например: 0x03 или 3 или ETX")
        marker_input.setMaximumWidth(120)
        buffer_layout.addWidget(marker_label)
        buffer_layout.addWidget(marker_input)
        
        buffer_layout.addStretch()

        layout.addLayout(main_h_layout)
        layout.addLayout(buffer_layout)
        
        # Слушател за режим на протокол
        def on_protocol_changed():
            if protocol_combo.currentText() == "Gilbarco 2Wire":
                buffer_checkbox.setChecked(True)
                start_marker_input.setText("0x02")
                marker_input.setText("0x03")
                start_marker_input.setReadOnly(True)
                marker_input.setReadOnly(True)
            else:
                start_marker_input.setReadOnly(False)
                marker_input.setReadOnly(False)
        
        protocol_combo.currentTextChanged.connect(on_protocol_changed)
        
        group.setLayout(layout)
        return {
            "group": group,
            "enable_checkbox": enable_checkbox,
            "protocol_combo": protocol_combo,
            "port_combo": port_combo,
            "baud_combo": baud_combo,
            "databits_combo": databits_combo,
            "parity_combo": parity_combo,
            "stopbits_combo": stopbits_combo,
            "timeout_spin": timeout_spin,
            "refresh_btn": refresh_btn,
            "buffer_checkbox": buffer_checkbox,
            "marker_input": marker_input,
            "start_marker_input": start_marker_input
        }

    def refresh_ports(self):
        """Обновяване на списъка с COM портове"""
        ports = [port.device for port in serial.tools.list_ports.comports()]

        for cfg in self.port_configs.values():
            cfg["port_combo"].clear()
            if ports:
                cfg["port_combo"].addItems(ports)
            else:
                cfg["port_combo"].addItem("Няма намерени портове")
            
    def choose_log_directory(self):
        """Избор на директория за логване"""
        directory = QFileDialog.getExistingDirectory(self, "Избор на папка за лог файлове")
        if directory:
            self.log_file_path = directory
            self.log_file_btn.setText(f"📁 {os.path.basename(directory) or directory}")
            self.save_settings()

    def load_settings(self):
        """Зареждане на последно използваните настройки"""
        self.log_file_path = self.settings.value("log/dir", "")
        if self.log_file_path:
            self.log_file_btn.setText(f"📁 {os.path.basename(self.log_file_path) or self.log_file_path}")

        log_enabled = self.settings.value("log/enabled", "true")
        self.log_checkbox.setChecked(str(log_enabled).lower() == "true")

        for label, cfg in self.port_configs.items():
            cfg["enable_checkbox"].setChecked(self.settings.value(f"{label}/enabled", "true") == "true")
            cfg["protocol_combo"].setCurrentText(self.settings.value(f"{label}/protocol", cfg["protocol_combo"].currentText()))
            cfg["port_combo"].setCurrentText(self.settings.value(f"{label}/port", cfg["port_combo"].currentText()))
            cfg["baud_combo"].setCurrentText(self.settings.value(f"{label}/baud", cfg["baud_combo"].currentText()))
            cfg["databits_combo"].setCurrentText(self.settings.value(f"{label}/databits", cfg["databits_combo"].currentText()))
            cfg["parity_combo"].setCurrentText(self.settings.value(f"{label}/parity", cfg["parity_combo"].currentText()))
            cfg["stopbits_combo"].setCurrentText(self.settings.value(f"{label}/stopbits", cfg["stopbits_combo"].currentText()))
            cfg["timeout_spin"].setValue(int(self.settings.value(f"{label}/timeout", cfg["timeout_spin"].value())))
            cfg["buffer_checkbox"].setChecked(self.settings.value(f"{label}/buffer", "false") == "true")
            cfg["marker_input"].setText(self.settings.value(f"{label}/end_marker", cfg["marker_input"].text()))
            cfg["start_marker_input"].setText(self.settings.value(f"{label}/start_marker", cfg["start_marker_input"].text()))

    def save_settings(self):
        """Запазване на текущите настройки"""
        self.settings.setValue("log/dir", self.log_file_path or "")
        self.settings.setValue("log/enabled", self.log_checkbox.isChecked())

        for label, cfg in self.port_configs.items():
            self.settings.setValue(f"{label}/enabled", cfg["enable_checkbox"].isChecked())
            self.settings.setValue(f"{label}/protocol", cfg["protocol_combo"].currentText())
            self.settings.setValue(f"{label}/port", cfg["port_combo"].currentText())
            self.settings.setValue(f"{label}/baud", cfg["baud_combo"].currentText())
            self.settings.setValue(f"{label}/databits", cfg["databits_combo"].currentText())
            self.settings.setValue(f"{label}/parity", cfg["parity_combo"].currentText())
            self.settings.setValue(f"{label}/stopbits", cfg["stopbits_combo"].currentText())
            self.settings.setValue(f"{label}/timeout", cfg["timeout_spin"].value())
            self.settings.setValue(f"{label}/buffer", cfg["buffer_checkbox"].isChecked())
            self.settings.setValue(f"{label}/end_marker", cfg["marker_input"].text())
            self.settings.setValue(f"{label}/start_marker", cfg["start_marker_input"].text())

    def open_new_log_file(self, log_dir):
        """Отваряне на нов общ лог файл"""
        if self.log_file:
            self.log_file.write(f"\nКрай: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.close()

        os.makedirs(log_dir, exist_ok=True)
        log_filename = f"com_sniffer_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}.log"
        log_path = os.path.join(log_dir, log_filename)

        self.log_file = open(log_path, 'w', encoding='utf-8')
        self.log_file_size = 0

        self.log_file.write("=== COM Sniffer Log ===\n")
        self.log_file.write(f"Начало: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        rx1 = self.port_configs["RX1"]
        rx2 = self.port_configs["RX2"]
        self.log_file.write(
            f"RX1 -> Порт: {rx1['port_combo'].currentText()}, Скорост: {rx1['baud_combo'].currentText()} baud\n"
        )
        self.log_file.write(
            f"RX2 -> Порт: {rx2['port_combo'].currentText()}, Скорост: {rx2['baud_combo'].currentText()} baud\n"
        )
        self.log_file.write("=" * 50 + "\n\n")
        self.log_file.flush()
            
    def start_monitoring(self):
        """Начало на мониторинг"""
        # Проверка дали поне един порт е активен
        active_ports = [label for label, cfg in self.port_configs.items() if cfg["enable_checkbox"].isChecked()]
        
        if not active_ports:
            QMessageBox.warning(self, "Грешка", "Моля изберете поне един активен порт!")
            return
        
        for label, cfg in self.port_configs.items():
            if cfg["port_combo"].currentText() == "Няма намерени портове":
                QMessageBox.warning(self, "Грешка", "Няма намерени COM портове!")
                return

        port_1 = self.port_configs["RX1"]["port_combo"].currentText()
        port_2 = self.port_configs["RX2"]["port_combo"].currentText()
        
        # Проверка за дублирани портове само ако и двата са активни
        if (self.port_configs["RX1"]["enable_checkbox"].isChecked() and 
            self.port_configs["RX2"]["enable_checkbox"].isChecked() and 
            port_1 == port_2):
            QMessageBox.warning(self, "Грешка", "Моля изберете два различни COM порта.")
            return
        
        # Определяне на лог директория ако е включено логване
        log_dir = None
        if self.log_checkbox.isChecked():
            log_dir = self.log_file_path or os.path.join(os.path.expanduser("~"), "COM_Sniffer_Logs")
            self.open_new_log_file(log_dir)
        
        # Изключване на контроли
        for cfg in self.port_configs.values():
            cfg["protocol_combo"].setEnabled(False)
            cfg["port_combo"].setEnabled(False)
            cfg["baud_combo"].setEnabled(False)
            cfg["databits_combo"].setEnabled(False)
            cfg["parity_combo"].setEnabled(False)
            cfg["stopbits_combo"].setEnabled(False)
            cfg["timeout_spin"].setEnabled(False)
            cfg["refresh_btn"].setEnabled(False)
            cfg["enable_checkbox"].setEnabled(False)
            cfg["buffer_checkbox"].setEnabled(False)
            cfg["marker_input"].setEnabled(False)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        # Стартиране на читащия thread само за активни портове
        self.reader_threads = []
        for label, cfg in self.port_configs.items():
            if not cfg["enable_checkbox"].isChecked():
                continue
                
            port = cfg["port_combo"].currentText()
            baudrate = int(cfg["baud_combo"].currentText())
            databits = int(cfg["databits_combo"].currentText())
            parity_map = {"NONE": serial.PARITY_NONE, "EVEN": serial.PARITY_EVEN, "ODD": serial.PARITY_ODD}
            parity = parity_map[cfg["parity_combo"].currentText()]
            stopbits_map = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, "2": serial.STOPBITS_TWO}
            stopbits = stopbits_map[cfg["stopbits_combo"].currentText()]
            timeout = cfg["timeout_spin"].value() / 1000
            
            # Паметри за буфериране
            buffer_enabled = cfg["buffer_checkbox"].isChecked()
            end_marker = cfg["marker_input"].text() if buffer_enabled else ""
            start_marker = cfg["start_marker_input"].text() if buffer_enabled else ""

            reader_thread = SerialReaderThread(
                port, baudrate, databits, parity, stopbits, None, timeout,
                source_label=label, buffer_enabled=buffer_enabled, end_marker=end_marker, start_marker=start_marker
            )
            reader_thread.data_received.connect(self.on_data_received)
            reader_thread.status_changed.connect(self.on_status_changed)
            reader_thread.error_occurred.connect(self.on_error)
            reader_thread.start()
            self.reader_threads.append(reader_thread)
        
    def stop_monitoring(self):
        """Спиране на мониторинг"""
        if self.is_stopping:
            return
        self.is_stopping = True
        self.flush_pending()
        for reader_thread in self.reader_threads:
            reader_thread.stop()
            reader_thread.wait()
        self.reader_threads = []

        if self.log_file:
            self.log_file.flush()
            os.fsync(self.log_file.fileno())
            self.log_file.write(f"\nКрай: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.close()
            self.log_file = None
        
        # Включване на контроли
        for cfg in self.port_configs.values():
            cfg["protocol_combo"].setEnabled(True)
            cfg["port_combo"].setEnabled(True)
            cfg["baud_combo"].setEnabled(True)
            cfg["databits_combo"].setEnabled(True)
            cfg["parity_combo"].setEnabled(True)
            cfg["stopbits_combo"].setEnabled(True)
            cfg["timeout_spin"].setEnabled(True)
            cfg["refresh_btn"].setEnabled(True)
            cfg["enable_checkbox"].setEnabled(True)
            cfg["buffer_checkbox"].setEnabled(True)
            cfg["marker_input"].setEnabled(True)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.save_settings()
        self.is_stopping = False
        
    def on_data_received(self, label, data):
        """Обработка на получени данни"""
        self.pending_display.append(data)
        if len(self.pending_display) > self.max_pending_display:
            while len(self.pending_display) > self.max_pending_display:
                self.pending_display.popleft()
        if self.log_file:
            self.pending_log.append(data)
            self.pending_log_bytes += len(data.encode('utf-8'))
            if self.pending_log_bytes > self.max_pending_log_bytes:
                self.pending_log.clear()
                self.pending_log_bytes = 0
        if len(self.pending_display) >= 1000:
            self.flush_pending()

    def flush_pending(self):
        if self.pending_display:
            chunk = ''.join(self.pending_display)
            self.pending_display.clear()
            self.display_text.moveCursor(QTextCursor.End)
            self.display_text.insertPlainText(chunk)
            # Автоматично скролване към края
            cursor = self.display_text.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self.display_text.setTextCursor(cursor)
            self.display_text.ensureCursorVisible()

        if self.log_file and self.pending_log:
            log_chunk = ''.join(self.pending_log)
            self.pending_log.clear()
            self.log_file.write(log_chunk)
            self.log_file.flush()
            self.log_file_size += self.pending_log_bytes
            self.pending_log_bytes = 0
            if (self.log_file_size - self.last_fsync_size) >= self.fsync_interval:
                os.fsync(self.log_file.fileno())
                self.last_fsync_size = self.log_file_size
            if self.log_file_size >= self.max_log_size:
                log_dir = self.log_file_path or os.path.join(os.path.expanduser("~"), "COM_Sniffer_Logs")
                self.open_new_log_file(log_dir)
    
    def on_status_changed(self, label, status):
        """Обновяване на статус"""
        status_label = self.status_labels.get(label)
        if not status_label:
            return
        status_label.setText(f"{label}: {status}")
        if "✓" in status:
            status_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            status_label.setStyleSheet("color: red; font-weight: bold;")
    
    def on_error(self, label, error_msg):
        """Обработка на грешки"""
        if not self.is_stopping:
            QMessageBox.critical(self, "Грешка", f"{label}: {error_msg}")
            self.stop_monitoring()
    
    def clear_display(self):
        """Изчистване на екрана"""
        self.display_text.clear()

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)
    
    def update_info(self):
        """Обновяване на информацията"""
        info = "=== COM Sniffer ===\n\n"
        info += "Програма за мониторинг и логване на COM портове\n\n"
        info += "Функции:\n"
        info += "• Избор на COM порт от списъка на наличните\n"
        info += "• Конфигуриране на скорост и параметри\n"
        info += "• Едновременно наблюдение на два COM порта (RX1/RX2)\n"
        info += "• Визуализация на RX пакетите в реално време\n"
        info += "• Преобразуване на данни в HEX формат\n"
        info += "• Логване на данните в файл\n"
        info += "• Времеви печати за всеки пакет\n\n"
        info += "Налични COM портове:\n"
        for port in serial.tools.list_ports.comports():
            info += f"  • {port.device} - {port.description}\n"
        self.info_text.setText(info)


def main():
    setup_diagnostics()
    app = QApplication(sys.argv)
    sniffer = ComSniffer()
    sniffer.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
