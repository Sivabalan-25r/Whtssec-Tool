import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout, 
                               QVBoxLayout, QPushButton, QStackedWidget, QLabel, 
                               QTableWidget, QTableWidgetItem, QLineEdit, QTextEdit,
                               QProgressBar, QTabWidget, QGridLayout, QFormLayout, 
                               QRadioButton, QButtonGroup, QCheckBox, QHeaderView, QFileDialog, QScrollArea, QFrame)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QIcon

class WhtssecForensicTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Whtssec Forensic Tool")
        self.resize(1200, 800)
        self.setStyleSheet(self.get_dark_stylesheet())
        
        # Main layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Sidebar
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 25, 15, 25)
        sidebar_layout.setSpacing(10)
        sidebar.setFixedWidth(240)
        
        # App Title in Sidebar
        title_label = QLabel("WHTSSEC")
        title_label.setObjectName("appTitle")
        title_label.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(title_label)
        
        subtitle_label = QLabel("Forensic Extractor")
        subtitle_label.setStyleSheet("color: #a6adc8; font-size: 12px;")
        subtitle_label.setAlignment(Qt.AlignCenter)
        sidebar_layout.addWidget(subtitle_label)
        
        sidebar_layout.addSpacing(30)
        
        # Navigation Buttons
        self.nav_buttons = []
        nav_items = [
            ("🏠 Home / Dashboard", 0),
            ("📁 New Case", 1),
            ("🔌 Evidence Ingestion", 2),
            ("⏳ Extraction Progress", 3),
            ("📊 Report", 4),
            ("📤 Export", 5)
        ]
        
        self.stacked_widget = QStackedWidget()
        
        for name, index in nav_items:
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, idx=index: self.switch_page(idx))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            
        sidebar_layout.addStretch()
        
        # Bottom nav items
        bottom_nav_items = [
            ("⚙️ Settings", 6),
            ("ℹ️ About / Case Log", 7)
        ]
        for name, index in bottom_nav_items:
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, idx=index: self.switch_page(idx))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            
        main_layout.addWidget(sidebar)
        
        # Setup Pages
        self.setup_pages()
        main_layout.addWidget(self.stacked_widget)
        
        # Start at home
        self.switch_page(0)
        
    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        for btn in self.nav_buttons:
            btn.setChecked(False)
        self.nav_buttons[index].setChecked(True)

    def get_dark_stylesheet(self):
        return """
            QMainWindow {
                background-color: #1e1e2e;
            }
            QWidget {
                color: #cdd6f4;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 13px;
            }
            QLabel {
                font-family: "Segoe UI", "Roboto", sans-serif;
            }
            h1 {
                font-size: 24px;
                font-weight: bold;
                color: #cba6f7;
            }
            #sidebar {
                background-color: #11111b;
                border-right: 1px solid #313244;
            }
            #appTitle {
                font-size: 22px;
                font-weight: bold;
                color: #89b4fa;
                font-family: "Segoe UI", sans-serif;
                letter-spacing: 2px;
            }
            QPushButton {
                background-color: transparent;
                color: #bac2de;
                border: none;
                padding: 12px 15px;
                text-align: left;
                border-radius: 6px;
                font-size: 14px;
                font-family: "Segoe UI", sans-serif;
            }
            QPushButton:hover {
                background-color: #313244;
                color: #cdd6f4;
            }
            QPushButton:checked {
                background-color: #89b4fa;
                color: #11111b;
                font-weight: bold;
            }
            .PrimaryButton {
                background-color: #cba6f7;
                color: #11111b;
                border-radius: 6px;
                padding: 10px 20px;
                font-weight: bold;
                text-align: center;
            }
            .PrimaryButton:hover {
                background-color: #b4befe;
            }
            .Card {
                background-color: #181825;
                border-radius: 10px;
                border: 1px solid #313244;
                padding: 20px;
            }
            QLineEdit, QTextEdit {
                background-color: #11111b;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 10px;
                color: #a6e3a1; /* Monospace green color for input text */
            }
            QLineEdit:focus, QTextEdit:focus {
                border: 1px solid #89b4fa;
            }
            QTableWidget {
                background-color: #11111b;
                border: 1px solid #313244;
                border-radius: 6px;
                gridline-color: #313244;
                alternate-background-color: #181825;
            }
            QHeaderView::section {
                background-color: #181825;
                color: #bac2de;
                padding: 8px;
                border: none;
                border-right: 1px solid #313244;
                border-bottom: 1px solid #313244;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #45475a;
                border-radius: 6px;
                text-align: center;
                background-color: #11111b;
                color: #cdd6f4;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #a6e3a1;
                border-radius: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #313244;
                border-radius: 6px;
                background-color: #181825;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #11111b;
                color: #bac2de;
                border: 1px solid #313244;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #181825;
                color: #cdd6f4;
                border-bottom-color: #181825;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background-color: #313244;
            }
            .Badge {
                background-color: #a6e3a1;
                color: #11111b;
                padding: 4px 8px;
                border-radius: 10px;
                font-weight: bold;
                font-size: 11px;
            }
            .StatusText {
                color: #89b4fa;
                font-size: 18px;
                font-family: "Segoe UI", sans-serif;
            }
        """

    def create_page_container(self, title):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)
        
        header = QLabel(f"<h1>{title}</h1>")
        header.setStyleSheet("font-family: 'Segoe UI', sans-serif;")
        layout.addWidget(header)
        return page, layout
        
    def setup_pages(self):
        # 1. Home / Dashboard
        home_page, home_layout = self.create_page_container("Dashboard")
        
        home_header = QHBoxLayout()
        home_header.addStretch()
        new_case_btn = QPushButton("📁 New Case")
        new_case_btn.setProperty("class", "PrimaryButton")
        new_case_btn.setCursor(Qt.PointingHandCursor)
        new_case_btn.clicked.connect(lambda: self.switch_page(1))
        home_header.addWidget(new_case_btn)
        home_layout.insertLayout(0, home_header)
        
        # Table of past cases
        cases_table = QTableWidget(5, 4)
        cases_table.setAlternatingRowColors(True)
        cases_table.setHorizontalHeaderLabels(["Case Name", "Date", "Investigator", "Status"])
        cases_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        cases_table.verticalHeader().setVisible(False)
        cases_table.setEditTriggers(QTableWidget.NoEditTriggers)
        cases_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Placeholder data
        for i in range(5):
            cases_table.setItem(i, 0, QTableWidgetItem(f"CASE_2026_{i+1:03d}"))
            cases_table.setItem(i, 1, QTableWidgetItem("2026-08-06"))
            cases_table.setItem(i, 2, QTableWidgetItem("Inv. Smith"))
            status_item = QTableWidgetItem("COMPLETED" if i % 2 == 0 else "IN PROGRESS")
            status_item.setForeground(Qt.green if i % 2 == 0 else Qt.yellow)
            cases_table.setItem(i, 3, status_item)
            
        home_layout.addWidget(cases_table)
        
        empty_state = QLabel("No active cases currently being processed.")
        empty_state.setStyleSheet("color: #6c7086; font-style: italic; font-family: 'Segoe UI';")
        home_layout.addWidget(empty_state)
        self.stacked_widget.addWidget(home_page)
        
        # 2. New Case
        nc_page, nc_layout = self.create_page_container("New Case Setup")
        
        nc_form = QWidget()
        nc_form.setProperty("class", "Card")
        form_layout = QFormLayout(nc_form)
        form_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.setSpacing(15)
        
        case_name = QLineEdit()
        case_name.setPlaceholderText("e.g. CASE_2026_006")
        form_layout.addRow("Case Name:", case_name)
        
        investigator = QLineEdit()
        investigator.setPlaceholderText("e.g. John Doe")
        form_layout.addRow("Investigator Name:", investigator)
        
        notes = QTextEdit()
        notes.setPlaceholderText("Enter preliminary notes about this device extraction...")
        notes.setMaximumHeight(120)
        form_layout.addRow("Notes:", notes)
        
        out_dir_layout = QHBoxLayout()
        out_dir_edit = QLineEdit()
        out_dir_edit.setPlaceholderText("/path/to/evidence/folder")
        out_dir_btn = QPushButton("Browse...")
        out_dir_btn.setStyleSheet("background-color: #313244; padding: 10px; border-radius: 6px;")
        out_dir_layout.addWidget(out_dir_edit)
        out_dir_layout.addWidget(out_dir_btn)
        form_layout.addRow("Output Folder:", out_dir_layout)
        
        nc_layout.addWidget(nc_form)
        nc_layout.addStretch()
        
        start_case_btn = QPushButton("Start Case ->")
        start_case_btn.setProperty("class", "PrimaryButton")
        start_case_btn.clicked.connect(lambda: self.switch_page(2)) # Move to ingestion
        nc_layout.addWidget(start_case_btn, alignment=Qt.AlignRight)
        self.stacked_widget.addWidget(nc_page)
        
        # 3. Evidence Ingestion
        ing_page, ing_layout = self.create_page_container("Evidence Ingestion")
        
        stepper_label = QLabel("Step 1 of 4: Waiting for device connection...")
        stepper_label.setAlignment(Qt.AlignCenter)
        stepper_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; color: #bac2de;")
        ing_layout.addWidget(stepper_label)
        
        ing_layout.addStretch()
        
        status_card = QWidget()
        status_card.setProperty("class", "Card")
        status_card.setMinimumSize(400, 250)
        status_layout = QVBoxLayout(status_card)
        status_layout.setAlignment(Qt.AlignCenter)
        
        status_icon = QLabel("📱")
        status_icon.setStyleSheet("font-size: 72px;")
        status_icon.setAlignment(Qt.AlignCenter)
        status_text = QLabel("Waiting for device...")
        status_text.setProperty("class", "StatusText")
        status_text.setAlignment(Qt.AlignCenter)
        
        status_layout.addWidget(status_icon)
        status_layout.addWidget(status_text)
        
        # TODO: connect to backend device polling logic
        # if connected: status_text.setText("Device Connected - Waiting for authorization...")
        
        ing_center_layout = QHBoxLayout()
        ing_center_layout.addStretch()
        ing_center_layout.addWidget(status_card)
        ing_center_layout.addStretch()
        
        ing_layout.addLayout(ing_center_layout)
        ing_layout.addStretch()
        
        ing_actions = QHBoxLayout()
        ing_actions.addStretch()
        cancel_ing_btn = QPushButton("Cancel")
        cancel_ing_btn.setStyleSheet("background-color: #f38ba8; color: #11111b; border-radius: 6px; padding: 10px 20px; font-weight: bold;")
        
        # Mock connection to progress for preview purposes
        simulate_btn = QPushButton("Simulate Connection (Debug)")
        simulate_btn.setStyleSheet("background-color: #313244; color: #cdd6f4; border-radius: 6px; padding: 10px 20px;")
        simulate_btn.clicked.connect(lambda: self.switch_page(3))
        
        ing_actions.addWidget(cancel_ing_btn)
        ing_actions.addWidget(simulate_btn)
        ing_layout.addLayout(ing_actions)
        self.stacked_widget.addWidget(ing_page)
        
        # 4. Extraction Progress
        prog_page, prog_layout = self.create_page_container("Extraction Progress")
        
        prog_card = QWidget()
        prog_card.setProperty("class", "Card")
        pc_layout = QVBoxLayout(prog_card)
        pc_layout.setSpacing(15)
        
        status_head = QLabel("Extracting WhatsApp Database...")
        status_head.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; font-weight: bold;")
        pc_layout.addWidget(status_head)
        
        prog_bar = QProgressBar()
        prog_bar.setValue(14)
        prog_bar.setFixedHeight(25)
        pc_layout.addWidget(prog_bar)
        
        count_label = QLabel("12,400 / 87,000 files (14%)")
        count_label.setAlignment(Qt.AlignRight)
        pc_layout.addWidget(count_label)
        
        log_view = QTextEdit()
        log_view.setReadOnly(True)
        log_view.setText("[INFO] Connected to device Pixel 8 Pro\n[INFO] Requesting backup authorization...\n[INFO] Authorization granted.\n[INFO] Initiating block transfer...\n[INFO] Downloading block 1...")
        pc_layout.addWidget(log_view)
        
        # TODO: connect to backend extraction progress signals
        
        prog_layout.addWidget(prog_card)
        
        prog_btns = QHBoxLayout()
        prog_btns.addStretch()
        
        cancel_ext_btn = QPushButton("Cancel")
        cancel_ext_btn.setStyleSheet("background-color: transparent; border: 1px solid #f38ba8; color: #f38ba8; border-radius: 6px; padding: 10px 20px;")
        
        view_rep_btn = QPushButton("View Report (Debug)")
        view_rep_btn.setProperty("class", "PrimaryButton")
        view_rep_btn.clicked.connect(lambda: self.switch_page(4))
        
        prog_btns.addWidget(cancel_ext_btn)
        prog_btns.addWidget(view_rep_btn)
        prog_layout.addLayout(prog_btns)
        
        self.stacked_widget.addWidget(prog_page)
        
        # 5. Report
        rep_page, rep_layout = self.create_page_container("Forensic Report")
        
        tabs = QTabWidget()
        
        # -- Messages Tab
        msg_tab = QWidget()
        msg_layout = QVBoxLayout(msg_tab)
        msg_layout.setContentsMargins(15, 15, 15, 15)
        
        msg_table = QTableWidget(15, 4)
        msg_table.setAlternatingRowColors(True)
        msg_table.setHorizontalHeaderLabels(["Sender", "Timestamp", "Chat/Group", "Content"])
        msg_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        msg_table.verticalHeader().setVisible(False)
        msg_table.setSelectionBehavior(QTableWidget.SelectRows)
        for i in range(15):
            msg_table.setItem(i, 0, QTableWidgetItem(f"+1 555 019 {i:03d}"))
            msg_table.setItem(i, 1, QTableWidgetItem(f"2026-08-05 14:32:{i:02d}"))
            msg_table.setItem(i, 2, QTableWidgetItem("Project Phoenix" if i % 3 == 0 else "Direct Message"))
            msg_table.setItem(i, 3, QTableWidgetItem("Placeholder message content extracted from db..."))
        msg_layout.addWidget(msg_table)
        tabs.addTab(msg_tab, "💬 Messages")
        
        # -- Media Tab
        media_tab = QWidget()
        media_layout = QVBoxLayout(media_tab)
        media_layout.setContentsMargins(15, 15, 15, 15)
        media_scroll = QScrollArea()
        media_scroll.setWidgetResizable(True)
        media_scroll.setStyleSheet("QScrollArea { border: none; background-color: transparent; }")
        
        media_content = QWidget()
        media_grid = QGridLayout(media_content)
        media_grid.setSpacing(15)
        for i in range(16):
            thumb_container = QWidget()
            thumb_container.setStyleSheet("background-color: #313244; border-radius: 8px;")
            thumb_container.setFixedSize(140, 140)
            t_layout = QVBoxLayout(thumb_container)
            icon = QLabel("🖼️" if i % 2 == 0 else "🎥")
            icon.setFont(QFont("Arial", 36))
            icon.setAlignment(Qt.AlignCenter)
            label = QLabel(f"IMG_{i+1:04d}.jpg")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: #a6adc8; font-size: 11px;")
            t_layout.addWidget(icon)
            t_layout.addWidget(label)
            media_grid.addWidget(thumb_container, i // 4, i % 4)
            
        media_content.setLayout(media_grid)
        media_scroll.setWidget(media_content)
        media_layout.addWidget(media_scroll)
        tabs.addTab(media_tab, "🖼️ Media")
        
        # -- Device Info Tab
        info_tab = QWidget()
        info_layout = QVBoxLayout(info_tab)
        info_layout.setContentsMargins(15, 15, 15, 15)
        
        info_card = QWidget()
        info_card.setProperty("class", "Card")
        info_form = QFormLayout(info_card)
        info_form.setSpacing(20)
        info_form.setLabelAlignment(Qt.AlignRight)
        
        def add_info_row(label, value):
            v_lbl = QLabel(value)
            v_lbl.setStyleSheet("color: #a6e3a1; font-weight: bold;")
            info_form.addRow(f"{label}:", v_lbl)
            
        add_info_row("Device Model", "Google Pixel 8 Pro")
        add_info_row("Android Version", "14.0 (API 34)")
        add_info_row("IMEI / MEID", "351234567890123")
        add_info_row("Extraction Method", "ADB Backup / Root")
        add_info_row("Backup Timestamp", "2026-08-06 00:15:00 UTC")
        add_info_row("Timezone", "America/New_York (UTC-4)")
        
        info_layout.addWidget(info_card)
        info_layout.addStretch()
        tabs.addTab(info_tab, "📱 Device Info")
        
        # -- Hashes/Integrity Tab
        hash_tab = QWidget()
        hash_layout = QVBoxLayout(hash_tab)
        hash_layout.setContentsMargins(15, 15, 15, 15)
        
        hash_table = QTableWidget(4, 3)
        hash_table.setAlternatingRowColors(True)
        hash_table.setHorizontalHeaderLabels(["File Name", "Hash (SHA-256)", "Status"])
        hash_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        hash_table.verticalHeader().setVisible(False)
        hash_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        files = ["msgstore.db", "msgstore.db-wal", "wa.db", "key"]
        hashes = [
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            "b42a98f1262d16960d7037bce4e21a221f0cefa61f06f52e504c5dcbf4101e1d",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ]
        
        for i in range(4):
            hash_table.setItem(i, 0, QTableWidgetItem(files[i]))
            hash_table.setItem(i, 1, QTableWidgetItem(hashes[i]))
            status_item = QTableWidgetItem("VERIFIED")
            status_item.setForeground(Qt.green)
            hash_table.setItem(i, 2, status_item)
            
        hash_layout.addWidget(hash_table)
        tabs.addTab(hash_tab, "🔒 Hashes/Integrity")
        
        # -- Timeline Tab
        time_tab = QWidget()
        time_layout = QVBoxLayout(time_tab)
        time_layout.setContentsMargins(15, 15, 15, 15)
        
        time_table = QTableWidget(6, 3)
        time_table.setAlternatingRowColors(True)
        time_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Event Detail"])
        time_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        time_table.verticalHeader().setVisible(False)
        time_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        events = [
            ("2026-08-05 14:30:00", "MESSAGE", "Incoming from +1 555 019 000"),
            ("2026-08-05 14:31:12", "CALL", "Missed voice call from John Doe"),
            ("2026-08-05 14:32:05", "MEDIA", "Image received in Project Phoenix"),
            ("2026-08-05 14:35:00", "LOCATION", "Live location shared"),
            ("2026-08-05 15:00:22", "STATUS", "User status updated"),
            ("2026-08-05 15:10:00", "MESSAGE", "Outgoing text to Alice")
        ]
        
        for i, (ts, typ, desc) in enumerate(events):
            time_table.setItem(i, 0, QTableWidgetItem(ts))
            time_table.setItem(i, 1, QTableWidgetItem(typ))
            time_table.setItem(i, 2, QTableWidgetItem(desc))
            
        time_layout.addWidget(time_table)
        tabs.addTab(time_tab, "⏱️ Timeline")
        
        # TODO: connect to backend parsing logic to populate these tabs dynamically
        
        rep_layout.addWidget(tabs)
        self.stacked_widget.addWidget(rep_page)
        
        # 6. Export
        exp_page, exp_layout = self.create_page_container("Export Report")
        
        exp_card = QWidget()
        exp_card.setProperty("class", "Card")
        ec_layout = QVBoxLayout(exp_card)
        ec_layout.setSpacing(15)
        
        format_label = QLabel("Select Export Format:")
        format_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; font-weight: bold;")
        ec_layout.addWidget(format_label)
        
        format_group = QButtonGroup(self)
        rb_pdf = QRadioButton("📄 PDF Formal Report (Court Ready)")
        rb_csv = QRadioButton("📊 CSV Data Dump (For Analysis Tools)")
        rb_html = QRadioButton("🌐 HTML Interactive (Browser Navigable)")
        rb_pdf.setChecked(True)
        
        format_group.addButton(rb_pdf)
        format_group.addButton(rb_csv)
        format_group.addButton(rb_html)
        
        rb_layout = QVBoxLayout()
        rb_layout.setContentsMargins(20, 0, 0, 0)
        rb_layout.addWidget(rb_pdf)
        rb_layout.addWidget(rb_csv)
        rb_layout.addWidget(rb_html)
        ec_layout.addLayout(rb_layout)
        
        ec_layout.addSpacing(20)
        prev_label = QLabel("Preview Layout:")
        prev_label.setStyleSheet("font-family: 'Segoe UI'; font-size: 14px; font-weight: bold;")
        ec_layout.addWidget(prev_label)
        
        preview_frame = QLabel("📄 REPORT PREVIEW\n\nCase Name: CASE_2026_006\nInvestigator: John Doe\n\n[Visual Representation of PDF Layout]")
        preview_frame.setAlignment(Qt.AlignCenter)
        preview_frame.setStyleSheet("""
            background-color: #11111b; 
            border: 2px dashed #45475a; 
            border-radius: 8px; 
            padding: 60px;
            color: #bac2de;
            font-family: 'Segoe UI';
        """)
        ec_layout.addWidget(preview_frame)
        
        # TODO: connect to backend export logic based on radio selection
        
        exp_layout.addWidget(exp_card)
        exp_layout.addStretch()
        
        gen_rep_btn = QPushButton("Generate & Save Report")
        gen_rep_btn.setProperty("class", "PrimaryButton")
        exp_layout.addWidget(gen_rep_btn, alignment=Qt.AlignRight)
        
        self.stacked_widget.addWidget(exp_page)
        
        # 7. Settings
        set_page, set_layout = self.create_page_container("Application Settings")
        
        set_card = QWidget()
        set_card.setProperty("class", "Card")
        sf_layout = QFormLayout(set_card)
        sf_layout.setSpacing(20)
        sf_layout.setLabelAlignment(Qt.AlignRight)
        
        def add_path_setting(label, default_val):
            layout = QHBoxLayout()
            edit = QLineEdit(default_val)
            btn = QPushButton("Browse...")
            btn.setStyleSheet("background-color: #313244; padding: 8px; border-radius: 6px;")
            layout.addWidget(edit)
            layout.addWidget(btn)
            sf_layout.addRow(label, layout)
            
        add_path_setting("ADB Executable Path:", "/usr/bin/adb")
        add_path_setting("abe.jar Path:", "./tools/abe.jar")
        add_path_setting("Default Output Folder:", "~/cases/whtssec_extractions")
        
        theme_toggle = QCheckBox("Enable Dark Mode (Requires restart)")
        theme_toggle.setChecked(True)
        sf_layout.addRow("Theme:", theme_toggle)
        
        set_layout.addWidget(set_card)
        set_layout.addStretch()
        
        save_set_btn = QPushButton("Save Settings")
        save_set_btn.setProperty("class", "PrimaryButton")
        set_layout.addWidget(save_set_btn, alignment=Qt.AlignRight)
        
        self.stacked_widget.addWidget(set_page)
        
        # 8. About / Case Log
        abt_page, abt_layout = self.create_page_container("About & Audit Log")
        
        abt_card = QWidget()
        abt_card.setProperty("class", "Card")
        ac_layout = QVBoxLayout(abt_card)
        
        title = QLabel("Whtssec Forensic Tool")
        title.setStyleSheet("font-family: 'Segoe UI'; font-size: 20px; font-weight: bold; color: #89b4fa;")
        ac_layout.addWidget(title)
        
        ac_layout.addWidget(QLabel("Version 1.0.0-beta"))
        ac_layout.addWidget(QLabel("Developed for secure forensic evidence extraction from Android devices."))
        abt_layout.addWidget(abt_card)
        
        abt_layout.addSpacing(20)
        
        audit_title = QLabel("System Audit Trail")
        audit_title.setStyleSheet("font-family: 'Segoe UI'; font-size: 16px; font-weight: bold;")
        abt_layout.addWidget(audit_title)
        
        audit_table = QTableWidget(5, 3)
        audit_table.setAlternatingRowColors(True)
        audit_table.setHorizontalHeaderLabels(["Action", "Timestamp", "User/System"])
        audit_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        audit_table.verticalHeader().setVisible(False)
        audit_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        audit_events = [
            ("Application Started", "2026-08-06 00:00:01", "System"),
            ("User Login", "2026-08-06 00:00:05", "John Doe"),
            ("Case CASE_2026_006 Created", "2026-08-06 00:02:15", "John Doe"),
            ("ADB Connection Attempted", "2026-08-06 00:02:45", "System"),
            ("Extraction Initiated", "2026-08-06 00:05:00", "John Doe")
        ]
        
        for i, (action, ts, user) in enumerate(audit_events):
            audit_table.setItem(i, 0, QTableWidgetItem(action))
            audit_table.setItem(i, 1, QTableWidgetItem(ts))
            audit_table.setItem(i, 2, QTableWidgetItem(user))
            
        abt_layout.addWidget(audit_table)
        self.stacked_widget.addWidget(abt_page)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = WhtssecForensicTool()
    window.show()
    sys.exit(app.exec())
