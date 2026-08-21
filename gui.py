from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from classifier import classify_connections
from correlator import correlate_events
from parser import parse_logfile
from reporter import default_report_directory, export_json


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PROJECT_ROOT = Path(__file__).resolve().parent
SAMPLE_LOGS_DIR = PROJECT_ROOT / "sample_logs"


class DFIRApp(ctk.CTk):
    FONT_DISPLAY = "Segoe UI Variable Display"
    FONT_BODY = "Segoe UI Variable Text"
    FONT_CODE = "Cascadia Code"

    COLORS = {
        "canvas": "#070B14",
        "sidebar": "#0C1322",
        "sidebar_border": "#16233B",
        "panel": "#101B30",
        "panel_hover": "#172744",
        "card_subtle": "#0D172A",
        "border": "#1E3154",
        "border_light": "#2A4370",
        "muted": "#8295B3",
        "text_bright": "#F1F6FD",
        "text_sub": "#B0C3DE",
        "accent": "#3B82F6",
        "accent_hover": "#2563EB",
        "accent_glow": "#1D4ED8",
        "cyan": "#06B6D4",
        "purple": "#8B5CF6",
        "malicious": "#EF4444",
        "malicious_bg": "#361318",
        "malicious_border": "#63222B",
        "suspicious": "#F59E0B",
        "suspicious_bg": "#38250F",
        "suspicious_border": "#664319",
        "normal": "#10B981",
        "normal_bg": "#0C2E22",
        "normal_border": "#185943",
    }

    SAMPLE_PRESETS = [
        ("Select a sample scenario...", ""),
        ("🔴 SYN Flood Attack (tcpdump)", "syn_flood_attack.txt"),
        ("🔴 ICMP Flood Attack (tcpdump)", "icmp_flood_attack.txt"),
        ("🟠 RDP Brute Force (tcpdump)", "repeated_rdp_connections.txt"),
        ("🟠 Backdoor Port 4444 (tcpdump)", "suspicious_port.txt"),
        ("🟢 Normal Traffic & DNS (tcpdump)", "syn_flood.txt"),
        ("🔴 Wireshark SYN Flood (CSV)", "wireshark_syn_flood.csv"),
        ("🔴 Wireshark ICMP Flood (CSV)", "wireshark_icmp_flood.csv"),
        ("🟠 Wireshark DNS Redirect (CSV)", "wireshark_dns_redirect.csv"),
    ]

    def __init__(self):
        super().__init__()
        self.title("DFIR Log Analyser")
        self.geometry("1480x880")
        self.minsize(1180, 720)
        self.configure(fg_color=self.COLORS["canvas"])

        self.selected_file = tk.StringVar(value="No log file selected")
        self.search_var = tk.StringVar()
        self.severity_filter = tk.StringVar(value="All")
        self.sample_choice_var = tk.StringVar(value=self.SAMPLE_PRESETS[0][0])
        self.current_view = "traffic"
        self.connections = []
        self.nav_buttons = {}
        self.rule_status_labels = {}
        self.rule_hit_labels = {}
        self.sort_column = None
        self.sort_reverse = False

        self._configure_tree_style()
        self._build_ui()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())

    def _configure_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "DFIR.Treeview",
            background=self.COLORS["panel"],
            foreground="#EAF1FC",
            fieldbackground=self.COLORS["panel"],
            rowheight=36,
            borderwidth=0,
            font=(self.FONT_CODE, 10),
        )
        style.configure(
            "DFIR.Treeview.Heading",
            background="#152440",
            foreground="#A9C2E8",
            borderwidth=0,
            relief="flat",
            padding=(10, 8),
            font=(self.FONT_DISPLAY, 10, "bold"),
        )
        style.map(
            "DFIR.Treeview",
            background=[("selected", self.COLORS["accent"])],
            foreground=[("selected", "#FFFFFF")],
        )
        style.configure(
            "DFIR.Vertical.TScrollbar",
            background="#1E3154",
            troughcolor=self.COLORS["panel"],
            borderwidth=0,
            arrowsize=11,
        )
        style.configure(
            "DFIR.Horizontal.TScrollbar",
            background="#1E3154",
            troughcolor=self.COLORS["panel"],
            borderwidth=0,
            arrowsize=11,
        )
        style.map(
            "DFIR.Vertical.TScrollbar",
            background=[("active", self.COLORS["accent"])],
        )
        style.map(
            "DFIR.Horizontal.TScrollbar",
            background=[("active", self.COLORS["accent"])],
        )

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()

        self.main_content = ctk.CTkFrame(self, fg_color="transparent")
        self.main_content.grid(row=0, column=1, sticky="nsew", padx=(0, 24), pady=24)
        self.main_content.grid_columnconfigure(0, weight=1)
        self.main_content.grid_rowconfigure(1, weight=1)

        self._build_header(self.main_content)

        self.view_container = ctk.CTkFrame(self.main_content, fg_color="transparent")
        self.view_container.grid(row=1, column=0, sticky="nsew")
        self.view_container.grid_columnconfigure(0, weight=1)
        self.view_container.grid_rowconfigure(0, weight=1)

        self._build_traffic_view()
        self._build_rules_view()
        self._build_analytics_view()

        self._show_view("traffic")

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(
            self,
            width=260,
            corner_radius=0,
            fg_color=self.COLORS["sidebar"],
            border_width=1,
            border_color=self.COLORS["sidebar_border"],
        )
        sidebar.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        sidebar.grid_propagate(False)

        brand_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand_frame.pack(fill="x", padx=20, pady=(24, 20))

        badge = ctk.CTkLabel(
            brand_frame,
            text="DFIR",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=11, weight="bold"),
            fg_color=self.COLORS["accent"],
            text_color="#FFFFFF",
            corner_radius=6,
            width=46,
            height=22,
        )
        badge.pack(anchor="w", pady=(0, 6))

        ctk.CTkLabel(
            brand_frame,
            text="Log Analyser",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=22, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            brand_frame,
            text="Forensic Threat Hunter",
            font=ctk.CTkFont(family=self.FONT_BODY, size=11),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w")

        ctk.CTkFrame(sidebar, height=1, fg_color=self.COLORS["sidebar_border"]).pack(fill="x", padx=16, pady=(0, 16))

        self._sidebar_section_title(sidebar, "NAVIGATION")
        self._nav_item(sidebar, "refresh", "🔄", "Reset Workspace", self._refresh_workspace, is_action=True)
        self._nav_item(sidebar, "traffic", "🔍", "Traffic Sessions", lambda: self._show_view("traffic"), active=True)
        self._nav_item(sidebar, "rules", "🛡", "Threat Matrix & Rules", lambda: self._show_view("rules"), active=False)
        self._nav_item(sidebar, "analytics", "📊", "Forensic Analytics", lambda: self._show_view("analytics"), active=False)

        self._sidebar_section_title(sidebar, "LOAD SAMPLE LOGS")

        sample_dropdown_frame = ctk.CTkFrame(sidebar, fg_color="transparent")
        sample_dropdown_frame.pack(fill="x", padx=16, pady=(4, 12))

        sample_names = [name for name, _ in self.SAMPLE_PRESETS]
        self.sample_option_menu = ctk.CTkOptionMenu(
            sample_dropdown_frame,
            values=sample_names,
            variable=self.sample_choice_var,
            command=self._on_sample_selected,
            height=34,
            fg_color=self.COLORS["panel"],
            button_color="#1E3154",
            button_hover_color=self.COLORS["accent"],
            dropdown_fg_color=self.COLORS["panel"],
            dropdown_hover_color=self.COLORS["panel_hover"],
            font=ctk.CTkFont(family=self.FONT_BODY, size=11),
            dropdown_font=ctk.CTkFont(family=self.FONT_BODY, size=11),
        )
        self.sample_option_menu.pack(fill="x")

        self._sidebar_section_title(sidebar, "ACTIVE DETECTIONS (FILTER)")
        rules_box = ctk.CTkFrame(
            sidebar,
            fg_color=self.COLORS["card_subtle"],
            corner_radius=8,
            border_width=1,
            border_color=self.COLORS["sidebar_border"],
        )
        rules_box.pack(fill="x", padx=16, pady=(4, 16))

        detection_specs = [
            ("syn", "🔴 SYN Flood", "SYN Flood"),
            ("icmp", "🔴 ICMP Flood", "ICMP Flood"),
            ("brute", "🟠 SSH / RDP Brute", "Repeated"),
            ("port", "🟠 Suspicious Port", "suspicious port"),
            ("redirect", "🟠 DNS Redirection", "redirect"),
        ]

        self.rule_hit_labels = {}
        for key, name, filter_query in detection_specs:
            rf = ctk.CTkFrame(rules_box, fg_color="transparent")
            rf.pack(fill="x", padx=6, pady=2)

            btn = ctk.CTkButton(
                rf,
                text=name,
                anchor="w",
                height=26,
                font=ctk.CTkFont(family=self.FONT_BODY, size=11, weight="bold"),
                fg_color="transparent",
                hover_color=self.COLORS["panel_hover"],
                text_color=self.COLORS["text_sub"],
                command=lambda q=filter_query: self._filter_by_detection(q),
            )
            btn.pack(side="left", fill="x", expand=True)

            hit_badge = ctk.CTkLabel(
                rf,
                text="0",
                width=24,
                height=18,
                corner_radius=9,
                fg_color=self.COLORS["sidebar_border"],
                text_color=self.COLORS["muted"],
                font=ctk.CTkFont(family=self.FONT_CODE, size=10, weight="bold"),
            )
            hit_badge.pack(side="right", padx=(4, 4))
            self.rule_hit_labels[key] = hit_badge

        system_card = ctk.CTkFrame(
            sidebar,
            fg_color=self.COLORS["card_subtle"],
            corner_radius=8,
            border_width=1,
            border_color=self.COLORS["sidebar_border"],
        )
        system_card.pack(side="bottom", fill="x", padx=16, pady=16)

        ctk.CTkLabel(
            system_card,
            text="ENGINE STATUS",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=9, weight="bold"),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w", padx=12, pady=(10, 2))

        ctk.CTkLabel(
            system_card,
            text="● Heuristics Engine Active",
            font=ctk.CTkFont(family=self.FONT_BODY, size=11, weight="bold"),
            text_color=self.COLORS["normal"],
        ).pack(anchor="w", padx=12, pady=(0, 10))

    def _sidebar_section_title(self, parent, text):
        ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=10, weight="bold"),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w", padx=20, pady=(12, 4))

    def _nav_item(self, parent, key, icon, label, command, active=False, is_action=False):
        btn = ctk.CTkButton(
            parent,
            text=f"{icon}   {label}",
            anchor="w",
            height=38,
            corner_radius=8,
            font=ctk.CTkFont(family=self.FONT_BODY, size=12, weight="bold" if (active or is_action) else "normal"),
            fg_color="#182A4A" if active else ("#15243E" if is_action else "transparent"),
            hover_color=self.COLORS["panel_hover"],
            text_color="#FFFFFF" if (active or is_action) else self.COLORS["text_sub"],
            command=command,
        )
        btn.pack(fill="x", padx=16, pady=2)
        self.nav_buttons[key] = btn

    def _show_view(self, view_name):
        self.current_view = view_name
        for key, btn in self.nav_buttons.items():
            if key == "refresh":
                continue
            is_active = key == view_name
            btn.configure(
                fg_color="#182A4A" if is_active else "transparent",
                text_color="#FFFFFF" if is_active else self.COLORS["text_sub"],
                font=ctk.CTkFont(family=self.FONT_BODY, size=12, weight="bold" if is_active else "normal"),
            )

        if hasattr(self, "view_traffic"):
            self.view_traffic.grid_remove()
        if hasattr(self, "view_rules"):
            self.view_rules.grid_remove()
        if hasattr(self, "view_analytics"):
            self.view_analytics.grid_remove()

        if view_name == "traffic" and hasattr(self, "view_traffic"):
            self.view_traffic.grid(row=0, column=0, sticky="nsew")
        elif view_name == "rules" and hasattr(self, "view_rules"):
            self.view_rules.grid(row=0, column=0, sticky="nsew")
            self._update_rules_view()
        elif view_name == "analytics" and hasattr(self, "view_analytics"):
            self.view_analytics.grid(row=0, column=0, sticky="nsew")
            self._update_analytics_view()

    def _filter_by_detection(self, filter_query):
        self._show_view("traffic")
        current = self.search_var.get().strip()
        if current.lower() == filter_query.lower():
            self.search_var.set("")
        else:
            self.severity_filter.set("All")
            if hasattr(self, "filter_menu") and hasattr(self.filter_menu, "set"):
                self.filter_menu.set("All")
            self.search_var.set(filter_query)

    def _build_header(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        header.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            title_box,
            text="Security Investigation Console",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=24, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_box,
            text="Automated correlation and behavioral threat detection for tcpdump and Wireshark logs.",
            font=ctk.CTkFont(family=self.FONT_BODY, size=12),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w", pady=(2, 0))

        self.status_badge = ctk.CTkLabel(
            header,
            text="READY",
            width=110,
            height=30,
            corner_radius=15,
            fg_color=self.COLORS["normal_bg"],
            text_color=self.COLORS["normal"],
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=11, weight="bold"),
        )
        self.status_badge.grid(row=0, column=1, sticky="e")

    def _build_traffic_view(self):
        self.view_traffic = ctk.CTkFrame(self.view_container, fg_color="transparent")
        self.view_traffic.grid_columnconfigure(0, weight=1)
        self.view_traffic.grid_rowconfigure(2, weight=1)

        self._build_summary_cards(self.view_traffic)
        self._build_toolbar(self.view_traffic)
        self._build_results_area(self.view_traffic)

    def _build_summary_cards(self, parent):
        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1)

        self.metric_labels = {}
        specs = [
            ("TOTAL CONVERSATIONS", "total", self.COLORS["accent"], self.COLORS["panel"], "📡"),
            ("MALICIOUS DETECTIONS", "malicious", self.COLORS["malicious"], self.COLORS["malicious_bg"], "🛡️"),
            ("SUSPICIOUS ALERTS", "suspicious", self.COLORS["suspicious"], self.COLORS["suspicious_bg"], "⚠️"),
            ("NORMAL TRAFFIC", "normal", self.COLORS["normal"], self.COLORS["normal_bg"], "✅"),
        ]
        for column, (title, key, text_color, bg_color, icon) in enumerate(specs):
            card = ctk.CTkFrame(
                cards,
                fg_color=self.COLORS["panel"],
                corner_radius=10,
                border_width=1,
                border_color=self.COLORS["border"],
            )
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 6, 6 if column < 3 else 0))

            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", padx=16, pady=(14, 0))

            ctk.CTkLabel(
                top_row,
                text=title,
                font=ctk.CTkFont(family=self.FONT_BODY, size=10, weight="bold"),
                text_color=self.COLORS["muted"],
            ).pack(side="left")

            ctk.CTkLabel(
                top_row,
                text=icon,
                font=ctk.CTkFont(size=13),
            ).pack(side="right")

            value = ctk.CTkLabel(
                card,
                text="0",
                font=ctk.CTkFont(family=self.FONT_DISPLAY, size=28, weight="bold"),
                text_color=text_color,
            )
            value.pack(anchor="w", padx=16, pady=(2, 12))
            self.metric_labels[key] = value

    def _build_toolbar(self, parent):
        toolbar = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["panel"],
            corner_radius=10,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        toolbar.grid_columnconfigure(1, weight=1)

        self.browse_button = ctk.CTkButton(
            toolbar,
            text="Browse Log...",
            width=120,
            height=36,
            command=self._browse_file,
            fg_color="#1D335A",
            hover_color="#27467C",
            font=ctk.CTkFont(family=self.FONT_BODY, size=12, weight="bold"),
        )
        self.browse_button.grid(row=0, column=0, padx=(12, 8), pady=10)

        file_container = ctk.CTkFrame(toolbar, fg_color=self.COLORS["card_subtle"], corner_radius=6, height=36)
        file_container.grid(row=0, column=1, sticky="ew", padx=4, pady=10)
        file_container.grid_columnconfigure(0, weight=1)

        self.file_label = ctk.CTkLabel(
            file_container,
            textvariable=self.selected_file,
            anchor="w",
            text_color=self.COLORS["text_sub"],
            font=ctk.CTkFont(family=self.FONT_CODE, size=11),
        )
        self.file_label.grid(row=0, column=0, sticky="ew", padx=12, pady=6)

        self.analyse_button = ctk.CTkButton(
            toolbar,
            text="⚡ Run Analysis",
            width=125,
            height=36,
            command=self._run_analysis,
            fg_color=self.COLORS["accent"],
            hover_color=self.COLORS["accent_hover"],
            font=ctk.CTkFont(family=self.FONT_BODY, size=12, weight="bold"),
        )
        self.analyse_button.grid(row=0, column=2, padx=(8, 6), pady=10)

        self.export_button = ctk.CTkButton(
            toolbar,
            text="📥 Export JSON",
            width=115,
            height=36,
            command=self._export_results,
            state="disabled",
            fg_color="#134E3F",
            hover_color="#1A6854",
            font=ctk.CTkFont(family=self.FONT_BODY, size=12, weight="bold"),
        )
        self.export_button.grid(row=0, column=3, padx=(4, 12), pady=10)

    def _build_results_area(self, parent):
        area = ctk.CTkFrame(parent, fg_color="transparent")
        area.grid(row=2, column=0, sticky="nsew")
        area.grid_columnconfigure(0, weight=6)
        area.grid_columnconfigure(1, weight=4)
        area.grid_rowconfigure(0, weight=1)

        results = ctk.CTkFrame(
            area,
            fg_color=self.COLORS["panel"],
            corner_radius=10,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        results.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(2, weight=1)

        table_header = ctk.CTkFrame(results, fg_color="transparent")
        table_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        table_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            table_header,
            text="Network Sessions",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=16, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).grid(row=0, column=0, sticky="w")

        self.session_count_label = ctk.CTkLabel(
            table_header,
            text="0 sessions",
            font=ctk.CTkFont(family=self.FONT_CODE, size=11),
            text_color=self.COLORS["muted"],
        )
        self.session_count_label.grid(row=0, column=1, sticky="e")

        controls = ctk.CTkFrame(results, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        controls.grid_columnconfigure(0, weight=1)

        search_box = ctk.CTkFrame(controls, fg_color=self.COLORS["card_subtle"], corner_radius=6, border_width=1, border_color=self.COLORS["border"])
        search_box.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        search_box.grid_columnconfigure(0, weight=1)

        self.search_entry = ctk.CTkEntry(
            search_box,
            textvariable=self.search_var,
            placeholder_text="Filter by IP, port, reason, protocol...",
            height=32,
            border_width=0,
            fg_color="transparent",
            font=ctk.CTkFont(family=self.FONT_BODY, size=11),
        )
        self.search_entry.grid(row=0, column=0, sticky="ew", padx=(8, 0))

        ctk.CTkButton(
            search_box,
            text="✕",
            width=24,
            height=24,
            command=lambda: self.search_var.set(""),
            fg_color="transparent",
            hover_color=self.COLORS["panel_hover"],
            text_color=self.COLORS["muted"],
        ).grid(row=0, column=1, padx=(0, 4))

        self.filter_menu = ctk.CTkSegmentedButton(
            controls,
            values=["All", "Malicious", "Suspicious", "Normal"],
            variable=self.severity_filter,
            command=lambda _: self._refresh_table(),
            width=290,
            height=32,
            fg_color=self.COLORS["card_subtle"],
            selected_color=self.COLORS["accent"],
            selected_hover_color=self.COLORS["accent_hover"],
            font=ctk.CTkFont(family=self.FONT_BODY, size=11, weight="bold"),
        )
        self.filter_menu.grid(row=0, column=1)

        table_frame = ctk.CTkFrame(results, fg_color="transparent")
        table_frame.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 14))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        columns = ("source", "destination", "port", "events", "duration", "status", "reason")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="DFIR.Treeview", selectmode="browse")
        headings = {
            "source": "SOURCE IP",
            "destination": "DESTINATION IP",
            "port": "PORT",
            "events": "PKTS",
            "duration": "DURATION",
            "status": "SEVERITY",
            "reason": "ANALYSIS / REASON",
        }
        widths = {"source": 130, "destination": 140, "port": 65, "events": 60, "duration": 100, "status": 100, "reason": 320}
        minwidths = {"source": 115, "destination": 125, "port": 55, "events": 50, "duration": 95, "status": 90, "reason": 220}
        for col in columns:
            self.tree.heading(col, text=headings[col], command=lambda c=col: self._sort_by_column(c))
            self.tree.column(
                col,
                width=widths[col],
                minwidth=minwidths[col],
                anchor="center" if col in {"port", "events", "duration", "status"} else "w",
                stretch=col == "reason",
            )

        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._show_connection_detail)

        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview, style="DFIR.Vertical.TScrollbar")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview, style="DFIR.Horizontal.TScrollbar")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.tree.tag_configure("Malicious", foreground="#FF7B7B")
        self.tree.tag_configure("Suspicious", foreground="#FFD066")
        self.tree.tag_configure("Normal", foreground="#6CE5B8")

        self._build_detail_panel(area)

    def _build_detail_panel(self, parent):
        panel = ctk.CTkFrame(
            parent,
            fg_color=self.COLORS["panel"],
            corner_radius=10,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)

        detail_header = ctk.CTkFrame(panel, fg_color="transparent")
        detail_header.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))
        detail_header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            detail_header,
            text="Evidence & Forensic Inspector",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=16, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).grid(row=0, column=0, sticky="w")

        self.connection_banner = ctk.CTkFrame(
            panel,
            fg_color=self.COLORS["card_subtle"],
            corner_radius=8,
            border_width=1,
            border_color=self.COLORS["border"],
        )
        self.connection_banner.grid(row=1, column=0, sticky="ew", padx=16, pady=(6, 10))
        self.connection_banner.grid_columnconfigure(0, weight=1)

        self.banner_flow_label = ctk.CTkLabel(
            self.connection_banner,
            text="No connection selected",
            font=ctk.CTkFont(family=self.FONT_CODE, size=12, weight="bold"),
            text_color=self.COLORS["muted"],
        )
        self.banner_flow_label.grid(row=0, column=0, sticky="w", padx=12, pady=(8, 2))

        self.banner_meta_label = ctk.CTkLabel(
            self.connection_banner,
            text="Select any row in the network sessions table to inspect evidence.",
            font=ctk.CTkFont(family=self.FONT_BODY, size=11),
            text_color=self.COLORS["muted"],
        )
        self.banner_meta_label.grid(row=1, column=0, sticky="w", padx=12, pady=(0, 8))

        self.tabview = ctk.CTkTabview(
            panel,
            fg_color="transparent",
            segmented_button_fg_color=self.COLORS["card_subtle"],
            segmented_button_selected_color=self.COLORS["accent"],
            segmented_button_selected_hover_color=self.COLORS["accent_hover"],
            segmented_button_unselected_hover_color=self.COLORS["panel_hover"],
            text_color="#FFFFFF",
        )
        self.tabview.grid(row=2, column=0, sticky="nsew", padx=16, pady=(0, 14))

        self.tab_packets = self.tabview.add("Packet Stream")
        self.tab_threat = self.tabview.add("Threat Intel & MITRE")
        self.tab_raw = self.tabview.add("Raw Inspection")

        self.packet_stream_text = ctk.CTkTextbox(
            self.tab_packets,
            fg_color=self.COLORS["card_subtle"],
            border_width=0,
            font=(self.FONT_CODE, 10),
            text_color="#D5E4FC",
            wrap="none",
        )
        self.packet_stream_text.pack(fill="both", expand=True)

        self.threat_text = ctk.CTkTextbox(
            self.tab_threat,
            fg_color=self.COLORS["card_subtle"],
            border_width=0,
            font=(self.FONT_BODY, 11),
            text_color="#E0EBFB",
            wrap="word",
        )
        self.threat_text.pack(fill="both", expand=True)

        self.detail_text = ctk.CTkTextbox(
            self.tab_raw,
            fg_color=self.COLORS["card_subtle"],
            border_width=0,
            font=(self.FONT_CODE, 10),
            text_color="#D5E4FC",
            wrap="word",
        )
        self.detail_text.pack(fill="both", expand=True)

        self._set_detail(
            "DFIR Investigation Console Ready\n\n"
            "1. Click 'Browse Log...' or select a scenario from 'LOAD SAMPLE LOGS'.\n"
            "2. Click 'Run Analysis' to correlate sessions and execute heuristic classifiers.\n"
            "3. Select any connection to inspect timestamped packet streams and MITRE ATT&CK guidance."
        )

    def _build_rules_view(self):
        self.view_rules = ctk.CTkScrollableFrame(self.view_container, fg_color="transparent")
        self.view_rules.grid_columnconfigure(0, weight=1)

        header_frame = ctk.CTkFrame(self.view_rules, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            header_frame,
            text="Threat Detection Matrix & Heuristic Rules",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=20, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            header_frame,
            text="Behavioral correlation rules, threshold triggers, and MITRE ATT&CK mappings.",
            font=ctk.CTkFont(family=self.FONT_BODY, size=12),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w", pady=(2, 0))

        rules_catalog = [
            (
                "syn",
                "TCP SYN Flood Attack (Half-Open DoS)",
                "T1498.001 (Direct Network Flood)",
                "Flags connections where source host transmits >= 10 TCP SYN packets without completing the 3-way handshake (ack_count == 0), exhausting server backlog sockets.",
                "Threshold: >= 10 SYN packets & 0 client ACKs  |  Severity: CRITICAL",
                self.COLORS["malicious"],
            ),
            (
                "icmp",
                "ICMP Flood / Ping Flood Attack",
                "T1498.001 (Direct Network Flood)",
                "Identifies high-frequency ICMP Echo Requests (ping) originating from a single endpoint intended to congest network links or overwhelm host protocol stacks.",
                "Threshold: >= 10 ICMP packets in session  |  Severity: CRITICAL",
                self.COLORS["malicious"],
            ),
            (
                "brute",
                "RDP / SSH Credential Brute Force",
                "T1110.001 (Password Guessing)",
                "Detects repeated authentication and connection attempts against remote administration services (SSH port 22 or RDP port 3389) across client ephemeral ports.",
                "Threshold: >= 5 Auth attempts  |  Severity: HIGH",
                self.COLORS["suspicious"],
            ),
            (
                "port",
                "Known Backdoor / Reverse Shell Port Access",
                "T1571 (Non-Standard Port) / T1071",
                "Alerts immediately when traffic connects to well-known post-exploitation listener ports (4444 Metasploit/Meterpreter, 1337, 31337 Elite Backdoors).",
                "Target Ports: 4444, 1337, 31337  |  Severity: HIGH",
                self.COLORS["suspicious"],
            ),
            (
                "redirect",
                "DNS Redirection & Cache Poisoning Anomaly",
                "T1557 (AiTM) / T1584.008 (DNS Spoofing)",
                "Detects HTTP/HTTPS traffic addressed to an IP address that deviates from the authoritative DNS response parsed earlier in the session stream.",
                "Condition: Destination IP != Resolved DNS Record  |  Severity: MEDIUM",
                self.COLORS["suspicious"],
            ),
        ]

        self.rule_status_labels = {}
        for key, name, mitre, desc, thresh, color in rules_catalog:
            card = ctk.CTkFrame(
                self.view_rules,
                fg_color=self.COLORS["panel"],
                corner_radius=10,
                border_width=1,
                border_color=self.COLORS["border"],
            )
            card.pack(fill="x", pady=6)

            card_head = ctk.CTkFrame(card, fg_color="transparent")
            card_head.pack(fill="x", padx=16, pady=(12, 4))

            ctk.CTkLabel(
                card_head,
                text=name,
                font=ctk.CTkFont(family=self.FONT_DISPLAY, size=14, weight="bold"),
                text_color=color,
            ).pack(side="left")

            status_pill = ctk.CTkLabel(
                card_head,
                text="● IDLE / MONITORING",
                font=ctk.CTkFont(family=self.FONT_DISPLAY, size=10, weight="bold"),
                fg_color=self.COLORS["card_subtle"],
                text_color=self.COLORS["muted"],
                corner_radius=10,
                width=140,
                height=22,
            )
            status_pill.pack(side="right")
            self.rule_status_labels[key] = status_pill

            ctk.CTkLabel(
                card,
                text=f"MITRE ATT&CK: {mitre}",
                font=ctk.CTkFont(family=self.FONT_CODE, size=11, weight="bold"),
                text_color=self.COLORS["cyan"],
            ).pack(anchor="w", padx=16, pady=(0, 4))

            ctk.CTkLabel(
                card,
                text=desc,
                font=ctk.CTkFont(family=self.FONT_BODY, size=11),
                text_color=self.COLORS["text_sub"],
                wraplength=900,
                justify="left",
            ).pack(anchor="w", padx=16, pady=(0, 6))

            ctk.CTkLabel(
                card,
                text=thresh,
                font=ctk.CTkFont(family=self.FONT_CODE, size=10),
                text_color=self.COLORS["muted"],
            ).pack(anchor="w", padx=16, pady=(0, 12))

    def _update_rules_view(self):
        if not hasattr(self, "rule_status_labels"):
            return
        rule_hits = {
            "syn": sum(1 for c in self.connections if "syn flood" in c.reason.lower()),
            "icmp": sum(1 for c in self.connections if "icmp flood" in c.reason.lower()),
            "brute": sum(1 for c in self.connections if ("rdp" in c.reason.lower() or "ssh" in c.reason.lower())),
            "port": sum(1 for c in self.connections if "suspicious port" in c.reason.lower()),
            "redirect": sum(1 for c in self.connections if "redirect" in c.reason.lower()),
        }
        for key, pill in self.rule_status_labels.items():
            hits = rule_hits.get(key, 0)
            if hits > 0:
                pill.configure(
                    text=f"🚨 TRIGGERED ({hits} HITS)",
                    fg_color=self.COLORS["malicious_bg"] if key in ("syn", "icmp") else self.COLORS["suspicious_bg"],
                    text_color=self.COLORS["malicious"] if key in ("syn", "icmp") else self.COLORS["suspicious"],
                )
            else:
                pill.configure(
                    text="● IDLE / MONITORING",
                    fg_color=self.COLORS["card_subtle"],
                    text_color=self.COLORS["muted"],
                )

    def _build_analytics_view(self):
        self.view_analytics = ctk.CTkScrollableFrame(self.view_container, fg_color="transparent")
        self.view_analytics.grid_columnconfigure(0, weight=1)

        header_frame = ctk.CTkFrame(self.view_analytics, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 16))

        ctk.CTkLabel(
            header_frame,
            text="Forensic Traffic Analytics & Top Talkers",
            font=ctk.CTkFont(family=self.FONT_DISPLAY, size=20, weight="bold"),
            text_color=self.COLORS["text_bright"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            header_frame,
            text="Protocol distribution, IP endpoint rankings, and forensic timeline telemetry.",
            font=ctk.CTkFont(family=self.FONT_BODY, size=12),
            text_color=self.COLORS["muted"],
        ).pack(anchor="w", pady=(2, 0))

        self.analytics_text = ctk.CTkTextbox(
            self.view_analytics,
            fg_color=self.COLORS["panel"],
            border_width=1,
            border_color=self.COLORS["border"],
            font=(self.FONT_CODE, 11),
            text_color="#D5E4FC",
            height=500,
        )
        self.analytics_text.pack(fill="both", expand=True, pady=6)
        self.analytics_text.insert("1.0", "Load a log and run analysis to view protocol distribution and top talker analytics.")
        self.analytics_text.configure(state="disabled")

    def _update_analytics_view(self):
        if not hasattr(self, "analytics_text"):
            return

        if not self.connections:
            content = "No log data loaded. Click 'Browse Log...' or select a sample scenario from the left sidebar to run analysis."
        else:
            total_events = sum(c.event_count() for c in self.connections)
            total_sessions = len(self.connections)
            malicious_sessions = sum(1 for c in self.connections if c.classification == "Malicious")
            suspicious_sessions = sum(1 for c in self.connections if c.classification == "Suspicious")
            normal_sessions = sum(1 for c in self.connections if c.classification == "Normal")

            proto_counts = {}
            src_ip_counts = {}
            dst_ip_counts = {}
            for c in self.connections:
                src_ip_counts[c.src_ip] = src_ip_counts.get(c.src_ip, 0) + c.event_count()
                dst_ip_counts[c.dst_ip] = dst_ip_counts.get(c.dst_ip, 0) + c.event_count()
                for e in c.events:
                    proto_counts[e.protocol] = proto_counts.get(e.protocol, 0) + 1

            lines = [
                "=======================================================================================",
                "                           DIGITAL FORENSICS TELEMETRY REPORT                          ",
                "=======================================================================================",
                f" Active File           : {Path(self.selected_file.get()).name if self.selected_file.get() else 'N/A'}",
                f" Total Ingested Events : {total_events} packets",
                f" Correlated Sessions   : {total_sessions} conversations",
                f" Malicious Sessions    : {malicious_sessions} ({malicious_sessions/max(total_sessions,1)*100:.1f}%)",
                f" Suspicious Sessions   : {suspicious_sessions} ({suspicious_sessions/max(total_sessions,1)*100:.1f}%)",
                f" Normal Sessions       : {normal_sessions} ({normal_sessions/max(total_sessions,1)*100:.1f}%)",
                "",
                "---------------------------------------------------------------------------------------",
                " PROTOCOL DISTRIBUTION",
                "---------------------------------------------------------------------------------------",
            ]
            for proto, count in sorted(proto_counts.items(), key=lambda x: x[1], reverse=True):
                pct = count / max(total_events, 1) * 100
                bar = "#" * int(pct / 4)
                lines.append(f" {proto:<8} : {count:>5} pkts ({pct:>5.1f}%)  {bar}")

            lines.extend([
                "",
                "---------------------------------------------------------------------------------------",
                " TOP SOURCE TALKERS (TRANSMITTERS)",
                "---------------------------------------------------------------------------------------",
            ])
            for ip, count in sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:6]:
                lines.append(f" * {ip:<25} : {count:>5} packets transmitted")

            lines.extend([
                "",
                "---------------------------------------------------------------------------------------",
                " TOP DESTINATION TARGETS (RECEIVERS)",
                "---------------------------------------------------------------------------------------",
            ])
            for ip, count in sorted(dst_ip_counts.items(), key=lambda x: x[1], reverse=True)[:6]:
                lines.append(f" * {ip:<25} : {count:>5} packets received")

            content = "\n".join(lines)

        self.analytics_text.configure(state="normal")
        self.analytics_text.delete("1.0", "end")
        self.analytics_text.insert("1.0", content)
        self.analytics_text.configure(state="disabled")

    def _on_sample_selected(self, choice):
        preset = next((filename for label, filename in self.SAMPLE_PRESETS if label == choice), "")
        if not preset:
            return
        sample_path = SAMPLE_LOGS_DIR / preset
        if sample_path.exists():
            self.selected_file.set(str(sample_path))
            self._set_status("SAMPLE LOADED", self.COLORS["normal_bg"], self.COLORS["normal"])
            self._show_view("traffic")
            self._run_analysis()

    def _sort_by_column(self, col):
        if self.sort_column == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = col
            self.sort_reverse = False

        def sort_key(c):
            if col == "source":
                return c.src_ip
            elif col == "destination":
                return c.dst_ip
            elif col == "port":
                return c.dst_port or -1
            elif col == "events":
                return c.event_count()
            elif col == "duration":
                return c.duration()
            elif col == "status":
                return {"Malicious": 3, "Suspicious": 2, "Normal": 1}.get(c.classification, 0)
            elif col == "reason":
                return c.reason
            return 0

        self.connections.sort(key=sort_key, reverse=self.sort_reverse)
        self._refresh_table()

    def _browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select packet capture log or Wireshark CSV file",
            filetypes=[
                ("All Supported Forensic Logs", "*.txt *.log *.csv"),
                ("Wireshark CSV Exports", "*.csv"),
                ("tcpdump Text Capture", "*.txt *.log"),
                ("All Files", "*.*"),
            ],
        )
        if filepath:
            self.selected_file.set(filepath)
            self._set_status("READY", self.COLORS["normal_bg"], self.COLORS["normal"])

    def _refresh_workspace(self):
        if hasattr(self, "selected_file") and hasattr(self.selected_file, "set"):
            self.selected_file.set("No log file selected")
        if hasattr(self, "sample_choice_var") and hasattr(self.sample_choice_var, "set"):
            self.sample_choice_var.set(self.SAMPLE_PRESETS[0][0])
        if hasattr(self, "search_var") and hasattr(self.search_var, "set"):
            self.search_var.set("")
        if hasattr(self, "severity_filter") and hasattr(self.severity_filter, "set"):
            self.severity_filter.set("All")
        if hasattr(self, "filter_menu") and hasattr(self.filter_menu, "set"):
            self.filter_menu.set("All")

        self.connections = []
        self._update_metrics()
        self._refresh_table()

        if hasattr(self, "export_button") and hasattr(self.export_button, "configure"):
            self.export_button.configure(state="disabled")

        if hasattr(self, "banner_flow_label"):
            self.banner_flow_label.configure(
                text="No connection selected",
                text_color=self.COLORS["muted"],
            )
        if hasattr(self, "banner_meta_label"):
            self.banner_meta_label.configure(
                text="Select any row in the network sessions table to inspect evidence.",
                text_color=self.COLORS["muted"],
            )

        if hasattr(self, "packet_stream_text"):
            self.packet_stream_text.configure(state="normal")
            self.packet_stream_text.delete("1.0", "end")
            self.packet_stream_text.configure(state="disabled")

        if hasattr(self, "threat_text"):
            self.threat_text.configure(state="normal")
            self.threat_text.delete("1.0", "end")
            self.threat_text.configure(state="disabled")

        self._set_status("READY", self.COLORS["normal_bg"], self.COLORS["normal"])
        self._set_detail(
            "DFIR Investigation Console Ready\n\n"
            "1. Click 'Browse Log...' or select a scenario from 'LOAD SAMPLE LOGS'.\n"
            "2. Click 'Run Analysis' to correlate sessions and execute heuristic classifiers.\n"
            "3. Select any connection to inspect timestamped packet streams and MITRE ATT&CK guidance."
        )
        if hasattr(self, "_show_view"):
            self._show_view("traffic")

    def _focus_analysis(self):
        if hasattr(self, "_refresh_workspace"):
            self._refresh_workspace()
        else:
            DFIRApp._refresh_workspace(self)

    def _run_analysis(self):
        filepath = self.selected_file.get()
        if filepath in ("No log file selected", ""):
            self._set_status("SELECT A FILE", self.COLORS["suspicious_bg"], self.COLORS["suspicious"])
            return

        try:
            self._set_status("ANALYSING", "#162847", "#9CC1FF")
            self.update_idletasks()
            events, dns_map = parse_logfile(filepath)
            self.connections = classify_connections(correlate_events(events, dns_map))
            self._update_metrics()
            self._refresh_table()

            if hasattr(self, "export_button") and hasattr(self.export_button, "configure"):
                self.export_button.configure(state="normal")

            self._set_status("COMPLETE", self.COLORS["normal_bg"], self.COLORS["normal"])

            summary_info = (
                f"Analysis Complete: {Path(filepath).name}\n\n"
                f"• Ingested Events: {len(events)}\n"
                f"• Correlated Sessions: {len(self.connections)}\n"
                f"• DNS Host Mappings: {len(dns_map)}\n\n"
                "Select any session from the table to view packet timeline and SOC guidance."
            )
            self._set_detail(summary_info)

            if self.connections:
                threat_idx = next(
                    (i for i, c in enumerate(self.connections) if c.classification == "Malicious"),
                    next((i for i, c in enumerate(self.connections) if c.classification == "Suspicious"), 0),
                )
                if hasattr(self, "tree") and self.tree.get_children():
                    children = self.tree.get_children()
                    if str(threat_idx) in children:
                        self.tree.selection_set(str(threat_idx))
                        self.tree.focus(str(threat_idx))
                        self._show_connection_detail()

        except Exception as error:
            self.connections = []
            self._update_metrics()
            self._refresh_table()
            if hasattr(self, "export_button") and hasattr(self.export_button, "configure"):
                self.export_button.configure(state="disabled")
            self._set_status("ERROR", self.COLORS["malicious_bg"], self.COLORS["malicious"])
            self._set_detail(f"Analysis Failed:\n\n{error}")

    def _update_metrics(self):
        counts = {"total": len(self.connections), "malicious": 0, "suspicious": 0, "normal": 0}
        for conn in self.connections:
            counts[conn.classification.lower()] += 1
        for key, value in counts.items():
            if hasattr(self, "metric_labels") and key in self.metric_labels:
                self.metric_labels[key].configure(text=str(value))

        if hasattr(self, "rule_hit_labels") and self.rule_hit_labels:
            rule_counts = {
                "syn": sum(1 for c in self.connections if "syn flood" in c.reason.lower()),
                "icmp": sum(1 for c in self.connections if "icmp flood" in c.reason.lower()),
                "brute": sum(1 for c in self.connections if ("rdp" in c.reason.lower() or "ssh" in c.reason.lower())),
                "port": sum(1 for c in self.connections if "suspicious port" in c.reason.lower()),
                "redirect": sum(1 for c in self.connections if "redirect" in c.reason.lower()),
            }
            for key, badge in self.rule_hit_labels.items():
                hit_count = rule_counts.get(key, 0)
                if hit_count > 0:
                    badge.configure(
                        text=f"{hit_count}",
                        fg_color=self.COLORS["malicious"] if key in ("syn", "icmp") else self.COLORS["suspicious"],
                        text_color="#FFFFFF",
                    )
                else:
                    badge.configure(
                        text="0",
                        fg_color=self.COLORS["sidebar_border"],
                        text_color=self.COLORS["muted"],
                    )

    def _refresh_table(self):
        if not hasattr(self, "tree"):
            return
        for item in self.tree.get_children():
            self.tree.delete(item)

        query = self.search_var.get().strip().lower()
        selected_status = self.severity_filter.get()
        displayed_count = 0

        for index, conn in enumerate(self.connections):
            searchable = " ".join((
                conn.src_ip,
                conn.dst_ip,
                str(conn.dst_port or ""),
                str(conn.src_port or ""),
                conn.classification,
                conn.reason,
            )).lower()

            if query and query not in searchable:
                continue
            if selected_status != "All" and conn.classification != selected_status:
                continue

            displayed_count += 1
            port_str = str(conn.dst_port) if conn.dst_port else "-"
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                tags=(conn.classification,),
                values=(
                    conn.src_ip,
                    conn.dst_ip,
                    port_str,
                    conn.event_count(),
                    f"{conn.duration():.4f}s",
                    conn.classification.upper(),
                    conn.reason,
                ),
            )

        if hasattr(self, "session_count_label"):
            self.session_count_label.configure(text=f"Showing {displayed_count} of {len(self.connections)} sessions")

    def _show_connection_detail(self, _event=None):
        if not hasattr(self, "tree"):
            return
        selection = self.tree.selection()
        if not selection:
            return

        conn = self.connections[int(selection[0])]

        color = {
            "Malicious": self.COLORS["malicious"],
            "Suspicious": self.COLORS["suspicious"],
            "Normal": self.COLORS["normal"],
        }.get(conn.classification, self.COLORS["accent"])

        src_endpoint = f"{conn.src_ip}:{conn.src_port or '*'}"
        dst_endpoint = f"{conn.dst_ip}:{conn.dst_port or '*'}"

        if hasattr(self, "banner_flow_label"):
            self.banner_flow_label.configure(
                text=f"{src_endpoint}  ->  {dst_endpoint}",
                text_color=color,
            )
        if hasattr(self, "banner_meta_label"):
            self.banner_meta_label.configure(
                text=f"Severity: {conn.classification.upper()}  |  {conn.event_count()} packets  |  Duration: {conn.duration():.6f}s  |  {conn.reason}",
                text_color=self.COLORS["text_sub"],
            )

        packet_lines = [
            f"================================================================================",
            f"  SESSION PACKET TIMELINE ({conn.event_count()} Total Packets)                 ",
            f"================================================================================",
            f"{'TIME (s)':<12} {'PROTO':<6} {'FLAGS':<6} {'DETAILS'}",
            f"{'-'*12} {'-'*6} {'-'*6} {'-'*54}",
        ]
        for event in conn.events[:60]:
            flag_display = event.flags or "-"
            packet_lines.append(f"{event.timestamp:<12.6f} {event.protocol:<6} {flag_display:<6} {event.info}")
        if conn.event_count() > 60:
            packet_lines.append(f"\n... [{conn.event_count() - 60} additional packets omitted for performance]")

        if hasattr(self, "packet_stream_text"):
            self.packet_stream_text.configure(state="normal")
            self.packet_stream_text.delete("1.0", "end")
            self.packet_stream_text.insert("1.0", "\n".join(packet_lines))
            self.packet_stream_text.configure(state="disabled")

        threat_guidance = getattr(self, "_get_threat_guidance", DFIRApp._get_threat_guidance)(conn)
        if hasattr(self, "threat_text"):
            self.threat_text.configure(state="normal")
            self.threat_text.delete("1.0", "end")
            self.threat_text.insert("1.0", threat_guidance)
            self.threat_text.configure(state="disabled")

        evidence_lines = [
            f"STATUS  {conn.classification.upper()}",
            f"REASON  {conn.reason}",
            "",
            f"Source      {conn.src_ip}:{conn.src_port or 'N/A'}",
            f"Destination {conn.dst_ip}:{conn.dst_port or 'N/A'}",
            f"Events      {conn.event_count()}",
            f"Duration    {conn.duration():.6f}s",
            "",
            "PACKET SUMMARY",
        ]
        evidence_lines.extend(
            f"{e.timestamp:.6f}  {e.protocol:<4}  {e.flags or '-':<3}  {e.info}" for e in conn.events[:12]
        )
        if conn.event_count() > 12:
            evidence_lines.append(f"... {conn.event_count() - 12} more packets")

        self._set_detail("\n".join(evidence_lines))

    @staticmethod
    def _get_threat_guidance(conn) -> str:
        reason = conn.reason.lower()
        if "syn flood" in reason:
            return (
                "THREAT INTEL: TCP SYN FLOOD ATTACK (HALF-OPEN DoS)\n\n"
                "* Attack Category: Denial of Service\n"
                "* MITRE ATT&CK: T1498.001 (Direct Network Flood)\n"
                "* Indicator: Rapid succession of TCP SYN packets with 0 completed handshake ACKs.\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                "1. Verify if destination server backlog queue is exhausted.\n"
                "2. Enable SYN Cookies (syncookies) at host OS or Edge Firewall/Load Balancer.\n"
                "3. Implement rate-limiting per source IP on ingress edge router.\n"
                f"4. Block source IP [{conn.src_ip}] at perimeter firewall."
            )
        elif "icmp flood" in reason:
            return (
                "THREAT INTEL: ICMP FLOOD (PING FLOOD DoS)\n\n"
                "* Attack Category: Denial of Service\n"
                "* MITRE ATT&CK: T1498.001 (Direct Network Flood)\n"
                "* Indicator: High-frequency ICMP Echo requests without legitimate diagnostic purpose.\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                "1. Drop or rate-limit inbound ICMP Echo Request (type 8) at boundary firewalls.\n"
                f"2. Inspect router interface bandwidth towards destination [{conn.dst_ip}].\n"
                f"3. Blackhole attacking subnet for [{conn.src_ip}]."
            )
        elif "rdp" in reason:
            return (
                "THREAT INTEL: RDP BRUTE FORCE / PASSWORD GUESSING\n\n"
                "* Attack Category: Credential Access\n"
                "* MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)\n"
                "* Target Service: Remote Desktop Protocol (TCP Port 3389)\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                "1. Check Windows Security Event Log on destination (Event ID 4625: Failed Logon).\n"
                "2. Isolate RDP behind Corporate VPN / Zero Trust Network Access.\n"
                "3. Enforce Account Lockout policies and Multi-Factor Authentication (MFA).\n"
                f"4. Immediately block source IP [{conn.src_ip}] from external RDP access."
            )
        elif "ssh" in reason:
            return (
                "THREAT INTEL: SSH BRUTE FORCE ATTEMPTS\n\n"
                "* Attack Category: Credential Access\n"
                "* MITRE ATT&CK: T1110.001 (Brute Force)\n"
                "* Target Service: Secure Shell (TCP Port 22)\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                "1. Review auth.log / /var/log/secure on target server for invalid users.\n"
                "2. Disable SSH Password Authentication and enforce ED25519/RSA public keys.\n"
                "3. Deploy Fail2ban / CrowdSec to automatically blacklist abusive IPs.\n"
                f"4. Add [{conn.src_ip}] to firewall drop rules."
            )
        elif "suspicious port" in reason:
            return (
                "THREAT INTEL: KNOWN BACKDOOR / REVERSE SHELL PORT\n\n"
                "* Attack Category: Command and Control\n"
                "* MITRE ATT&CK: T1571 (Non-Standard Port) / T1071 (Application Layer Protocol)\n"
                f"* Target Port: {conn.dst_port or conn.src_port} (Commonly associated with Meterpreter/Netcat)\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                f"1. Isolate the affected endpoint [{conn.src_ip if conn.src_port in (4444, 1337, 31337) else conn.dst_ip}].\n"
                "2. Collect memory dump and list active processes (e.g. netstat -ano, ps aux).\n"
                "3. Investigate parent process spawning network connection (cmd.exe, powershell.exe, sh, bash).\n"
                "4. Check for persistence mechanisms in registry/cron jobs."
            )
        elif "redirect" in reason:
            return (
                "THREAT INTEL: TRAFFIC REDIRECTION / DNS SPOOFING\n\n"
                "* Attack Category: Adversary-in-the-Middle\n"
                "* MITRE ATT&CK: T1557 (AiTM) / T1584.008 (DNS Spoofing)\n"
                "* Indicator: HTTP/HTTPS traffic routed to an IP address that deviates from resolved DNS record.\n\n"
                "SOC TRIAGE & RESPONSE PLAYBOOK:\n"
                "1. Audit local client hosts file and DHCP-assigned DNS server configurations.\n"
                "2. Inspect network switches for ARP Cache Poisoning or Rogue DHCP servers.\n"
                "3. Verify SSL/TLS certificates presented by the destination endpoint."
            )
        else:
            return (
                "TRAFFIC STATUS: BENIGN / NORMAL NETWORK ACTIVITY\n\n"
                "* Classification: Normal Traffic\n"
                "* Behavior: Standard TCP/UDP exchange conforming to expected protocol behaviors.\n"
                "* SOC Recommendation: No active incident response required. Log retained for audit trail."
            )

    def _export_results(self):
        if not self.connections:
            return
        try:
            report_dir = default_report_directory()
            report_dir.mkdir(parents=True, exist_ok=True)
            stem = Path(self.selected_file.get()).stem if self.selected_file.get() else "network_analysis"
            selected_path = filedialog.asksaveasfilename(
                title="Save Forensic Analysis Report",
                initialdir=str(report_dir),
                initialfile=f"{stem}_report.json",
                defaultextension=".json",
                filetypes=[("JSON Security Reports", "*.json")],
            )
            if not selected_path:
                self._set_status("EXPORT CANCELLED", self.COLORS["suspicious_bg"], self.COLORS["suspicious"])
                return

            output_path = export_json(self.connections, self.selected_file.get(), selected_path)
            self._set_status("EXPORTED", self.COLORS["normal_bg"], self.COLORS["normal"])
            self._set_detail(f"Security Report Successfully Exported:\n\nPath: {output_path}")
        except Exception as error:
            self._set_status("EXPORT ERROR", self.COLORS["malicious_bg"], self.COLORS["malicious"])
            self._set_detail(f"Export Failed:\n\n{error}")

    def _set_status(self, text, background, foreground):
        if hasattr(self, "status_badge") and hasattr(self.status_badge, "configure"):
            self.status_badge.configure(text=text, fg_color=background, text_color=foreground)

    def _set_detail(self, text):
        if hasattr(self, "detail_text") and hasattr(self.detail_text, "configure"):
            self.detail_text.configure(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("1.0", text)
            self.detail_text.configure(state="disabled")


if __name__ == "__main__":
    app = DFIRApp()
    app.mainloop()
