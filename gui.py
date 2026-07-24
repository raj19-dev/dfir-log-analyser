

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from classifier import classify_connections
from correlator import correlate_events
from parser import parse_tcpdump
from reporter import default_report_directory, export_json


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class DFIRApp(ctk.CTk):
    """A dashboard for loading, reviewing, and exporting tcpdump analysis."""

    COLORS = {
        "canvas": "#0B1220",
        "sidebar": "#101A2D",
        "panel": "#14233B",
        "panel_hover": "#1B3151",
        "border": "#263B5B",
        "muted": "#91A4C1",
        "accent": "#4F8CFF",
        "malicious": "#F05252",
        "suspicious": "#F6B34B",
        "normal": "#32C48D",
    }

    def __init__(self):
        super().__init__()
        self.title("DFIR Log Analyser")
        self.geometry("1440x860")
        self.minsize(1120, 700)
        self.configure(fg_color=self.COLORS["canvas"])

        self.selected_file = tk.StringVar(value="No log file selected")
        self.search_var = tk.StringVar()
        self.severity_filter = tk.StringVar(value="All")
        self.connections = []

        self._configure_tree_style()
        self._build_ui()
        self.search_var.trace_add("write", lambda *_: self._refresh_table())

    def _configure_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "DFIR.Treeview",
            background=self.COLORS["panel"],
            foreground="#E9F1FF",
            fieldbackground=self.COLORS["panel"],
            rowheight=34,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "DFIR.Treeview.Heading",
            background="#1B3151",
            foreground="#BFD4F7",
            borderwidth=0,
            relief="flat",
            font=("Segoe UI Semibold", 10),
        )
        style.map(
            "DFIR.Treeview",
            background=[("selected", self.COLORS["accent"])],
            foreground=[("selected", "#FFFFFF")],
        )

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=0, column=1, sticky="nsew", padx=(0, 30), pady=30)
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(3, weight=1)
        self._build_header(content)
        self._build_summary_cards(content)
        self._build_toolbar(content)
        self._build_results_area(content)

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=self.COLORS["sidebar"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        ctk.CTkLabel(
            sidebar,
            text="DFIR",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#FFFFFF",
        ).pack(anchor="w", padx=26, pady=(34, 0))
        ctk.CTkLabel(
            sidebar,
            text="LOG ANALYSER",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=self.COLORS["accent"],
        ).pack(anchor="w", padx=28, pady=(0, 36))

        self._nav_item(sidebar, "Analyse logs", self._focus_analysis, active=True)

    def _nav_item(self, parent, label, command, active=False):
        ctk.CTkButton(
            parent,
            text=label,
            anchor="w",
            height=42,
            corner_radius=8,
            font=ctk.CTkFont(size=13, weight="bold" if active else "normal"),
            fg_color="#1C3760" if active else "transparent",
            hover_color=self.COLORS["panel_hover"],
            text_color="#FFFFFF" if active else self.COLORS["muted"],
            command=command,
        ).pack(fill="x", padx=16, pady=3)

    def _build_header(self, parent):
        header = ctk.CTkFrame(parent, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            header,
            text="Security overview",
            font=ctk.CTkFont(size=28, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Inspect tcpdump traffic and surface high-priority activity.",
            font=ctk.CTkFont(size=13),
            text_color=self.COLORS["muted"],
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.status_badge = ctk.CTkLabel(
            header,
            text="READY",
            width=78,
            height=28,
            corner_radius=14,
            fg_color="#173B35",
            text_color=self.COLORS["normal"],
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.status_badge.grid(row=0, column=1, rowspan=2, sticky="e")

    def _build_summary_cards(self, parent):
        cards = ctk.CTkFrame(parent, fg_color="transparent")
        cards.grid(row=1, column=0, sticky="ew", pady=(0, 18))
        for column in range(4):
            cards.grid_columnconfigure(column, weight=1)

        self.metric_labels = {}
        specs = [
            ("Total connections", "total", self.COLORS["accent"]),
            ("Malicious", "malicious", self.COLORS["malicious"]),
            ("Suspicious", "suspicious", self.COLORS["suspicious"]),
            ("Normal", "normal", self.COLORS["normal"]),
        ]
        for column, (title, key, color) in enumerate(specs):
            card = ctk.CTkFrame(cards, fg_color=self.COLORS["panel"], corner_radius=12, border_width=1, border_color=self.COLORS["border"])
            card.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 7, 7 if column < 3 else 0))
            ctk.CTkLabel(card, text=title.upper(), font=ctk.CTkFont(size=10, weight="bold"), text_color=self.COLORS["muted"]).pack(anchor="w", padx=18, pady=(15, 2))
            value = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=30, weight="bold"), text_color=color)
            value.pack(anchor="w", padx=18, pady=(0, 15))
            self.metric_labels[key] = value

    def _build_toolbar(self, parent):
        toolbar = ctk.CTkFrame(parent, fg_color=self.COLORS["panel"], corner_radius=12, border_width=1, border_color=self.COLORS["border"])
        toolbar.grid(row=2, column=0, sticky="ew", pady=(0, 18))
        toolbar.grid_columnconfigure(1, weight=1)

        self.browse_button = ctk.CTkButton(toolbar, text="Browse log", width=112, command=self._browse_file, fg_color="#244B80", hover_color="#315F9E")
        self.browse_button.grid(row=0, column=0, padx=14, pady=14)
        ctk.CTkLabel(toolbar, textvariable=self.selected_file, anchor="w", text_color=self.COLORS["muted"], font=ctk.CTkFont(size=12)).grid(row=0, column=1, sticky="ew", padx=(0, 12))
        ctk.CTkButton(toolbar, text="Analyse", width=100, command=self._run_analysis, fg_color=self.COLORS["accent"], hover_color="#3D78E7", font=ctk.CTkFont(weight="bold")).grid(row=0, column=2, padx=(0, 8), pady=14)
        self.export_button = ctk.CTkButton(toolbar, text="Export JSON", width=105, command=self._export_results, state="disabled", fg_color="#1D6E55", hover_color="#258A6B")
        self.export_button.grid(row=0, column=3, padx=(0, 14), pady=14)

    def _build_results_area(self, parent):
        area = ctk.CTkFrame(parent, fg_color="transparent")
        area.grid(row=3, column=0, sticky="nsew")
        area.grid_columnconfigure(0, weight=3)
        area.grid_columnconfigure(1, weight=1)
        area.grid_rowconfigure(0, weight=1)

        results = ctk.CTkFrame(area, fg_color=self.COLORS["panel"], corner_radius=12, border_width=1, border_color=self.COLORS["border"])
        results.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(results, text="Connection activity", font=ctk.CTkFont(size=17, weight="bold")).grid(row=0, column=0, sticky="w", padx=18, pady=(16, 0))
        controls = ctk.CTkFrame(results, fg_color="transparent")
        controls.grid(row=1, column=0, sticky="ew", padx=18, pady=12)
        controls.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(controls, textvariable=self.search_var, placeholder_text="Search IP, port, reason...", height=34).grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.filter_menu = ctk.CTkSegmentedButton(controls, values=["All", "Malicious", "Suspicious", "Normal"], variable=self.severity_filter, command=lambda _: self._refresh_table(), width=310)
        self.filter_menu.grid(row=0, column=1)

        table_frame = ctk.CTkFrame(results, fg_color="transparent")
        table_frame.grid(row=2, column=0, sticky="nsew", padx=18, pady=(0, 18))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)
        columns = ("source", "destination", "port", "events", "duration", "status", "reason")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", style="DFIR.Treeview", selectmode="browse")
        headings = {"source": "SOURCE", "destination": "DESTINATION", "port": "PORT", "events": "EVENTS", "duration": "DURATION", "status": "STATUS", "reason": "REASON"}
        widths = {"source": 135, "destination": 145, "port": 58, "events": 65, "duration": 82, "status": 100, "reason": 220}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="center" if column in {"port", "events", "duration", "status"} else "w", stretch=column == "reason")
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._show_connection_detail)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.tag_configure("Malicious", foreground="#FF8585")
        self.tree.tag_configure("Suspicious", foreground="#FFD075")
        self.tree.tag_configure("Normal", foreground="#74E7BA")

        self._build_detail_panel(area)

    def _build_detail_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=self.COLORS["panel"], corner_radius=12, border_width=1, border_color=self.COLORS["border"])
        panel.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        ctk.CTkLabel(panel, text="Connection details", font=ctk.CTkFont(size=17, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(panel, text="Select a table row to inspect evidence.", font=ctk.CTkFont(size=11), text_color=self.COLORS["muted"]).pack(anchor="w", padx=18, pady=(0, 12))
        self.detail_text = ctk.CTkTextbox(panel, fg_color="#0E1A2D", border_width=0, font=("Consolas", 11), text_color="#D7E5FF", wrap="word")
        self.detail_text.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self._set_detail("No connection selected\n\nRun an analysis, then select a row to view its evidence and packet summary.")

    def _browse_file(self):
        filepath = filedialog.askopenfilename(title="Select tcpdump log file", filetypes=[("Log files", "*.txt *.log"), ("All files", "*.*")])
        if filepath:
            self.selected_file.set(filepath)
            self._set_status("READY", "#173B35", self.COLORS["normal"])

    def _focus_analysis(self):
        """Open the log picker directly from the sidebar navigation."""
        self._set_status("SELECT A FILE", "#17315A", "#9CC1FF")
        self._browse_file()

    def _run_analysis(self):
        filepath = self.selected_file.get()
        if filepath == "No log file selected":
            self._set_status("SELECT A FILE", "#4A3218", self.COLORS["suspicious"])
            return
        try:
            self._set_status("ANALYSING", "#17315A", "#9CC1FF")
            self.update_idletasks()
            events, dns_map = parse_tcpdump(filepath)
            self.connections = classify_connections(correlate_events(events, dns_map))
            self._update_metrics()
            self._refresh_table()
            self.export_button.configure(state="normal")
            self._set_status("COMPLETE", "#173B35", self.COLORS["normal"])
            self._set_detail(f"Analysis complete\n\nFile: {Path(filepath).name}\nParsed events: {len(events)}\nConnections: {len(self.connections)}\n\nSelect a connection to inspect it.")
        except Exception as error:
            self.connections = []
            self._update_metrics()
            self._refresh_table()
            self.export_button.configure(state="disabled")
            self._set_status("ERROR", "#492126", self.COLORS["malicious"])
            self._set_detail(f"Analysis failed\n\n{error}")

    def _update_metrics(self):
        counts = {"total": len(self.connections), "malicious": 0, "suspicious": 0, "normal": 0}
        for connection in self.connections:
            counts[connection.classification.lower()] += 1
        for key, value in counts.items():
            self.metric_labels[key].configure(text=str(value))

    def _refresh_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        query = self.search_var.get().strip().lower()
        selected_status = self.severity_filter.get()
        for index, connection in enumerate(self.connections):
            searchable = " ".join((connection.src_ip, connection.dst_ip, str(connection.dst_port), connection.classification, connection.reason)).lower()
            if query and query not in searchable:
                continue
            if selected_status != "All" and connection.classification != selected_status:
                continue
            self.tree.insert("", "end", iid=str(index), tags=(connection.classification,), values=(connection.src_ip, connection.dst_ip, connection.dst_port or "N/A", connection.event_count(), f"{connection.duration():.4f}s", connection.classification, connection.reason))

    def _show_connection_detail(self, _event=None):
        selection = self.tree.selection()
        if not selection:
            return
        connection = self.connections[int(selection[0])]
        lines = [
            f"STATUS  {connection.classification.upper()}",
            f"REASON  {connection.reason}",
            "",
            f"Source      {connection.src_ip}:{connection.src_port or 'N/A'}",
            f"Destination {connection.dst_ip}:{connection.dst_port or 'N/A'}",
            f"Events      {connection.event_count()}",
            f"Duration    {connection.duration():.6f}s",
            "",
            "PACKET SUMMARY",
        ]
        lines.extend(f"{event.timestamp:.6f}  {event.protocol:<4}  {event.flags or '-':<3}  {event.info}" for event in connection.events[:12])
        if connection.event_count() > 12:
            lines.append(f"... {connection.event_count() - 12} more packets")
        self._set_detail("\n".join(lines))

    def _export_results(self):
        if not self.connections:
            return
        try:
            report_directory = default_report_directory()
            report_directory.mkdir(parents=True, exist_ok=True)
            selected_path = filedialog.asksaveasfilename(
                title="Save analysis report",
                initialdir=str(report_directory),
                initialfile=f"{Path(self.selected_file.get()).stem}_report.json",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")],
            )
            if not selected_path:
                self._set_status("EXPORT CANCELLED", "#4A3218", self.COLORS["suspicious"])
                return
            output_path = export_json(self.connections, self.selected_file.get(), selected_path)
            self._set_status("EXPORTED", "#173B35", self.COLORS["normal"])
            self._set_detail(f"Report exported\n\nJSON file:\n{output_path}")
        except Exception as error:
            self._set_status("EXPORT ERROR", "#492126", self.COLORS["malicious"])
            self._set_detail(f"Export failed\n\n{error}")

    def _set_status(self, text, background, foreground):
        self.status_badge.configure(text=text, fg_color=background, text_color=foreground)

    def _set_detail(self, text):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")


if __name__ == "__main__":
    app = DFIRApp()
    app.mainloop()
