from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import gui
from models import Connection, Event

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LOG = PROJECT_ROOT / "sample_logs" / "syn_flood_attack.txt"


class Value:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class Widget:
    def __init__(self):
        self.configurations = []
        self.focused = False

    def configure(self, **kwargs):
        self.configurations.append(kwargs)

    def focus_set(self):
        self.focused = True


class CallbackHarness:
    COLORS = gui.DFIRApp.COLORS

    def __init__(self, filepath=str(SAMPLE_LOG)):
        self.selected_file = Value(filepath)
        self.search_var = Value("query")
        self.severity_filter = Value("Suspicious")
        self.connections = []
        self.export_button = Widget()
        self.browse_button = Widget()
        self.statuses = []
        self.details = []
        self.metrics_updated = 0
        self.table_refreshed = 0

    def _set_status(self, *args):
        self.statuses.append(args)

    def _set_detail(self, message):
        self.details.append(message)

    def _update_metrics(self):
        self.metrics_updated += 1

    def _refresh_table(self):
        self.table_refreshed += 1

    def update_idletasks(self):
        pass

    def _browse_file(self):
        return gui.DFIRApp._browse_file(self)

    def _refresh_workspace(self):
        return gui.DFIRApp._refresh_workspace(self)

    def _export_results(self):
        return gui.DFIRApp._export_results(self)


class GuiCallbackTests(unittest.TestCase):
    def test_browse_button_selects_file(self):
        harness = CallbackHarness()
        with patch.object(gui.filedialog, "askopenfilename", return_value="C:/logs/example.txt"):
            gui.DFIRApp._browse_file(harness)
        self.assertEqual(harness.selected_file.get(), "C:/logs/example.txt")
        self.assertEqual(harness.statuses[-1][0], "READY")

    def test_analyse_button_runs_pipeline(self):
        harness = CallbackHarness()
        gui.DFIRApp._run_analysis(harness)
        self.assertEqual(len(harness.connections), 2)
        self.assertEqual(harness.statuses[-1][0], "COMPLETE")
        self.assertEqual(harness.export_button.configurations[-1]["state"], "normal")

    def test_export_button_exports_current_connections(self):
        harness = CallbackHarness()
        gui.DFIRApp._run_analysis(harness)
        target = "C:/Users/Test/Documents/DFIR Log Analyser/reports/report.json"
        with TemporaryDirectory() as temporary_directory:
            with patch.object(gui, "default_report_directory", return_value=Path(temporary_directory)), patch.object(gui.filedialog, "asksaveasfilename", return_value=target), patch.object(gui, "export_json") as export:
                gui.DFIRApp._export_results(harness)
        export.assert_called_once_with(harness.connections, str(SAMPLE_LOG), target)
        self.assertEqual(harness.statuses[-1][0], "EXPORTED")

    def test_navigation_resets_filters(self):
        harness = CallbackHarness(filepath="C:/logs/example.txt")
        harness.search_var.set("malicious_ip")
        harness.severity_filter.set("Malicious")
        gui.DFIRApp._focus_analysis(harness)
        self.assertEqual(harness.search_var.get(), "")
        self.assertEqual(harness.severity_filter.get(), "All")

    def test_row_selection_shows_connection_evidence(self):
        harness = CallbackHarness()
        connection = Connection(src_ip="10.0.0.5", dst_ip="192.168.1.10", src_port=50000, dst_port=4444)
        connection.classification = "Suspicious"
        connection.reason = "Connection to suspicious port 4444"
        connection.add_event(Event(1.0, "10.0.0.5", "192.168.1.10", "TCP", "S", 50000, 4444, "Flags [S]"))
        harness.connections = [connection]
        harness.tree = type("Tree", (), {"selection": lambda self: ("0",)})()
        gui.DFIRApp._show_connection_detail(harness)
        self.assertIn("PACKET SUMMARY", harness.details[-1])
        self.assertIn("10.0.0.5:50000", harness.details[-1])


if __name__ == "__main__":
    unittest.main()
