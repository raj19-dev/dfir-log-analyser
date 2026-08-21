from pathlib import Path
import unittest

from classifier import classify_connections
from correlator import correlate_events
from parser import (
    parse_logfile,
    parse_tcpdump,
    parse_line,
    split_host_port,
    timestamp_to_seconds,
)
from models import Connection, Event

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SYN_ATTACK = PROJECT_ROOT / "sample_logs" / "syn_flood_attack.txt"
SAMPLE_ICMP_ATTACK = PROJECT_ROOT / "sample_logs" / "icmp_flood_attack.txt"
SAMPLE_RDP = PROJECT_ROOT / "sample_logs" / "repeated_rdp_connections.txt"
SAMPLE_SUSP_PORT = PROJECT_ROOT / "sample_logs" / "suspicious_port.txt"
SAMPLE_SYN_NORMAL = PROJECT_ROOT / "sample_logs" / "syn_flood.txt"


class TcpdumpParserTests(unittest.TestCase):
    def test_split_host_port_ipv4_and_service_names(self):
        self.assertEqual(split_host_port("192.168.1.5.12345"), ("192.168.1.5", 12345))
        self.assertEqual(split_host_port("10.0.0.1.80"), ("10.0.0.1", 80))
        self.assertEqual(split_host_port("10.0.0.1.http"), ("10.0.0.1", 80))
        self.assertEqual(split_host_port("dns.google.domain"), ("dns.google", 53))
        self.assertEqual(split_host_port("yummyrecipesforme.com.http"), ("yummyrecipesforme.com", 80))
        self.assertEqual(split_host_port("server.example.com.https"), ("server.example.com", 443))
        self.assertEqual(split_host_port("10.10.10.5.ms-wbt-server"), ("10.10.10.5", 3389))
        self.assertEqual(split_host_port("192.168.1.10"), ("192.168.1.10", None))

    def test_timestamp_to_seconds_formats(self):
        self.assertAlmostEqual(timestamp_to_seconds("14:00:01.500000"), 14 * 3600 + 1.5)
        self.assertAlmostEqual(timestamp_to_seconds("2023-10-10 14:00:01.500000"), 14 * 3600 + 1.5)
        self.assertAlmostEqual(timestamp_to_seconds("5.123456"), 5.123456)

    def test_parse_syn_flood_attack_log(self):
        events, dns_map = parse_logfile(str(SAMPLE_SYN_ATTACK))
        self.assertEqual(len(events), 14)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)

        malicious = [c for c in classified if c.classification == "Malicious"]
        self.assertTrue(len(malicious) > 0)
        self.assertIn("SYN Flood detected", malicious[0].reason)

    def test_parse_icmp_flood_attack_log(self):
        events, dns_map = parse_logfile(str(SAMPLE_ICMP_ATTACK))
        self.assertEqual(len(events), 10)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)

        malicious = [c for c in classified if c.classification == "Malicious"]
        self.assertTrue(len(malicious) > 0)
        self.assertIn("ICMP Flood detected", malicious[0].reason)

    def test_parse_repeated_rdp_connections_log(self):
        events, dns_map = parse_logfile(str(SAMPLE_RDP))
        self.assertEqual(len(events), 5)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)

        suspicious = [c for c in classified if c.classification == "Suspicious"]
        self.assertEqual(len(suspicious), 5)
        self.assertIn("Repeated RDP connection attempts", suspicious[0].reason)

    def test_parse_suspicious_port_log(self):
        events, dns_map = parse_logfile(str(SAMPLE_SUSP_PORT))
        self.assertEqual(len(events), 3)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)

        suspicious = [c for c in classified if c.classification == "Suspicious"]
        self.assertEqual(len(suspicious), 1)
        self.assertIn("4444", suspicious[0].reason)

    def test_parse_syn_flood_sample_normal_and_dns(self):
        events, dns_map = parse_logfile(str(SAMPLE_SYN_NORMAL))
        self.assertEqual(len(events), 14)
        self.assertIn("yummyrecipesforme.com", dns_map)
        self.assertEqual(dns_map["yummyrecipesforme.com"], "203.0.113.22")
        self.assertIn("greatrecipesforme.com", dns_map)
        self.assertEqual(dns_map["greatrecipesforme.com"], "192.0.2.17")

        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)
        for conn in classified:
            self.assertEqual(conn.classification, "Normal")

    def test_syn_flood_with_server_synack_response_detected(self):
        connections = []
        for i in range(12):
            conn = Connection(src_ip="192.168.1.100", dst_ip="10.0.0.1", src_port=50000 + i, dst_port=80)
            conn.add_event(Event(1.0 + i * 0.01, "192.168.1.100", "10.0.0.1", "TCP", "S", 50000 + i, 80, "Flags [S]"))
            conn.add_event(Event(1.0 + i * 0.01 + 0.001, "10.0.0.1", "192.168.1.100", "TCP", "S.", 80, 50000 + i, "Flags [S.]"))
            connections.append(conn)

        classified = classify_connections(connections)
        malicious = [c for c in classified if c.classification == "Malicious"]
        self.assertEqual(len(malicious), 12)
        self.assertIn("SYN Flood detected", malicious[0].reason)


if __name__ == "__main__":
    unittest.main()
