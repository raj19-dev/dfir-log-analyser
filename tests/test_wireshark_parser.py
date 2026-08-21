from pathlib import Path
import unittest

from classifier import classify_connections
from correlator import correlate_events
from parser import parse_logfile, extract_wireshark_flags

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SYN_CSV = PROJECT_ROOT / "sample_logs" / "wireshark_syn_flood.csv"
SAMPLE_ICMP_CSV = PROJECT_ROOT / "sample_logs" / "wireshark_icmp_flood.csv"
SAMPLE_REDIRECT_CSV = PROJECT_ROOT / "sample_logs" / "wireshark_dns_redirect.csv"


class WiresharkParserTests(unittest.TestCase):
    def test_extract_wireshark_flags(self):
        self.assertEqual(extract_wireshark_flags("54321 -> 80 [SYN] Seq=0"), "S")
        self.assertEqual(extract_wireshark_flags("80 -> 54321 [SYN, ACK] Seq=0"), "S.")
        self.assertEqual(extract_wireshark_flags("54321 -> 80 [ACK] Seq=1"), ".")
        self.assertEqual(extract_wireshark_flags("54321 -> 80 [FIN, ACK] Seq=1"), "F.")

    def test_parse_wireshark_syn_flood_csv(self):
        events, dns_map = parse_logfile(str(SAMPLE_SYN_CSV))
        self.assertEqual(len(events), 12)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)
        
        malicious = [c for c in classified if c.classification == "Malicious"]
        self.assertTrue(len(malicious) > 0)
        self.assertIn("SYN Flood", malicious[0].reason)

    def test_parse_wireshark_icmp_flood_csv(self):
        events, dns_map = parse_logfile(str(SAMPLE_ICMP_CSV))
        self.assertEqual(len(events), 11)
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)
        
        malicious = [c for c in classified if c.classification == "Malicious"]
        self.assertTrue(len(malicious) > 0)
        self.assertIn("ICMP Flood", malicious[0].reason)

    def test_parse_wireshark_dns_redirect_csv(self):
        events, dns_map = parse_logfile(str(SAMPLE_REDIRECT_CSV))
        self.assertEqual(len(events), 5)
        self.assertIn("yummyrecipesforme.com", dns_map)
        self.assertEqual(dns_map["yummyrecipesforme.com"], "192.168.1.50")
        
        connections = correlate_events(events, dns_map)
        classified = classify_connections(connections)
        
        suspicious = [c for c in classified if c.classification == "Suspicious"]
        self.assertTrue(len(suspicious) > 0)
        self.assertIn("Possible traffic redirect", suspicious[0].reason)


if __name__ == "__main__":
    unittest.main()
