import argparse
from parser import parse_logfile
from correlator import correlate_events
from classifier import classify_connections
from reporter import display_report, export_json


def main():
    arg_parser = argparse.ArgumentParser(
        description="DFIR Log Analyser: Correlates and classifies network log events (tcpdump & Wireshark CSV)",
        epilog="Example: python analyser.py sample_logs/syn_flood_attack.txt"
    )
    
    arg_parser.add_argument(
        "logfile",
        help="Path to the tcpdump log file (.txt/.log) or Wireshark CSV file (.csv) to analyse"
    )
    
    arg_parser.add_argument(
        "--export",
        action="store_true",
        help="Export results to JSON file"
    )
    
    args = arg_parser.parse_args()
    
    events, dns_map = parse_logfile(args.logfile)
    connections = correlate_events(events, dns_map)
    connections = classify_connections(connections)
    display_report(connections, args.logfile)
    
    if args.export:
        export_json(connections, args.logfile)


if __name__ == "__main__":
    main()