import argparse
from parser import parse_tcpdump
from correlator import correlate_events
from classifier import classify_connections
from reporter import display_report, export_json

def main():
    # CLI argument setup
    arg_parser = argparse.ArgumentParser(
        description="DFIR Log Analyser: Correlates and classifies network log events",
        epilog="Example: python analyser.py sample_logs/syn_flood.txt"
    )
    
    arg_parser.add_argument(
        "logfile",
        help="Path to the tcpdump log file to analyse"
    )
    
    arg_parser.add_argument(
        "--export",
        action="store_true",
        help="Export results to JSON file in output/ folder"
    )
    
    args = arg_parser.parse_args()
    
    # Run the pipeline
    events, dns_map = parse_tcpdump(args.logfile)
    connections = correlate_events(events, dns_map)
    connections = classify_connections(connections)
    display_report(connections, args.logfile)
    
    if args.export:
        export_json(connections, args.logfile)

if __name__ == "__main__":
    main()