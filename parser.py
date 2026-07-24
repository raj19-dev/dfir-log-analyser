import re
from models import Event

def parse_tcpdump(filepath: str):
    """Reads a tcpdump text file and returns events and dns_map"""
    events = []
    dns_map = {}
    pending_queries = {}

    with open(filepath, 'r') as f:
        lines = f.readlines()

    joined_lines = []
    current_line = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if re.match(r'^\d+:\d+:\d+\.\d+', line):
            if current_line:
                joined_lines.append(current_line)
            current_line = line
        else:
            
            current_line += " " + line

   
    if current_line:
        joined_lines.append(current_line)

    for line in joined_lines:
        if line.startswith('...'):
            continue
        parse_dns_response(line, dns_map, pending_queries)
        event = parse_line(line)
        if event:
            events.append(event)

    return events, dns_map


def parse_line(line: str) -> Event | None:
    """Parses a single tcpdump line into an Event object"""

    pattern = r'(\d+:\d+:\d+\.\d+)\s+IP\s+([\w.\-]+)\s+>\s+([\w.\-]+):\s*(.*)'
    match = re.match(pattern, line)

    if not match:
        return None

    timestamp_str = match.group(1)
    src = match.group(2)
    dst = match.group(3)
    info = match.group(4)

    
    timestamp = timestamp_to_seconds(timestamp_str)

    
    src_ip, src_port = split_host_port(src)
    dst_ip, dst_port = split_host_port(dst)

    
    # tcpdump's normal text output does not include the word "UDP" on every
    # UDP packet. DNS query/response syntax is therefore used as a fallback.
    protocol = "TCP"
    if "ICMP" in line:
        protocol = "ICMP"
    elif "UDP" in line or re.search(r'\b\d+\+?\s+(?:A|AAAA|CNAME|MX|TXT)\?', info) or re.search(r'\b\d+\s+\d+/\d+/\d+\s+', info):
        protocol = "UDP"

    
    flags = None
    flags_match = re.search(r'Flags \[([^\]]+)\]', info)
    if flags_match:
        flags = flags_match.group(1)

    return Event(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        flags=flags,
        src_port=src_port,
        dst_port=dst_port,
        info=info,
        raw_line=line
    )

def split_host_port(host_str: str):
    """Splits host.port into (host, port) — handles hostnames and IPs"""
    # Try numeric port at end
    match = re.match(r'^(.*?)\.(\d+)$', host_str)
    if match:
        return match.group(1), int(match.group(2))
    return host_str, None

def timestamp_to_seconds(ts: str) -> float:
    """Converts HH:MM:SS.microseconds to total seconds as float"""
    parts = ts.split(':')
    hours = int(parts[0])
    minutes = int(parts[1])
    seconds = float(parts[2])
    return hours * 3600 + minutes * 60 + seconds

def parse_dns_response(line: str, dns_map: dict, pending_queries: dict):
    """Extracts domain -> IP mappings from DNS query/response pairs"""
    
    
    query_pattern = r'\d+:\d+:\d+\.\d+\s+IP\s+[\w.\-]+\s+>\s+[\w.\-]+:\s+(\d+)\+\s+A\?\s+([\w.\-]+)\.'
    query_match = re.match(query_pattern, line)
    if query_match:
        query_id = query_match.group(1)
        domain = query_match.group(2)
        # DNS transaction IDs are not globally unique. Include the endpoints
        # so simultaneous clients cannot overwrite each other's queries.
        endpoint_match = re.match(r'\d+:\d+:\d+\.\d+\s+IP\s+([\w.\-]+)\s+>\s+([\w.\-]+):', line)
        if endpoint_match:
            pending_queries[(query_id, endpoint_match.group(1), endpoint_match.group(2))] = domain
        return
    
    
    response_pattern = r'\d+:\d+:\d+\.\d+\s+IP\s+[\w.\-]+\s+>\s+[\w.\-]+:\s+(\d+)\s+\d+/\d+/\d+\s+A\s+([\d.]+)'
    response_match = re.match(response_pattern, line)
    if response_match:
        query_id = response_match.group(1)
        resolved_ip = response_match.group(2)
        endpoint_match = re.match(r'\d+:\d+:\d+\.\d+\s+IP\s+([\w.\-]+)\s+>\s+([\w.\-]+):', line)
        if endpoint_match:
            query_key = (query_id, endpoint_match.group(2), endpoint_match.group(1))
            if query_key in pending_queries:
                domain = pending_queries[query_key]
                dns_map[domain] = resolved_ip
                del pending_queries[query_key]
