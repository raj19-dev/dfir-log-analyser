import csv
import re
import socket
from models import Event

SERVICE_PORT_MAP = {
    "domain": 53,
    "http": 80,
    "https": 443,
    "ssh": 22,
    "telnet": 23,
    "ftp": 21,
    "ftp-data": 20,
    "smtp": 25,
    "smtps": 465,
    "submission": 587,
    "pop3": 110,
    "pop3s": 995,
    "imap": 143,
    "imaps": 993,
    "ntp": 123,
    "snmp": 161,
    "snmptrap": 162,
    "ldap": 389,
    "ldaps": 636,
    "mysql": 3306,
    "postgresql": 5432,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "rdp": 3389,
    "ms-wbt-server": 3389,
    "microsoft-ds": 445,
    "netbios-ssn": 139,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "kerberos": 88,
    "kpasswd": 464,
    "syslog": 514,
    "mdns": 5353,
}


def parse_logfile(filepath: str) -> tuple[list[Event], dict]:
    if filepath.lower().endswith('.csv'):
        return parse_wireshark_csv(filepath)

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if ',' in line and any(k in line.lower() for k in ['"no."', 'time', 'source', 'destination', 'protocol', 'info']):
                    return parse_wireshark_csv(filepath)
                break
    except Exception:
        pass

    return parse_tcpdump(filepath)


def is_tcpdump_packet_start(line: str) -> bool:
    return bool(
        re.match(r'^(?:\d{4}-\d{2}-\d{2}\s+)?(?:[A-Za-z]{3}\s+\d+\s+)?\d+:\d+:\d+(?:\.\d+)?', line)
        or re.match(r'^\d+\.\d+\s+IP', line)
    )


def parse_tcpdump(filepath: str) -> tuple[list[Event], dict]:
    events = []
    dns_map = {}
    pending_queries = {}

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    joined_lines = []
    current_line = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith('...') or line.startswith('…') or line.startswith('#') or line.startswith('---'):
            if current_line:
                joined_lines.append(current_line)
                current_line = ""
            continue

        if is_tcpdump_packet_start(line):
            if current_line:
                joined_lines.append(current_line)
            current_line = line
        else:
            current_line += " " + line

    if current_line:
        joined_lines.append(current_line)

    for line in joined_lines:
        parse_dns_response(line, dns_map, pending_queries)
        event = parse_line(line)
        if event:
            events.append(event)

    return events, dns_map


def parse_wireshark_csv(filepath: str) -> tuple[list[Event], dict]:
    events = []
    dns_map = {}
    pending_queries = {}

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return [], {}

        header_clean = [h.strip().strip('"').lower() for h in header]

        col_map = {}
        for idx, col in enumerate(header_clean):
            if col in ('time', 'time (s)', 'time_relative', 'timestamp'):
                col_map['time'] = idx
            elif col in ('source', 'src', 'source ip', 'ip.src'):
                col_map['source'] = idx
            elif col in ('destination', 'dst', 'destination ip', 'ip.dst'):
                col_map['destination'] = idx
            elif col in ('protocol', 'proto'):
                col_map['protocol'] = idx
            elif col in ('info', 'summary', 'information'):
                col_map['info'] = idx
            elif col in ('src port', 'source port', 'srcport', 'sport', 'tcp.srcport', 'udp.srcport'):
                col_map['src_port'] = idx
            elif col in ('dst port', 'destination port', 'dstport', 'dport', 'tcp.dstport', 'udp.dstport'):
                col_map['dst_port'] = idx

        for row_idx, row in enumerate(reader):
            if not row or len(row) < 3:
                continue

            def get_val(key):
                idx = col_map.get(key)
                if idx is not None and idx < len(row):
                    return row[idx].strip()
                return ""

            time_str = get_val('time')
            src_val = get_val('source')
            dst_val = get_val('destination')
            protocol_val = get_val('protocol').upper() or "TCP"
            info_val = get_val('info')
            src_port_val = get_val('src_port')
            dst_port_val = get_val('dst_port')

            timestamp = 0.0
            if time_str:
                try:
                    timestamp = float(time_str)
                except ValueError:
                    if ':' in time_str:
                        try:
                            timestamp = timestamp_to_seconds(time_str)
                        except ValueError:
                            timestamp = float(row_idx)
                    else:
                        timestamp = float(row_idx)

            src_ip, src_port_extracted = split_host_port(src_val)
            dst_ip, dst_port_extracted = split_host_port(dst_val)

            src_port = None
            dst_port = None

            if src_port_val.isdigit():
                src_port = int(src_port_val)
            elif src_port_extracted is not None:
                src_port = src_port_extracted

            if dst_port_val.isdigit():
                dst_port = int(dst_port_val)
            elif dst_port_extracted is not None:
                dst_port = dst_port_extracted

            if (src_port is None or dst_port is None) and info_val:
                port_match = re.search(r'(\d+)\s*(?:→|>|->)\s*(\d+)', info_val)
                if port_match:
                    if src_port is None:
                        src_port = int(port_match.group(1))
                    if dst_port is None:
                        dst_port = int(port_match.group(2))

            protocol = protocol_val
            if protocol in ("DNS", "NTP"):
                protocol = "UDP"
            elif protocol in ("HTTP", "HTTPS", "TLS", "SSH", "RDP", "FTP"):
                protocol = "TCP"

            flags = extract_wireshark_flags(info_val)
            parse_wireshark_dns(info_val, src_ip, dst_ip, dns_map, pending_queries)

            raw_line = ",".join(row)
            event = Event(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                flags=flags,
                src_port=src_port,
                dst_port=dst_port,
                info=info_val,
                raw_line=raw_line
            )
            events.append(event)

    return events, dns_map


def extract_wireshark_flags(info: str) -> str | None:
    flags_match = re.search(r'\[([A-Z,\s]+)\]', info)
    if not flags_match:
        return None

    flag_str = flags_match.group(1).upper()
    parts = [p.strip() for p in flag_str.split(',')]
    flag_set = set(parts)

    res = []
    if "SYN" in flag_set or "SYN" in flag_str:
        res.append("S")
    if "FIN" in flag_set or "FIN" in flag_str:
        res.append("F")
    if "RST" in flag_set or "RST" in flag_str:
        res.append("R")
    if "PSH" in flag_set or "PSH" in flag_str:
        res.append("P")
    if "ACK" in flag_set or "ACK" in flag_str:
        res.append(".")

    return "".join(res) if res else flag_str


def parse_wireshark_dns(info: str, src_ip: str, dst_ip: str, dns_map: dict, pending_queries: dict):
    if not info:
        return

    query_match = re.search(r'Standard query (0x[0-9a-fA-F]+|\d+)\s+A\s+([\w.\-]+)', info)
    if query_match:
        query_id = query_match.group(1)
        domain = query_match.group(2).rstrip('.')
        pending_queries[(query_id, src_ip, dst_ip)] = domain
        return

    response_match = re.search(r'Standard query response (0x[0-9a-fA-F]+|\d+).*\bA\s+([\d.]+)', info)
    if response_match:
        query_id = response_match.group(1)
        resolved_ip = response_match.group(2)
        query_key = (query_id, dst_ip, src_ip)
        if query_key in pending_queries:
            domain = pending_queries[query_key]
            dns_map[domain] = resolved_ip
            del pending_queries[query_key]
        else:
            domain_in_resp = re.search(r'Standard query response (?:0x[0-9a-fA-F]+|\d+)\s+A\s+([\w.\-]+)', info)
            if domain_in_resp:
                domain = domain_in_resp.group(1).rstrip('.')
                dns_map[domain] = resolved_ip


def parse_line(line: str) -> Event | None:
    pattern = r'^(?:.*?\s+)?(?:IP6?|ARP)\s+([^\s>]+)\s+>\s+([^:]+):\s*(.*)'
    match = re.search(pattern, line)

    if not match:
        return None

    src = match.group(1)
    dst = match.group(2)
    info = match.group(3)

    timestamp = timestamp_to_seconds(line)
    src_ip, src_port = split_host_port(src)
    dst_ip, dst_port = split_host_port(dst)

    protocol = "TCP"
    if "ICMP" in line.upper() or "ICMP6" in line.upper():
        protocol = "ICMP"
    elif (
        "UDP" in line.upper()
        or src_port == 53
        or dst_port == 53
        or src_port == 123
        or dst_port == 123
        or re.search(r'\b\d+\+?\s+(?:A|AAAA|CNAME|MX|TXT|PTR|SOA|NS|ANY|SRV)\?', info)
        or re.search(r'\b\d+\*?\s+\d+/\d+/\d+', info)
    ):
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


def resolve_port_name(port_str: str) -> int | None:
    if not port_str:
        return None
    if port_str.isdigit():
        return int(port_str)

    clean_name = port_str.lower().strip()
    if clean_name in SERVICE_PORT_MAP:
        return SERVICE_PORT_MAP[clean_name]

    try:
        return socket.getservbyname(clean_name)
    except Exception:
        return None


def split_host_port(host_str: str):
    if not host_str:
        return "", None

    match_v6_bracket = re.match(r'^\[([a-fA-F0-9:]+)\][:.](\w+)$', host_str)
    if match_v6_bracket:
        port = resolve_port_name(match_v6_bracket.group(2))
        return match_v6_bracket.group(1), port

    match_colon = re.match(r'^(.*?):(\w+)$', host_str)
    if match_colon:
        port = resolve_port_name(match_colon.group(2))
        if port is not None:
            return match_colon.group(1), port

    match_ip_port = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.([a-zA-Z0-9\-]+)$', host_str)
    if match_ip_port:
        ip = match_ip_port.group(1)
        suffix = match_ip_port.group(2)
        port = resolve_port_name(suffix)
        if port is not None:
            return ip, port

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host_str):
        return host_str, None

    match_dot = re.match(r'^(.*?)\.([a-zA-Z0-9\-]+)$', host_str)
    if match_dot:
        base = match_dot.group(1)
        suffix = match_dot.group(2)
        port = resolve_port_name(suffix)
        if port is not None:
            return base, port

    return host_str, None


def timestamp_to_seconds(ts: str) -> float:
    ts = ts.strip()
    try:
        return float(ts)
    except ValueError:
        pass

    time_match = re.search(r'(\d+):(\d+):(\d+(?:\.\d+)?)', ts)
    if time_match:
        hours = int(time_match.group(1))
        minutes = int(time_match.group(2))
        seconds = float(time_match.group(3))
        return hours * 3600 + minutes * 60 + seconds

    return 0.0


def parse_dns_response(line: str, dns_map: dict, pending_queries: dict):
    query_match = re.search(r'(?:^|:\s+)(\d+)\+?\s+(?:\[.*?\]\s+)?A\?\s+([a-zA-Z0-9.\-]+)', line)
    if query_match:
        query_id = query_match.group(1)
        domain = query_match.group(2).rstrip('.')
        endpoint_match = re.search(r'IP6?\s+([^\s>]+)\s+>\s+([^:]+):', line)
        if endpoint_match:
            src, _ = split_host_port(endpoint_match.group(1))
            dst, _ = split_host_port(endpoint_match.group(2))
            pending_queries[(query_id, src, dst)] = domain
        return

    response_match = re.search(r'(?:^|:\s+)(\d+)\*?\s+\d+/\d+/\d+.*?\bA\s+([\d.]+)', line)
    if response_match:
        query_id = response_match.group(1)
        resolved_ip = response_match.group(2)
        endpoint_match = re.search(r'IP6?\s+([^\s>]+)\s+>\s+([^:]+):', line)
        if endpoint_match:
            src, _ = split_host_port(endpoint_match.group(1))
            dst, _ = split_host_port(endpoint_match.group(2))
            query_key = (query_id, dst, src)
            if query_key in pending_queries:
                domain = pending_queries[query_key]
                dns_map[domain] = resolved_ip
                del pending_queries[query_key]
                return

        matching_keys = [k for k in pending_queries if k[0] == query_id]
        if matching_keys:
            domain = pending_queries[matching_keys[0]]
            dns_map[domain] = resolved_ip
            del pending_queries[matching_keys[0]]
            return

        domain_match = re.search(r'\b([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)+)\.?\s+A\s+([\d.]+)', line)
        if domain_match:
            domain = domain_match.group(1).rstrip('.')
            dns_map[domain] = domain_match.group(2)
