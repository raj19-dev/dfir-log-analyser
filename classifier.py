from models import Connection

SYN_FLOOD_THRESHOLD = 10
ICMP_FLOOD_THRESHOLD = 10
SSH_BRUTE_FORCE_THRESHOLD = 5
RDP_BRUTE_FORCE_THRESHOLD = 5

SUSPICIOUS_PORTS = [
    4444,
    1337,
    31337
]


def classify_connections(connections: list[Connection]) -> list[Connection]:
    service_syn_counts = build_service_syn_counts(connections)
    for conn in connections:
        classify_single(conn, service_syn_counts)
    return connections


def classify_single(connection: Connection, service_syn_counts: dict):
    if detect_syn_flood(connection, service_syn_counts):
        connection.classification = "Malicious"
        connection.reason = "SYN Flood detected"
        return

    if detect_icmp_flood(connection):
        connection.classification = "Malicious"
        connection.reason = "ICMP Flood detected"
        return

    if detect_ssh_bruteforce(connection, service_syn_counts):
        connection.classification = "Suspicious"
        connection.reason = "Repeated SSH connection attempts"
        return

    if detect_rdp_bruteforce(connection, service_syn_counts):
        connection.classification = "Suspicious"
        connection.reason = "Repeated RDP connection attempts"
        return

    if detect_suspicious_port(connection):
        connection.classification = "Suspicious"
        port = connection.dst_port if connection.dst_port in SUSPICIOUS_PORTS else connection.src_port
        connection.reason = f"Connection to suspicious port {port}"
        return

    if detect_redirect(connection):
        connection.classification = "Suspicious"
        connection.reason = "Possible traffic redirect"
        return

    connection.classification = "Normal"
    connection.reason = "No suspicious patterns detected"


def is_syn_packet(flags: str | None) -> bool:
    if not flags:
        return False
    return ("S" in flags or "SYN" in flags) and ("." not in flags and "ACK" not in flags)


def is_established_ack_packet(flags: str | None) -> bool:
    if not flags:
        return False
    return ("." in flags or "ACK" in flags) and ("S" not in flags and "SYN" not in flags)


def detect_syn_flood(
    connection: Connection,
    service_syn_counts: dict | None = None
) -> bool:
    syn_count = 0
    ack_count = 0

    for event in connection.events:
        if is_syn_packet(event.flags):
            syn_count += 1
        elif is_established_ack_packet(event.flags):
            ack_count += 1

    if syn_count >= SYN_FLOOD_THRESHOLD and ack_count == 0:
        return True

    if service_syn_counts:
        key = (connection.src_ip, connection.dst_ip, connection.dst_port)
        val = service_syn_counts.get(key)
        if isinstance(val, dict):
            if val.get("syn_count", 0) >= SYN_FLOOD_THRESHOLD and val.get("ack_count", 0) == 0:
                return True
        elif isinstance(val, int):
            if val >= SYN_FLOOD_THRESHOLD and ack_count == 0:
                return True

    return False


def detect_icmp_flood(connection: Connection) -> bool:
    icmp_count = sum(
        1
        for event in connection.events
        if event.protocol == "ICMP"
    )
    return icmp_count >= ICMP_FLOOD_THRESHOLD


def build_service_syn_counts(connections: list[Connection]) -> dict:
    stats = {}
    for connection in connections:
        key = (connection.src_ip, connection.dst_ip, connection.dst_port)
        if key not in stats:
            stats[key] = {"syn_count": 0, "ack_count": 0}

        for event in connection.events:
            if is_syn_packet(event.flags):
                stats[key]["syn_count"] += 1
            elif is_established_ack_packet(event.flags):
                stats[key]["ack_count"] += 1
    return stats


def detect_ssh_bruteforce(
    connection: Connection,
    service_syn_counts: dict
) -> bool:
    if connection.dst_port != 22:
        return False

    key = (connection.src_ip, connection.dst_ip, connection.dst_port)
    val = service_syn_counts.get(key, 0)
    syn_count = val.get("syn_count", 0) if isinstance(val, dict) else val
    return syn_count >= SSH_BRUTE_FORCE_THRESHOLD


def detect_rdp_bruteforce(
    connection: Connection,
    service_syn_counts: dict
) -> bool:
    if connection.dst_port != 3389:
        return False

    key = (connection.src_ip, connection.dst_ip, connection.dst_port)
    val = service_syn_counts.get(key, 0)
    syn_count = val.get("syn_count", 0) if isinstance(val, dict) else val
    return syn_count >= RDP_BRUTE_FORCE_THRESHOLD


def detect_suspicious_port(connection: Connection) -> bool:
    return (
        connection.dst_port in SUSPICIOUS_PORTS
        or connection.src_port in SUSPICIOUS_PORTS
    )


def detect_redirect(connection: Connection) -> bool:
    if not connection.dns_map:
        return False

    if connection.dst_port == 53 or connection.src_port == 53 or connection.dst_ip.endswith('.domain'):
        return False

    dst_clean = connection.dst_ip
    for suffix in ['.http', '.https', '.domain']:
        dst_clean = dst_clean.replace(suffix, '')

    if is_ip_address(dst_clean):
        if connection.dst_port in (80, 443, 8080, 8443) or any(
            event.protocol in ("HTTP", "HTTPS", "TCP") for event in connection.events
        ):
            return dst_clean not in connection.dns_map.values()
        return False

    return False


def is_ip_address(value: str) -> bool:
    parts = value.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
