from models import Connection

# =========================
# Detection Thresholds
# =========================

SYN_FLOOD_THRESHOLD = 10
ICMP_FLOOD_THRESHOLD = 10

SSH_BRUTE_FORCE_THRESHOLD = 5
RDP_BRUTE_FORCE_THRESHOLD = 5

SUSPICIOUS_PORTS = [
    4444,
    1337,
    31337
]


# =========================
# Main Classifier
# =========================

def classify_connections(connections: list[Connection]) -> list[Connection]:

    service_syn_counts = build_service_syn_counts(connections)

    for conn in connections:
        classify_single(conn, service_syn_counts)

    return connections


# =========================
# Single Connection Check
# =========================

def classify_single(connection: Connection, service_syn_counts: dict):

    if detect_syn_flood(connection):
        connection.classification = "Malicious"
        connection.reason = (
            "SYN Flood detected"
        )
        return

    if detect_icmp_flood(connection):
        connection.classification = "Malicious"
        connection.reason = (
            "ICMP Flood detected"
        )
        return

    if detect_ssh_bruteforce(connection, service_syn_counts):
        connection.classification = "Suspicious"
        connection.reason = (
            "Repeated SSH connection attempts"
        )
        return

    if detect_rdp_bruteforce(connection, service_syn_counts):
        connection.classification = "Suspicious"
        connection.reason = (
            "Repeated RDP connection attempts"
        )
        return

    if detect_suspicious_port(connection):
        connection.classification = "Suspicious"
        connection.reason = (
            f"Connection to suspicious port "
            f"{connection.dst_port}"
        )
        return

    if detect_redirect(connection):
        connection.classification = "Suspicious"
        connection.reason = (
            "Possible traffic redirect"
        )
        return

    connection.classification = "Normal"
    connection.reason = (
        "No suspicious patterns detected"
    )


# =========================
# SYN Flood
# =========================

def detect_syn_flood(
    connection: Connection
) -> bool:

    syn_count = 0
    ack_count = 0

    for event in connection.events:

        if not event.flags:
            continue

        if event.flags == "S":
            syn_count += 1

        if "." in event.flags \
                or "A" in event.flags:
            ack_count += 1

    return (
        syn_count >= SYN_FLOOD_THRESHOLD
        and ack_count == 0
    )


# =========================
# ICMP Flood
# =========================

def detect_icmp_flood(
    connection: Connection
) -> bool:

    icmp_count = sum(
        1
        for event in connection.events
        if event.protocol == "ICMP"
    )

    return (
        icmp_count >= ICMP_FLOOD_THRESHOLD
    )


# =========================
# SSH Brute Force
# =========================

def build_service_syn_counts(connections: list[Connection]) -> dict:
    """Count SYN attempts across client ports for each target service."""
    counts = {}
    for connection in connections:
        key = (connection.src_ip, connection.dst_ip, connection.dst_port)
        counts[key] = counts.get(key, 0) + sum(
            1 for event in connection.events if event.flags == "S"
        )
    return counts


def detect_ssh_bruteforce(
    connection: Connection,
    service_syn_counts: dict
) -> bool:

    if connection.dst_port != 22:
        return False

    syn_count = service_syn_counts[
        (connection.src_ip, connection.dst_ip, connection.dst_port)
    ]

    return (
        syn_count >= SSH_BRUTE_FORCE_THRESHOLD
    )


# =========================
# RDP Brute Force
# =========================

def detect_rdp_bruteforce(
    connection: Connection,
    service_syn_counts: dict
) -> bool:

    if connection.dst_port != 3389:
        return False

    syn_count = service_syn_counts[
        (connection.src_ip, connection.dst_ip, connection.dst_port)
    ]

    return (
        syn_count >= RDP_BRUTE_FORCE_THRESHOLD
    )


# =========================
# Suspicious Ports
# =========================

def detect_suspicious_port(
    connection: Connection
) -> bool:

    return (
        connection.dst_port
        in SUSPICIOUS_PORTS
    )


# =========================
# Redirect Detection
# =========================

def detect_redirect(connection: Connection) -> bool:

    if not connection.dns_map:
        return False

    dst_clean = connection.dst_ip

    for suffix in [
        '.http',
        '.https',
        '.domain'
    ]:
        dst_clean = dst_clean.replace(
            suffix,
            ''
        )

    if dst_clean not in connection.dns_map:
        return False

    # A redirect is only meaningful when traffic is addressed to an IP and it
    # differs from the IP returned for the requested domain.  A hostname in a
    # synthetic tcpdump log cannot prove a redirect.
    resolved_ip = connection.dns_map[dst_clean]
    return is_ip_address(connection.dst_ip) and connection.dst_ip != resolved_ip


def is_ip_address(value: str) -> bool:
    parts = value.split('.')
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
