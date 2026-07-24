from models import Event, Connection

def correlate_events(events: list[Event], dns_map: dict) -> list[Connection]:
    """
    Groups events into connections.

    A connection is identified by the two endpoints and ports, regardless of
    packet direction.  This keeps TCP request and response packets together.
    """

    connections = {}

    for event in events:

        endpoint_a = (event.src_ip, event.src_port)
        endpoint_b = (event.dst_ip, event.dst_port)
        key = tuple(sorted((endpoint_a, endpoint_b), key=lambda endpoint: (endpoint[0], endpoint[1] or -1)))

        if key not in connections:
            connections[key] = Connection(
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                dst_port=event.dst_port,
                src_port=event.src_port,
                dns_map=dns_map
            )

        connections[key].add_event(event)

    return list(connections.values())
