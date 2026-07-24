from dataclasses import dataclass, field
from typing import List, Optional
@dataclass
class Event:
    """Represents a single line/event from a tcpdump log"""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    flags: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: Optional[str] = None
    raw_line: str = ""

@dataclass
class Connection:
    """Represents a group of related events - pne conversation between two IPs"""
    src_ip: str
    dst_ip: str
    dst_port: Optional[int] = None
    src_port: Optional[int] = None
    events: List[Event] = field(default_factory=list)
    classification: str = "Normal"
    reason: str = ""
    dns_map: dict = field(default_factory = dict) #domain -> resolved IP

    def add_event(self, event: Event):
        self.events.append(event)

    def duration(self) -> float:
        if len(self.events) < 2:
            return 0.0
        return self.events[-1].timestamp - self.events[0].timestamp
    def event_count(self) -> int:
        return len(self.events)
