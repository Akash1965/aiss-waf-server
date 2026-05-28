"""
Hand-written Python equivalents of the AISS protobuf messages.
Run proto/generate.sh to replace with proper protoc-generated stubs.
"""
from dataclasses import dataclass, field
from typing import List


@dataclass
class TelemetryEvent:
    request_id:  str   = ""
    agent_id:    str   = ""
    client_ip:   str   = ""
    method:      str   = ""
    uri:         str   = ""
    action:      str   = ""
    tier:        int   = 0
    cve_id:      str   = ""
    rule_name:   str   = ""
    reason:      str   = ""
    ml_score:    float = 0.0
    latency_ms:  float = 0.0
    server_type: str   = ""
    timestamp:   int   = 0


@dataclass
class TelemetryBatch:
    events: List[TelemetryEvent] = field(default_factory=list)


@dataclass
class TelemetryAck:
    accepted: int = 0
    message:  str = ""


@dataclass
class UpdateRequest:
    agent_id: str = ""
    since:    str = ""
    api_key:  str = ""


@dataclass
class CVESignature:
    id:               int   = 0
    cve_id:           str   = ""
    name:             str   = ""
    pattern:          str   = ""
    flags:            str   = ""
    severity:         str   = ""
    cvss:             float = 0.0
    affected_product: str   = ""
    active:           bool  = True
    modified_at:      str   = ""


@dataclass
class AgentInfo:
    id:          str = ""
    hostname:    str = ""
    ip:          str = ""
    server_type: str = ""
    version:     str = ""
    mode:        str = ""
    api_key:     str = ""


@dataclass
class AgentAck:
    ok:      bool = False
    message: str  = ""
