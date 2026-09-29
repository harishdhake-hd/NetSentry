"""
backend/database/models.py

SQLAlchemy ORM models for NetSentry.
Represents packets, flows, DNS events, detections, and more.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean, 
    LargeBinary, Index, ForeignKey, Text, Enum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class CaptureSession(Base):
    """Represents a packet capture session."""
    __tablename__ = "capture_sessions"

    id = Column(Integer, primary_key=True)
    interface = Column(String(255), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    stopped_at = Column(DateTime, nullable=True)
    packets_captured = Column(Integer, default=0)
    packets_parsed = Column(Integer, default=0)
    packets_stored = Column(Integer, default=0)
    parser_errors = Column(Integer, default=0)
    status = Column(String(50), default="running")  # running, stopped, error

    # Relationships
    packets = relationship("Packet", back_populates="capture_session")
    flows = relationship("Flow", back_populates="capture_session")

    __table_args__ = (
        Index("idx_capture_sessions_started_at", "started_at"),
    )


class Packet(Base):
    """Represents a captured network packet."""
    __tablename__ = "packets"

    id = Column(Integer, primary_key=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id"), nullable=False)
    
    # Timestamp
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Layer 2 (Ethernet/MAC)
    src_mac = Column(String(17), nullable=True)  # Format: AA:BB:CC:DD:EE:FF
    dst_mac = Column(String(17), nullable=True)

    # Layer 3 (IP)
    src_ip = Column(String(45), nullable=True, index=True)  # IPv4 or IPv6
    dst_ip = Column(String(45), nullable=True, index=True)
    ip_version = Column(Integer, nullable=True)  # 4 or 6
    protocol = Column(String(10), nullable=True, index=True)  # TCP, UDP, ICMP, etc.
    ttl = Column(Integer, nullable=True)
    packet_length = Column(Integer, nullable=True)

    # Layer 4 (Transport)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)

    # TCP specific
    tcp_flags = Column(String(10), nullable=True)  # S, A, F, R, P, U, etc.
    tcp_seq = Column(Integer, nullable=True)
    tcp_ack = Column(Integer, nullable=True)

    # ICMP specific
    icmp_type = Column(Integer, nullable=True)
    icmp_code = Column(Integer, nullable=True)

    # ARP specific
    arp_operation = Column(String(50), nullable=True)  # request, reply
    arp_src_ip = Column(String(45), nullable=True)
    arp_dst_ip = Column(String(45), nullable=True)
    arp_src_mac = Column(String(17), nullable=True)
    arp_dst_mac = Column(String(17), nullable=True)

    # DNS specific
    dns_query_name = Column(String(255), nullable=True)
    dns_query_type = Column(String(10), nullable=True)  # A, AAAA, CNAME, etc.
    dns_is_response = Column(Boolean, nullable=True)

    # Relationships
    capture_session = relationship("CaptureSession", back_populates="packets")
    flow = relationship("Flow", back_populates="packets")
    flow_id = Column(Integer, ForeignKey("flows.id"), nullable=True)

    __table_args__ = (
        Index("idx_packets_timestamp", "timestamp"),
        Index("idx_packets_src_ip", "src_ip"),
        Index("idx_packets_dst_ip", "dst_ip"),
        Index("idx_packets_protocol", "protocol"),
        Index("idx_packets_capture_session_id", "capture_session_id"),
    )


class Flow(Base):
    """Represents a network flow (src_ip:src_port -> dst_ip:dst_port / protocol)."""
    __tablename__ = "flows"

    id = Column(Integer, primary_key=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id"), nullable=False)

    # Flow identifier
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False)  # TCP, UDP, ICMP, etc.

    # Flow statistics
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)

    # Relationships
    capture_session = relationship("CaptureSession", back_populates="flows")
    packets = relationship("Packet", back_populates="flow")

    __table_args__ = (
        Index("idx_flow_src_ip_dst_ip_protocol", "src_ip", "dst_ip", "protocol"),
        Index("idx_flow_timestamp", "first_seen"),
    )


class DNSEvent(Base):
    """Represents a DNS query/response event."""
    __tablename__ = "dns_events"

    id = Column(Integer, primary_key=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id"), nullable=False)

    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # DNS details
    query_name = Column(String(255), nullable=False)
    query_type = Column(String(10), nullable=False)  # A, AAAA, CNAME, MX, etc.
    query_class = Column(String(10), nullable=True)  # IN, etc.
    is_response = Column(Boolean, default=False)
    response_code = Column(String(10), nullable=True)  # NOERROR, NXDOMAIN, etc.

    # Source information
    src_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    
    # Destination (DNS server)
    dst_ip = Column(String(45), nullable=False)
    dst_port = Column(Integer, nullable=True)

    __table_args__ = (
        Index("idx_dns_events_timestamp", "timestamp"),
        Index("idx_dns_events_query_name", "query_name"),
        Index("idx_dns_events_src_ip", "src_ip"),
    )


class Detection(Base):
    """Represents a detection event (alert)."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True)
    capture_session_id = Column(Integer, ForeignKey("capture_sessions.id"), nullable=False)

    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    rule_name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    description = Column(Text, nullable=True)

    # Source/Destination context
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)

    # Additional context
    metadata = Column(Text, nullable=True)  # JSON for extra details

    __table_args__ = (
        Index("idx_detections_timestamp", "timestamp"),
        Index("idx_detections_rule_name", "rule_name"),
        Index("idx_detections_severity", "severity"),
    )


class Incident(Base):
    """Represents a grouped set of detections."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    status = Column(String(50), default="open")  # open, investigating, resolved, false_positive
    
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True)

    __table_args__ = (
        Index("idx_incidents_created_at", "created_at"),
        Index("idx_incidents_status", "status"),
    )


class Asset(Base):
    """Represents a network asset (host, service, etc.)."""
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    ip_address = Column(String(45), nullable=False, unique=True, index=True)
    hostname = Column(String(255), nullable=True)
    mac_address = Column(String(17), nullable=True)
    asset_type = Column(String(50), nullable=True)  # host, server, router, etc.
    
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, nullable=False)


class ThreatIndicator(Base):
    """Represents a threat indicator (known malicious IP, domain, etc.)."""
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    indicator_type = Column(String(50), nullable=False)  # ip, domain, email, hash, etc.
    indicator_value = Column(String(255), nullable=False, index=True)
    threat_level = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    source = Column(String(255), nullable=True)  # AbuseIPDB, AlienVault, etc.
    last_seen = Column(DateTime, nullable=True)


class Rule(Base):
    """Represents a detection rule."""
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, nullable=True)
    rule_type = Column(String(50), nullable=False)  # e.g., PORT_SCAN, SYN_FLOOD, etc.
    enabled = Column(Boolean, default=True)
    severity = Column(String(20), nullable=False)
    
    # Rule logic (JSON or expression)
    rule_logic = Column(Text, nullable=True)


class ResponseAudit(Base):
    """Audit log for incident response actions."""
    __tablename__ = "response_audit"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    action = Column(String(255), nullable=False)
    user = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_response_audit_timestamp", "timestamp"),
    )
