"""
backend/database/repository.py

Repository pattern for database operations.
Provides high-level methods for storing packets, flows, DNS events, etc.
"""

from datetime import datetime
from sqlalchemy.orm import Session

from backend.database.models import (
    Packet, Flow, DNSEvent, Detection, CaptureSession
)


class PacketRepository:
    """Repository for packet operations."""

    @staticmethod
    def create_packet(session: Session, capture_session_id: int, packet_data: dict) -> Packet:
        """Create and store a packet."""
        packet = Packet(
            capture_session_id=capture_session_id,
            **packet_data
        )
        session.add(packet)
        session.commit()
        return packet

    @staticmethod
    def get_packets_by_session(session: Session, capture_session_id: int, limit: int = 100):
        """Get recent packets from a capture session."""
        return session.query(Packet)\
            .filter(Packet.capture_session_id == capture_session_id)\
            .order_by(Packet.timestamp.desc())\
            .limit(limit)\
            .all()

    @staticmethod
    def get_packets_by_ip(session: Session, ip: str, limit: int = 100):
        """Get packets involving a specific IP."""
        return session.query(Packet)\
            .filter((Packet.src_ip == ip) | (Packet.dst_ip == ip))\
            .order_by(Packet.timestamp.desc())\
            .limit(limit)\
            .all()


class FlowRepository:
    """Repository for flow operations."""

    @staticmethod
    def get_or_create_flow(
        session: Session,
        capture_session_id: int,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str
    ) -> Flow:
        """Get existing flow or create a new one."""
        flow = session.query(Flow).filter(
            Flow.capture_session_id == capture_session_id,
            Flow.src_ip == src_ip,
            Flow.dst_ip == dst_ip,
            Flow.src_port == src_port,
            Flow.dst_port == dst_port,
            Flow.protocol == protocol
        ).first()

        if not flow:
            flow = Flow(
                capture_session_id=capture_session_id,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                packet_count=1,
                byte_count=0
            )
            session.add(flow)
        else:
            flow.packet_count += 1
            flow.last_seen = datetime.utcnow()

        session.commit()
        return flow

    @staticmethod
    def update_flow(
        session: Session,
        flow: Flow,
        packet_length: int = 0
    ) -> Flow:
        """Update flow statistics."""
        flow.packet_count += 1
        flow.byte_count += packet_length
        flow.last_seen = datetime.utcnow()
        session.commit()
        return flow

    @staticmethod
    def get_flows_by_session(session: Session, capture_session_id: int, limit: int = 100):
        """Get flows from a capture session."""
        return session.query(Flow)\
            .filter(Flow.capture_session_id == capture_session_id)\
            .order_by(Flow.last_seen.desc())\
            .limit(limit)\
            .all()

    @staticmethod
    def get_flows_by_ip(session: Session, ip: str, limit: int = 100):
        """Get flows involving a specific IP."""
        return session.query(Flow)\
            .filter((Flow.src_ip == ip) | (Flow.dst_ip == ip))\
            .order_by(Flow.last_seen.desc())\
            .limit(limit)\
            .all()

    @staticmethod
    def cleanup_expired_flows(session: Session, timeout_seconds: int):
        """Delete flows that haven't been updated in timeout_seconds."""
        from datetime import timedelta
        cutoff_time = datetime.utcnow() - timedelta(seconds=timeout_seconds)
        session.query(Flow).filter(Flow.last_seen < cutoff_time).delete()
        session.commit()


class DNSEventRepository:
    """Repository for DNS event operations."""

    @staticmethod
    def create_dns_event(session: Session, capture_session_id: int, dns_data: dict) -> DNSEvent:
        """Create and store a DNS event."""
        dns_event = DNSEvent(
            capture_session_id=capture_session_id,
            **dns_data
        )
        session.add(dns_event)
        session.commit()
        return dns_event

    @staticmethod
    def get_dns_events_by_query(session: Session, query_name: str, limit: int = 100):
        """Get DNS events for a specific query."""
        return session.query(DNSEvent)\
            .filter(DNSEvent.query_name == query_name)\
            .order_by(DNSEvent.timestamp.desc())\
            .limit(limit)\
            .all()

    @staticmethod
    def get_dns_events_by_ip(session: Session, ip: str, limit: int = 100):
        """Get DNS events involving a specific IP."""
        return session.query(DNSEvent)\
            .filter((DNSEvent.src_ip == ip) | (DNSEvent.dst_ip == ip))\
            .order_by(DNSEvent.timestamp.desc())\
            .limit(limit)\
            .all()


class CaptureSessionRepository:
    """Repository for capture session operations."""

    @staticmethod
    def create_session(session: Session, interface: str) -> CaptureSession:
        """Create a new capture session."""
        capture_session = CaptureSession(
            interface=interface,
            status="running"
        )
        session.add(capture_session)
        session.commit()
        return capture_session

    @staticmethod
    def get_active_session(session: Session) -> CaptureSession:
        """Get the currently active capture session."""
        return session.query(CaptureSession)\
            .filter(CaptureSession.status == "running")\
            .order_by(CaptureSession.started_at.desc())\
            .first()

    @staticmethod
    def update_session_stats(
        session: Session,
        capture_session_id: int,
        packets_captured: int = None,
        packets_parsed: int = None,
        packets_stored: int = None,
        parser_errors: int = None
    ) -> CaptureSession:
        """Update capture session statistics."""
        capture_session = session.query(CaptureSession)\
            .filter(CaptureSession.id == capture_session_id)\
            .first()

        if capture_session:
            if packets_captured is not None:
                capture_session.packets_captured = packets_captured
            if packets_parsed is not None:
                capture_session.packets_parsed = packets_parsed
            if packets_stored is not None:
                capture_session.packets_stored = packets_stored
            if parser_errors is not None:
                capture_session.parser_errors = parser_errors

            session.commit()

        return capture_session

    @staticmethod
    def stop_session(session: Session, capture_session_id: int) -> CaptureSession:
        """Mark a capture session as stopped."""
        capture_session = session.query(CaptureSession)\
            .filter(CaptureSession.id == capture_session_id)\
            .first()

        if capture_session:
            capture_session.status = "stopped"
            capture_session.stopped_at = datetime.utcnow()
            session.commit()

        return capture_session

    @staticmethod
    def get_session_by_id(session: Session, capture_session_id: int) -> CaptureSession:
        """Get a capture session by ID."""
        return session.query(CaptureSession)\
            .filter(CaptureSession.id == capture_session_id)\
            .first()
