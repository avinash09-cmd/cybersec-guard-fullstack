"""
database.py
-----------
SQLAlchemy models + session setup.

Targets MySQL in production via:
    mysql+pymysql://<user>:<password>@localhost/cybersecguard

For quick local testing without a MySQL server installed, set the
DATABASE_URL environment variable to a SQLite file instead, e.g.:
    export DATABASE_URL=sqlite:///dev.db
"""

import os
import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "mysql+pymysql://root:password@localhost/cybersecguard"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    engine = Column(String(32), default="nmap")           # "nmap" or "socket-fallback"
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    ports = relationship("ScanPort", backref="scan", cascade="all, delete-orphan")


class ScanPort(Base):
    __tablename__ = "scan_ports"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scan_results.id"))
    port = Column(Integer, nullable=False)
    service = Column(String(64))
    banner = Column(Text)
    risk_note = Column(Text)


class TrafficSession(Base):
    __tablename__ = "traffic_sessions"
    id = Column(Integer, primary_key=True)
    engine = Column(String(32), default="tshark")          # "tshark" or "scapy-fallback"
    packet_count = Column(Integer, default=0)
    protocol_summary = Column(Text)                        # JSON string
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    alerts = relationship("TrafficAlert", backref="session", cascade="all, delete-orphan")


class TrafficAlert(Base):
    __tablename__ = "traffic_alerts"
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey("traffic_sessions.id"))
    alert_type = Column(String(64))                        # arp_spoof | syn_flood | port_scan
    message = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class VaultMaster(Base):
    """Single-row table: bcrypt hash of the master password used to unlock the vault."""
    __tablename__ = "vault_master"
    id = Column(Integer, primary_key=True)
    bcrypt_hash = Column(String(255), nullable=False)
    pbkdf2_salt = Column(String(255), nullable=False)       # base64, used to derive the AES key


class VaultEntry(Base):
    __tablename__ = "vault_entries"
    id = Column(Integer, primary_key=True)
    site = Column(String(255), nullable=False)
    username = Column(String(255))
    encrypted_password = Column(Text, nullable=False)       # Fernet ciphertext, base64
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


def init_db():
    Base.metadata.create_all(engine)


def get_session():
    return SessionLocal()
