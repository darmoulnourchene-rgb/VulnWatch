from sqlalchemy import Column, String, Float, Boolean, DateTime, Integer, Text, ForeignKey
from sqlalchemy.orm import declarative_base
from datetime import datetime

Base = declarative_base()


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True)  # ex: "CVE-2024-3400"
    vendor = Column(String, nullable=False, index=True)
    product = Column(String, nullable=True)          # produit principal (rétrocompatibilité)
    products = Column(Text, nullable=True)            # JSON list — tous les produits affectés
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, default=0.0, index=True)
    severity = Column(String, nullable=False, index=True)  # CRITICAL / HIGH / MEDIUM / LOW / UNSCORED
    unscored = Column(Boolean, default=False)  # True = NVD n'a pas encore attribué de score CVSS
    published_date = Column(String, nullable=True)    # ISO string
    patch_available = Column(Boolean, default=False)
    kev_status = Column(Boolean, default=False, index=True)
    versions = Column(String, nullable=True)
    references = Column(Text, nullable=True)          # JSON list de liens
    source = Column(String, nullable=True)             # "NVD", "NVD + Fortinet PSIRT", ...
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    vendor = Column(String, nullable=False)
    reason = Column(String, nullable=False)   # "new_critical" ou "newly_kev"
    message = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    acknowledged = Column(Boolean, default=False)

class SyncLog(Base):
    
    __tablename__ = "sync_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String, default="running")  # running / success / error
    trigger = Column(String, default="manual")   # manual / scheduled / api
    total_collected = Column(Integer, default=0)
    new_count = Column(Integer, default=0)
    updated_count = Column(Integer, default=0)
    alerts_created = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)