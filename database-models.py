from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Text, JSON, Enum, Table
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime
import enum
import uuid

Base = declarative_base()

# Association tables
user_roles = Table('user_roles', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

asset_tags = Table('asset_tags', Base.metadata,
    Column('asset_id', Integer, ForeignKey('assets.id')),
    Column('tag_id', Integer, ForeignKey('tags.id'))
)

# Enums
class UserStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"

class AlertSeverity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AssetType(enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    CLOUD_RESOURCE = "cloud_resource"
    IOT_DEVICE = "iot_device"

class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ComplianceFramework(enum.Enum):
    CIS = "cis"
    NIST = "nist"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    GDPR = "gdpr"

# Models
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255))
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    status = Column(Enum(UserStatus), default=UserStatus.PENDING)
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255))
    last_login = Column(DateTime(timezone=True))
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    api_keys = relationship("APIKey", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    alerts = relationship("Alert", back_populates="assigned_to")
    scans = relationship("SecurityScan", back_populates="initiated_by")

class Role(Base):
    __tablename__ = 'roles'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    permissions = Column(JSON, default=list)
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")

class Asset(Base):
    __tablename__ = 'assets'

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    name = Column(String(255), nullable=False)
    asset_type = Column(Enum(AssetType), nullable=False)
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    hostname = Column(String(255))
    operating_system = Column(String(100))
    location = Column(String(255))
    owner = Column(String(255))
    department = Column(String(100))
    criticality = Column(Integer, default=3)  # 1-5 scale
    is_monitored = Column(Boolean, default=True)
    metadata = Column(JSON, default=dict)
    last_scan = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    tags = relationship("Tag", secondary=asset_tags, back_populates="assets")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    scan_results = relationship("ScanResult", back_populates="asset")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(AlertSeverity), nullable=False)
    cvss_score = Column(Float)
    cvss_vector = Column(String(255))
    asset_id = Column(Integer, ForeignKey('assets.id'))
    scan_id = Column(Integer, ForeignKey('security_scans.id'))
    status = Column(String(50), default='open')  # open, mitigated, resolved, accepted
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True))
    resolution_notes = Column(Text)
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    references = Column(JSON, default=list)
    
    # Relationships
    asset = relationship("Asset", back_populates="vulnerabilities")
    scan = relationship("SecurityScan", back_populates="vulnerabilities")

class SecurityScan(Base):
    __tablename__ = 'security_scans'

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    scan_type = Column(String(50), nullable=False)  # vulnerability, compliance, full
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    targets = Column(JSON, default=list)
    initiated_by_id = Column(Integer, ForeignKey('users.id'))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    progress = Column(Integer, default=0)
    results_summary = Column(JSON, default=dict)
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    initiated_by = relationship("User", back_populates="scans")
    scan_results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan")

class ScanResult(Base):
    __tablename__ = 'scan_results'

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey('security_scans.id'))
    asset_id = Column(Integer, ForeignKey('assets.id'))
    result_type = Column(String(50))  # vulnerability, compliance, configuration
    findings = Column(JSON, default=dict)
    score = Column(Float)
    passed_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    scan = relationship("SecurityScan", back_populates="scan_results")
    asset = relationship("Asset", back_populates="scan_results")

class Alert(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Enum(AlertSeverity), nullable=False)
    category = Column(String(100))
    source = Column(String(100))  # system, scan, user, external
    status = Column(String(50), default='open')  # open, acknowledged, resolved, false_positive
    assigned_to_id = Column(Integer, ForeignKey('users.id'))
    metadata = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    resolution_notes = Column(Text)
    
    # Relationships
    assigned_to = relationship("User", back_populates="alerts")
    comments = relationship("AlertComment", back_populates="alert", cascade="all, delete-orphan")

class AlertComment(Base):
    __tablename__ = 'alert_comments'

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey('alerts.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="comments")
    user = relationship("User")

class ComplianceCheck(Base):
    __tablename__ = 'compliance_checks'

    id = Column(Integer, primary_key=True, index=True)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    control_id = Column(String(50), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    category = Column(String(100))
    severity = Column(String(50))
    automated = Column(Boolean, default=True)
    check_script = Column(Text)
    remediation_steps = Column(Text)
    references = Column(JSON, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class ComplianceResult(Base):
    __tablename__ = 'compliance_results'

    id = Column(Integer, primary_key=True, index=True)
    check_id = Column(Integer, ForeignKey('compliance_checks.id'))
    asset_id = Column(Integer, ForeignKey('assets.id'))
    scan_id = Column(Integer, ForeignKey('security_scans.id'))
    status = Column(String(50))  # passed, failed, not_applicable
    evidence = Column(JSON, default=dict)
    notes = Column(Text)
    checked_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    check = relationship("ComplianceCheck")
    asset = relationship("Asset")
    scan = relationship("SecurityScan")

class ThreatIntelligence(Base):
    __tablename__ = 'threat_intelligence'

    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String(50))  # ip, domain, hash, email, url
    indicator_value = Column(String(500), unique=True, nullable=False)
    threat_type = Column(String(100))
    severity = Column(Enum(AlertSeverity))
    confidence = Column(Integer)  # 0-100
    source = Column(String(100))
    description = Column(Text)
    metadata = Column(JSON, default=dict)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    status = Column(String(50))  # success, failure
    details = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")

class APIKey(Base):
    __tablename__ = 'api_keys'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String(100), nullable=False)
    key_hash = Column(String(255), unique=True, nullable=False)
    scopes = Column(JSON, default=list)
    expires_at = Column(DateTime(timezone=True))
    last_used = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="api_keys")

class Tag(Base):
    __tablename__ = 'tags'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False)
    color = Column(String(7))  # Hex color
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    assets = relationship("Asset", secondary=asset_tags, back_populates="tags")

class SecurityPolicy(Base):
    __tablename__ = 'security_policies'

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    policy_type = Column(String(50))  # password, access, network, data
    rules = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    enforcement_mode = Column(String(50), default='audit')  # audit, enforce
    created_by_id = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    created_by = relationship("User")