
from database import db
from datetime import datetime


# ==========================================
# REGISTERED IOT DEVICES
# ==========================================

class Device(db.Model):

    __tablename__ = "device"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    device_code = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    device_type = db.Column(
        db.String(50),
        nullable=False
    )

    manufacturer = db.Column(
        db.String(100),
        nullable=True
    )

    model_number = db.Column(
        db.String(100),
        nullable=True
    )

    firmware_version = db.Column(
        db.String(100)
    )

    status = db.Column(
        db.String(30),
        default="registered"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================
# IOT TELEMETRY
# ==========================================

class Telemetry(db.Model):

    __tablename__ = "telemetry"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    device_code = db.Column(
        db.String(50),
        nullable=False
    )

    temperature = db.Column(db.Float)

    humidity = db.Column(db.Float)

    network_rate = db.Column(db.Float)

    failed_logins = db.Column(db.Integer)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================
# AI SECURITY FINDINGS
# ==========================================

class Finding(db.Model):

    __tablename__ = "finding"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    device_code = db.Column(
        db.String(50),
        nullable=False
    )

    finding_type = db.Column(
        db.String(100)
    )

    severity = db.Column(
        db.String(20)
    )

    anomaly_score = db.Column(
        db.Float
    )

    description = db.Column(
        db.Text
    )

    recommendation = db.Column(
        db.Text
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================
# IOT VULNERABILITY ASSESSMENT
# ==========================================

class VulnerabilityFinding(db.Model):

    __tablename__ = "vulnerability_finding"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    scan_id = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    device_code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    vulnerability_name = db.Column(
        db.String(200),
        nullable=False
    )

    cve_id = db.Column(
        db.String(30),
        nullable=True
    )

    severity = db.Column(
        db.String(20),
        nullable=False
    )

    cvss_score = db.Column(
        db.Float,
        nullable=True
    )

    description = db.Column(
        db.Text
    )

    recommendation = db.Column(
        db.Text
    )

    detection_method = db.Column(
        db.String(100)
    )

    status = db.Column(
        db.String(30),
        default="OPEN"
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# ==========================================
# NETWORK SCAN HISTORY
# ==========================================

class NetworkScan(db.Model):

    __tablename__ = "network_scan"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    scan_id = db.Column(
        db.String(100),
        unique=True,
        nullable=False,
        index=True
    )

    device_code = db.Column(
        db.String(50),
        nullable=False,
        index=True
    )

    ip_address = db.Column(
        db.String(45),
        nullable=False
    )

    host_status = db.Column(
        db.String(30)
    )

    total_open_ports = db.Column(
        db.Integer,
        default=0
    )

    ports_json = db.Column(
        db.Text,
        nullable=False
    )

    findings_json = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )



class AndroidScan(db.Model):

    __tablename__ = "android_scan"

    id = db.Column(db.Integer, primary_key=True)

    scan_id = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    adb_id = db.Column(db.String(100))

    manufacturer = db.Column(db.String(100))

    model = db.Column(db.String(100))

    android_version = db.Column(db.String(50))

    security_patch = db.Column(db.String(50))

    kernel_version = db.Column(db.String(100))

    sdk_version = db.Column(db.String(50))

    status = db.Column(db.String(30))

    total_findings = db.Column(db.Integer, default=0)

    findings_json = db.Column(db.Text)

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )
