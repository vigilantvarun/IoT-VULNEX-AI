
import json
import uuid
import ipaddress

from flask import Flask, render_template, request, jsonify

from config import Config
from database import db
from database.models import (
    Device,
    Telemetry,
    Finding,
    VulnerabilityFinding,
    NetworkScan,
    AndroidScan
)

from vulnerability_scanner.scanner import assess_device
from vulnerability_scanner.network_scanner import scan_network_device
from vulnerability_scanner.network_analyzer import analyze_network_scan
from vulnerability_scanner.android_scanner import assess_android_device
from ai_engine.detect_anomaly import IoTAnomalyDetector


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


# ==========================================
# INITIALIZE AI DETECTOR
# ==========================================

detector = IoTAnomalyDetector()
detector.train_model()


# ==========================================
# CREATE DATABASE TABLES
# ==========================================

with app.app_context():
    db.create_all()


# ==========================================
# HOME / DASHBOARD
# ==========================================

@app.route("/")
def home():

    device_count = Device.query.count()
    alert_count = Finding.query.count()
    telemetry_count = Telemetry.query.count()

    normal_count = max(0, telemetry_count - alert_count)

    return render_template(
        "dashboard.html",
        devices=device_count,
        alerts=alert_count,
        telemetry=telemetry_count,
        normal=normal_count
    )


# ==========================================
# DEVICE MANAGEMENT
# ==========================================

@app.route("/devices")
def devices_page():

    all_devices = Device.query.all()

    return render_template(
        "devices.html",
        devices=all_devices
    )


@app.route("/add-device", methods=["POST"])
def add_device():

    name = request.form.get("name", "").strip()
    code = request.form.get("device_code", "").strip()
    device_type = request.form.get("device_type", "").strip()

    manufacturer = request.form.get("manufacturer", "").strip()
    model_number = request.form.get("model_number", "").strip()
    firmware = request.form.get("firmware_version", "").strip()

    if not name or not code or not device_type:
        return "Please enter all required fields.", 400

    existing = Device.query.filter_by(
        device_code=code
    ).first()

    if existing:
        return "Device code already exists.", 409

    device = Device(
        device_code=code,
        name=name,
        device_type=device_type,
        manufacturer=manufacturer or None,
        model_number=model_number or None,
        firmware_version=firmware or None,
        status="active"
    )

    try:
        db.session.add(device)
        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Device registered successfully",
            "device_code": code,
            "manufacturer": manufacturer,
            "model_number": model_number
        }), 201

    except Exception:
        db.session.rollback()
        app.logger.exception("Device registration failed")

        return jsonify({
            "success": False,
            "message": "Device registration failed."
        }), 500


# ==========================================
# RECEIVE IOT TELEMETRY
# ==========================================

@app.route("/api/telemetry", methods=["POST"])
def receive_telemetry():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "JSON object required"}), 400

    device_code = str(
        data.get("device_code", "")
    ).strip()

    if not device_code:
        return jsonify({"error": "Device code required"}), 400

    device = Device.query.filter_by(
        device_code=device_code
    ).first()

    if not device:
        return jsonify({"error": "Device not registered"}), 404

    try:
        temperature = float(data["temperature"])
        humidity = float(data["humidity"])
        network_rate = float(data["network_rate"])
        failed_logins = int(data["failed_logins"])

        if not all(
            map(
                lambda x: x == x and abs(x) != float("inf"),
                [temperature, humidity, network_rate]
            )
        ):
            raise ValueError("Sensor values must be finite")

        if not 0 <= humidity <= 100:
            raise ValueError("Invalid humidity")

        if network_rate < 0 or failed_logins < 0:
            raise ValueError("Invalid network values")

    except (KeyError, ValueError, TypeError):
        return jsonify({"error": "Invalid telemetry values"}), 400

    try:

        telemetry = Telemetry(
            device_code=device_code,
            temperature=temperature,
            humidity=humidity,
            network_rate=network_rate,
            failed_logins=failed_logins
        )

        db.session.add(telemetry)

        result = detector.detect_anomaly(
            temperature,
            humidity,
            network_rate,
            failed_logins
        )

        if result["status"] == "ANOMALY DETECTED":

            finding = Finding(
                device_code=device_code,
                finding_type="AI Anomaly Detection",
                severity=result["risk"],
                anomaly_score=float(result["anomaly_score"]),
                description=f"Unusual telemetry detected from {device_code}",
                recommendation=(
                    "Inspect device readings, network activity "
                    "and login history."
                )
            )

            db.session.add(finding)

        db.session.commit()

        return jsonify({
            "device_code": device_code,
            "ai_analysis": {
                "status": result["status"],
                "risk": result["risk"],
                "anomaly_score": float(result["anomaly_score"])
            },
            "telemetry": {
                "temperature": temperature,
                "humidity": humidity,
                "network_rate": network_rate,
                "failed_logins": failed_logins
            }
        }), 200

    except Exception:
        db.session.rollback()
        app.logger.exception("Telemetry processing failed")

        return jsonify({
            "error": "Telemetry processing failed."
        }), 500


# ==========================================
# LIVE DASHBOARD STATISTICS
# ==========================================

@app.route("/api/dashboard-stats")
def dashboard_stats():

    device_count = Device.query.count()
    telemetry_count = Telemetry.query.count()
    alert_count = Finding.query.count()

    normal_count = max(0, telemetry_count - alert_count)

    recent_telemetry = Telemetry.query.order_by(
        Telemetry.created_at.desc()
    ).limit(10).all()

    recent_alerts = Finding.query.order_by(
        Finding.created_at.desc()
    ).limit(10).all()

    return jsonify({
        "devices": device_count,
        "telemetry": telemetry_count,
        "alerts": alert_count,
        "normal": normal_count,

        "recent_readings": [
            {
                "device_code": item.device_code,
                "temperature": item.temperature,
                "humidity": item.humidity,
                "network_rate": item.network_rate,
                "failed_logins": item.failed_logins
            }
            for item in recent_telemetry
        ],

        "recent_alerts": [
            {
                "device_code": item.device_code,
                "severity": item.severity,
                "score": item.anomaly_score,
                "description": item.description
            }
            for item in recent_alerts
        ]
    })


# ==========================================
# ALERTS AND ANALYTICS
# ==========================================

@app.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@app.route("/analytics")
def analytics_page():
    return render_template("analytics.html")


@app.route("/api/alerts")
def get_alerts():

    findings = Finding.query.order_by(
        Finding.created_at.desc()
    ).limit(50).all()

    return jsonify([
        {
            "id": item.id,
            "device_code": item.device_code,
            "type": item.finding_type,
            "severity": item.severity,
            "score": float(item.anomaly_score or 0),
            "description": item.description,
            "recommendation": item.recommendation,
            "created_at": (
                item.created_at.isoformat()
                if item.created_at else None
            )
        }
        for item in findings
    ])


# ==========================================
# SYSTEM HEALTH
# ==========================================

@app.route("/api/health")
def health():

    return jsonify({
        "project": "IoT VULNEX AI",
        "status": "online",
        "ai_engine": "ready"
    })


# ==========================================
# FIRMWARE VULNERABILITY SCANNING
# ==========================================

@app.route("/vulnerability-scan")
def vulnerability_scan():

    devices = Device.query.order_by(
        Device.created_at.desc()
    ).all()

    return render_template(
        "vulnerability_scan.html",
        devices=devices
    )


@app.route("/api/vulnerability-scan/<device_code>", methods=["POST"])
def run_vulnerability_scan(device_code):

    device = Device.query.filter_by(
        device_code=device_code
    ).first()

    if not device:
        return jsonify({
            "success": False,
            "message": "Device not found."
        }), 404

    try:

        result = assess_device(device)

        for item in result["findings"]:

            finding = VulnerabilityFinding(
                scan_id=result["scan_id"],
                device_code=result["device_code"],
                vulnerability_name=item["vulnerability_name"],
                cve_id=item["cve_id"],
                severity=item["severity"],
                cvss_score=item["cvss_score"],
                description=item["description"],
                recommendation=item["recommendation"],
                detection_method=item["detection_method"],
                status="OPEN"
            )

            db.session.add(finding)

        db.session.commit()

        return jsonify({
            "success": True,
            "message": "Scan completed successfully.",
            "result": result
        })

    except Exception:
        db.session.rollback()
        app.logger.exception("Vulnerability scan failed")

        return jsonify({
            "success": False,
            "message": "The scan could not be completed."
        }), 500


@app.route("/api/vulnerabilities")
def get_vulnerabilities():

    findings = VulnerabilityFinding.query.order_by(
        VulnerabilityFinding.created_at.desc()
    ).limit(100).all()

    return jsonify([
        {
            "id": item.id,
            "scan_id": item.scan_id,
            "device_code": item.device_code,
            "vulnerability_name": item.vulnerability_name,
            "cve_id": item.cve_id,
            "severity": item.severity,
            "cvss_score": item.cvss_score,
            "description": item.description,
            "recommendation": item.recommendation,
            "detection_method": item.detection_method,
            "status": item.status,
            "created_at": item.created_at.isoformat()
        }
        for item in findings
    ])


# ==========================================
# NETWORK SCANNING
# ==========================================

@app.route("/api/network-scan", methods=["POST"])
def api_network_scan():

    data = request.get_json(silent=True) or {}

    device_code = str(data.get("device_code", "")).strip()
    ip_address = str(data.get("ip_address", "")).strip()

    if not device_code or not ip_address:
        return jsonify({
            "success": False,
            "message": "Device code and IP address are required."
        }), 400

    device = Device.query.filter_by(
        device_code=device_code
    ).first()

    if device is None:
        return jsonify({
            "success": False,
            "message": "Device is not registered."
        }), 404

    result = scan_network_device(ip_address)

    if not result["success"]:
        return jsonify({
            "success": False,
            "message": result["message"]
        }), 400

    analysis = analyze_network_scan(result)

    if not analysis["success"]:
        return jsonify({
            "success": False,
            "message": analysis["message"]
        }), 400

    scan_id = str(uuid.uuid4())

    try:

        scan_record = NetworkScan(
            scan_id=scan_id,
            device_code=device_code,
            ip_address=result["ip_address"],
            host_status=result.get("host_status", "unknown"),
            total_open_ports=result.get("total_open_ports", 0),
            ports_json=json.dumps(result.get("ports", [])),
            findings_json=json.dumps(analysis.get("findings", []))
        )

        db.session.add(scan_record)
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Network scan history save failed")

        return jsonify({
            "success": False,
            "message": "Scan completed, but saving scan history failed."
        }), 500

    return jsonify({
        "success": True,
        "message": "Network scan completed and saved successfully.",
        "scan_id": scan_id,
        "device_code": device_code,
        "device_name": device.name,
        "result": result,
        "analysis": analysis
    })


@app.route("/api/network-scan-history")
def get_network_scan_history():

    device_code = request.args.get("device_code", "").strip()

    query = NetworkScan.query

    if device_code:
        query = query.filter_by(device_code=device_code)

    scans = query.order_by(
        NetworkScan.created_at.desc()
    ).limit(100).all()

    return jsonify([
        {
            "scan_id": item.scan_id,
            "device_code": item.device_code,
            "ip_address": item.ip_address,
            "host_status": item.host_status,
            "total_open_ports": item.total_open_ports,
            "ports": json.loads(item.ports_json),
            "findings": json.loads(item.findings_json),
            "created_at": (
                item.created_at.isoformat()
                if item.created_at else None
            )
        }
        for item in scans
    ])


# ==========================================
# NETWORK DISCOVERY
# ==========================================

@app.route("/api/discover-devices", methods=["GET"])
def api_discover_devices():

    from vulnerability_scanner.device_discovery import discover_devices

    network = request.args.get(
        "network",
        "192.168.31.0/24"
    )

    result = discover_devices(network)

    return jsonify(result)


@app.route("/network-discovery")
def network_discovery():
    return render_template("network_discovery.html")


@app.route("/api/scan-discovered-device", methods=["POST"])
def scan_discovered_device():

    data = request.get_json(silent=True) or {}

    ip_address = str(data.get("ip_address", "")).strip()

    try:

        target = ipaddress.ip_address(ip_address)

        if target.version != 4 or not target.is_private:
            return jsonify({
                "status": "ERROR",
                "message": "Only private IPv4 addresses are allowed."
            }), 400

    except ValueError:

        return jsonify({
            "status": "ERROR",
            "message": "Invalid IP address."
        }), 400

    scan_result = scan_network_device(str(target))

    if not scan_result.get("success"):

        return jsonify({
            "status": "ERROR",
            "message": scan_result.get("message", "Scan failed.")
        }), 500

    analysis = analyze_network_scan(scan_result)

    return jsonify({
        "status": "SUCCESS",
        "message": "Device service scan completed.",
        "scan_result": scan_result,
        "analysis": analysis
    })


# ==========================================
# ANDROID SECURITY ASSESSMENT
# ==========================================

@app.route("/api/android-assessment", methods=["GET"])
def android_assessment():

    result = assess_android_device()

    if result.get("status") == "SUCCESS":

        device = result.get("device", {})
        findings = result.get("findings", [])

        try:

            scan_record = AndroidScan(
                scan_id=result.get("scan_id"),
                adb_id=device.get("adb_id"),
                manufacturer=device.get("manufacturer"),
                model=device.get("model"),
                android_version=device.get("android_version"),
                security_patch=device.get("security_patch"),
                kernel_version=device.get("kernel_version"),
                sdk_version=device.get("sdk_version"),
                status=result.get("status"),
                total_findings=result.get("total_findings", 0),
                findings_json=json.dumps(findings)
            )

            db.session.add(scan_record)
            db.session.commit()

            result["history_saved"] = True

        except Exception as error:

            db.session.rollback()
            app.logger.exception("Android scan history save failed")

            result["history_saved"] = False
            result["history_error"] = str(error)

    return jsonify(result)


# ==========================================
# ANDROID ASSESSMENT PAGE
# ==========================================

@app.route("/android-assessment")
def android_assessment_page():
    return render_template("android_assessment.html")


# ==========================================
# ANDROID SCAN HISTORY API
# ==========================================

@app.route("/api/android-scan-history")
def android_scan_history():

    scans = AndroidScan.query.order_by(
        AndroidScan.created_at.desc()
    ).limit(100).all()

    return jsonify([
        {
            "scan_id": item.scan_id,
            "adb_id": item.adb_id,
            "manufacturer": item.manufacturer,
            "model": item.model,
            "android_version": item.android_version,
            "security_patch": item.security_patch,
            "kernel_version": item.kernel_version,
            "sdk_version": item.sdk_version,
            "status": item.status,
            "total_findings": item.total_findings,
            "findings": json.loads(item.findings_json or "[]"),
            "created_at": (
                item.created_at.isoformat()
                if item.created_at else None
            )
        }
        for item in scans
    ])


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )
