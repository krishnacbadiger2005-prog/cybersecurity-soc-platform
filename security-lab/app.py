# Security Lab Telemetry Application
import os
import sys
import importlib.util
from flask import Flask, render_template, request, jsonify, Response, redirect, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)


def _load_lab_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(BASE_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_lab_db = _load_lab_module("lab_db_runtime", "database.py")
_detector = _load_lab_module("lab_detector_runtime", "detector.py")
_reports = _load_lab_module("lab_reports_runtime", "reports.py")

get_total_attempts = _lab_db.get_total_attempts
get_successful_attempts = _lab_db.get_successful_attempts
get_failed_attempts = _lab_db.get_failed_attempts
get_recent_events = _lab_db.get_recent_events
get_top_ips = _lab_db.get_top_ips
get_dashboard_stats = _lab_db.get_dashboard_stats
get_security_alerts = _lab_db.get_security_alerts
get_login_timeline = _lab_db.get_login_timeline
get_dashboard_data = _lab_db.get_dashboard_data
get_report_date_bounds = _lab_db.get_report_date_bounds
get_events_for_report = _lab_db.get_events_for_report
get_alerts_for_report = _lab_db.get_alerts_for_report
clear_all_logs = _lab_db.clear_all_logs

detect_suspicious_ips = _detector.detect_suspicious_ips
generate_security_report = _reports.generate_security_report
generate_security_pdf = _reports.generate_security_pdf

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)


@app.route("/")
@app.route("/dashboard")
def dashboard():
    time_range = request.args.get("range", "all")
    source = request.args.get("source", "all")

    stats = get_dashboard_stats(time_range, source)
    successful_logins = stats["successful_logins"]
    failed_logins = stats["failed_logins"]
    suspicious_activity = stats["suspicious_activity"]
    security_alerts = stats["security_alerts"]

    recent_events = get_recent_events(10, time_range, source)
    top_ips = get_top_ips(10, time_range, source)
    alerts = get_security_alerts(10, time_range)
    login_timeline = get_login_timeline(time_range, source)
    suspicious_ips = detect_suspicious_ips()

    total_attempts = successful_logins + failed_logins
    min_date, max_date = get_report_date_bounds()

    return render_template(
        "dashboard.html",
        stats=stats,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_activity=suspicious_activity,
        security_alerts=security_alerts,
        # Backward compatibility for Phase 3 & 4
        total_attempts=total_attempts,
        successful_attempts=successful_logins,
        failed_attempts=failed_logins,
        suspicious_ips=suspicious_ips,
        # Tables & Visualizations
        recent_events=recent_events,
        top_ips=top_ips,
        alerts=alerts,
        login_timeline=login_timeline,
        current_range=time_range,
        current_source=source,
        # Report Date Bounds
        start_date=min_date,
        end_date=max_date
    )


@app.route("/api/metrics")
def api_metrics():
    """API endpoint for live telemetry and automated verification."""
    time_range = request.args.get("range", "all")
    source = request.args.get("source", "all")
    data = get_dashboard_data(time_range, source)
    return jsonify({
        "total_attempts": data["total_attempts"],
        "successful_attempts": data["successful_attempts"],
        "failed_attempts": data["failed_attempts"],
        "successful_logins": data["successful_logins"],
        "failed_logins": data["failed_logins"],
        "suspicious_activity": data["suspicious_activity"],
        "security_alerts": data["security_alerts"],
        "recent_events": [e._dict if hasattr(e, "_dict") else e for e in data["recent_events"]],
        "top_source_ips": [i._dict if hasattr(i, "_dict") else i for i in data["top_source_ips"]],
        "alerts": [a._dict if hasattr(a, "_dict") else a for a in data["alerts"]],
        "timeline": data["timeline"],
        "current_range": time_range,
        "current_source": source
    })


@app.route("/export-report")
def export_report():
    """
    Export security monitoring report in CSV or PDF format.
    Query parameters:
      - start_date (YYYY-MM-DD)
      - end_date (YYYY-MM-DD)
      - format ('csv' or 'pdf')
      - source ('all', 'portfolio', 'linux')
    """
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()
    report_format = request.args.get("format", "csv").lower().strip()
    source = request.args.get("source", "all").strip()

    min_date, max_date = get_report_date_bounds()
    if not start_date:
        start_date = min_date
    if not end_date:
        end_date = max_date

    # Validate date range
    if start_date and end_date and start_date > end_date:
        return Response("Invalid date range.", status=400, mimetype="text/plain")

    events = get_events_for_report(start_date, end_date, source)
    alerts = get_alerts_for_report(start_date, end_date)

    if report_format == "pdf":
        pdf_data = generate_security_pdf(events, alerts, start_date, end_date)
        filename = f"security_report_{start_date}_to_{end_date}.pdf"
        return Response(
            pdf_data,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )

    # Default: CSV export
    csv_data = generate_security_report(events, alerts, start_date, end_date)
    filename = f"security_report_{start_date}_to_{end_date}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.route("/export-pdf")
def export_pdf():
    """Direct alias route for PDF export."""
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()
    source = request.args.get("source", "all").strip()

    min_date, max_date = get_report_date_bounds()
    if not start_date:
        start_date = min_date
    if not end_date:
        end_date = max_date

    if start_date and end_date and start_date > end_date:
        return Response("Invalid date range.", status=400, mimetype="text/plain")

    events = get_events_for_report(start_date, end_date, source)
    alerts = get_alerts_for_report(start_date, end_date)
    pdf_data = generate_security_pdf(events, alerts, start_date, end_date)
    filename = f"security_report_{start_date}_to_{end_date}.pdf"
    return Response(
        pdf_data,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}"
        }
    )


@app.route("/clear-logs", methods=["GET", "POST"])
def clear_logs():
    """Clear all login events, security alerts, and sample logs to start fresh."""
    clear_all_logs()
    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)

