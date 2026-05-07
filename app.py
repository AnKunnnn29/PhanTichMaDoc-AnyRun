# -*- coding: utf-8 -*-
"""
app.py  –  Flask web server cho AnyRun IR Tool GUI
Chạy: python app.py  →  truy cập http://localhost:5000
"""
import io, sys, os, json, threading, time
from werkzeug.utils import secure_filename
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import Flask, request, jsonify, send_from_directory
from analyzer import MalwareAnalyzer
from incident_response import IncidentResponseGenerator
from demo_data import DEMO_REPORT, DEMO_IOC
from demo_data_wannacry import DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC
from demo_data_redline import DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC

app = Flask(__name__, static_folder="static", template_folder="templates")

analyzer = MalwareAnalyzer()
ir_gen   = IncidentResponseGenerator()

# ── helpers ────────────────────────────────────────────────────────────────

def _build_payload(report_json, ioc_json):
    result   = analyzer.parse_report(report_json, ioc_json)
    playbook = ir_gen.generate(result)
    f = result.file_info

    actions_list = []
    for a in playbook.actions:
        actions_list.append({
            "priority": a.priority,
            "phase": a.phase,
            "category": a.category,
            "title": a.title,
            "description": a.description,
            "commands": a.commands,
            "notes": a.notes,
        })

    return {
        "task_uuid":    result.task_uuid,
        "analysis_url": result.analysis_url,
        "os_env":       result.os_env,
        "duration":     result.duration_seconds,
        "file": {
            "name":      f.name      if f else "",
            "size":      f.size      if f else 0,
            "type":      f.file_type if f else "",
            "md5":       f.md5       if f else "",
            "sha1":      f.sha1      if f else "",
            "sha256":    f.sha256    if f else "",
        } if f else None,
        "threat": {
            "verdict":      result.threat_info.verdict,
            "threat_level": result.threat_info.threat_level,
            "threat_name":  result.threat_info.threat_name,
            "tags":         result.threat_info.tags,
            "mitre":        result.threat_info.mitre_techniques,
        },
        "network": {
            "ips":     result.network.ip_addresses,
            "domains": result.network.domains,
            "urls":    result.network.urls,
            "http":    result.network.http_requests[:20],
            "dns":     result.network.dns_queries,
        },
        "processes": {
            "list":     result.processes.processes[:30],
            "injected": result.processes.injected_processes,
            "dropped":  result.processes.dropped_files,
            "registry": result.processes.registry_keys[:20],
            "mutexes":  result.processes.mutexes,
        },
        "playbook": {
            "malware_name":  playbook.malware_name,
            "severity":      playbook.severity,
            "threat_level":  playbook.threat_level,
            "summary":       playbook.summary,
            "mitigation":    playbook.mitigation_summary,
            "actions":       actions_list,
            "ioc_blocklist": playbook.ioc_blocklist,
        },
    }

# ── routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/api/demo/<string:malware>", methods=["GET"])
def demo(malware):
    try:
        if malware == "wannacry":
            return jsonify({"ok": True, "data": _build_payload(DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC)})
        elif malware == "redline":
            return jsonify({"ok": True, "data": _build_payload(DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC)})
        else:
            return jsonify({"ok": True, "data": _build_payload(DEMO_REPORT, DEMO_IOC)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze():
    body    = request.get_json(force=True) or {}
    api_key = body.get("api_key", "").strip()
    task_id = body.get("task_id", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "Thiếu API key"}), 400
    if not task_id:
        return jsonify({"ok": False, "error": "Thiếu Task UUID"}), 400
    try:
        from anyrun_client import AnyRunClient, AnyRunAPIError
        client      = AnyRunClient(api_key)
        report_json = client.get_task_report(task_id)
        ioc_json    = client.get_task_iocs(task_id)
        return jsonify({"ok": True, "data": _build_payload(report_json, ioc_json)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/submit/url", methods=["POST"])
def submit_url():
    body    = request.get_json(force=True) or {}
    api_key = body.get("api_key", "").strip()
    url     = body.get("url", "").strip()
    if not api_key or not url:
        return jsonify({"ok": False, "error": "Thiếu api_key hoặc url"}), 400
    try:
        from anyrun_client import AnyRunClient
        client  = AnyRunClient(api_key)
        res     = client.submit_url(url)
        task_id = res.get("data", {}).get("taskid", "")
        return jsonify({"ok": True, "task_id": task_id,
                        "message": f"Đã submit! Task ID: {task_id}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/submit/file", methods=["POST"])
def submit_file():
    api_key = request.form.get("api_key", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "Thiếu API key"}), 400
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Không có file"}), 400
    f         = request.files["file"]
    safe_name = secure_filename(f.filename) or "upload_tmp"
    tmp_path  = os.path.join(os.getcwd(), "tmp_upload_" + safe_name)
    f.save(tmp_path)
    try:
        from anyrun_client import AnyRunClient
        client  = AnyRunClient(api_key)
        res     = client.submit_file(tmp_path)
        task_id = res.get("data", {}).get("taskid", "")
        return jsonify({"ok": True, "task_id": task_id,
                        "message": f"Đã submit! Task ID: {task_id}"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

# ── Submit + Wait + Analyze (như main.py) ─────────────────────────────────

# Lưu trạng thái task đang chờ: {task_id: {status, progress, message, data, _created_at}}
_task_jobs = {}
_task_lock = threading.Lock()
_JOB_TTL   = 1800  # 30 phút – tự động xóa entry cũ


def _cleanup_old_jobs():
    """Background thread: xóa các job đã hoàn tất/lỗi và cũ hơn TTL."""
    while True:
        time.sleep(300)  # kiểm tra mỗi 5 phút
        cutoff = time.time() - _JOB_TTL
        with _task_lock:
            expired = [
                tid for tid, job in _task_jobs.items()
                if job.get("_created_at", 0) < cutoff
                and job.get("status") in ("done", "error")
            ]
            for tid in expired:
                del _task_jobs[tid]


_cleanup_thread = threading.Thread(target=_cleanup_old_jobs, daemon=True)
_cleanup_thread.start()

def _poll_and_analyze(api_key, task_id, max_wait=300):
    """Chạy trong thread riêng: polling → analyze → lưu kết quả."""
    from anyrun_client import AnyRunClient, AnyRunAPIError, AnyRunNotFoundError
    client  = AnyRunClient(api_key)
    elapsed = 0
    interval = 10
    steps = [
        "Đã submit lên Any.Run sandbox...",
        "Sandbox đang khởi động môi trường...",
        "Đang chạy mẫu trong sandbox...",
        "Đang thu thập kết quả phân tích...",
        "Đang trích xuất IOC...",
    ]
    step_idx = 0
    with _task_lock:
        _task_jobs[task_id] = {"status": "running", "progress": 5,
                               "message": steps[0], "data": None, "error": None,
                               "_created_at": time.time()}
    while elapsed < max_wait:
        time.sleep(interval)
        elapsed += interval
        pct = min(85, int(elapsed / max_wait * 100))
        msg = steps[min(step_idx, len(steps)-1)]
        step_idx += 1
        with _task_lock:
            _task_jobs[task_id]["progress"] = pct
            _task_jobs[task_id]["message"]  = msg
        try:
            report = client.get_task_report(task_id)
            status = report.get("data",{}).get("analysis",{}).get("status","")
            if status in ("done", "failed"):
                ioc_json = client.get_task_iocs(task_id)
                payload  = _build_payload(report, ioc_json)
                with _task_lock:
                    _task_jobs[task_id] = {"status": "done", "progress": 100,
                                           "message": "Hoàn tất!", "data": payload, "error": None}
                return
        except AnyRunNotFoundError:
            pass
        except Exception as e:
            with _task_lock:
                _task_jobs[task_id] = {"status": "error", "progress": 0,
                                       "message": str(e), "data": None, "error": str(e)}
            return
    with _task_lock:
        _task_jobs[task_id] = {"status": "error", "progress": 0,
                               "message": f"Timeout sau {max_wait}s – sandbox chưa hoàn tất.",
                               "data": None, "error": "timeout"}

@app.route("/api/submit_analyze/url", methods=["POST"])
def submit_analyze_url():
    """Submit URL → polling → analyze (1 bước, như main.py --url)."""
    body    = request.get_json(force=True) or {}
    api_key = body.get("api_key","").strip()
    url     = body.get("url","").strip()
    if not api_key or not url:
        return jsonify({"ok": False, "error": "Thiếu api_key hoặc url"}), 400
    try:
        from anyrun_client import AnyRunClient
        client  = AnyRunClient(api_key)
        res     = client.submit_url(url)
        task_id = res.get("data",{}).get("taskid","")
        if not task_id:
            return jsonify({"ok": False, "error": "Không nhận được task ID từ Any.Run"}), 400
        t = threading.Thread(target=_poll_and_analyze, args=(api_key, task_id), daemon=True)
        t.start()
        return jsonify({"ok": True, "task_id": task_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/submit_analyze/file", methods=["POST"])
def submit_analyze_file():
    """Submit file → polling → analyze (1 bước, như main.py --file)."""
    api_key = request.form.get("api_key","").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "Thiếu API key"}), 400
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "Không có file"}), 400
    f         = request.files["file"]
    safe_name = secure_filename(f.filename) or "upload_tmp"
    tmp_path  = os.path.join(os.getcwd(), "tmp_upload_" + safe_name)
    f.save(tmp_path)
    try:
        from anyrun_client import AnyRunClient
        client  = AnyRunClient(api_key)
        res     = client.submit_file(tmp_path)
        task_id = res.get("data",{}).get("taskid","")
        if not task_id:
            return jsonify({"ok": False, "error": "Không nhận được task ID từ Any.Run"}), 400
        t = threading.Thread(target=_poll_and_analyze, args=(api_key, task_id), daemon=True)
        t.start()
        return jsonify({"ok": True, "task_id": task_id})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.route("/api/task_status/<task_id>", methods=["GET"])
def task_status(task_id):
    """Polling endpoint: trả về trạng thái job đang chờ."""
    with _task_lock:
        job = _task_jobs.get(task_id)
    if not job:
        return jsonify({"ok": False, "error": "Không tìm thấy job"}), 404
    return jsonify({"ok": True, **job})

@app.route("/api/open_reports", methods=["GET"])
def open_reports():
    """Mở thư mục reports trong File Explorer."""
    reports_dir = os.path.join(os.getcwd(), "reports")
    os.makedirs(reports_dir, exist_ok=True)
    if sys.platform == "win32":
        os.startfile(reports_dir)
    return jsonify({"ok": True, "path": reports_dir})

@app.route("/api/history", methods=["POST"])
def history():
    body    = request.get_json(force=True) or {}
    api_key = body.get("api_key", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "Thiếu API key"}), 400
    try:
        from anyrun_client import AnyRunClient
        client = AnyRunClient(api_key)
        res    = client.get_history(limit=15)
        tasks  = res.get("data", {}).get("tasks", []) or []
        return jsonify({"ok": True, "tasks": tasks})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/export", methods=["POST"])
def export_report():
    body = request.get_json(force=True) or {}
    fmt  = body.get("format", "json")  # "json" | "markdown"
    data = body.get("data")
    if not data:
        return jsonify({"ok": False, "error": "Không có data"}), 400
    import datetime
    now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("reports", exist_ok=True)
    if fmt == "markdown":
        path = f"reports/IR_Report_{now}.md"
        _write_markdown(data, path)
    else:
        path = f"reports/IR_Report_{now}.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
    return jsonify({"ok": True, "path": path})

def _write_markdown(data: dict, path: str):
    import datetime
    t = data.get("threat", {})
    f = data.get("file") or {}
    p = data.get("playbook", {})
    lines = [
        f"# Báo Cáo Phản Ứng Sự Cố – {p.get('malware_name','')}",
        f"",
        f"> **Ngày tạo:** {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}  ",
        f"> **Mức độ:** `{p.get('severity','')}`  ",
        f"> **Any.Run:** {data.get('analysis_url','')}",
        f"",
        f"## Tổng quan",
        f"",
        f"| | |","|---|---|",
        f"| Tên mã độc | {p.get('malware_name','')} |",
        f"| Verdict | {t.get('verdict','')} |",
        f"| Threat Level | {t.get('threat_level','')}/4 |",
        f"| OS | {data.get('os_env','')} |",
    ]
    if f:
        lines += ["","## File","",
            f"| MD5 | `{f.get('md5','')}` |",
            f"| SHA256 | `{f.get('sha256','')}` |"]
    lines += ["","## MITRE ATT&CK","",
        "| ID | Technique | Tactic |","|---|---|---|",
        *[f"| {m['id']} | {m['name']} | {m['tactic']} |"
          for m in t.get("mitre",[])],
        "","## IR Playbook",""]
    for a in p.get("actions",[]):
        lines += [f"### {a['title']}","",a['description'],""]
        if a.get("commands"):
            lines += ["```powershell", *a["commands"], "```",""]
    lines += ["","## IOC Blocklist","",
        "**IPs:** " + ", ".join(p.get("ioc_blocklist",{}).get("ip_addresses",[])[:20]),
        "","**Domains:** " + ", ".join(p.get("ioc_blocklist",{}).get("domains",[])[:20])]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

if __name__ == "__main__":
    print("=== AnyRun IR Tool Web GUI ===")
    print("Truy cập: http://localhost:5000")
    app.run(debug=False, port=5000, host="0.0.0.0")
