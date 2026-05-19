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
from ml_engine import MLThreatPredictor
from markdown_importer import markdown_to_anyrun_report
from ai_assistant import answer_remediation
from reporter import build_malware_analysis
from history_store import (
    extract_hashes_from_report,
    find_exact_cached_payload,
    find_family_cached_payload,
    load_history as load_local_history,
    record_analysis,
    task_uuid_from_report,
)

app = Flask(__name__, static_folder="static", template_folder="templates")

analyzer = MalwareAnalyzer()
ir_gen   = IncidentResponseGenerator()
ml_predictor = MLThreatPredictor()

# ── helpers ────────────────────────────────────────────────────────────────

def _build_payload(report_json, ioc_json, use_cache=True, source="manual"):
    report_hashes = extract_hashes_from_report(report_json, ioc_json)
    task_uuid = task_uuid_from_report(report_json)
    if use_cache:
        cached = find_exact_cached_payload(task_uuid, report_hashes)
        if cached:
            return cached

    result   = analyzer.parse_report(report_json, ioc_json)

    if use_cache:
        cached = find_family_cached_payload(
            result.threat_info.threat_name,
            current_task_uuid=result.task_uuid,
            hashes=report_hashes,
        )
        if cached:
            return cached

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

    ml_result = ml_predictor.predict(result)

    payload = {
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
            "ml":           ml_result,
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
        "malware_analysis": build_malware_analysis(result),
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
    record_analysis(payload, source=source)
    return payload

def _load_json_upload(field_name, required=True):
    upload = request.files.get(field_name)
    if not upload:
        if required:
            raise ValueError(f"Thiếu file JSON: {field_name}")
        return {}
    try:
        return json.load(upload.stream)
    except Exception as exc:
        raise ValueError(f"File {field_name} không phải JSON hợp lệ: {exc}") from exc

def _load_report_upload(field_name, supplemental_text=""):
    upload = request.files.get(field_name)
    if not upload:
        raise ValueError(f"Thiếu file report: {field_name}")
    raw = upload.read()
    filename = upload.filename or "report"
    text = raw.decode("utf-8-sig", errors="replace")
    if supplemental_text:
        text = f"{text}\n\n## Manually copied ANY.RUN indicators\n{supplemental_text}"
    if not text.strip():
        raise ValueError(
            f"File report '{filename}' đang rỗng (0 byte). "
            "Hãy tải lại Results/Text Report từ Any.Run; không dùng file Get Sample .bin."
        )
    if filename.lower().endswith((".md", ".txt")):
        return markdown_to_anyrun_report(text, filename)
    try:
        return json.loads(text)
    except Exception:
        return markdown_to_anyrun_report(text, filename)

# ── routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/api/demo/<string:malware>", methods=["GET"])
def demo(malware):
    try:
        if malware == "wannacry":
            return jsonify({"ok": True, "data": _build_payload(DEMO_WANNACRY_REPORT, DEMO_WANNACRY_IOC, source="demo:wannacry")})
        elif malware == "redline":
            return jsonify({"ok": True, "data": _build_payload(DEMO_REDLINE_REPORT, DEMO_REDLINE_IOC, source="demo:redline")})
        else:
            return jsonify({"ok": True, "data": _build_payload(DEMO_REPORT, DEMO_IOC, source="demo:emotet")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
def analyze():
    body    = request.get_json(force=True) or {}
    api_key = body.get("api_key", "").strip()
    task_id = body.get("task_id", "").strip()
    force_analyze = bool(body.get("force_analyze", False))
    if not api_key:
        return jsonify({"ok": False, "error": "Thiếu API key"}), 400
    if not task_id:
        return jsonify({"ok": False, "error": "Thiếu Task UUID"}), 400
    try:
        from anyrun_client import AnyRunClient, AnyRunAPIError
        client      = AnyRunClient(api_key)
        report_json = client.get_task_report(task_id)
        ioc_json    = client.get_task_iocs(task_id)
        return jsonify({"ok": True, "data": _build_payload(report_json, ioc_json, use_cache=not force_analyze, source="anyrun:task")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/analyze/json", methods=["POST"])
def analyze_json_upload():
    """Free-account workflow: import JSON/Markdown exported manually from Any.Run."""
    try:
        supplemental_text = request.form.get("supplemental_text", "")
        force_analyze = request.form.get("force_analyze", "").lower() in ("1", "true", "yes")
        report_json = _load_report_upload("report_file", supplemental_text)
        ioc_json = _load_json_upload("ioc_file", required=False)
        return jsonify({"ok": True, "data": _build_payload(report_json, ioc_json, use_cache=not force_analyze, source="import")})
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
                payload  = _build_payload(report, ioc_json, source="anyrun:submit")
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

@app.route("/api/history/local", methods=["GET"])
def local_history():
    """Local app history: analyses already parsed by this tool."""
    items = []
    for item in load_local_history():
        clean = {k: v for k, v in item.items() if k != "payload"}
        items.append(clean)
    return jsonify({"ok": True, "items": items})

@app.route("/api/history/local/latest", methods=["GET"])
def local_history_latest():
    """Return the newest local analysis payload so the UI can survive reloads."""
    for item in load_local_history():
        payload = item.get("payload")
        if payload:
            return jsonify({"ok": True, "data": payload})
    return jsonify({"ok": False, "error": "Chua co lich su phan tich"}), 404

@app.route("/api/history/local/save", methods=["POST"])
def local_history_save():
    """Persist a browser-restored analysis payload into local backend history."""
    body = request.get_json(force=True) or {}
    data = body.get("data") or {}
    source = body.get("source") or "browser"
    if not data:
        return jsonify({"ok": False, "error": "Chua co du lieu phan tich"}), 400
    try:
        entry = record_analysis(data, source=source)
        clean = {k: v for k, v in entry.items() if k != "payload"}
        return jsonify({"ok": True, "item": clean})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/history/local/<path:item_id>", methods=["GET"])
def local_history_item(item_id):
    for item in load_local_history():
        if item.get("id") == item_id:
            payload = item.get("payload")
            if payload:
                return jsonify({"ok": True, "data": payload})
    return jsonify({"ok": False, "error": "Khong tim thay muc lich su"}), 404

@app.route("/api/ai/remediation", methods=["POST"])
def ai_remediation():
    body = request.get_json(force=True) or {}
    question = body.get("question", "")
    data = body.get("data") or {}
    if not data:
        return jsonify({"ok": False, "error": "Chua co du lieu phan tich"}), 400
    try:
        return jsonify({"ok": True, **answer_remediation(question, data)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

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

def _ensure_malware_analysis(data: dict) -> dict:
    existing = data.get("malware_analysis")
    if existing:
        return existing

    threat = data.get("threat", {}) or {}
    file_info = data.get("file") or {}
    network = data.get("network", {}) or {}
    processes = data.get("processes", {}) or {}
    mitre = threat.get("mitre", []) or []
    technique_ids = {str(item.get("id", "")).upper() for item in mitre if item.get("id")}

    proc_names = ", ".join(
        item.get("name", "")
        for item in (processes.get("list", []) or [])[:5]
        if item.get("name")
    )
    behavior = []
    if any(t.startswith("T1566") for t in technique_ids):
        behavior.append("Dấu hiệu truy cập ban đầu là phishing/attachment theo MITRE T1566; cần đối chiếu email gateway để tìm thư đã phát tán mẫu.")
    if any(t.startswith(("T1059", "T1204")) for t in technique_ids):
        behavior.append(f"Sau khi được kích hoạt, mẫu thực thi lệnh hoặc script trên Windows; process liên quan quan sát được: {proc_names or 'chưa đủ dữ liệu process'}.")
    injected = processes.get("injected", []) or []
    if injected or any(t.startswith("T1055") for t in technique_ids):
        behavior.append(f"Mã độc có dấu hiệu process injection vào {', '.join(injected[:5]) or 'process hợp lệ của Windows'}, giúp che giấu hành vi dưới tiến trình tin cậy.")
    if any(t.startswith("T1547") for t in technique_ids) or processes.get("registry"):
        behavior.append(f"Cơ chế duy trì hiện diện được thể hiện qua {len(processes.get('registry', []) or [])} registry key/autostart artifact.")
    if network.get("ips") or network.get("domains") or network.get("urls"):
        behavior.append(f"Mẫu có hoạt động C2/tải payload qua mạng: {len(network.get('ips', []) or [])} IP, {len(network.get('domains', []) or [])} domain và {len(network.get('urls', []) or [])} URL được ghi nhận.")
    if any(t.startswith("T1486") for t in technique_ids):
        behavior.append("Có hành vi ransomware/mã hóa dữ liệu; ưu tiên cô lập máy và bảo vệ backup offline trước khi phục hồi.")
    if not behavior:
        behavior.append("Báo cáo Any.Run chưa đủ tín hiệu để dựng toàn bộ chuỗi hành vi; phần dưới liệt kê các IOC và artifact đã quan sát được.")

    spread = []
    filename = file_info.get("name", "")
    if any(t.startswith("T1566") for t in technique_ids):
        spread.append("Vector lây nhiễm ban đầu nhiều khả năng là email phishing có đính kèm hoặc liên kết độc hại.")
    if filename and any(ext in filename.lower() for ext in (".doc", ".docm", ".xls", ".xlsm", ".rtf")):
        spread.append(f"File đầu vào `{filename}` là tài liệu Office/RTF, phù hợp kịch bản người dùng mở file rồi macro/script tải payload kế tiếp.")
    if any(t.startswith(("T1210", "T1021", "T1133")) for t in technique_ids):
        spread.append("Có dấu hiệu lateral movement/remote service; cần săn tìm host khác có cùng IOC trong log nội bộ.")
    joined_net = " ".join((network.get("urls", []) or []) + (network.get("domains", []) or [])).lower()
    if any(ind in joined_net for ind in ("payload", "download", "update", "cdn")):
        spread.append("Các URL/domain có mẫu tên như payload/update/cdn cho thấy malware có thể tải stage tiếp theo từ hạ tầng ngoài.")
    if not spread:
        spread.append("Chưa thấy bằng chứng tự lây lan rõ ràng trong dữ liệu sandbox; cần kiểm tra email, proxy, SMB, VPN và EDR để xác định phạm vi thật.")

    rows = []
    if file_info:
        rows.append({
            "role": "Mẫu đầu vào",
            "name": file_info.get("name", ""),
            "sha256": file_info.get("sha256", ""),
            "type": file_info.get("type", ""),
        })
    for item in processes.get("dropped", []) or []:
        rows.append({
            "role": "File được drop/tạo mới",
            "name": item.get("name", ""),
            "sha256": item.get("sha256", ""),
            "type": item.get("type", ""),
        })

    origin = []
    if file_info:
        origin.append(f"Nguồn quan sát trực tiếp là mẫu được gửi vào sandbox: `{file_info.get('name', '')}` ({file_info.get('type', '') or 'chưa rõ loại file'}), SHA256 `{file_info.get('sha256', '') or 'N/A'}`.")
    if network.get("urls"):
        origin.append(f"Hạ tầng liên quan gồm các URL đầu tiên: {', '.join(f'`{u}`' for u in network.get('urls', [])[:3])}.")
    if network.get("domains"):
        origin.append(f"Domain liên quan: {', '.join(f'`{d}`' for d in network.get('domains', [])[:5])}. Cần tra WHOIS/passive DNS/threat intel để xác định chủ thể vận hành.")
    origin.append("Lưu ý: sandbox chỉ chứng minh nguồn/hạ tầng quan sát được trong phiên chạy, không đủ để quy kết quốc gia hoặc nhóm APT nếu thiếu threat intelligence độc lập.")

    return {
        "behavior": behavior,
        "spread": spread,
        "affected_files": rows,
        "origin": origin,
    }

def _write_markdown(data: dict, path: str):
    import datetime
    t = data.get("threat", {})
    f = data.get("file") or {}
    p = data.get("playbook", {})
    ma = _ensure_malware_analysis(data)
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
    lines += [
        "",
        "## Phân tích chi tiết mã độc",
        "",
        "### Cách mã độc hoạt động",
        *[f"- {item}" for item in ma.get("behavior", [])],
        "",
        "### Cách lây lan / vector xâm nhập",
        *[f"- {item}" for item in ma.get("spread", [])],
        "",
        "### File bị nhiễm hoặc bị tạo/drop",
        "",
        "| Vai trò | File | SHA256 | Loại |",
        "|---|---|---|---|",
        *[
            f"| {row.get('role','')} | `{row.get('name','')}` | `{row.get('sha256','') or 'N/A'}` | {row.get('type','') or 'N/A'} |"
            for row in ma.get("affected_files", [])
        ],
        "",
        "### Nguồn gốc và hạ tầng liên quan",
        *[f"- {item}" for item in ma.get("origin", [])],
        "",
    ]
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
