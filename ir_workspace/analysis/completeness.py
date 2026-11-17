"""Say which parts of a sandbox report are empty, so a gap in the source is not read as a clean result.

A report can lack a section because the sample did nothing of that kind, or because the
source did not export it (a public page that loads data later, a text export without
registry events). The two cannot be told apart from the report alone, so the pipeline
states the gap instead of concluding anything from it.
"""
from __future__ import annotations


def _count(value) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def data_completeness(report: dict) -> dict:
    content = (report.get("data") or {}).get("content") or {}
    network = content.get("network") if isinstance(content.get("network"), dict) else {}
    sections = [
        ("processes", "Tiến trình", _count(content.get("processes"))),
        ("network", "Hoạt động mạng",
         sum(_count(network.get(key)) for key in ("connections", "httpRequests", "dnsRequests"))),
        ("files", "Tệp được tạo hoặc sửa", _count(content.get("dropped"))),
        ("registry", "Registry", _count(content.get("registry"))),
        ("behaviors", "Hành vi do sandbox phát hiện", _count(content.get("behaviors")) + _count(content.get("mitre"))),
    ]
    missing = [title for _, title, count in sections if not count]
    note = ""
    if missing:
        note = ("Báo cáo nguồn không có dữ liệu về: " + ", ".join(missing).lower() + ". Thiếu dữ liệu không có nghĩa "
                "là mẫu không có hành vi đó; có thể nguồn không xuất phần này. Các kết luận về phần thiếu cần được "
                "kiểm tra lại bằng báo cáo đầy đủ hơn.")
    return {"sections": [{"id": key, "title": title, "count": count} for key, title, count in sections],
            "missing": missing, "complete": not missing, "note": note}
