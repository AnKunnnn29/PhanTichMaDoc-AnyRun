"""
anyrun_client.py
~~~~~~~~~~~~~~~~
Client wrapper cho Any.Run Sandbox API v1.
Tài liệu: https://api.any.run/
"""

import time
import requests
from typing import Optional


class AnyRunAPIError(Exception):
    """Exception cơ sở cho Any.Run API errors."""
    pass


class AnyRunAuthError(AnyRunAPIError):
    """Lỗi xác thực (401/403)."""
    pass


class AnyRunNotFoundError(AnyRunAPIError):
    """Task/resource không tìm thấy (404)."""
    pass


class AnyRunRateLimitError(AnyRunAPIError):
    """Vượt quá rate limit (429)."""
    pass


class AnyRunClient:
    """
    Client tương tác với Any.Run Sandbox REST API.

    Ví dụ sử dụng:
        client = AnyRunClient(api_key="YOUR_KEY")
        report  = client.get_task_report("task-uuid-here")
        iocs    = client.get_task_iocs("task-uuid-here")
    """

    BASE_URL = "https://api.any.run/v1"

    def __init__(self, api_key: str, timeout: int = 30):
        if not api_key or api_key == "your_api_key_here":
            raise AnyRunAuthError(
                "API key không hợp lệ. Vui lòng cung cấp API key từ app.any.run"
            )
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"API-Key {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        try:
            resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.ConnectionError as exc:
            raise AnyRunAPIError(f"Không kết nối được tới Any.Run API: {exc}") from exc
        except requests.Timeout:
            raise AnyRunAPIError("Any.Run API timeout sau khi chờ quá lâu.")

        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 401:
            raise AnyRunAuthError("API key không hợp lệ hoặc đã hết hạn (401).")
        elif resp.status_code == 403:
            raise AnyRunAuthError("Không có quyền truy cập tài nguyên này (403).")
        elif resp.status_code == 404:
            raise AnyRunNotFoundError(f"Không tìm thấy task/resource tại {url} (404).")
        elif resp.status_code == 429:
            raise AnyRunRateLimitError(
                "Vượt quá giới hạn tốc độ API. Vui lòng chờ và thử lại (429)."
            )
        else:
            raise AnyRunAPIError(
                f"Lỗi HTTP {resp.status_code}: {resp.text[:300]}"
            )

    # ------------------------------------------------------------------ #
    # Public API methods                                                   #
    # ------------------------------------------------------------------ #

    def get_task_report(self, task_uuid: str) -> dict:
        """
        Lấy báo cáo phân tích đầy đủ cho một task.
        GET /report/{taskUuid}/summary/json
        """
        return self._request("GET", f"/report/{task_uuid}/summary/json")

    def get_task_iocs(self, task_uuid: str) -> dict:
        """
        Lấy danh sách Indicators of Compromise (IOC).
        GET /report/{taskUuid}/ioc/json
        """
        return self._request("GET", f"/report/{task_uuid}/ioc/json")

    def get_history(self, team: bool = False, skip: int = 0, limit: int = 25) -> dict:
        """
        Lấy lịch sử phân tích của tài khoản.
        GET /analysis
        """
        params = {"team": str(team).lower(), "skip": skip, "limit": limit}
        return self._request("GET", "/analysis", params=params)

    def submit_url(
        self,
        url: str,
        os: str = "windows10x64_office",
        privacy_type: int = 1,
        timeout_seconds: int = 60,
        network: str = "default",
    ) -> dict:
        """
        Gửi URL để phân tích.
        POST /analysis
        """
        payload = {
            "obj_type": "url",
            "obj_url": url,
            "env_os": os,
            "opt_privacy_type": privacy_type,
            "opt_timeout": timeout_seconds,
            "opt_network_connect": network,
        }
        return self._request("POST", "/analysis", json=payload)

    def submit_file(
        self,
        file_path: str,
        os: str = "windows10x64_office",
        privacy_type: int = 1,
        timeout_seconds: int = 60,
    ) -> dict:
        """
        Gửi file để phân tích sandbox.
        POST /analysis (multipart)
        """
        import os as _os
        if not _os.path.isfile(file_path):
            raise FileNotFoundError(f"File không tồn tại: {file_path}")
        # Tạo bản sao headers không có Content-Type để requests tự set boundary
        headers = {k: v for k, v in self.session.headers.items() if k != "Content-Type"}
        with open(file_path, "rb") as fh:
            files = {"file": (_os.path.basename(file_path), fh)}
            data = {
                "obj_type": "file",
                "env_os": os,
                "opt_privacy_type": str(privacy_type),
                "opt_timeout": str(timeout_seconds),
            }
            url = f"{self.BASE_URL}/analysis"
            resp = self.session.post(
                url, headers=headers, files=files, data=data,
                timeout=self.timeout
            )
        if resp.status_code == 200:
            return resp.json()
        raise AnyRunAPIError(f"Lỗi submit file {resp.status_code}: {resp.text[:300]}")

    def wait_for_task(
        self,
        task_uuid: str,
        poll_interval: int = 10,
        max_wait: int = 300,
    ) -> dict:
        """
        Chờ đến khi task hoàn thành rồi trả về report.
        """
        elapsed = 0
        while elapsed < max_wait:
            try:
                report = self.get_task_report(task_uuid)
                status = (
                    report.get("data", {})
                    .get("analysis", {})
                    .get("status", "")
                )
                if status in ("done", "failed"):
                    return report
            except AnyRunNotFoundError:
                pass  # Task chưa sẵn sàng
            time.sleep(poll_interval)
            elapsed += poll_interval
        raise TimeoutError(
            f"Task {task_uuid} không hoàn thành sau {max_wait}s"
        )
