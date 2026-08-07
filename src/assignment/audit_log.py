"""
Assignment 11 — Audit Log.
  Tương ứng assignment11.md §4.4 — correlation ID xuyên suốt input/output.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.

Bốn câu hỏi mà một bản ghi phải trả lời được:
  1. Request nào bị block?          -> blocked
  2. Bị block ở layer nào?          -> layer (+ pattern)
  3. Latency bao lâu?               -> latency_ms
  4. Reviewer/action decision là gì? -> reviewer_id, approval_id, action_*

Nguyên tắc bất di bất dịch: KHÔNG ghi secret hay PII thô vào log.
Log là thứ bị copy đi xa nhất (ship sang SIEM, dump ra file, gửi cho support),
nên một API key lọt vào đây còn nguy hiểm hơn lọt vào một câu trả lời. Vì vậy
mọi text đều đi qua content_filter trước khi lưu — dùng lại đúng bộ lọc đã bảo
vệ response và egress, để ba nơi không bao giờ lệch định nghĩa "nhạy cảm".
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from guardrails.output_guardrails import content_filter

MAX_TEXT_PREVIEW = 300


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_request_id() -> str:
    """Correlation ID cho một request, dùng chung từ input tới output/action."""
    return "REQ-" + uuid.uuid4().hex[:12].upper()


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline).

    Vòng đời: record_input() mở một request và trả về request_id; record_output()
    đóng lại đúng request đó và tính latency. Request chưa đóng vẫn được export
    với status "incomplete" — một request biến mất giữa chừng chính là dấu hiệu
    sự cố, giấu đi thì mất luôn manh mối.
    """

    def __init__(self, redact: bool = True):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}
        self.redact = redact

    # ---------------------------------------------------------------- helpers
    def _safe_text(self, text: str) -> tuple[str, list]:
        """Trả về (text đã redact, danh sách loại vấn đề tìm thấy)."""
        raw = text or ""
        if not self.redact:
            return raw[:MAX_TEXT_PREVIEW], []
        verdict = content_filter(raw)
        # Chỉ giữ TÊN loại vấn đề ("api_key"), không giữ giá trị khớp được.
        issue_types = [i.split(":")[0].strip() for i in verdict["issues"]]
        return verdict["redacted"][:MAX_TEXT_PREVIEW], issue_types

    # ------------------------------------------------------------------ input
    def record_input(self, *, user_id: str, text: str, request_id: str | None = None) -> str:
        """Mở một request và ghi mốc thời gian bắt đầu.

        Returns:
            request_id — truyền tiếp cho record_output để nối hai đầu.
        """
        request_id = request_id or new_request_id()
        preview, issues = self._safe_text(text)
        self._open[request_id] = {
            "request_id": request_id,
            "user_id": user_id,
            "input_preview": preview,
            "input_issues": issues,
            "input_chars": len(text or ""),
            "started_at": utc_now_iso(),
            "_start_ts": time.perf_counter(),
        }
        return request_id

    # ----------------------------------------------------------------- output
    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        pattern: str | None = None,
        judge_verdict: str | None = None,
        reviewer_id: str | None = None,
        approval_id: str | None = None,
        action: str | None = None,
        action_allowed: bool | None = None,
        destination: str | None = None,
    ) -> dict:
        """Đóng request, tính latency và ghi quyết định của từng lớp.

        Các tham số sau ``request_id`` đều tuỳ chọn: một request chỉ hỏi đáp
        thông thường thì không có reviewer, còn một lệnh chuyển tiền thì có đủ
        reviewer_id/approval_id/action_allowed.
        """
        opened = self._open.pop(request_id, None) if request_id else None
        if opened is None:
            # Không tìm thấy đầu vào tương ứng: vẫn ghi, nhưng đánh dấu rõ để
            # người điều tra biết bản ghi này thiếu nửa đầu.
            opened = {
                "request_id": request_id or new_request_id(),
                "user_id": user_id,
                "input_preview": None,
                "input_issues": [],
                "input_chars": 0,
                "started_at": None,
                "_start_ts": None,
                "orphan_output": True,
            }

        start_ts = opened.pop("_start_ts", None)
        latency_ms = round((time.perf_counter() - start_ts) * 1000, 2) if start_ts else None

        preview, issues = self._safe_text(text)
        entry = {
            **opened,
            "finished_at": utc_now_iso(),
            "latency_ms": latency_ms,
            "output_preview": preview,
            "output_issues": issues,
            "blocked": bool(blocked),
            "layer": layer,
            "pattern": pattern,
            "judge_verdict": judge_verdict,
            "reviewer_id": reviewer_id,
            "approval_id": approval_id,
            "action": action,
            "action_allowed": action_allowed,
            "destination": destination,
            "status": "complete",
        }
        self.logs.append(entry)
        return entry

    # ------------------------------------------------------------- điều tra
    def trace(self, request_id: str) -> dict | None:
        """Lấy toàn bộ vòng đời của một request theo correlation ID."""
        for entry in self.logs:
            if entry.get("request_id") == request_id:
                return entry
        pending = self._open.get(request_id)
        return {**pending, "status": "incomplete"} if pending else None

    def blocked_records(self) -> list[dict]:
        """Các request bị chặn — câu hỏi số 1 của checkpoint."""
        return [e for e in self.logs if e.get("blocked")]

    def by_layer(self) -> dict[str, int]:
        """Đếm số lần chặn theo layer — câu hỏi số 2."""
        counts: dict[str, int] = {}
        for e in self.blocked_records():
            key = e.get("layer") or "unknown"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def latency_stats(self) -> dict:
        """Thống kê latency — câu hỏi số 3."""
        values = [e["latency_ms"] for e in self.logs if e.get("latency_ms") is not None]
        if not values:
            return {"count": 0, "avg_ms": None, "max_ms": None, "min_ms": None}
        return {
            "count": len(values),
            "avg_ms": round(sum(values) / len(values), 2),
            "max_ms": max(values),
            "min_ms": min(values),
        }

    def summary(self) -> dict:
        return {
            "total": len(self.logs),
            "blocked": len(self.blocked_records()),
            "incomplete": len(self._open),
            "by_layer": self.by_layer(),
            "latency": self.latency_stats(),
            "with_reviewer": sum(1 for e in self.logs if e.get("reviewer_id")),
        }

    # ------------------------------------------------------------------ export
    def export_json(self, filepath: str = "outputs/audit_log.json") -> Path:
        """Write logs to disk (JSON array).

        Kèm cả request chưa đóng, đánh dấu status="incomplete": một request treo
        giữa chừng là bằng chứng sự cố, không được im lặng bỏ qua.
        """
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        rows = list(self.logs)
        for pending in self._open.values():
            row = {k: v for k, v in pending.items() if not k.startswith("_")}
            row.update({"status": "incomplete", "blocked": False, "layer": None})
            rows.append(row)

        path.write_text(
            json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path
