"""
Assignment 11 — Monitoring & Alerts.
  Tương ứng assignment11.md §4.4 — alert block-rate / rate-limit / judge-fail.

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.

Vì sao ba chỉ số này, không phải chỉ đếm số lần chặn:
  - block rate tăng vọt = đang có người dò tìm có hệ thống, HOẶC guardrail vừa
    bị chỉnh tay quá chặt và đang chặn nhầm khách thật. Cả hai đều cần người
    xem ngay, và đó là lý do alert phải nói rõ giá trị lẫn ngưỡng để phân biệt.
  - rate-limit hits = tấn công theo khối lượng (flooding, dò brute-force).
  - judge fail rate = model đang trả lời sai/lệch chủ đề một cách có hệ thống;
    regex không thấy gì vì đây là lỗi ngữ nghĩa, không phải chuỗi cấm.

Snapshot phải REPLAY được: cùng bộ counter phải cho ra cùng bộ alert, để lúc
điều tra sự cố ta dựng lại đúng trạng thái monitoring tại thời điểm đó thay vì
đoán từ trí nhớ.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    # ---------------------------------------------------------------- counters
    def record_request(
        self,
        *,
        blocked: bool = False,
        layer: str | None = None,
        judged: bool = False,
        judge_failed: bool = False,
    ) -> None:
        """Cập nhật counter sau mỗi request. Gọi từ pipeline, một lần/request.

        Gom vào một chỗ thay vì để pipeline tự cộng từng biến: đếm rời rạc là
        cách nhanh nhất để block_rate lệch khỏi thực tế mà không ai phát hiện.
        """
        self.total_requests += 1
        if blocked:
            self.blocked_requests += 1
        if layer == "rate_limiter":
            self.rate_limit_hits += 1
        if judged:
            self.judge_checks += 1
            if judge_failed:
                self.judge_fails += 1

    # ------------------------------------------------------------------ alerts
    def check_metrics(self) -> list[Alert]:
        """Tính lại tỷ lệ và phát alert khi vượt ngưỡng.

        Xoá alert cũ ở đầu mỗi lần gọi để hàm này idempotent: gọi hai lần liên
        tiếp phải ra cùng kết quả, không nhân đôi cảnh báo. Nhờ vậy nó dùng
        được cả cho giám sát định kỳ lẫn cho replay một snapshot cũ.
        """
        self.alerts = []

        block_rate = (
            self.blocked_requests / self.total_requests if self.total_requests else 0.0
        )
        if block_rate > self.block_rate_threshold:
            self.alerts.append(
                Alert(
                    metric="block_rate",
                    value=round(block_rate, 4),
                    threshold=self.block_rate_threshold,
                    message=(
                        f"Block rate {block_rate:.0%} vượt ngưỡng "
                        f"{self.block_rate_threshold:.0%} "
                        f"({self.blocked_requests}/{self.total_requests} request). "
                        "Khả năng đang bị dò tìm có hệ thống, hoặc guardrail vừa "
                        "bị siết quá tay và đang chặn nhầm khách thật."
                    ),
                )
            )

        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            self.alerts.append(
                Alert(
                    metric="rate_limit_hits",
                    value=self.rate_limit_hits,
                    threshold=self.rate_limit_hit_threshold,
                    message=(
                        f"Rate limiter chặn {self.rate_limit_hits} lần, vượt ngưỡng "
                        f"{self.rate_limit_hit_threshold}. Dấu hiệu flooding hoặc "
                        "dò brute-force từ một nhóm nhỏ user."
                    ),
                )
            )

        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        if judge_fail_rate > self.judge_fail_rate_threshold:
            self.alerts.append(
                Alert(
                    metric="judge_fail_rate",
                    value=round(judge_fail_rate, 4),
                    threshold=self.judge_fail_rate_threshold,
                    message=(
                        f"Judge đánh trượt {judge_fail_rate:.0%} "
                        f"({self.judge_fails}/{self.judge_checks}), vượt ngưỡng "
                        f"{self.judge_fail_rate_threshold:.0%}. Lỗi ngữ nghĩa — "
                        "model trả lời sai/lệch chủ đề mà regex không nhìn thấy."
                    ),
                )
            )

        return self.alerts

    # ------------------------------------------------------------------ replay
    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            # Ngưỡng đi kèm counter, nếu không thì replay sau này sẽ dùng ngưỡng
            # hiện hành chứ không phải ngưỡng lúc sự cố xảy ra.
            "thresholds": {
                "block_rate": self.block_rate_threshold,
                "rate_limit_hits": self.rate_limit_hit_threshold,
                "judge_fail_rate": self.judge_fail_rate_threshold,
            },
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }

    @classmethod
    def from_snapshot(cls, data: dict) -> "MonitoringAlert":
        """Dựng lại trạng thái monitoring từ một snapshot đã lưu.

        Đây là phần "incident replay": mở metrics.json của lúc sự cố, dựng lại
        đúng counter VÀ đúng ngưỡng, chạy check_metrics() rồi đối chiếu với
        alert đã ghi. Nếu khớp thì kết luận điều tra đứng vững; nếu lệch thì
        ngưỡng đã bị đổi giữa chừng — bản thân điều đó cũng là phát hiện.
        """
        thresholds = data.get("thresholds", {})
        monitor = cls(
            block_rate_threshold=thresholds.get("block_rate", 0.5),
            rate_limit_hit_threshold=thresholds.get("rate_limit_hits", 5),
            judge_fail_rate_threshold=thresholds.get("judge_fail_rate", 0.3),
            total_requests=data.get("total_requests", 0),
            blocked_requests=data.get("blocked_requests", 0),
            rate_limit_hits=data.get("rate_limit_hits", 0),
            judge_checks=data.get("judge_checks", 0),
            judge_fails=data.get("judge_fails", 0),
        )
        monitor.check_metrics()
        return monitor

    # ------------------------------------------------------------------ export
    def export_json(self, filepath: str = "outputs/metrics.json") -> Path:
        """Write metrics + alerts to JSON.

        Luôn chạy check_metrics() trước khi ghi, để file trên đĩa không bao giờ
        chứa counter mới kèm alert cũ.
        """
        self.check_metrics()
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path


def replay_snapshot(source: str | Path | dict) -> dict:
    """Replay một snapshot (đường dẫn metrics.json hoặc dict) và trả kết quả đối chiếu.

    Returns:
        dict: {"recomputed_alerts", "recorded_alerts", "matches"}
    """
    if isinstance(source, (str, Path)):
        data = json.loads(Path(source).read_text(encoding="utf-8"))
    else:
        data = source

    monitor = MonitoringAlert.from_snapshot(data)
    recomputed = sorted(a.metric for a in monitor.alerts)
    recorded = sorted(a.get("metric") for a in data.get("alerts", []))
    return {
        "recomputed_alerts": recomputed,
        "recorded_alerts": recorded,
        "matches": recomputed == recorded,
    }
