"""
Assignment 11 — Rate Limiter (đã hoàn thành).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow.

        Sliding window thay vì fixed window: fixed window cho phép dồn 2×limit
        quanh mốc reset (10 request cuối phút này + 10 request đầu phút sau).
        Sliding window đo đúng "N request gần nhất trong W giây" nên không có
        khe hở đó.

        Đây là lớp ĐẦU TIÊN vì nó rẻ nhất — chặn được flooding trước khi tốn
        bất kỳ regex hay token LLM nào. Nó cũng là lớp duy nhất chặn được kiểu
        tấn công mà từng request đều hợp lệ, chỉ có số lượng là bất thường
        (dò brute-force, đốt quota).
        """
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # 1) Bỏ các mốc đã trôi ra khỏi cửa sổ. deque cho phép popleft O(1),
        #    nên chi phí không phụ thuộc lịch sử dài bao nhiêu.
        cutoff = now - self.window_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        # 2) Đủ hạn mức -> chặn, và nói rõ còn bao lâu để client lùi đúng nhịp
        #    thay vì thử lại liên tục.
        if len(window) >= self.max_requests:
            wait = self.window_seconds - (now - window[0])
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Try again in {wait:.0f}s."
            )

        # 3) Còn chỗ -> ghi nhận và cho qua.
        window.append(now)
        return None

    def snapshot(self) -> dict:
        """Số liệu cho monitoring / results.json."""
        return {
            "max_requests": self.max_requests,
            "window_seconds": self.window_seconds,
            "sent": self.total_count,
            "passed": self.total_count - self.blocked_count,
            "blocked": self.blocked_count,
        }
