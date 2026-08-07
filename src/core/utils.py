"""
Lab 11 — Helper Utilities
"""
import asyncio
import os
import time

from google.genai import types

# ---------------------------------------------------------------------------
# Điều tiết nhịp gọi model
#
# Gói free của Gemini giới hạn theo SỐ REQUEST MỖI PHÚT. Bộ test bắn hơn 20
# lượt gọi liên tiếp trong vài giây nên chạm trần ngay, và khi đó retry cũng
# chỉ chữa cháy: mỗi lần thử lại vẫn tính vào hạn mức.
#
# Cách đúng là giãn nhịp NGAY TỪ ĐẦU: giữ khoảng cách tối thiểu giữa hai lượt
# gọi để tốc độ nằm dưới trần. Chậm hơn vài chục giây nhưng chạy trọn bộ, còn
# hơn nhanh mà mất sạch bằng chứng.
#
# Chỉnh qua biến môi trường LLM_MIN_INTERVAL_SECONDS nếu bạn có gói trả phí.
# ---------------------------------------------------------------------------
_DEFAULT_INTERVAL = (
    "0.5" if os.environ.get("LLM_PROVIDER", "").strip().lower() == "openai"
    else "4.5"
)  # OpenAI trả phí có trần cao hơn nhiều nên không cần giãn như Gemini free
MIN_CALL_INTERVAL = float(
    os.environ.get("LLM_MIN_INTERVAL_SECONDS", _DEFAULT_INTERVAL)
)
_throttle_lock = asyncio.Lock()
_last_call_ts = 0.0


async def _throttle():
    """Chờ đủ MIN_CALL_INTERVAL kể từ lượt gọi trước (dùng chung toàn tiến trình)."""
    global _last_call_ts
    async with _throttle_lock:
        wait = MIN_CALL_INTERVAL - (time.monotonic() - _last_call_ts)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_call_ts = time.monotonic()


def is_rate_limited(exc: Exception) -> bool:
    """Nhận diện lỗi 429 / RESOURCE_EXHAUSTED của Gemini.

    Bắt theo tên lớp lẫn nội dung message vì SDK gói lỗi qua nhiều tầng và tên
    lớp cụ thể (_ResourceExhaustedError) là chi tiết nội bộ, có thể đổi.
    """
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    return (
        "resourceexhausted" in name
        or "429" in text
        or "resource_exhausted" in text
        or "quota" in text
        or "rate limit" in text
    )


async def call_with_retry(make_coro, *, attempts: int = 4, base_delay: float = 4.0,
                          label: str = "llm"):
    """Gọi một coroutine, lùi theo cấp số nhân khi bị rate limit.

    Vì sao cần: bộ test bắn hơn 10 lượt gọi trong vài giây nên chạm trần RPM
    của gói free. Không có retry thì cả bộ bằng chứng biến thành
    "[llm error]" — bài vẫn chạy xong nhưng mất sạch nội dung để chấm.

    ``make_coro`` là một callable trả về coroutine MỚI mỗi lần gọi; không nhận
    thẳng coroutine vì một coroutine đã await thì không await lại được.
    """
    delay = base_delay
    last = None
    for attempt in range(1, attempts + 1):
        try:
            return await make_coro()
        except Exception as e:
            last = e
            if not is_rate_limited(e) or attempt == attempts:
                raise
            print(f"    [{label}] rate limited, chờ {delay:.0f}s rồi thử lại "
                  f"({attempt}/{attempts - 1})")
            await asyncio.sleep(delay)
            delay *= 2
    raise last


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to the agent and get the response.

    Args:
        agent: The LlmAgent instance
        runner: The InMemoryRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation

    Returns:
        Tuple of (response_text, session)
    """
    await _throttle()  # giữ nhịp dưới trần RPM trước khi chạm tới model

    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session
