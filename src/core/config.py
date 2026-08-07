"""
Lab 11 — Configuration & API Key Setup

Chọn nhà cung cấp model qua biến môi trường LLM_PROVIDER ("gemini" | "openai").
Không thay cứng tên model ở từng file agent: khi một nhà cung cấp hết quota
giữa buổi làm bài, đổi một biến trong .env phải đủ để chạy tiếp, thay vì phải
sửa 5 file rồi lo sót chỗ nào.
"""
import os


def setup_api_key():
    """Load Google API key from .env / environment, or prompt as a last resort.

    Nạp .env trước: SUBMISSION.md yêu cầu key nằm trong .env chứ không commit,
    nên nếu không đọc file đó thì cách làm đúng lại là cách duy nhất không chạy
    được. STUDENT_ID cũng lấy từ đây, tránh outputs/*.json bị ghi nhầm SE00000.
    """
    try:
        from dotenv import load_dotenv
        from pathlib import Path

        # src/core/config.py -> repo root
        load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    except ImportError:
        pass  # python-dotenv không có thì vẫn dùng biến môi trường sẵn có

    if not os.environ.get("GOOGLE_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = input("Enter Google API Key: ")
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "0"
    print(f"API key loaded. STUDENT_ID={os.environ.get('STUDENT_ID', '(chưa đặt)')}")


# ============================================================
# Model factory
# ============================================================

DEFAULT_GEMINI_MODEL = "gemini-3.1-flash-lite"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"


def get_provider() -> str:
    """Nhà cung cấp đang dùng: "openai" nếu LLM_PROVIDER=openai, còn lại "gemini"."""
    return os.environ.get("LLM_PROVIDER", "gemini").strip().lower()


def get_model():
    """Trả về thứ mà LlmAgent(model=...) nhận được.

    Gemini: một chuỗi tên model — ADK tự hiểu.
    OpenAI: một đối tượng LiteLlm — ADK gọi OpenAI qua LiteLLM, nhưng phần còn
    lại của pipeline (plugin, guardrail, judge) không cần biết gì về khác biệt
    này. Đó là lý do bọc ở một chỗ duy nhất.
    """
    if get_provider() == "openai":
        model_name = os.environ.get("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip()
        try:
            from google.adk.models.lite_llm import LiteLlm
        except ImportError as e:  # pragma: no cover — phụ thuộc môi trường
            raise RuntimeError(
                "LLM_PROVIDER=openai cần gói litellm. Cài bằng: pip install litellm"
            ) from e
        if not os.environ.get("OPENAI_API_KEY"):
            raise RuntimeError("LLM_PROVIDER=openai nhưng thiếu OPENAI_API_KEY trong .env")
        return LiteLlm(model=f"openai/{model_name}")

    return os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip()


def model_label() -> str:
    """Tên model dạng chuỗi, dùng để in log và ghi vào báo cáo."""
    if get_provider() == "openai":
        return f"openai/{os.environ.get('OPENAI_MODEL', DEFAULT_OPENAI_MODEL)}"
    return os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)


# Allowed banking topics (used by topic_filter)
ALLOWED_TOPICS = [
    "banking", "account", "transaction", "transfer",
    "loan", "interest", "savings", "credit",
    "deposit", "withdrawal", "balance", "payment",
    "tai khoan", "giao dich", "tiet kiem", "lai suat",
    "chuyen tien", "the tin dung", "so du", "vay",
    "ngan hang", "atm",
]

# Blocked topics (immediate reject)
BLOCKED_TOPICS = [
    "hack", "exploit", "weapon", "drug", "illegal",
    "violence", "gambling", "bomb", "kill", "steal",
]
