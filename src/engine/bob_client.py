"""
IBM Bob Inference Client
------------------------
Thin, dependency-free HTTP wrapper around the IBM Bob inference API
(OpenAI-compatible /v1/chat/completions endpoint).

Credentials are read exclusively from environment variables — never hardcoded.

Environment variables (set in .env at repo root or in the OS environment):
    BOB_INFERENCE_API_KEY  — Inference-scoped API key from bob.ibm.com
    BOB_INFERENCE_URL      — Optional override; defaults to us-east gateway
    BOB_MODEL              — Optional model name override; defaults to "fast"

Usage
-----
    from engine.bob_client import BobClient, BobUnavailable

    client = BobClient()
    if client.available:
        text = client.chat("Explain this incident …", max_tokens=400)
    else:
        text = None   # graceful fallback — caller renders template BLUF
"""

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Defaults ─────────────────────────────────────────────────────────────────
_DEFAULT_URL = "https://api.us-east.bob.ibm.com/inference/v1"
_DEFAULT_MODEL = "fast"
_TIMEOUT = 30          # seconds per request
_MAX_RETRIES = 1       # one retry on 5xx


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader — no external dependencies."""
    if not path.exists():
        return
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip())


# Load .env from repo root (two levels up from this file: src/engine/ → src/ → repo/)
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_load_dotenv(_REPO_ROOT / ".env")


class BobUnavailable(Exception):
    """Raised when the Bob API key is absent or the API cannot be reached."""


class BobClient:
    """
    Stateless client for the IBM Bob inference API.

    Instantiation is cheap — create one per Streamlit session via
    ``@st.cache_resource``.

    Attributes
    ----------
    available : bool
        True when BOB_INFERENCE_API_KEY is set and the API is reachable.
    model : str
        Active model name sent in every request.
    """

    def __init__(self) -> None:
        self._api_key: str = os.environ.get("BOB_INFERENCE_API_KEY", "").strip()
        self._base_url: str = os.environ.get(
            "BOB_INFERENCE_URL", _DEFAULT_URL
        ).rstrip("/")
        self.model: str = os.environ.get("BOB_MODEL", _DEFAULT_MODEL)
        self.available: bool = bool(self._api_key)

        if not self.available:
            logger.warning(
                "BOB_INFERENCE_API_KEY not set — Bob AI layer disabled. "
                "Dashboard will use template-based BLUF."
            )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            # Bob inference API uses X-API-Key, not Bearer Authorization
            "X-API-Key": self._api_key,
            "User-Agent": "IBM Bob/1.126.0+bob2.1.0",
        }

    def _post(self, payload: dict, attempt: int = 0) -> dict:
        """POST to /chat/completions, return parsed JSON response dict."""
        url = f"{self._base_url}/chat/completions"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers=self._headers(), method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = ""
            if exc.fp:
                try:
                    body = exc.fp.read().decode("utf-8", errors="replace")[:400]
                except Exception:
                    pass
            # Retry once on 5xx
            if exc.code >= 500 and attempt < _MAX_RETRIES:
                logger.warning("Bob API %d — retrying. Body: %s", exc.code, body)
                return self._post(payload, attempt + 1)
            raise BobUnavailable(
                f"Bob API returned HTTP {exc.code}: {body}"
            ) from exc
        except OSError as exc:
            raise BobUnavailable(f"Bob API network error: {exc}") from exc

    # ── Public API ────────────────────────────────────────────────────────────

    def chat(
        self,
        prompt: str,
        *,
        system: str = "You are a cybersecurity intelligence analyst assistant.",
        max_tokens: int = 600,
        temperature: float = 0.2,
    ) -> str:
        """
        Send a single-turn chat prompt and return the text response.

        Parameters
        ----------
        prompt : str
            User message — must be grounded in actual incident data by the caller.
        system : str
            System persona instruction.
        max_tokens : int
            Maximum response tokens.
        temperature : float
            Sampling temperature (0 = deterministic).

        Returns
        -------
        str
            The model's reply text.

        Raises
        ------
        BobUnavailable
            When the client is not configured or the API call fails.
        """
        if not self.available:
            raise BobUnavailable("BOB_INFERENCE_API_KEY not configured.")

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        logger.debug("Bob request: model=%s max_tokens=%d", self.model, max_tokens)
        response = self._post(payload)

        try:
            text = response["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BobUnavailable(
                f"Unexpected Bob API response format: {response}"
            ) from exc

        logger.debug("Bob response length: %d chars", len(text))
        return text.strip()

    def chat_safe(
        self,
        prompt: str,
        fallback: str = "",
        **kwargs,
    ) -> tuple[str, bool]:
        """
        Like ``chat()`` but catches all errors and returns (text, ok).

        Returns
        -------
        (text, True)  on success
        (fallback, False) on any error — caller can render template BLUF instead
        """
        try:
            return self.chat(prompt, **kwargs), True
        except BobUnavailable as exc:
            logger.warning("Bob unavailable: %s", exc)
            return fallback, False
        except Exception as exc:  # noqa: BLE001
            logger.error("Bob unexpected error: %s", exc)
            return fallback, False


# Module-level singleton (one per Python process / Streamlit session)
_client: Optional[BobClient] = None


def get_bob_client() -> BobClient:
    """Return the process-level BobClient singleton."""
    global _client
    if _client is None:
        _client = BobClient()
    return _client
