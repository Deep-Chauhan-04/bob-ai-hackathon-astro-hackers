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
            key = key.strip()
            val = val.strip().strip("'\"")
            # Keep non-empty OS values authoritative, but recover when a
            # launcher exported the variable as an empty string.
            if key and (not os.environ.get(key, "").strip()):
                os.environ[key] = val


# Load .env from multiple candidate locations (repo root and src/).
# Non-empty OS values take priority; the first non-empty file value wins.
_REPO_ROOT = Path(__file__).resolve().parents[2]
for _env_candidate in (
    _REPO_ROOT / ".env",          # repo root  (standard)
    _REPO_ROOT / "src" / ".env",  # src/.env   (where this project keeps it)
):
    _load_dotenv(_env_candidate)


class BobUnavailable(Exception):
    """Raised when the Bob API key is absent or the API cannot be reached."""


# Connectivity diagnostic reasons surfaced to the UI
DIAG_NO_KEY = "BOB_INFERENCE_API_KEY not set in .env"
DIAG_NETWORK = (
    "Network/firewall blocked the Bob gateway (HTTP 403). "
    "This is common on corporate/campus networks. "
    "Try connecting via VPN or a hotspot, then restart the app."
)
DIAG_UNAUTH = (
    "API key rejected by Bob gateway (HTTP 401/403). "
    "Re-generate an Inference-scoped key at bob.ibm.com > Account > API Keys."
)
DIAG_UNKNOWN = "Bob API returned an unexpected error — check the logs."


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
    diag : str
        Human-readable diagnosis shown in the UI when available=False.
    """

    def __init__(self) -> None:
        self._api_key: str = os.environ.get("BOB_INFERENCE_API_KEY", "").strip()
        self._base_url: str = os.environ.get(
            "BOB_INFERENCE_URL", _DEFAULT_URL
        ).rstrip("/")
        self.model: str = os.environ.get("BOB_MODEL", _DEFAULT_MODEL)
        self.available: bool = bool(self._api_key)
        self.diag: str = "" if self._api_key else DIAG_NO_KEY

        if not self.available:
            logger.warning(
                "BOB_INFERENCE_API_KEY not set — Bob AI layer disabled. "
                "Dashboard will use template-based BLUF."
            )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _headers(self, use_bearer: bool = False) -> dict:
        auth = (
            {"Authorization": f"Bearer {self._api_key}"}
            if use_bearer
            else {"X-API-Key": self._api_key}
        )
        return {
            "Content-Type": "application/json",
            "User-Agent": "SOC-Platform/1.0",
            **auth,
        }

    def _post(self, payload: dict, attempt: int = 0) -> dict:
        """
        POST to /chat/completions. Tries X-API-Key first, then Bearer.
        Returns parsed JSON response dict.
        """
        url = f"{self._base_url}/chat/completions"
        data = json.dumps(payload).encode("utf-8")

        last_exc: Optional[Exception] = None
        for use_bearer in (False, True):   # try X-API-Key, then Bearer
            req = urllib.request.Request(
                url, data=data, headers=self._headers(use_bearer), method="POST"
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
                # 5xx — retry once with same header scheme before trying next
                if exc.code >= 500 and attempt < _MAX_RETRIES:
                    logger.warning("Bob API %d — retrying. Body: %s", exc.code, body)
                    return self._post(payload, attempt + 1)
                last_exc = exc
                logger.debug(
                    "Bob auth attempt (bearer=%s) failed HTTP %d", use_bearer, exc.code
                )
                continue
            except OSError as exc:
                raise BobUnavailable(f"Bob API network error: {exc}") from exc

        # Both header schemes failed — raise with diagnostics
        if last_exc is not None:
            code = getattr(last_exc, "code", 0)
            if code == 403 and "<!DOCTYPE" in str(last_exc):
                # Cloudflare/WAF HTML page — network block, not auth error
                raise BobUnavailable(DIAG_NETWORK) from last_exc
            if code in (401, 403):
                raise BobUnavailable(DIAG_UNAUTH) from last_exc
            raise BobUnavailable(
                f"Bob API returned HTTP {code}: {last_exc}"
            ) from last_exc
        raise BobUnavailable(DIAG_UNKNOWN)

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
    ) -> "tuple[str, bool]":
        """
        Like ``chat()`` but catches all errors and returns (text, ok).

        Returns
        -------
        (text, True)   on success — text is the model reply
        (diag, False)  on any error — diag is a human-readable reason string
                       that can be shown directly in the UI
        """
        try:
            return self.chat(prompt, **kwargs), True
        except BobUnavailable as exc:
            msg = str(exc) or fallback
            logger.warning("Bob unavailable: %s", msg)
            return msg, False
        except Exception as exc:  # noqa: BLE001
            msg = f"Unexpected error: {exc}"
            logger.error("Bob unexpected error: %s", exc)
            return msg, False


# Module-level singleton (one per Python process / Streamlit session)
_client: Optional[BobClient] = None


def get_bob_client() -> BobClient:
    """Return the process-level BobClient singleton."""
    global _client
    if _client is None:
        _client = BobClient()
    return _client
