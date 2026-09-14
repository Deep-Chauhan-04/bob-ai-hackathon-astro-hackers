"""
Abuse.ch URLhaus IOC Feed Integration
--------------------------------------
Downloads the URLhaus CSV feed, caches it locally, and provides fast
IP/URL/domain lookup for cross-correlation with SIEM telemetry.
"""

import csv
import gzip
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "cache"
CACHE_FILE = CACHE_DIR / "urlhaus_cache.json"
CACHE_TTL_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Embedded offline seed – a handful of well-known bad IPs/domains so the
# demo works 100% without internet access.
# ---------------------------------------------------------------------------
OFFLINE_SEED: List[Dict] = [
    {"url": "http://198.50.128.218/Mozi.m", "host": "198.50.128.218", "ip": "198.50.128.218",
     "tags": "Mozi,botnet", "url_status": "online", "threat": "malware_download"},
    {"url": "http://45.95.146.143/b2f628/", "host": "45.95.146.143", "ip": "45.95.146.143",
     "tags": "Emotet,trojan", "url_status": "online", "threat": "malware_download"},
    {"url": "http://190.211.254.179/bins/Mirai.arm7", "host": "190.211.254.179",
     "ip": "190.211.254.179", "tags": "Mirai,botnet", "url_status": "online", "threat": "malware_download"},
    {"url": "http://141.98.10.124/cobalt", "host": "141.98.10.124", "ip": "141.98.10.124",
     "tags": "CobaltStrike,C2", "url_status": "online", "threat": "c2"},
    {"url": "http://103.75.201.2/bins/", "host": "103.75.201.2", "ip": "103.75.201.2",
     "tags": "Mirai,IoT", "url_status": "online", "threat": "malware_download"},
]


class URLhausFeed:
    """Downloads and indexes the URLhaus IOC feed for fast lookup."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self._cache_dir / "urlhaus_cache.json"
        self._ip_index: Dict[str, List[Dict]] = {}
        self._host_index: Dict[str, List[Dict]] = {}
        self._records: List[Dict] = []
        self._loaded_at: Optional[float] = None

    # ------------------------------------------------------------------
    def load(self, force_refresh: bool = False) -> int:
        """Load feed from cache or download fresh copy. Returns record count."""
        if not force_refresh and self._is_cache_valid():
            return self._load_from_cache()
        try:
            count = self._download_and_cache()
            return count
        except Exception as exc:  # noqa: BLE001
            logger.warning("URLhaus download failed (%s). Falling back to cache/seed.", exc)
            if self._cache_file.exists():
                return self._load_from_cache()
            return self._load_seed()

    def _is_cache_valid(self) -> bool:
        if not self._cache_file.exists():
            return False
        age = time.time() - self._cache_file.stat().st_mtime
        return age < CACHE_TTL_SECONDS

    def _download_and_cache(self) -> int:
        logger.info("Downloading URLhaus feed from %s …", URLHAUS_CSV_URL)
        resp = requests.get(URLHAUS_CSV_URL, timeout=15)
        resp.raise_for_status()
        content = resp.content
        if content[:2] == b"\x1f\x8b":
            content = gzip.decompress(content)
        records = self._parse_csv(content.decode("utf-8", errors="replace"))
        self._build_index(records)
        payload = {
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "records": records[:20000],  # cap to keep cache small
        }
        self._cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("URLhaus feed: %d records downloaded and cached.", len(records))
        return len(records)

    def _load_from_cache(self) -> int:
        data = json.loads(self._cache_file.read_text(encoding="utf-8"))
        records = data.get("records", [])
        self._build_index(records)
        logger.info("URLhaus feed loaded from cache: %d records.", len(records))
        return len(records)

    def _load_seed(self) -> int:
        self._build_index(OFFLINE_SEED)
        logger.info("URLhaus feed: using offline seed (%d records).", len(OFFLINE_SEED))
        return len(OFFLINE_SEED)

    @staticmethod
    def _parse_csv(text: str) -> List[Dict]:
        """
        URLhaus CSV is headerless, positional:
        id, date_added, url, url_status, date_modified, threat, tags, urlhaus_link, source
        Each field is double-quoted and comma-separated.
        """
        import re
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Use csv reader to handle quoted fields
            try:
                parts = next(csv.reader([line]))
            except StopIteration:
                continue
            if len(parts) < 6:
                continue
            url = parts[2] if len(parts) > 2 else ""
            url_status = parts[3] if len(parts) > 3 else ""
            threat = parts[5] if len(parts) > 5 else ""
            tags = parts[6] if len(parts) > 6 else ""
            # Extract host from URL
            host = ""
            ip = ""
            m = re.match(r"https?://([^/:\s]+)", url)
            if m:
                host = m.group(1)
                # Simple IP detection
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                    ip = host
            records.append({
                "url": url,
                "host": host,
                "ip": ip,
                "tags": tags,
                "url_status": url_status,
                "threat": threat,
            })
        return records

    def _build_index(self, records: List[Dict]) -> None:
        self._records = records
        self._ip_index = {}
        self._host_index = {}
        for rec in records:
            ip = (rec.get("ip") or "").strip()
            host = (rec.get("host") or "").strip()
            if ip:
                self._ip_index.setdefault(ip, []).append(rec)
            if host and host != ip:
                self._host_index.setdefault(host, []).append(rec)
        self._loaded_at = time.time()

    # ------------------------------------------------------------------
    # Lookup API
    # ------------------------------------------------------------------
    def lookup_ip(self, ip: str) -> List[Dict]:
        """Return IOC records matching a given IP address."""
        return self._ip_index.get(ip.strip(), [])

    def lookup_host(self, host: str) -> List[Dict]:
        """Return IOC records matching a hostname or domain."""
        return self._host_index.get(host.strip(), [])

    def is_malicious_ip(self, ip: str) -> bool:
        return bool(self.lookup_ip(ip))

    def get_tags(self, ip: str) -> List[str]:
        hits = self.lookup_ip(ip)
        tags: List[str] = []
        for h in hits:
            for tag in (h.get("tags") or "").split(","):
                t = tag.strip()
                if t and t not in tags:
                    tags.append(t)
        return tags

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def loaded_at(self) -> Optional[str]:
        if self._loaded_at is None:
            return None
        return datetime.fromtimestamp(self._loaded_at, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def stats(self) -> Dict:
        return {
            "total_records": self.record_count,
            "unique_ips": len(self._ip_index),
            "unique_hosts": len(self._host_index),
            "loaded_at": self.loaded_at,
        }


# Module-level singleton for convenience
_feed: Optional[URLhausFeed] = None


def get_feed(force_refresh: bool = False) -> URLhausFeed:
    global _feed
    if _feed is None:
        _feed = URLhausFeed()
        _feed.load(force_refresh=force_refresh)
    return _feed
