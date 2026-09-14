"""
MITRE ATT&CK STIX 2.1 Parser
------------------------------
Downloads the official MITRE ATT&CK Enterprise STIX 2.1 bundle,
caches it locally, and exposes a fast lookup API for techniques,
tactics, and mitigations.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)
CACHE_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "cache"
STIX_CACHE = CACHE_DIR / "mitre_attack.json"
CACHE_TTL = 86400  # 24 h


# ---------------------------------------------------------------------------
# Embedded compact technique catalogue – ensures offline demo resilience.
# Each entry covers the techniques actually observed in master_events.csv.
# ---------------------------------------------------------------------------
BUILTIN_TECHNIQUES: Dict[str, Dict] = {
    "T1110": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries try to gain access to accounts by systematically guessing "
            "passwords without prior knowledge of the correct credential."
        ),
        "detection": (
            "Monitor authentication logs for high-volume failed logins. "
            "Alert on >10 failures/minute from the same source IP."
        ),
        "mitigations": [
            "Account Lockout Policy",
            "Multi-Factor Authentication",
            "Password Complexity Requirements",
        ],
        "platforms": ["Linux", "Windows", "Network"],
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries exploit vulnerabilities in internet-facing applications "
            "(web servers, VPNs, databases) to gain initial access."
        ),
        "detection": (
            "Web-application firewall alerts, IDS signatures for known CVEs, "
            "anomalous HTTP error patterns."
        ),
        "mitigations": [
            "Update and Patch Software Regularly",
            "Web Application Firewall",
            "Network Segmentation",
        ],
        "platforms": ["Linux", "Windows", "Network"],
    },
    "T1498": {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries perform network flooding to degrade or block availability "
            "of a target network resource (DDoS)."
        ),
        "detection": (
            "Volumetric anomaly detection, traffic rate thresholds, "
            "flow record analysis for packet floods."
        ),
        "mitigations": [
            "Filter Network Traffic (ACLs / Scrubbing)",
            "DDoS Protection Services",
            "Upstream Network Provider Notification",
        ],
        "platforms": ["Network"],
    },
    "T1499": {
        "id": "T1499",
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": (
            "Adversaries exhaust resources on individual hosts (CPU, memory, "
            "connections) causing service disruption."
        ),
        "detection": (
            "Host-based performance monitoring, resource saturation alerts, "
            "connection-rate anomalies."
        ),
        "mitigations": [
            "Rate Limiting",
            "Load Balancers and Redundancy",
            "Resource Quotas",
        ],
        "platforms": ["Linux", "Windows"],
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": (
            "Adversaries communicate with compromised systems using standard "
            "application-layer protocols (HTTP/S, DNS, SMTP) to blend in."
        ),
        "detection": (
            "DNS query frequency anomalies, unusual HTTP beaconing intervals, "
            "JA3/JA3S TLS fingerprinting."
        ),
        "mitigations": [
            "Network Intrusion Detection / Prevention",
            "DNS Sinkholes",
            "Proxy / SSL Inspection",
        ],
        "platforms": ["Linux", "Windows", "macOS", "Network"],
    },
    "T1595": {
        "id": "T1595",
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Adversaries probe victim network infrastructure by sending crafted "
            "packets to gather information about targets."
        ),
        "detection": (
            "High-rate SYN/ICMP/UDP sweeps, port-scan signatures in IDS/IPS, "
            "honeypot hits."
        ),
        "mitigations": [
            "Firewall Rules to Block Probing",
            "Rate Limiting on Ingress",
            "Deception Technologies (Honeypots)",
        ],
        "platforms": ["Network"],
    },
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Adversaries obtain and use legitimate account credentials to gain "
            "initial access, maintain persistence, or escalate privileges."
        ),
        "detection": (
            "Impossible-travel logins, off-hours authentication, new device "
            "or geo-location anomalies."
        ),
        "mitigations": [
            "Privileged Account Management",
            "Multi-Factor Authentication",
            "Account Use Policies",
        ],
        "platforms": ["Linux", "Windows", "Cloud"],
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries steal data via protocols other than the C2 channel "
            "(DNS tunnelling, ICMP, SMTP, FTP)."
        ),
        "detection": (
            "Large DNS query payloads, abnormal data volumes on non-standard ports, "
            "DLP sensor alerts."
        ),
        "mitigations": [
            "Data Loss Prevention (DLP)",
            "Network Protocol Filtering",
            "Encrypt and Monitor Sensitive Data",
        ],
        "platforms": ["Linux", "Windows", "macOS", "Network"],
    },
}

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


class MitreAttack:
    """MITRE ATT&CK Enterprise technique/tactic/mitigation lookup."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self._cache_dir = cache_dir or CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self._cache_dir / "mitre_attack.json"
        self._techniques: Dict[str, Dict] = {}
        self._tactics: Dict[str, List[str]] = {}  # tactic -> [technique_ids]
        self._loaded_from_stix = False

    # ------------------------------------------------------------------
    def load(self, force_refresh: bool = False) -> int:
        """Load STIX bundle from cache or download. Returns technique count."""
        if not force_refresh and self._is_cache_valid():
            try:
                return self._load_from_cache()
            except Exception as exc:  # noqa: BLE001
                logger.warning("STIX cache load failed: %s", exc)

        try:
            count = self._download_and_cache()
            return count
        except Exception as exc:  # noqa: BLE001
            logger.warning("STIX download failed (%s). Using built-in catalogue.", exc)
            return self._load_builtin()

    def _is_cache_valid(self) -> bool:
        if not self._cache_file.exists():
            return False
        age = time.time() - self._cache_file.stat().st_mtime
        return age < CACHE_TTL

    def _download_and_cache(self) -> int:
        logger.info("Downloading MITRE ATT&CK STIX bundle …")
        resp = requests.get(STIX_URL, timeout=30)
        resp.raise_for_status()
        bundle = resp.json()
        techniques = self._parse_stix(bundle)
        self._cache_file.write_text(
            json.dumps({"techniques": techniques}, indent=2), encoding="utf-8"
        )
        self._techniques = {t["id"]: t for t in techniques}
        self._build_tactic_index()
        self._loaded_from_stix = True
        logger.info("MITRE ATT&CK loaded: %d techniques.", len(techniques))
        return len(techniques)

    def _load_from_cache(self) -> int:
        data = json.loads(self._cache_file.read_text(encoding="utf-8"))
        techniques = data.get("techniques", [])
        self._techniques = {t["id"]: t for t in techniques}
        self._build_tactic_index()
        self._loaded_from_stix = True
        logger.info("MITRE ATT&CK loaded from cache: %d techniques.", len(techniques))
        return len(techniques)

    def _load_builtin(self) -> int:
        self._techniques = dict(BUILTIN_TECHNIQUES)
        self._build_tactic_index()
        logger.info("MITRE ATT&CK using built-in catalogue: %d techniques.", len(self._techniques))
        return len(self._techniques)

    @staticmethod
    def _parse_stix(bundle: Dict) -> List[Dict]:
        techniques = []
        tactic_map: Dict[str, str] = {}  # short-name -> display name

        for obj in bundle.get("objects", []):
            if obj.get("type") == "x-mitre-tactic":
                short = obj.get("x_mitre_shortname", "")
                name = obj.get("name", "")
                if short:
                    tactic_map[short] = name

        mitigations: Dict[str, List[str]] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
                tgt = obj.get("target_ref", "")
                src = obj.get("source_ref", "")
                mitigations.setdefault(tgt, []).append(src)

        mitigation_names: Dict[str, str] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") == "course-of-action":
                mitigation_names[obj["id"]] = obj.get("name", "")

        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext = obj.get("x_mitre_platforms", [])
            phases = obj.get("kill_chain_phases", [])
            tids = [
                ref.get("external_id", "")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack"
            ]
            if not tids:
                continue
            tid = tids[0]
            tactics_list = [
                tactic_map.get(p.get("phase_name", ""), p.get("phase_name", "")).title()
                for p in phases
            ]
            mits = [
                mitigation_names.get(m, m)
                for m in mitigations.get(obj["id"], [])
                if mitigation_names.get(m)
            ]
            techniques.append({
                "id": tid,
                "name": obj.get("name", ""),
                "tactic": " / ".join(tactics_list) if tactics_list else "Unknown",
                "description": (obj.get("description") or "")[:500],
                "detection": (obj.get("x_mitre_detection") or "")[:400],
                "mitigations": mits[:5],
                "platforms": ext,
            })
        return techniques

    def _build_tactic_index(self) -> None:
        self._tactics = {}
        for tid, tech in self._techniques.items():
            for tac in tech.get("tactic", "").split(" / "):
                t = tac.strip()
                if t:
                    self._tactics.setdefault(t, []).append(tid)

    # ------------------------------------------------------------------
    # Lookup API
    # ------------------------------------------------------------------
    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Fetch technique details by ID (e.g. 'T1110')."""
        t = self._techniques.get(technique_id.upper())
        if t is None:
            # Fall back to built-in if STIX bundle loaded but missing entry
            t = BUILTIN_TECHNIQUES.get(technique_id.upper())
        return t

    def get_techniques_for_tactic(self, tactic: str) -> List[Dict]:
        """All techniques associated with a given tactic."""
        ids = self._tactics.get(tactic, [])
        return [self._techniques[i] for i in ids if i in self._techniques]

    def enrich_event(self, mitre_technique: str, mitre_tactic: str) -> Dict:
        """Return enrichment dict for a single event."""
        tech = self.get_technique(mitre_technique) if mitre_technique else None
        return {
            "technique_id": mitre_technique or "",
            "technique_name": tech["name"] if tech else mitre_tactic,
            "tactic": tech["tactic"] if tech else mitre_tactic,
            "description": tech["description"] if tech else "",
            "detection": tech["detection"] if tech else "",
            "mitigations": tech["mitigations"] if tech else [],
            "platforms": tech["platforms"] if tech else [],
        }

    @property
    def tactic_order(self) -> List[str]:
        return TACTIC_ORDER

    def all_technique_ids(self) -> List[str]:
        return list(self._techniques.keys())

    def stats(self) -> Dict:
        return {
            "technique_count": len(self._techniques),
            "tactic_count": len(self._tactics),
            "source": "STIX 2.1" if self._loaded_from_stix else "built-in catalogue",
        }


# Module-level singleton
_mitre: Optional[MitreAttack] = None


def get_mitre(force_refresh: bool = False) -> MitreAttack:
    global _mitre
    if _mitre is None:
        _mitre = MitreAttack()
        _mitre.load(force_refresh=force_refresh)
    return _mitre
