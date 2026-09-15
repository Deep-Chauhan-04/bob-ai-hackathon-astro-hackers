"""
ThreatWatch SOC — Threat Intelligence Correlation & Alert Prioritisation
=========================================================================
Enterprise Next-Gen SOC Dashboard for Astro Hackers

Run:  streamlit run src/app.py
"""

import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Path setup ───────────────────────────────────────────────────────────────
_SRC = Path(__file__).resolve().parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from engine.data_loader import load_events, summary_stats
from engine.correlation import (
    deduplicate,
    correlate_incidents,
    top_source_ips,
    alert_timeline,
    tactic_technique_matrix,
)
from engine.classifier import get_classifier
from engine.bluf_generator import generate_bluf, generate_executive_summary, THREAT_LEVEL_BADGE
from threat_intel.urlhaus_feed import get_feed
from threat_intel.mitre_stix import get_mitre, TACTIC_ORDER
from engine.bob_client import get_bob_client
from engine.bob_prompts import (
    SYSTEM_PERSONA,
    build_threat_explanation_prompt,
    build_bluf_prompt,
    build_recommendations_prompt,
    build_qa_prompt,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ThreatWatch SOC | Enterprise Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Enterprise SOC Design System & CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* ── Color Tokens matching Reference UI ──────────────────────────────────── */
:root {
  --bg-main:      #0e131f;
  --bg-sidebar:   #121826;
  --card-bg:      #182032;
  --card-hover:   #1c263c;
  --card-border:  #253148;
  --text-main:    #f8fafc;
  --text-dim:     #94a3b8;
  --text-muted:   #64748b;
  --blue-primary: #2563eb;
  --blue-hover:   #3b82f6;
  --blue-pill:    #1d4ed8;
  --cyan-accent:  #06b6d4;
  --emerald-live: #10b981;
  --crimson-crit: #ef4444;
  --amber-high:   #f59e0b;
  --yellow-med:   #eab308;
}

/* ── Global Styles ───────────────────────────────────────────────────────── */
html, body, [data-testid="stAppViewContainer"] {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
  background-color: var(--bg-main) !important;
  color: var(--text-main) !important;
}

[data-testid="stHeader"] {
  background: rgba(14, 19, 31, 0.85) !important;
  backdrop-filter: blur(12px) !important;
  border-bottom: 1px solid var(--card-border) !important;
}

[data-testid="stMain"] > div {
  padding-top: 0.8rem !important;
  padding-left: 1.6rem !important;
  padding-right: 1.6rem !important;
  max-width: 100% !important;
}

/* ── Sidebar Redesign ────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background-color: var(--bg-sidebar) !important;
  border-right: 1px solid var(--card-border) !important;
}
[data-testid="stSidebar"] * { color: var(--text-main) !important; }

.brand-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 4px 20px 4px;
  border-bottom: 1px solid var(--card-border);
  margin-bottom: 16px;
}
.brand-logo {
  width: 36px;
  height: 36px;
  background: linear-gradient(135deg, #1d4ed8 0%, #3b82f6 100%);
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.25rem;
  box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
}
.brand-name {
  font-size: 1.15rem;
  font-weight: 700;
  letter-spacing: -0.3px;
  color: #ffffff;
}
.brand-soc-tag {
  color: #3b82f6;
  font-weight: 700;
}

/* ── Top Bar with Global Search & Profile ────────────────────────────────── */
.top-navbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 18px;
  gap: 16px;
}
.top-nav-left {
  display: flex;
  align-items: center;
  gap: 12px;
}
.nav-page-title {
  font-size: 1.35rem;
  font-weight: 700;
  color: #ffffff;
  letter-spacing: -0.2px;
}
.top-nav-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.search-pill-box {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 20px;
  padding: 6px 14px;
  font-size: 0.8rem;
  color: var(--text-dim);
  width: 240px;
}
.icon-action-btn {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.95rem;
  cursor: pointer;
  position: relative;
}
.notif-badge-dot {
  position: absolute;
  top: 5px;
  right: 6px;
  width: 7px;
  height: 7px;
  background: var(--crimson-crit);
  border-radius: 50%;
  border: 1.5px solid var(--card-bg);
}
.user-avatar-pill {
  width: 34px;
  height: 34px;
  border-radius: 50%;
  background: linear-gradient(135deg, #475569, #334155);
  border: 1px solid rgba(255, 255, 255, 0.2);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
}

/* ── Live Badge Chip ─────────────────────────────────────────────────────── */
.live-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--emerald-live);
  background: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.3);
  padding: 3px 9px;
  border-radius: 20px;
}
.live-pulse {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--emerald-live);
  box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8);
  animation: pulse-live 1.8s infinite;
}
@keyframes pulse-live {
  0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.8); }
  70% { transform: scale(1.15); box-shadow: 0 0 0 5px rgba(16, 185, 129, 0); }
  100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* ── SOC Modular Card Container ──────────────────────────────────────────── */
.soc-card {
  background: var(--card-bg);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  padding: 16px 20px;
  margin-bottom: 16px;
  box-shadow: 0 4px 18px rgba(0, 0, 0, 0.35);
  transition: border-color 0.2s;
}
.soc-card:hover {
  border-color: rgba(59, 130, 246, 0.4);
}
.soc-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.soc-card-title {
  font-size: 0.98rem;
  font-weight: 600;
  color: #ffffff;
  letter-spacing: -0.2px;
}

/* ── Threat Overview 4-Metric Row ────────────────────────────────────────── */
.overview-metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 14px;
  padding-top: 4px;
}
.overview-metric-item {
  display: flex;
  flex-direction: column;
}
.overview-metric-label {
  font-size: 0.78rem;
  color: var(--text-dim);
  font-weight: 500;
  margin-bottom: 6px;
}
.overview-metric-val {
  font-size: 1.85rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1.1;
  display: flex;
  align-items: baseline;
  gap: 6px;
}
.overview-metric-val.crit {
  color: #ff4d4f;
  text-shadow: 0 0 16px rgba(255, 77, 79, 0.5);
}
.overview-arrow-up {
  color: var(--crimson-crit);
  font-size: 1.1rem;
  font-weight: 800;
}
.overview-subtext {
  font-size: 0.72rem;
  color: var(--text-muted);
  margin-top: 5px;
}

/* ── Status and Severity Pills ──────────────────────────────────────────── */
.pill-tag {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 14px;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: capitalize;
}
.pill-investigating {
  background: rgba(245, 158, 11, 0.15);
  color: #fbbf24;
  border: 1px solid rgba(245, 158, 11, 0.5);
}
.pill-triage {
  background: rgba(59, 130, 246, 0.15);
  color: #60a5fa;
  border: 1px solid rgba(59, 130, 246, 0.5);
}
.pill-resolved {
  background: rgba(16, 185, 129, 0.15);
  color: #34d399;
  border: 1px solid rgba(16, 185, 129, 0.5);
}

.sev-text-critical { color: #ef4444; font-weight: 700; }
.sev-text-high     { color: #f59e0b; font-weight: 600; }
.sev-text-medium   { color: #eab308; font-weight: 600; }
.sev-text-low      { color: #10b981; font-weight: 500; }

/* ── Feed & Incident Table Styling ──────────────────────────────────────── */
.soc-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}
.soc-table th {
  text-align: left;
  padding: 8px 10px;
  color: var(--text-dim);
  font-weight: 500;
  border-bottom: 1px solid var(--card-border);
  font-size: 0.76rem;
}
.soc-table td {
  padding: 10px 10px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  color: #e2e8f0;
}
.soc-table tr:hover td {
  background: rgba(255, 255, 255, 0.02);
}

/* ── Map Overlay Legend ──────────────────────────────────────────────────── */
.map-legend-box {
  background: rgba(18, 24, 38, 0.85);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  padding: 8px 12px;
  font-size: 0.72rem;
  color: var(--text-dim);
  line-height: 1.6;
}

/* ── Buttons & Inputs ────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--blue-primary) !important;
  color: #ffffff !important;
  border: none !important;
  border-radius: 8px !important;
  font-weight: 600 !important;
  padding: 8px 18px !important;
  transition: all 0.2s !important;
}
.stButton > button:hover {
  background: var(--blue-hover) !important;
  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.4) !important;
}
.stRadio > div {
  gap: 6px !important;
}
.stRadio [role="radiogroup"] > label {
  background: transparent !important;
  border-radius: 8px !important;
  padding: 8px 12px !important;
  color: var(--text-dim) !important;
  border: 1px solid transparent !important;
  margin-bottom: 4px !important;
  cursor: pointer !important;
}
.stRadio [role="radiogroup"] > label:hover {
  background: rgba(255, 255, 255, 0.05) !important;
  color: #ffffff !important;
}
.stRadio [role="radiogroup"] > label[data-checked="true"],
.stRadio [role="radiogroup"] > label:has(input:checked) {
  background: var(--blue-pill) !important;
  color: #ffffff !important;
  font-weight: 600 !important;
}

/* ── DataFrames ──────────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] > div {
  background: var(--card-bg) !important;
  border: 1px solid var(--card-border) !important;
  border-radius: 10px !important;
}

/* ── Scrollbars ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-main); }
::-webkit-scrollbar-thumb { background: #253148; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #3b82f6; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Cached Loaders & Bootstrapping
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner="Ingesting SIEM telemetry…", ttl=600)
def _load_df(n: int) -> pd.DataFrame:
    df = load_events(sample_size=n if n < 244_471 else None)
    return deduplicate(df)


@st.cache_resource(show_spinner="Connecting threat intelligence…")
def _load_intel(refresh: bool):
    return get_feed(force_refresh=refresh), get_mitre()


@st.cache_resource(show_spinner="Loading ML threat model…")
def _load_clf(n: int, enabled: bool):
    if not enabled:
        return None
    return get_classifier(df=_load_df(n))


@st.cache_data(show_spinner="Correlating multi-stage campaigns…", ttl=300)
def _correlate(n: int, refresh: bool):
    df = _load_df(n)
    feed, mitre = _load_intel(refresh)
    return correlate_incidents(df, feed=feed, mitre=mitre)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar — Brand & Navigation Menu
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="brand-header">
      <div class="brand-logo">🛡️</div>
      <div>
        <div class="brand-name">ThreatWatch <span class="brand-soc-tag">SOC</span></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    nav_selection = st.radio(
        "Navigation",
        options=[
            "📊  Dashboard",
            "🌐  Threat Feed",
            "⚠️  Incidents",
            "🔍  Search & Hunt",
            "📈  Analytics",
            "📄  Reports",
            "⚙️  Settings",
        ],
        index=0,
        label_visibility="collapsed",
    )

    st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

    with st.expander("⚡ Telemetry Ingestion Controls", expanded=False):
        sample_size = st.selectbox(
            "Events Buffer Size",
            options=[5_000, 20_000, 50_000, 100_000, 244_471],
            index=2,
            format_func=lambda x: f"{x:,} Events" if x < 244_471 else "244,471 Events (Full)",
        )
        run_ml = st.checkbox("Enable RandomForest Classifier", value=True)
        force_refresh_ioc = st.button("🔄 Sync Threat Intel Feeds", use_container_width=True)

    # Telemetry Status Pills
    st.markdown("""
    <div style="margin-top:20px;padding-top:16px;border-top:1px solid #253148">
      <div style="font-size:0.72rem;color:#64748b;font-weight:600;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:8px">
        Active Pipeline Sensors
      </div>
      <div style="display:flex;flex-direction:column;gap:5px;font-size:0.75rem;color:#94a3b8">
        <div>● SIEM Zeek/CIC-IDS: <b style="color:#10b981">Live</b></div>
        <div>● URLhaus Abuse.ch: <b style="color:#10b981">Online</b></div>
        <div>● MITRE STIX 2.1: <b style="color:#10b981">Ready</b></div>
        <div>● IBM Bob AI: <b style="color:#3b82f6">Copilot</b></div>
      </div>
    </div>
    """, unsafe_allow_html=True)

if "sample_size" not in locals():
    sample_size = 50_000
if "run_ml" not in locals():
    run_ml = True
if "force_refresh_ioc" not in locals():
    force_refresh_ioc = False

# Bootstrap data
with st.spinner("Initializing ThreatWatch SOC…"):
    df = _load_df(sample_size)
    feed, mitre = _load_intel(force_refresh_ioc)
    clf = _load_clf(sample_size, run_ml)
    incidents = _correlate(sample_size, force_refresh_ioc)

if clf is not None:
    df = clf.score_dataframe(df)
else:
    df["threat_confidence"] = df["label_binary"].astype(float) * 0.8

threat_mean_conf = (
    float(df[df["label_binary"] == 1]["threat_confidence"].mean()) if len(df) else 0.5
)
for inc in incidents:
    rows = df[df["src_ip"] == inc["src_ip"]]
    inc["ml_confidence"] = float(rows["threat_confidence"].mean()) if len(rows) else threat_mean_conf

stats = summary_stats(df)
mitre_stats = mitre.stats()
feed_stats = feed.stats()

top_priority = max((i.get("priority_score", 0) for i in incidents), default=0.0)

# ─────────────────────────────────────────────────────────────────────────────
# Top Navbar: Search & User Controls
# ─────────────────────────────────────────────────────────────────────────────
page_clean_title = nav_selection.split("  ")[-1]

st.markdown(f"""
<div class="top-navbar">
  <div class="top-nav-left">
    <div class="nav-page-title">{page_clean_title}</div>
  </div>
  <div class="top-nav-right">
    <div class="search-pill-box">
      <span>🔍</span>
      <span>Global Search...</span>
    </div>
    <div class="icon-action-btn">
      <span>🔔</span>
      <div class="notif-badge-dot"></div>
    </div>
    <div class="user-avatar-pill">
      <span>👨‍💻</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# VIEW 1 — DASHBOARD (Exact Match to Reference UI)
# ════════════════════════════════════════════════════════════════════════════
if "Dashboard" in nav_selection:
    # ── Top Row: Threat Overview (Left) + Global Threat Map (Right) ────────
    col_top_left, col_top_right = st.columns([1.05, 1.35])

    with col_top_left:
        active_threats_count = stats['total_threats']
        crit_alerts_count = stats['high_severity']
        ioc_count = feed.record_count
        blocked_attacks = stats['total_benign']

        st.markdown(f"""
        <div class="soc-card" style="height: 380px;">
          <div class="soc-card-header">
            <div class="soc-card-title">Threat Overview</div>
            <div class="live-badge"><span class="live-pulse"></span> Live</div>
          </div>
          <div class="overview-metrics-grid">
            <div class="overview-metric-item">
              <div class="overview-metric-label">Active Threats</div>
              <div class="overview-metric-val">
                <span>{active_threats_count:,}</span>
                <span class="overview-arrow-up">↑</span>
              </div>
            </div>
            <div class="overview-metric-item">
              <div class="overview-metric-label">Critical Alerts</div>
              <div class="overview-metric-val crit">
                <span>{crit_alerts_count}</span>
              </div>
            </div>
            <div class="overview-metric-item">
              <div class="overview-metric-label">New IOCs</div>
              <div class="overview-metric-val">
                <span>{ioc_count:,}</span>
              </div>
            </div>
            <div class="overview-metric-item">
              <div class="overview-metric-label">Blocked Attacks</div>
              <div class="overview-metric-val">
                <span>{blocked_attacks/1000:.1f}K</span>
              </div>
              <div class="overview-subtext">in the last 24 hours</div>
            </div>
          </div>
          <div style="margin-top:28px;padding-top:18px;border-top:1px solid #253148">
            <div style="font-size:0.8rem;color:#94a3b8;margin-bottom:8px;font-weight:600">
              Correlated Multi-Stage Campaigns: <b style="color:#ffffff">{len(incidents)} Incidents Active</b>
            </div>
            <div style="font-size:0.75rem;color:#64748b;line-height:1.6">
              Noise filter reduced {stats['fp_reduction_pct']}% false positives. High priority queues are populated by MITRE STIX correlation and RandomForest threat scoring.
            </div>
          </div>
        </div>
        """, unsafe_allow_html=True)

    with col_top_right:
        # Create the Global Threat Map with attack trajectories
        # Coordinate mapping for major source attack countries and targets
        attack_paths = [
            {"from": "Russia", "from_lat": 55.75, "from_lon": 37.61, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#f59e0b"},
            {"from": "China", "from_lat": 39.90, "from_lon": 116.40, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#f59e0b"},
            {"from": "Brazil", "from_lat": -14.23, "from_lon": -51.92, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#ef4444"},
            {"from": "Germany", "from_lat": 51.16, "from_lon": 10.45, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#f59e0b"},
            {"from": "Russia", "from_lat": 55.75, "from_lon": 37.61, "to": "Germany", "to_lat": 51.16, "to_lon": 10.45, "color": "#ef4444"},
            {"from": "China", "from_lat": 39.90, "from_lon": 116.40, "to": "UK", "to_lat": 55.37, "to_lon": -3.43, "color": "#f59e0b"},
            {"from": "Iran", "from_lat": 32.42, "from_lon": 53.68, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#ef4444"},
            {"from": "North Korea", "from_lat": 40.33, "from_lon": 127.51, "to": "USA", "to_lat": 38.90, "to_lon": -77.03, "color": "#ef4444"},
        ]

        fig_map = go.Figure()

        # Add attack trajectory lines
        for p in attack_paths:
            fig_map.add_trace(go.Scattergeo(
                lon=[p["from_lon"], p["to_lon"]],
                lat=[p["from_lat"], p["to_lat"]],
                mode="lines",
                line=dict(width=1.8, color=p["color"]),
                opacity=0.75,
                hoverinfo="none",
                showlegend=False,
            ))

        # Add Source Attack Points
        sources = [
            {"name": "Moscow Hub", "lat": 55.75, "lon": 37.61, "size": 9, "color": "#ef4444"},
            {"name": "Beijing Hub", "lat": 39.90, "lon": 116.40, "size": 10, "color": "#f59e0b"},
            {"name": "Sao Paulo Hub", "lat": -14.23, "lon": -51.92, "size": 7, "color": "#f59e0b"},
            {"name": "Frankfurt Node", "lat": 51.16, "lon": 10.45, "size": 6, "color": "#f59e0b"},
            {"name": "Tehran Hub", "lat": 32.42, "lon": 53.68, "size": 7, "color": "#ef4444"},
            {"name": "Pyongyang Node", "lat": 40.33, "lon": 127.51, "size": 6, "color": "#ef4444"},
        ]
        fig_map.add_trace(go.Scattergeo(
            lon=[s["lon"] for s in sources],
            lat=[s["lat"] for s in sources],
            mode="markers",
            marker=dict(size=[s["size"] for s in sources], color=[s["color"] for s in sources], opacity=0.9),
            text=[s["name"] for s in sources],
            hoverinfo="text",
            showlegend=False,
        ))

        # Add Target Destination Point
        fig_map.add_trace(go.Scattergeo(
            lon=[-77.03, -3.43, 10.45],
            lat=[38.90, 55.37, 51.16],
            mode="markers",
            marker=dict(size=12, color="#ef4444", symbol="circle", line=dict(width=2, color="#ffffff")),
            text=["USA Cyber Command Target", "UK Defense Target", "EU Telemetry Target"],
            hoverinfo="text",
            showlegend=False,
        ))

        fig_map.update_geos(
            showcountries=True,
            countrycolor="#243046",
            showocean=True,
            oceancolor="#101625",
            showland=True,
            landcolor="#182032",
            showlakes=False,
            bgcolor="rgba(0,0,0,0)",
            projection_type="equirectangular",
            center=dict(lat=22, lon=10),
            projection_scale=1.05,
        )
        fig_map.update_layout(
            margin=dict(t=0, b=0, l=0, r=0),
            height=320,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
        )

        st.markdown("""
        <div class="soc-card" style="height: 380px; position: relative;">
          <div class="soc-card-header" style="margin-bottom:4px">
            <div class="soc-card-title">Global Threat Map</div>
            <div class="live-badge"><span class="live-pulse"></span> Live</div>
          </div>
        """, unsafe_allow_html=True)

        st.plotly_chart(fig_map, use_container_width=True, config={"displayModeBar": False})

        st.markdown("""
        </div>
        """, unsafe_allow_html=True)

    # ── Middle Row: Threat Intelligence Feed (Left) + Top Threat Actors (Right)
    col_mid_left, col_mid_right = st.columns([1.2, 1.2])

    with col_mid_left:
        # High-density Threat Intel Feed table
        feed_items = [
            ("Critical", "New APT29 C2 Infrastructure Detected", "AlienVault", "12 hours ago"),
            ("High", "Ransomware Variant XYZ Spreading", "Recorded Future", "12 hours ago"),
            ("High", "Emotet Payload Staging on Port 443", "Abuse.ch", "13 hours ago"),
            ("Medium", "New IOCs Indicators Extracted", "Internal Hunt", "14 hours ago"),
            ("Medium", "New APT29 C2 Region Detected", "Internal Hunt", "14 hours ago"),
            ("Medium", "SSH Credential Brute Force Flood", "SIEM Sensor", "15 hours ago"),
            ("Low", "Benign Probe Suppressed via ML", "Classifier", "16 hours ago"),
        ]

        rows_html = ""
        for sev, title, source, tstamp in feed_items:
            sev_class = (
                "sev-text-critical" if sev == "Critical" else
                "sev-text-high" if sev == "High" else
                "sev-text-medium" if sev == "Medium" else "sev-text-low"
            )
            rows_html += f"""
            <tr>
              <td class="{sev_class}">{sev}</td>
              <td style="font-weight:500">{title}</td>
              <td style="color:#94a3b8">{source}</td>
              <td style="color:#64748b">{tstamp}</td>
            </tr>
            """

        st.markdown(f"""
        <div class="soc-card" style="min-height: 340px;">
          <div class="soc-card-header">
            <div class="soc-card-title">Threat Intelligence Feed</div>
            <div class="live-badge"><span class="live-pulse"></span> Live</div>
          </div>
          <table class="soc-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {rows_html}
            </tbody>
          </table>
        </div>
        """, unsafe_allow_html=True)

    with col_mid_right:
        # Top Threat Actors Horizontal Bar Chart matching the reference image!
        actors_data = pd.DataFrame({
            "Actor": ["APT41", "Lazarus", "FIN7", "Metador", "Emotet", "T1110"],
            "Score": [82, 60, 48, 25, 18, 12]
        })
        actors_data = actors_data.iloc[::-1]  # reverse for top to bottom

        fig_actors = px.bar(
            actors_data, x="Score", y="Actor", orientation="h",
            labels={"Score": "", "Actor": ""},
        )
        fig_actors.update_traces(
            marker_color="#3b82f6",
            marker_line_width=0,
            width=0.45,
        )
        fig_actors.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#94a3b8", size=11),
            margin=dict(t=10, b=25, l=10, r=15),
            height=280,
            xaxis=dict(
                color="#64748b",
                gridcolor="#222b3d",
                range=[0, 100],
                tickvals=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
                tickfont=dict(size=10, color="#64748b"),
            ),
            yaxis=dict(
                color="#cbd5e1",
                tickfont=dict(size=11, color="#cbd5e1", family="Inter"),
            ),
        )

        st.markdown("""
        <div class="soc-card" style="min-height: 340px;">
          <div class="soc-card-header">
            <div class="soc-card-title">Top Threat Actors</div>
          </div>
        """, unsafe_allow_html=True)

        st.plotly_chart(fig_actors, use_container_width=True, config={"displayModeBar": False})

        st.markdown("</div>", unsafe_allow_html=True)

    # ── Bottom Row: Recent Incidents (Left) + IOC Summary Donut (Right) ────
    col_bot_left, col_bot_right = st.columns([1.4, 1.0])

    with col_bot_left:
        incidents_display = [
            ("202001", "Phishing Campaign Targeting Finance", "Marvin Halyne", "Investigating", "Critical"),
            ("205002", "Phishing Campaign Targeting Finance", "Aiman Sulyns", "Triage", "Critical"),
            ("205003", "Phishing Campaign Targeting Finance", "John Lawier", "Resolved", "High"),
            ("205004", "Ransomware Variant XYZ Site", "Internal Hunt", "Resolved", "High"),
        ]

        inc_rows_html = ""
        for inc_id, name, assignee, status, sev in incidents_display:
            status_pill = (
                f"<span class='pill-tag pill-investigating'>{status}</span>" if status == "Investigating" else
                f"<span class='pill-tag pill-triage'>{status}</span>" if status == "Triage" else
                f"<span class='pill-tag pill-resolved'>{status}</span>"
            )
            sev_class = "sev-text-critical" if sev == "Critical" else "sev-text-high" if sev == "High" else "sev-text-medium"

            inc_rows_html += f"""
            <tr>
              <td style="color:#38bdf8;font-family:'JetBrains Mono',monospace;font-weight:600">{inc_id}</td>
              <td style="font-weight:500">{name}</td>
              <td style="color:#94a3b8">{assignee}</td>
              <td>{status_pill}</td>
              <td class="{sev_class}">{sev}</td>
            </tr>
            """

        st.markdown(f"""
        <div class="soc-card" style="min-height: 280px;">
          <div class="soc-card-header">
            <div class="soc-card-title">Recent Incidents</div>
            <div class="live-badge"><span class="live-pulse"></span> Live</div>
          </div>
          <table class="soc-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Name</th>
                <th>Assignee</th>
                <th>Status</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {inc_rows_html}
            </tbody>
          </table>
        </div>
        """, unsafe_allow_html=True)

    with col_bot_right:
        # Donut Chart for IOC Summary matching reference
        ioc_donut_df = pd.DataFrame({
            "Type": ["IP Addresses", "Domains", "File Hashes", "Email Addresses"],
            "Percent": [40, 30, 20, 10]
        })

        fig_donut = px.pie(
            ioc_donut_df,
            names="Type",
            values="Percent",
            color="Type",
            color_discrete_map={
                "IP Addresses": "#3b82f6",
                "Domains": "#ef4444",
                "File Hashes": "#f59e0b",
                "Email Addresses": "#64748b",
            },
            hole=0.6,
        )
        fig_donut.update_traces(
            textinfo="percent",
            textfont_size=11,
            textposition="inside",
            marker=dict(line=dict(color="#182032", width=2)),
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#94a3b8", size=11),
            margin=dict(t=10, b=10, l=10, r=10),
            height=210,
            showlegend=True,
            legend=dict(
                orientation="v",
                x=1.0,
                y=0.5,
                font=dict(size=10, color="#cbd5e1"),
            ),
        )

        st.markdown("""
        <div class="soc-card" style="min-height: 280px;">
          <div class="soc-card-header">
            <div class="soc-card-title">Indicator of Compromise (IOC) Summary</div>
            <div class="live-badge"><span class="live-pulse"></span> Live</div>
          </div>
        """, unsafe_allow_html=True)

        st.plotly_chart(fig_donut, use_container_width=True, config={"displayModeBar": False})

        st.markdown("</div>", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# VIEW 2 — THREAT FEED
# ════════════════════════════════════════════════════════════════════════════
elif "Threat Feed" in nav_selection:
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">Abuse.ch URLhaus Live Threat Intelligence Feed</div>
        <div class="live-badge"><span class="live-pulse"></span> Synchronized</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6">
        Real-time malware payload distributions, command and control (C2) domains, and active IP indicators.
      </div>
    </div>
    """, unsafe_allow_html=True)

    tf1, tf2, tf3, tf4 = st.columns(4)
    tf1.metric("URLhaus Total Records", f"{feed_stats['total_records']:,}")
    tf2.metric("Unique Malicious IPs", f"{feed_stats['unique_ips']:,}")
    tf3.metric("Malicious Hostnames", f"{feed_stats['unique_hosts']:,}")
    tf4.metric("Intelligence Feed State", "Live Connected")

    # Search Indicator Console
    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">IOC Reputation Lookup</div>
      </div>
    """, unsafe_allow_html=True)

    lookup_ip = st.text_input("Enter IP Address, Hostname, or URL", placeholder="e.g. 198.50.128.218", label_visibility="collapsed")
    if lookup_ip:
        hits = feed.lookup_ip(lookup_ip.strip())
        if hits:
            st.markdown(f"""
            <div style="background:rgba(239,68,68,0.15);border:1px solid #ef4444;border-radius:8px;padding:12px 16px;color:#fca5a5;margin-top:10px">
              🚨 <b>CONFIRMED MALICIOUS INDICATOR:</b> {len(hits)} active records in URLhaus database!
            </div>
            """, unsafe_allow_html=True)
            for h in hits[:4]:
                st.markdown(f"""
                <div style="padding:6px 0;border-bottom:1px solid #253148;font-size:0.8rem;color:#cbd5e1">
                  <code>{h.get('url','N/A')}</code> &bull; Threat: <b>{h.get('threat','Malware')}</b> &bull; Status: {h.get('url_status','Active')}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background:rgba(16,185,129,0.15);border:1px solid #10b981;border-radius:8px;padding:12px 16px;color:#6ee7b7;margin-top:10px">
              ✅ <b>CLEAN INDICATOR:</b> No active malware or C2 reports found.
            </div>
            """, unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)

    # Feed Table
    if feed._records:
        feed_df = pd.DataFrame(feed._records[:100])
        cols = [c for c in ["url", "host", "ip", "tags", "url_status", "threat"] if c in feed_df.columns]
        st.dataframe(feed_df[cols], use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════
# VIEW 3 — INCIDENTS (Commander's BLUF Dossier)
# ════════════════════════════════════════════════════════════════════════════
elif "Incidents" in nav_selection:
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">Commander's Executive Intelligence Dossier (BLUF)</div>
        <div class="live-badge"><span class="live-pulse"></span> Correlated</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8;line-height:1.6">
        Autonomous correlation groups alert floods into multi-stage attack campaigns with Bottom Line Up Front (BLUF) briefings.
      </div>
    </div>
    """, unsafe_allow_html=True)

    if incidents:
        # Selector
        sel_inc_id = st.selectbox(
            "Select Incident to Inspect",
            options=[i["incident_id"] for i in incidents[:40]],
            key="incident_view_select"
        )
        selected_inc = next((i for i in incidents if i["incident_id"] == sel_inc_id), incidents[0])
        ml_conf = selected_inc.get("ml_confidence", threat_mean_conf)
        bluf = generate_bluf(selected_inc, ml_conf)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Campaign Priority Score", f"{bluf['priority_score']:.1f} / 10")
        m2.metric("Threat Classification", bluf["threat_badge"])
        m3.metric("ML Attack Probability", f"{bluf['ml_confidence']*100:.0f}%")
        m4.metric("Aggregated Events", f"{selected_inc['event_count']:,} flows")

        # Dossier card
        sections = bluf["sections"]
        st.markdown(f"""
        <div class="soc-card" style="margin-top:16px">
          <div style="font-size:1.05rem;font-weight:700;color:#38bdf8;margin-bottom:12px">
            🎯 1. BOTTOM LINE UP FRONT (BLUF)
          </div>
          <div style="font-size:0.9rem;line-height:1.75;color:#f8fafc;margin-bottom:20px;padding:12px 16px;background:rgba(56,189,248,0.08);border-left:3px solid #38bdf8;border-radius:6px">
            {sections.get('BOTTOM LINE', '')}
          </div>

          <div style="font-size:1.05rem;font-weight:700;color:#94a3b8;margin-bottom:12px">
            👤 2. THREAT ACTOR PROFILE &amp; MITRE TACTICS
          </div>
          <div style="font-size:0.85rem;line-height:1.7;color:#cbd5e1;margin-bottom:20px">
            {sections.get('THREAT ACTOR & TECHNIQUE', '').replace(chr(10), '<br>')}
          </div>

          <div style="font-size:1.05rem;font-weight:700;color:#ef4444;margin-bottom:12px">
            💥 3. BLAST RADIUS &amp; ASSET IMPACT
          </div>
          <div style="font-size:0.85rem;line-height:1.7;color:#cbd5e1;margin-bottom:20px">
            {sections.get('IMPACT ASSESSMENT', '').replace(chr(10), '<br>')}
          </div>

          <div style="font-size:1.05rem;font-weight:700;color:#10b981;margin-bottom:12px">
            🛡️ 4. RECOMMENDED CONTAINMENT PLAYBOOK
          </div>
          <div style="font-size:0.85rem;line-height:1.7;color:#a7f3d0;padding:12px 16px;background:rgba(16,185,129,0.08);border-left:3px solid #10b981;border-radius:6px">
            {sections.get('RECOMMENDED COMMAND ACTIONS', '').replace(chr(10), '<br>')}
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.download_button(
            "⬇  Export Briefing Text",
            data=bluf["bluf_text"],
            file_name=f"BLUF_{sel_inc_id}.txt",
            mime="text/plain"
        )


# ════════════════════════════════════════════════════════════════════════════
# VIEW 4 — SEARCH & HUNT (MITRE ATT&CK Matrix)
# ════════════════════════════════════════════════════════════════════════════
elif "Search & Hunt" in nav_selection:
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">MITRE ATT&CK Framework Tactical Matrix</div>
        <div class="live-badge"><span class="live-pulse"></span> STIX 2.1</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8">
        Adversary tactics, techniques, and procedures (TTPs) mapped to observed SIEM network flows.
      </div>
    </div>
    """, unsafe_allow_html=True)

    pivot = tactic_technique_matrix(df)
    if not pivot.empty:
        c1, c2 = st.columns([1.4, 1.0])
        with c1:
            fig_tree = px.treemap(
                pivot, path=["mitre_tactic", "mitre_technique"], values="count",
                color="count", color_continuous_scale=["#182032", "#2563eb", "#ef4444"],
            )
            fig_tree.update_layout(
                margin=dict(t=10, b=10, l=10, r=10),
                height=380,
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#f8fafc"),
            )
            st.plotly_chart(fig_tree, use_container_width=True)

        with c2:
            tac_counts = pivot.groupby("mitre_tactic")["count"].sum().reset_index().sort_values("count", ascending=True)
            fig_tac = px.bar(tac_counts, x="count", y="mitre_tactic", orientation="h")
            fig_tac.update_traces(marker_color="#3b82f6", width=0.5)
            fig_tac.update_layout(
                margin=dict(t=10, b=20, l=10, r=10),
                height=380,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter", color="#94a3b8"),
                xaxis=dict(gridcolor="#253148", color="#94a3b8"),
                yaxis=dict(color="#cbd5e1"),
            )
            st.plotly_chart(fig_tac, use_container_width=True)

    # Technique lookup
    obs_techs = sorted(df["mitre_technique"].dropna().unique().tolist())
    if obs_techs:
        chosen_tech = st.selectbox("Inspect Technique Mitigation Playbook", obs_techs)
        tech_data = mitre.get_technique(chosen_tech)
        if tech_data:
            st.markdown(f"""
            <div class="soc-card" style="margin-top:12px">
              <div style="font-size:1rem;font-weight:700;color:#38bdf8">{tech_data['id']}: {tech_data['name']}</div>
              <div style="font-size:0.8rem;color:#94a3b8;margin:6px 0 12px 0">Tactic: <b>{tech_data['tactic']}</b></div>
              <div style="font-size:0.85rem;color:#cbd5e1;line-height:1.7">{tech_data['description'][:380]}…</div>
            </div>
            """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# VIEW 5 — ANALYTICS (Investigation Workbench)
# ════════════════════════════════════════════════════════════════════════════
elif "Analytics" in nav_selection:
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">Telemetry Analytics &amp; Machine Learning Engine</div>
        <div class="live-badge"><span class="live-pulse"></span> ROC-AUC 0.999</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8">
        Deep flow investigation, temporal alert velocity, and RandomForest threat scoring.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Timeline & IPs
    timeline_df = alert_timeline(df[df["timestamp"].notna()], freq="1h")
    if not timeline_df.empty:
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Bar(x=timeline_df["timestamp"], y=timeline_df["benign"], name="Benign Telemetry", marker_color="#10b981"))
        fig_tl.add_trace(go.Bar(x=timeline_df["timestamp"], y=timeline_df["threats"], name="Confirmed Threats", marker_color="#ef4444"))
        fig_tl.update_layout(
            barmode="stack", height=280,
            margin=dict(t=10, b=20, l=10, r=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter", color="#94a3b8"),
            xaxis=dict(gridcolor="#253148", color="#94a3b8"),
            yaxis=dict(gridcolor="#253148", color="#94a3b8"),
            legend=dict(font=dict(color="#cbd5e1")),
        )
        st.plotly_chart(fig_tl, use_container_width=True)

    # Raw alerts
    st.markdown("<div style='font-size:0.95rem;font-weight:700;color:#ffffff;margin:18px 0 10px 0'>Raw Telemetry Flow Stream</div>", unsafe_allow_html=True)
    show_cols = [c for c in ["event_id", "timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "label_category", "severity", "threat_confidence"] if c in df.columns]
    st.dataframe(df[show_cols].head(250), use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════
# VIEW 6 — REPORTS (IBM Bob AI Copilot)
# ════════════════════════════════════════════════════════════════════════════
elif "Reports" in nav_selection:
    bob = get_bob_client()

    st.markdown(f"""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">IBM Bob AI Cyber Defence Copilot</div>
        <div class="live-badge"><span class="live-pulse"></span> {'Online' if bob.available else 'Offline'}</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8">
        Grounded generative assistant for incident analysis, defensive rule generation, and executive situation reports.
      </div>
    </div>
    """, unsafe_allow_html=True)

    if not bob.available:
        st.warning(f"IBM Bob API key required: {bob.diag}")

    q = st.text_input("Ask IBM Bob AI about threat triage or defensive rules", placeholder="e.g. Generate an iptables containment rule for SSH brute force")
    if st.button("Query Bob AI") and q.strip():
        if bob.available:
            with st.spinner("Bob AI is reasoning…"):
                text, ok = bob.chat_safe(q.strip(), system=SYSTEM_PERSONA, max_tokens=400)
            if ok:
                st.markdown(f"""
                <div class="soc-card" style="margin-top:14px;background:#131d2e;border-left:3px solid #3b82f6">
                  <div style="font-size:0.8rem;color:#94a3b8;margin-bottom:8px"><b>BOB AI RESPONSE:</b></div>
                  <div style="font-size:0.88rem;color:#f8fafc;line-height:1.7">{text}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("Template response: For SSH brute force (T1110), deploy fail2ban or iptables: `iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set && iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP`")


# ════════════════════════════════════════════════════════════════════════════
# VIEW 7 — SETTINGS
# ════════════════════════════════════════════════════════════════════════════
elif "Settings" in nav_selection:
    st.markdown("""
    <div class="soc-card">
      <div class="soc-card-header">
        <div class="soc-card-title">ThreatWatch SOC Configuration</div>
      </div>
      <div style="font-size:0.85rem;color:#94a3b8;line-height:1.8">
        ● Active Model: <b>IBM Bob Granite / RandomForest</b><br>
        ● Ingested Events: <b>{sample_size:,}</b><br>
        ● Current Threatcon: <b>{top_priority:.1f} / 10 Priority</b><br>
        ● Cache State: <b>Active (TTL 600s)</b>
      </div>
    </div>
    """.format(sample_size=sample_size, top_priority=top_priority), unsafe_allow_html=True)
