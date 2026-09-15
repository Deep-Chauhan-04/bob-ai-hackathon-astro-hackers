"""
Threat Intelligence Correlation & Alert Prioritisation Assistant
=================================================================
Streamlit Defence Command Center — Main Application Entry Point

Run:  streamlit run src/app.py
"""

import logging
import sys
from pathlib import Path

# ── Path setup so sibling modules resolve correctly ──────────────────────────
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
    page_title="SOC Threat Intelligence Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Design tokens & full CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Palette ────────────────────────────────────────────────────────────── */
:root {
  --bg:        #080c12;
  --surface:   #0d1117;
  --surface2:  #161b22;
  --surface3:  #1c2128;
  --border:    #21262d;
  --border2:   #30363d;
  --text:      #e6edf3;
  --muted:     #8b949e;
  --blue:      #388bfd;
  --blue-lt:   #58a6ff;
  --blue-dim:  #1f3358;
  --teal:      #39d353;
  --red:       #da3633;
  --red-dim:   #3d1c1c;
  --orange:    #d29922;
  --orange-dim:#2e2008;
  --purple:    #bc8cff;
  --glow-blue: 0 0 12px rgba(56,139,253,0.35);
  --glow-red:  0 0 12px rgba(218,54,51,0.4);
}

/* ── App shell ──────────────────────────────────────────────────────────── */
[data-testid="stAppViewContainer"] {
  background: var(--bg);
  color: var(--text);
  background-image:
    radial-gradient(ellipse at 10% 0%, rgba(56,139,253,0.04) 0%, transparent 60%),
    radial-gradient(ellipse at 90% 80%, rgba(188,140,255,0.03) 0%, transparent 55%);
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stMain"] > div { padding-top: 1rem; }

/* ── Sidebar ────────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
  background: var(--surface2) !important;
  border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }
[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stCheckbox label { color: var(--muted) !important; font-size: 0.8rem !important; }

/* ── Typography ─────────────────────────────────────────────────────────── */
h1 { color: var(--text) !important; font-size: 1.55rem !important; font-weight: 700 !important; letter-spacing: -0.3px; }
h2 { color: var(--blue-lt) !important; font-size: 1.15rem !important; font-weight: 600 !important; border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-bottom: 12px !important; }
h3, h4 { color: #79c0ff !important; font-weight: 600 !important; }
h5, h6 { color: var(--muted) !important; font-weight: 500 !important; }
p, li, span { color: var(--text) !important; }

/* ── Metrics ────────────────────────────────────────────────────────────── */
div[data-testid="metric-container"] {
  background: var(--surface2) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
  padding: 14px 16px !important;
  transition: border-color 0.2s;
}
div[data-testid="metric-container"]:hover { border-color: var(--blue-dim) !important; }
div[data-testid="metric-container"] label { color: var(--muted) !important; font-size: 0.72rem !important; text-transform: uppercase; letter-spacing: 0.6px; }
div[data-testid="metric-container"] [data-testid="stMetricValue"] { color: var(--text) !important; font-size: 1.6rem !important; font-weight: 700 !important; }
div[data-testid="metric-container"] [data-testid="stMetricDelta"] { font-size: 0.72rem !important; }

/* ── Tabs ───────────────────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
  background: var(--surface2) !important;
  border-radius: 10px !important;
  padding: 4px !important;
  gap: 2px !important;
  border: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
  background: transparent !important;
  color: var(--muted) !important;
  border-radius: 7px !important;
  padding: 7px 16px !important;
  font-size: 0.82rem !important;
  font-weight: 500 !important;
  border: none !important;
  transition: all 0.18s !important;
}
.stTabs [data-baseweb="tab"]:hover { background: var(--surface3) !important; color: var(--text) !important; }
.stTabs [aria-selected="true"] {
  background: var(--blue-dim) !important;
  color: var(--blue-lt) !important;
  border-bottom: none !important;
  box-shadow: var(--glow-blue) !important;
}
[data-testid="stTabsContent"] { padding-top: 20px !important; }

/* ── Buttons ────────────────────────────────────────────────────────────── */
.stButton > button {
  background: var(--blue-dim) !important;
  color: var(--blue-lt) !important;
  border: 1px solid var(--blue) !important;
  border-radius: 8px !important;
  padding: 7px 18px !important;
  font-size: 0.83rem !important;
  font-weight: 600 !important;
  transition: all 0.18s !important;
  letter-spacing: 0.2px;
}
.stButton > button:hover {
  background: var(--blue) !important;
  color: #fff !important;
  box-shadow: var(--glow-blue) !important;
  transform: translateY(-1px);
}
.stDownloadButton > button {
  background: var(--surface3) !important;
  color: var(--muted) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
  font-size: 0.78rem !important;
}
.stDownloadButton > button:hover { border-color: var(--blue) !important; color: var(--blue-lt) !important; }

/* ── Inputs ─────────────────────────────────────────────────────────────── */
.stTextInput input, .stSelectbox select,
[data-baseweb="select"] > div,
[data-baseweb="input"] > div {
  background: var(--surface2) !important;
  border: 1px solid var(--border2) !important;
  border-radius: 8px !important;
  color: var(--text) !important;
}
.stTextInput input:focus, [data-baseweb="input"] > div:focus-within {
  border-color: var(--blue) !important;
  box-shadow: var(--glow-blue) !important;
}
.stMultiSelect [data-baseweb="tag"] { background: var(--blue-dim) !important; color: var(--blue-lt) !important; }
.stSlider [data-baseweb="slider"] { color: var(--blue-lt) !important; }
.stCheckbox label { font-size: 0.83rem !important; color: var(--muted) !important; }

/* ── Dataframes ─────────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] > div, .dataframe-container {
  background: var(--surface2) !important;
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
  overflow: hidden;
}
[data-testid="stDataFrame"] th {
  background: var(--surface3) !important;
  color: var(--muted) !important;
  font-size: 0.72rem !important;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 1px solid var(--border2) !important;
}
[data-testid="stDataFrame"] td { color: var(--text) !important; font-size: 0.8rem !important; }
[data-testid="stDataFrame"] tr:hover td { background: var(--surface3) !important; }

/* ── Alerts / banners ───────────────────────────────────────────────────── */
[data-testid="stAlert"] {
  border-radius: 10px !important;
  border-left-width: 3px !important;
  font-size: 0.84rem !important;
}
[data-testid="stAlert"][data-baseweb="notification"] { border-left-color: var(--blue) !important; }

/* ── Expanders ──────────────────────────────────────────────────────────── */
details { background: var(--surface2) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; margin-bottom: 6px !important; }
details summary { color: var(--blue-lt) !important; font-weight: 600 !important; padding: 10px 14px !important; font-size: 0.85rem !important; }
details[open] { border-color: var(--blue-dim) !important; }

/* ── Custom cards ───────────────────────────────────────────────────────── */
.kpi-strip {
  display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 18px;
}
.kpi-card {
  flex: 1 1 140px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 16px;
  min-width: 120px;
}
.kpi-card .kpi-label {
  font-size: 0.68rem; color: var(--muted);
  text-transform: uppercase; letter-spacing: 0.7px; margin-bottom: 4px;
}
.kpi-card .kpi-value { font-size: 1.55rem; font-weight: 700; color: var(--text); line-height: 1; }
.kpi-card .kpi-sub { font-size: 0.7rem; color: var(--muted); margin-top: 3px; }
.kpi-card.red   { border-color: #3d1c1c; }  /* severity accent */
.kpi-card.blue  { border-color: var(--blue-dim); }
.kpi-card.green { border-color: #1a3d2e; }

.section-header {
  display: flex; align-items: center; gap: 8px;
  font-size: 0.78rem; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1px;
  margin: 20px 0 10px;
}
.section-header::after {
  content: ''; flex: 1; height: 1px; background: var(--border);
}

.bluf-box {
  background: var(--surface);
  border: 1px solid var(--blue);
  border-radius: 8px;
  padding: 18px;
  font-family: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
  font-size: 0.79rem;
  color: #c9d1d9;
  white-space: pre-wrap;
  max-height: 440px;
  overflow-y: auto;
  line-height: 1.6;
  box-shadow: inset 0 0 30px rgba(56,139,253,0.04);
}

.incident-card {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-left: 3px solid var(--blue);
  border-radius: 10px;
  padding: 14px 18px;
  margin-bottom: 8px;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.incident-card:hover { border-left-color: var(--blue-lt); box-shadow: var(--glow-blue); }
.incident-card.critical { border-left-color: var(--red) !important; }
.incident-card.critical:hover { box-shadow: var(--glow-red) !important; }

.badge {
  display: inline-block;
  padding: 2px 9px; border-radius: 20px;
  font-size: 0.68rem; font-weight: 700; letter-spacing: 0.4px;
  text-transform: uppercase;
}
.badge-severe   { background:#3d1c1c; color:#ff7b7b; border:1px solid #da3633; }
.badge-critical { background:#2e1a0c; color:#ffa657; border:1px solid #bd561d; }
.badge-high     { background:#2e2008; color:#e3b341; border:1px solid #d29922; }
.badge-medium   { background:#0d2044; color:#79c0ff; border:1px solid #388bfd; }
.badge-low      { background:#0a2618; color:#56d364; border:1px solid #2ea043; }
.badge-benign   { background:#1c2128; color:#8b949e; border:1px solid #30363d; }

.source-pill {
  display: inline-block;
  background: var(--surface3); border: 1px solid var(--border2);
  border-radius: 6px; padding: 3px 10px; font-size: 0.7rem; color: var(--muted);
  margin: 2px;
}

.conn-ok   { color: #56d364; font-weight: 600; }
.conn-fail { color: #ff7b7b; font-weight: 600; }

/* ── Sidebar brand block ────────────────────────────────────────────────── */
.sidebar-brand {
  padding: 6px 0 14px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 14px;
}
.sidebar-brand .brand-title {
  font-size: 1rem; font-weight: 700; color: var(--text); letter-spacing: -0.2px;
}
.sidebar-brand .brand-sub {
  font-size: 0.72rem; color: var(--muted); margin-top: 2px;
}

/* ── Plotly charts dark background propagation ──────────────────────────── */
.js-plotly-plot .plotly { background: transparent !important; }

/* ── Scrollbar ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--surface); }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Shared Plotly dark layout helper
# ─────────────────────────────────────────────────────────────────────────────
_DARK = dict(
    paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
    font=dict(color="#c9d1d9", size=11),
    legend=dict(font=dict(color="#c9d1d9"), bgcolor="rgba(0,0,0,0)", borderwidth=0),
    margin=dict(t=40, b=30, l=10, r=10),
    xaxis=dict(color="#8b949e", gridcolor="#21262d", linecolor="#30363d"),
    yaxis=dict(color="#8b949e", gridcolor="#21262d", linecolor="#30363d"),
    hoverlabel=dict(bgcolor="#161b22", font_color="#e6edf3", bordercolor="#388bfd"),
)

def _apply_dark(fig, height=320, **overrides):
    layout = dict(_DARK)
    layout["height"] = height
    layout.update(overrides)
    fig.update_layout(**layout)
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="sidebar-brand">
      <div class="brand-title">🛡️ SOC Platform</div>
      <div class="brand-sub">Threat Intelligence &amp; Alert Prioritisation</div>
    </div>
    """, unsafe_allow_html=True)

    sample_size = st.selectbox(
        "Dataset sample size",
        options=[5_000, 20_000, 50_000, 100_000, 244_471],
        index=2,
        format_func=lambda x: f"{x:,} events" if x < 244_471 else "Full dataset (244k)",
    )
    run_ml = st.checkbox("Enable ML classifier", value=True)

    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
    force_refresh_ioc = st.button("🔄  Refresh URLhaus Feed", use_container_width=True)

    st.markdown("""
    <div class="section-header">Intelligence Sources</div>
    <span class="source-pill">📁 master_events.csv</span>
    <span class="source-pill">🌐 Abuse.ch URLhaus</span>
    <span class="source-pill">🎯 MITRE ATT&CK</span>
    <span class="source-pill">🤖 IBM Bob AI</span>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Cached loaders
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner="Loading SIEM events…", ttl=600)
def _load_df(n: int) -> pd.DataFrame:
    df = load_events(sample_size=n if n < 244_471 else None)
    return deduplicate(df)


@st.cache_resource(show_spinner="Loading threat intelligence feeds…")
def _load_intel(refresh: bool):
    return get_feed(force_refresh=refresh), get_mitre()


@st.cache_resource(show_spinner="Training ML classifier…")
def _load_clf(n: int, enabled: bool):
    if not enabled:
        return None
    return get_classifier(df=_load_df(n))


@st.cache_data(show_spinner="Correlating incidents…", ttl=300)
def _correlate(n: int, refresh: bool):
    df = _load_df(n)
    feed, mitre = _load_intel(refresh)
    return correlate_incidents(df, feed=feed, mitre=mitre)


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────
with st.spinner("Loading platform…"):
    df        = _load_df(sample_size)
    feed, mitre = _load_intel(force_refresh_ioc)
    clf       = _load_clf(sample_size, run_ml)
    incidents = _correlate(sample_size, force_refresh_ioc)

if clf is not None:
    with st.spinner("Scoring events…"):
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


# ─────────────────────────────────────────────────────────────────────────────
# Top header
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">
  <div style="font-size:2rem">🛡️</div>
  <div>
    <div style="font-size:1.4rem;font-weight:700;color:#e6edf3;letter-spacing:-0.5px">
      Threat Intelligence Correlation &amp; Alert Prioritisation
    </div>
    <div style="font-size:0.78rem;color:#8b949e;margin-top:1px">
      Defence SOC Intelligence Platform · IBM Bob AI Powered
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

# KPI strip
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Total Events",       f"{stats['total_events']:,}")
c2.metric("Threat Events",      f"{stats['total_threats']:,}",
          delta=f"{100*stats['total_threats']/max(stats['total_events'],1):.1f}%",
          delta_color="inverse")
c3.metric("Noise Filtered",     f"{stats['total_benign']:,}",
          delta=f"{stats['fp_reduction_pct']}% reduction")
c4.metric("High-Severity",      f"{stats['high_severity']:,}", delta_color="inverse")
c5.metric("Active Incidents",   f"{len(incidents)}")
c6.metric("IOC Records",        f"{feed.record_count:,}")

st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Main tabs
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📋  Commander's BLUF",
    "🔬  SOC Workbench",
    "🎯  MITRE ATT&CK",
    "🌐  Threat Intel",
    "🤖  Bob AI Copilot",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — Commander's Executive BLUF
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("## 📋 Commander's Executive Intelligence Brief")

    # Executive summary banner
    exec_summary = generate_executive_summary(incidents, stats)
    st.markdown(f"""
    <div style="background:#0d1e38;border:1px solid #1f3358;border-left:3px solid #388bfd;
                border-radius:10px;padding:14px 18px;font-size:0.84rem;color:#c9d1d9;
                line-height:1.7;margin-bottom:16px">
      {exec_summary}
    </div>""", unsafe_allow_html=True)

    if incidents:
        top_priority = max(i.get("priority_score", 0) for i in incidents)
        crit_count   = sum(1 for i in incidents if i.get("priority_score", 0) >= 6)
        gauge_color  = ("#da3633" if top_priority >= 8 else
                        "#d29922" if top_priority >= 5 else "#2ea043")

        gauge_col, kpi_col, tbl_col = st.columns([1, 1, 2])

        with gauge_col:
            fig_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=top_priority,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "Peak Priority", "font": {"color": "#8b949e", "size": 11}},
                gauge={
                    "axis": {"range": [0, 10], "tickcolor": "#8b949e", "tickfont": {"size": 9}},
                    "bar": {"color": gauge_color, "thickness": 0.22},
                    "bgcolor": "#0d1117",
                    "bordercolor": "#21262d",
                    "steps": [
                        {"range": [0, 4],  "color": "#0a1628"},
                        {"range": [4, 7],  "color": "#1a1a0a"},
                        {"range": [7, 10], "color": "#1a0a0a"},
                    ],
                    "threshold": {"line": {"color": "#da3633", "width": 2},
                                  "thickness": 0.75, "value": 7},
                },
                number={"font": {"color": "#e6edf3", "size": 36}, "suffix": "/10"},
            ))
            _apply_dark(fig_g, height=220,
                        margin=dict(t=30, b=0, l=10, r=10))
            st.plotly_chart(fig_g, use_container_width=True)

        with kpi_col:
            st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
            badge_cls = "badge-severe" if top_priority >= 8 else "badge-high" if top_priority >= 5 else "badge-low"
            badge_txt = "SEVERE" if top_priority >= 8 else "HIGH" if top_priority >= 5 else "LOW"
            st.markdown(f"""
            <div class="incident-card {'critical' if top_priority>=6 else ''}">
              <div style="font-size:0.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.7px">Threat Posture</div>
              <div style="margin:6px 0"><span class="badge {badge_cls}">{badge_txt}</span></div>
              <div style="font-size:0.8rem;color:#8b949e">
                <b style="color:#e6edf3">{len(incidents)}</b> active incidents<br>
                <b style="color:#da3633">{crit_count}</b> critical / severe<br>
                <b style="color:#e6edf3">{stats['high_severity']:,}</b> high-sev alerts
              </div>
            </div>""", unsafe_allow_html=True)

        with tbl_col:
            inc_rows = []
            for inc in incidents[:10]:
                ml_conf = inc.get("ml_confidence", threat_mean_conf)
                bluf    = generate_bluf(inc, ml_conf)
                inc_rows.append({
                    "Incident":    inc["incident_id"],
                    "Source IP":   inc["src_ip"],
                    "Priority":    f"{inc.get('priority_score', 0):.1f}",
                    "Level":       bluf["threat_badge"],
                    "Events":      inc["event_count"],
                    "Tactics":     ", ".join(inc.get("tactics", [])[:2]),
                    "Techniques":  ", ".join(inc.get("techniques", [])[:2]),
                    "IOC":         "✅" if inc.get("ioc_hits") else "—",
                })
            st.markdown('<div class="section-header">Top Prioritised Incidents</div>',
                        unsafe_allow_html=True)
            st.dataframe(pd.DataFrame(inc_rows), use_container_width=True, hide_index=True)

    # ── Incident BLUF selector ────────────────────────────────────────────
    st.markdown('<div class="section-header">Incident BLUF Report</div>',
                unsafe_allow_html=True)

    if not incidents:
        st.markdown("""
        <div style="background:var(--surface2);border:1px dashed #30363d;border-radius:10px;
                    padding:28px;text-align:center;color:#8b949e;font-size:0.85rem">
          ⚠️  No correlated incidents in the current sample.
          Increase the dataset size in the sidebar.
        </div>""", unsafe_allow_html=True)
    else:
        sel_id  = st.selectbox("Select incident", [i["incident_id"] for i in incidents[:30]],
                               key="bluf_select")
        sel_inc = next((i for i in incidents if i["incident_id"] == sel_id), None)
        if sel_inc:
            ml_conf = sel_inc.get("ml_confidence", threat_mean_conf)
            bluf    = generate_bluf(sel_inc, ml_conf)

            b1, b2, b3, b4 = st.columns(4)
            b1.metric("Priority Score",  f"{bluf['priority_score']:.1f} / 10")
            b2.metric("Threat Level",    bluf["threat_badge"])
            b3.metric("ML Confidence",   f"{bluf['ml_confidence']*100:.0f}%")
            b4.metric("Corr. Events",    f"{sel_inc['event_count']:,}")

            for section, body in bluf["sections"].items():
                with st.expander(f"▶  {section}", expanded=(section == "BOTTOM LINE")):
                    st.markdown(body)

            st.markdown('<div class="section-header">Full BLUF Report</div>',
                        unsafe_allow_html=True)
            st.markdown(f"<div class='bluf-box'>{bluf['bluf_text']}</div>",
                        unsafe_allow_html=True)
            st.download_button("⬇  Export BLUF (.txt)", data=bluf["bluf_text"],
                               file_name=f"BLUF_{sel_id}.txt", mime="text/plain")


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — SOC Investigation Workbench
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("## 🔬 SOC Analyst Investigation Workbench")

    # ── Filter bar ───────────────────────────────────────────────────────
    f1, f2, f3 = st.columns([3, 1, 1])
    with f1:
        tactic_filter = st.multiselect(
            "Filter by tactic",
            options=sorted(df["mitre_tactic"].dropna().unique().tolist()),
            default=[],
        )
    with f2:
        severity_min = st.slider("Min severity", 0, 5, 0)
    with f3:
        show_threats_only = st.checkbox("Threats only", value=True)

    filtered = df.copy()
    if show_threats_only:
        filtered = filtered[filtered["label_binary"] == 1]
    if tactic_filter:
        filtered = filtered[filtered["mitre_tactic"].isin(tactic_filter)]
    if severity_min > 0:
        filtered = filtered[filtered["severity"] >= severity_min]

    st.markdown(
        f"<div style='font-size:0.8rem;color:#8b949e;margin-bottom:6px'>"
        f"<b style='color:#e6edf3'>{len(filtered):,}</b> events match current filters</div>",
        unsafe_allow_html=True,
    )

    # ── Alert timeline ────────────────────────────────────────────────────
    st.markdown('<div class="section-header">Alert Volume Timeline</div>',
                unsafe_allow_html=True)
    timeline_df = alert_timeline(df[df["timestamp"].notna()], freq="1h")
    if not timeline_df.empty:
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Bar(
            x=timeline_df["timestamp"], y=timeline_df["benign"],
            name="Benign", marker_color="#238636", opacity=0.75,
        ))
        fig_tl.add_trace(go.Bar(
            x=timeline_df["timestamp"], y=timeline_df["threats"],
            name="Threats", marker_color="#da3633", opacity=0.9,
        ))
        _apply_dark(fig_tl, height=260,
                    barmode="stack",
                    xaxis=dict(title="", color="#8b949e", gridcolor="#21262d"),
                    yaxis=dict(title="Events", color="#8b949e", gridcolor="#21262d"),
                    margin=dict(t=10, b=30, l=10, r=10))
        st.plotly_chart(fig_tl, use_container_width=True)

    # ── Top IPs + Category side by side ──────────────────────────────────
    ip_col, cat_col = st.columns([3, 2])

    with ip_col:
        st.markdown('<div class="section-header">Top Threat Source IPs</div>',
                    unsafe_allow_html=True)
        top_ips_df = top_source_ips(df, n=12)
        if not top_ips_df.empty:
            fig_ips = px.bar(
                top_ips_df, x="event_count", y="src_ip", orientation="h",
                color="max_severity", color_continuous_scale=["#1a3d2e", "#d29922", "#da3633"],
                labels={"event_count": "Threat Events", "src_ip": "Source IP"},
            )
            _apply_dark(fig_ips, height=380,
                        yaxis=dict(autorange="reversed", color="#8b949e", gridcolor="#21262d"),
                        xaxis=dict(color="#8b949e", gridcolor="#21262d"),
                        coloraxis_colorbar=dict(
                            tickfont=dict(color="#8b949e"), thickness=10,
                            title=dict(text="Sev", font=dict(color="#8b949e")),
                        ))
            st.plotly_chart(fig_ips, use_container_width=True)

    with cat_col:
        st.markdown('<div class="section-header">Attack Categories</div>',
                    unsafe_allow_html=True)
        cat_counts = (
            df[df["label_binary"] == 1]["label_category"]
            .value_counts().reset_index()
        )
        cat_counts.columns = ["Category", "Count"]
        fig_cat = px.pie(
            cat_counts, names="Category", values="Count",
            color_discrete_sequence=[
                "#da3633", "#388bfd", "#d29922", "#bc8cff",
                "#56d364", "#f78166", "#79c0ff", "#ffa657",
            ],
            hole=0.45,
        )
        fig_cat.update_traces(textposition="inside", textinfo="percent",
                              textfont_size=9)
        _apply_dark(fig_cat, height=380, margin=dict(t=10, b=10, l=10, r=10),
                    showlegend=True,
                    legend=dict(font=dict(size=9, color="#8b949e"), x=1, y=0.5))
        st.plotly_chart(fig_cat, use_container_width=True)

    # ── ML section ───────────────────────────────────────────────────────
    if "threat_confidence" in df.columns and run_ml:
        ml_left, ml_right = st.columns(2)

        with ml_left:
            st.markdown('<div class="section-header">ML Classifier Confidence Distribution</div>',
                        unsafe_allow_html=True)
            fig_conf = px.histogram(
                df, x="threat_confidence", color="label_binary",
                nbins=60, barmode="overlay",
                color_discrete_map={0: "#238636", 1: "#da3633"},
                labels={"threat_confidence": "Threat Confidence", "label_binary": "Label"},
                opacity=0.8,
            )
            _apply_dark(fig_conf, height=260,
                        xaxis=dict(title="Confidence Score", color="#8b949e", gridcolor="#21262d"),
                        yaxis=dict(title="Count", color="#8b949e", gridcolor="#21262d"))
            st.plotly_chart(fig_conf, use_container_width=True)

        with ml_right:
            if clf:
                fi = clf.feature_importances()
                if fi:
                    fi_df = pd.DataFrame(fi).head(10)
                    st.markdown('<div class="section-header">Top Feature Importances</div>',
                                unsafe_allow_html=True)
                    fig_fi = px.bar(
                        fi_df, x="importance", y="feature", orientation="h",
                        color="importance",
                        color_continuous_scale=["#0d2044", "#388bfd", "#79c0ff"],
                    )
                    _apply_dark(fig_fi, height=260,
                                yaxis=dict(autorange="reversed", color="#8b949e"),
                                xaxis=dict(title="Importance", color="#8b949e"),
                                coloraxis_showscale=False)
                    st.plotly_chart(fig_fi, use_container_width=True)

    # ── Protocol distribution ─────────────────────────────────────────────
    st.markdown('<div class="section-header">Protocol Distribution</div>',
                unsafe_allow_html=True)
    prot_counts = df["protocol"].value_counts().reset_index()
    prot_counts.columns = ["Protocol", "Count"]
    fig_prot = px.bar(
        prot_counts, x="Protocol", y="Count",
        color="Protocol",
        color_discrete_sequence=["#388bfd", "#56d364", "#bc8cff", "#ffa657"],
    )
    _apply_dark(fig_prot, height=200, showlegend=False,
                xaxis=dict(color="#8b949e", gridcolor="#21262d"),
                yaxis=dict(color="#8b949e", gridcolor="#21262d"))
    st.plotly_chart(fig_prot, use_container_width=True)

    # ── Raw alert table ───────────────────────────────────────────────────
    st.markdown('<div class="section-header">Raw Alert Table</div>',
                unsafe_allow_html=True)
    cols_show = ["event_id", "timestamp", "src_ip", "dst_ip", "dst_port",
                 "protocol", "label_category", "mitre_tactic", "mitre_technique",
                 "severity", "threat_confidence", "source_dataset"]
    cols_present = [c for c in cols_show if c in filtered.columns]
    st.dataframe(
        filtered[cols_present].sort_values("severity", ascending=False).head(200),
        use_container_width=True, hide_index=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — MITRE ATT&CK Matrix
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("## 🎯 MITRE ATT&CK Tactical Matrix Navigator")

    m1, m2, m3 = st.columns(3)
    m1.metric("Techniques in DB", mitre_stats["technique_count"])
    m2.metric("Tactics",          mitre_stats["tactic_count"])
    m3.metric("Source",           mitre_stats["source"])

    # Treemap + tactic bar
    pivot = tactic_technique_matrix(df)
    if not pivot.empty:
        heat_col, bar_col = st.columns([3, 2])
        with heat_col:
            st.markdown('<div class="section-header">Technique Coverage Treemap</div>',
                        unsafe_allow_html=True)
            fig_heat = px.treemap(
                pivot, path=["mitre_tactic", "mitre_technique"], values="count",
                color="count", color_continuous_scale=["#0d1117", "#388bfd", "#da3633"],
            )
            fig_heat.update_traces(
                textfont_size=11,
                marker=dict(cornerradius=3, pad=dict(t=4, l=4, r=4, b=4)),
            )
            _apply_dark(fig_heat, height=400,
                        margin=dict(t=10, b=10, l=10, r=10),
                        coloraxis_showscale=False)
            st.plotly_chart(fig_heat, use_container_width=True)

        with bar_col:
            st.markdown('<div class="section-header">Events by Tactic</div>',
                        unsafe_allow_html=True)
            tac_counts = pivot.groupby("mitre_tactic")["count"].sum().reset_index()
            tac_counts = tac_counts.sort_values("count", ascending=True)
            fig_tac = px.bar(
                tac_counts, x="count", y="mitre_tactic", orientation="h",
                color="count", color_continuous_scale=["#1f3358", "#388bfd", "#da3633"],
                labels={"mitre_tactic": "", "count": "Events"},
            )
            _apply_dark(fig_tac, height=400,
                        coloraxis_showscale=False,
                        xaxis=dict(title="Event Count", color="#8b949e", gridcolor="#21262d"),
                        yaxis=dict(color="#8b949e"),
                        margin=dict(t=10, b=30, l=10, r=10))
            st.plotly_chart(fig_tac, use_container_width=True)

    # Kill-chain radar + technique detail side by side
    radar_col, detail_col = st.columns([1, 1])

    with radar_col:
        st.markdown('<div class="section-header">Kill-Chain Tactic Radar</div>',
                    unsafe_allow_html=True)
        tac_event_counts = df[df["label_binary"] == 1]["mitre_tactic"].value_counts().to_dict()
        radar_tactics = [t for t in TACTIC_ORDER if t in tac_event_counts]
        radar_values  = [tac_event_counts.get(t, 0) for t in radar_tactics]
        if radar_tactics:
            fig_radar = go.Figure(go.Scatterpolar(
                r=radar_values, theta=radar_tactics,
                fill="toself", name="Observed",
                line=dict(color="#388bfd", width=2),
                fillcolor="rgba(56,139,253,0.15)",
            ))
            fig_radar.update_layout(
                polar=dict(
                    bgcolor="#0d1117",
                    radialaxis=dict(visible=True, color="#8b949e", gridcolor="#21262d"),
                    angularaxis=dict(color="#8b949e"),
                ),
                paper_bgcolor="#0d1117", font=dict(color="#c9d1d9"),
                height=360, showlegend=False,
                margin=dict(t=20, b=20, l=20, r=20),
                hoverlabel=dict(bgcolor="#161b22", font_color="#e6edf3"),
            )
            st.plotly_chart(fig_radar, use_container_width=True)

    with detail_col:
        st.markdown('<div class="section-header">Technique Detail Lookup</div>',
                    unsafe_allow_html=True)
        observed_techs = sorted(
            t for t in df["mitre_technique"].dropna().unique()
            if isinstance(t, str) and t.strip() not in ("", "nan")
        )
        if observed_techs:
            sel_tech = st.selectbox("Select technique", observed_techs, key="tech_select")
            tech = mitre.get_technique(sel_tech)
            if tech:
                st.markdown(f"""
                <div class="incident-card">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px">
                    <div>
                      <span style="font-family:monospace;color:#79c0ff;font-size:0.85rem;font-weight:700">{tech['id']}</span>
                      <span style="color:#e6edf3;font-weight:600;font-size:0.9rem;margin-left:8px">{tech['name']}</span>
                    </div>
                    <span class="badge badge-medium">{tech['tactic'].split(' / ')[0]}</span>
                  </div>
                  <div style="font-size:0.78rem;color:#8b949e;margin-bottom:8px">
                    <b style="color:#c9d1d9">Platforms:</b> {', '.join(tech.get('platforms', [])[:4])}
                  </div>
                  <div style="font-size:0.78rem;color:#c9d1d9;line-height:1.6;margin-bottom:8px">
                    {tech['description'][:320]}…
                  </div>
                </div>""", unsafe_allow_html=True)
                if tech.get("mitigations"):
                    st.markdown('<div style="font-size:0.75rem;color:#8b949e;font-weight:600;'
                                'text-transform:uppercase;letter-spacing:.6px;margin:8px 0 4px">Mitigations</div>',
                                unsafe_allow_html=True)
                    for mit in tech["mitigations"][:4]:
                        st.markdown(
                            f"<div style='font-size:0.79rem;color:#c9d1d9;padding:3px 0;"
                            f"border-left:2px solid #388bfd;padding-left:8px;margin-bottom:3px'>"
                            f"{mit}</div>",
                            unsafe_allow_html=True,
                        )


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — Threat Intel & IOC Feed
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("## 🌐 Threat Intelligence & IOC Feed Explorer")

    i1, i2, i3, i4 = st.columns(4)
    i1.metric("URLhaus Records",   f"{feed_stats['total_records']:,}")
    i2.metric("Malicious IPs",     f"{feed_stats['unique_ips']:,}")
    i3.metric("Malicious Hosts",   f"{feed_stats['unique_hosts']:,}")
    i4.metric("Feed Updated",      feed_stats["loaded_at"] or "Offline seed")

    # Lookup + cross-correlation
    st.markdown('<div class="section-header">IP Reputation Lookup</div>',
                unsafe_allow_html=True)
    lk_col, res_col = st.columns([1, 2])

    with lk_col:
        query_ip = st.text_input("Enter IP address", placeholder="e.g. 198.50.128.218",
                                 key="ip_lookup")
        if query_ip:
            hits = feed.lookup_ip(query_ip.strip())
            if hits:
                st.markdown(f"""
                <div style="background:#3d1c1c;border:1px solid #da3633;border-radius:8px;
                            padding:10px 14px;font-size:0.82rem;color:#ff7b7b;margin-top:6px">
                  ⚠️ <b>MALICIOUS</b> — {len(hits)} IOC record(s) found
                </div>""", unsafe_allow_html=True)
                for h in hits[:3]:
                    st.markdown(
                        f"<div style='font-size:0.75rem;color:#8b949e;padding:4px 0;"
                        f"border-bottom:1px solid #21262d'>"
                        f"<code style='color:#79c0ff'>{h.get('url','N/A')[:60]}</code><br>"
                        f"Tags: <b style='color:#ffa657'>{h.get('tags','—')}</b> · "
                        f"Status: {h.get('url_status','—')} · {h.get('threat','—')}"
                        f"</div>",
                        unsafe_allow_html=True,
                    )
            else:
                st.markdown("""
                <div style="background:#0a2618;border:1px solid #2ea043;border-radius:8px;
                            padding:10px 14px;font-size:0.82rem;color:#56d364;margin-top:6px">
                  ✅ <b>CLEAN</b> — No URLhaus IOC records found
                </div>""", unsafe_allow_html=True)

    with res_col:
        st.markdown('<div class="section-header">IOC Hits in Current Dataset</div>',
                    unsafe_allow_html=True)
        threat_ips = df[df["label_binary"] == 1]["src_ip"].dropna().unique()
        ioc_matches = []
        for ip in threat_ips[:500]:
            h_list = feed.lookup_ip(ip)
            if h_list:
                tags = ", ".join(
                    t.strip() for h in h_list
                    for t in (h.get("tags") or "").split(",") if t.strip()
                )
                ioc_matches.append({
                    "IP": ip, "IOC Records": len(h_list),
                    "Tags": tags[:60], "Threat": h_list[0].get("threat", ""),
                })
        if ioc_matches:
            st.dataframe(pd.DataFrame(ioc_matches), use_container_width=True, hide_index=True)
        else:
            st.markdown("""
            <div style="background:#161b22;border:1px dashed #30363d;border-radius:8px;
                        padding:16px;font-size:0.82rem;color:#8b949e;text-align:center">
              No direct URLhaus matches in current sample IPs.<br>
              <span style="font-size:0.74rem">URLhaus tracks malware-hosting URLs —
              DDoS/brute-force IPs differ by campaign.</span>
            </div>""", unsafe_allow_html=True)

    # URLhaus feed sample
    st.markdown('<div class="section-header">Live URLhaus Feed Sample (top 50)</div>',
                unsafe_allow_html=True)
    if feed._records:
        feed_df = pd.DataFrame(feed._records[:50])
        display_cols = [c for c in ["url", "host", "ip", "tags", "url_status", "threat"]
                        if c in feed_df.columns]
        st.dataframe(feed_df[display_cols], use_container_width=True, hide_index=True)

    # Source status cards
    st.markdown('<div class="section-header">Intelligence Source Status</div>',
                unsafe_allow_html=True)
    src_data = [
        ("📁", "SIEM Telemetry",       f"{stats['total_events']:,} events ingested",   True),
        ("🌐", "Abuse.ch URLhaus",
         f"{feed_stats['total_records']:,} IOCs · {feed_stats['unique_ips']:,} IPs · {feed_stats['loaded_at'] or 'offline'}",
         True),
        ("🎯", "MITRE ATT&CK STIX 2.1",
         f"{mitre_stats['technique_count']} techniques · {mitre_stats['tactic_count']} tactics · {mitre_stats['source']}",
         True),
        ("🤖", "ML Classifier",
         f"RandomForest · {sample_size:,} samples" if (clf and run_ml) else "Disabled",
         clf is not None and run_ml),
    ]
    sc1, sc2 = st.columns(2)
    for i, (icon, name, detail, ok) in enumerate(src_data):
        col = sc1 if i % 2 == 0 else sc2
        dot = '<span class="conn-ok">●</span>' if ok else '<span class="conn-fail">●</span>'
        col.markdown(f"""
        <div class="incident-card" style="margin-bottom:8px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:0.85rem;font-weight:600;color:#e6edf3">{icon}  {name}</span>
            {dot}
          </div>
          <div style="font-size:0.75rem;color:#8b949e;margin-top:4px">{detail}</div>
        </div>""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — IBM Bob AI Copilot
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown("## 🤖 IBM Bob AI Copilot — Incident Intelligence")
    st.markdown(
        "<div style='font-size:0.82rem;color:#8b949e;margin-bottom:12px'>"
        "Dynamic threat explanations, BLUF summaries, prioritised recommendations, "
        "and free-form Q&A — all grounded strictly in pipeline data.</div>",
        unsafe_allow_html=True,
    )

    # ── Bob availability banner ───────────────────────────────────────────
    @st.cache_resource(show_spinner=False)
    def _get_bob():
        return get_bob_client()

    bob = _get_bob()

    if not bob.available:
        diag = bob.diag or "Set `BOB_INFERENCE_API_KEY` in `src/.env` and restart the app."
        st.markdown(f"""
        <div style="background:#2e1a0c;border:1px solid #d29922;border-left:3px solid #ffa657;
                    border-radius:10px;padding:12px 16px;font-size:0.82rem;color:#ffa657;
                    margin-bottom:8px">
          ⚠️ <b>Bob AI layer offline</b> — {diag}
        </div>
        <div style="font-size:0.75rem;color:#8b949e;margin-bottom:12px">
          Template-based BLUF is still available on the Commander's BLUF tab.
          General SOC Q&A remains available below when Bob is connected.
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="background:#0a2618;border:1px solid #2ea043;border-left:3px solid #56d364;
                    border-radius:10px;padding:12px 16px;font-size:0.82rem;color:#56d364;
                    margin-bottom:12px">
          ✅ <b>IBM Bob connected</b> &nbsp;·&nbsp; model: <code>{bob.model}</code>
          &nbsp;·&nbsp; endpoint: <code>{bob._base_url}</code>
        </div>""", unsafe_allow_html=True)

    def _show_bob_result(text: str, ok: bool, download_name: str = "") -> None:
        if ok:
            if download_name:
                st.markdown(f"<div class='bluf-box'>{text}</div>", unsafe_allow_html=True)
                st.download_button("⬇  Export", data=text,
                                   file_name=download_name, mime="text/plain")
            else:
                st.markdown(
                    f"<div style='background:#0d1e38;border:1px solid #1f3358;border-radius:8px;"
                    f"padding:14px 18px;font-size:0.83rem;color:#c9d1d9;line-height:1.7'>"
                    f"{text}</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(f"""
            <div style="background:#3d1c1c;border:1px solid #da3633;border-radius:8px;
                        padding:12px 16px;font-size:0.82rem;color:#ff7b7b">
              ⚠️ <b>Bob could not respond:</b> {text}
            </div>""", unsafe_allow_html=True)

    # ── Incident features ─────────────────────────────────────────────────
    if incidents:
        st.markdown('<div class="section-header">Incident Analysis</div>',
                    unsafe_allow_html=True)
        bob_incident_id = st.selectbox(
            "Select incident",
            options=[i["incident_id"] for i in incidents[:30]],
            key="bob_incident_selector",
        )
        bob_inc     = next((i for i in incidents if i["incident_id"] == bob_incident_id), None)

        if bob_inc:
            bob_ml_conf = bob_inc.get("ml_confidence", threat_mean_conf)

            bm1, bm2, bm3, bm4 = st.columns(4)
            bm1.metric("Source IP",     bob_inc["src_ip"])
            bm2.metric("Priority",      f"{bob_inc.get('priority_score', 0):.1f} / 10")
            bm3.metric("ML Confidence", f"{bob_ml_conf*100:.0f}%")
            bm4.metric("Events",        f"{bob_inc['event_count']:,}")

            st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

            b_tab1, b_tab2, b_tab3, b_tab4 = st.tabs([
                "🔍  Threat Explanation",
                "📋  Dynamic BLUF",
                "⚡  Recommendations",
                "💬  Incident Q&A",
            ])

            with b_tab1:
                st.markdown("#### Why is this incident a genuine threat?")
                if not bob.available:
                    st.info("Connect IBM Bob (see status above) to get AI explanations.")
                elif st.button("🔍  Generate Threat Explanation", key="btn_explain"):
                    with st.spinner("Bob is analysing the incident…"):
                        prompt = build_threat_explanation_prompt(bob_inc, bob_ml_conf)
                        text, ok = bob.chat_safe(prompt, system=SYSTEM_PERSONA,
                                                 max_tokens=500, temperature=0.2)
                    _show_bob_result(text, ok)
                else:
                    st.caption("Click to generate a Bob AI threat explanation.")

            with b_tab2:
                st.markdown("#### Bob-generated BLUF Intelligence Brief")
                if not bob.available:
                    st.info("Connect IBM Bob (see status above) to get AI-generated BLUF.")
                elif st.button("📋  Generate Dynamic BLUF", key="btn_bluf"):
                    with st.spinner("Bob is writing the intelligence brief…"):
                        prompt = build_bluf_prompt(bob_inc, bob_ml_conf)
                        text, ok = bob.chat_safe(prompt, system=SYSTEM_PERSONA,
                                                 max_tokens=700, temperature=0.15)
                    _show_bob_result(text, ok,
                                     download_name=f"BOB_BLUF_{bob_incident_id}.txt")
                else:
                    st.caption("Click to generate a Bob AI BLUF brief.")

            with b_tab3:
                st.markdown("#### Prioritised Analyst Action Plan")
                if not bob.available:
                    st.info("Connect IBM Bob (see status above) to get AI recommendations.")
                elif st.button("⚡  Generate Action Plan", key="btn_recs"):
                    with st.spinner("Bob is formulating actions…"):
                        prompt = build_recommendations_prompt(bob_inc, bob_ml_conf)
                        text, ok = bob.chat_safe(prompt, system=SYSTEM_PERSONA,
                                                 max_tokens=500, temperature=0.2)
                    _show_bob_result(text, ok)
                else:
                    st.caption("Click to generate a Bob AI action plan.")

            with b_tab4:
                st.markdown("#### Ask Bob about this incident")
                if not bob.available:
                    st.info("Connect IBM Bob (see status above) to use Q&A.")
                else:
                    question = st.text_input(
                        "Your question",
                        placeholder="e.g. What protocol was used? Is this a DDoS? "
                                    "Should we block the source IP immediately?",
                        key="bob_incident_qa_input",
                    )
                    if st.button("💬  Ask Bob", key="btn_incident_qa"):
                        if not question.strip():
                            st.warning("Please enter a question first.")
                        else:
                            with st.spinner("Bob is answering…"):
                                prompt = build_qa_prompt(bob_inc, bob_ml_conf, question)
                                text, ok = bob.chat_safe(prompt, system=SYSTEM_PERSONA,
                                                         max_tokens=300, temperature=0.2)
                            if ok:
                                st.markdown(
                                    f"<div style='font-size:0.8rem;color:#8b949e;margin-bottom:4px'>"
                                    f"<b style='color:#e6edf3'>Q:</b> {question}</div>",
                                    unsafe_allow_html=True,
                                )
                            _show_bob_result(text, ok)
                    else:
                        st.caption("Bob answers using only incident data — no hallucinated facts.")
    else:
        st.markdown("""
        <div style="background:#161b22;border:1px dashed #30363d;border-radius:10px;
                    padding:22px;text-align:center;color:#8b949e;font-size:0.84rem;margin-bottom:12px">
          ℹ️ No correlated incidents in the current sample.<br>
          Increase dataset size in the sidebar, then use General SOC Q&A below.
        </div>""", unsafe_allow_html=True)

    # ── General SOC Q&A ───────────────────────────────────────────────────
    st.markdown('<div class="section-header">General SOC Q&A</div>', unsafe_allow_html=True)
    st.caption("Ask Bob any cybersecurity or SOC question — not tied to a specific incident.")

    if not bob.available:
        st.markdown("""
        <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;
                    padding:12px 16px;font-size:0.82rem;color:#8b949e">
          Set <code>BOB_INFERENCE_API_KEY</code> in <code>src/.env</code> and restart to enable Q&A.
        </div>""", unsafe_allow_html=True)
    else:
        general_q = st.text_input(
            "Ask a general question",
            placeholder="e.g. What is T1110 Brute Force? How do I detect C2 beaconing?",
            key="bob_general_qa_input",
        )
        if st.button("💬  Ask Bob", key="btn_general_qa"):
            if not general_q.strip():
                st.warning("Please enter a question first.")
            else:
                with st.spinner("Bob is answering…"):
                    text, ok = bob.chat_safe(
                        general_q.strip(), system=SYSTEM_PERSONA,
                        max_tokens=400, temperature=0.3,
                    )
                if ok:
                    st.markdown(
                        f"<div style='font-size:0.8rem;color:#8b949e;margin-bottom:4px'>"
                        f"<b style='color:#e6edf3'>Q:</b> {general_q}</div>",
                        unsafe_allow_html=True,
                    )
                _show_bob_result(text, ok)
        else:
            st.caption("Click Ask Bob to get an answer.")
