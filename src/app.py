"""
Threat Intelligence Correlation & Alert Prioritisation Assistant
=================================================================
Streamlit Defence Command Center — Main Application Entry Point

Run:  streamlit run src/app.py
"""

import logging
import os
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
from threat_intel.mitre_stix import get_mitre, TACTIC_ORDER, BUILTIN_TECHNIQUES

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
# Custom CSS — dark command-centre aesthetic
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stAppViewContainer"] { background: #0d1117; color: #e6edf3; }
[data-testid="stSidebar"] { background: #161b22; border-right: 1px solid #30363d; }
[data-testid="stSidebar"] * { color: #e6edf3 !important; }
h1, h2, h3 { color: #58a6ff !important; }
h4, h5, h6 { color: #79c0ff !important; }
.metric-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    padding: 16px 20px; margin-bottom: 8px;
}
.bluf-box {
    background: #0d1117; border: 1px solid #388bfd; border-radius: 6px;
    padding: 16px; font-family: 'Courier New', monospace; font-size: 0.82rem;
    color: #c9d1d9; white-space: pre-wrap; max-height: 400px; overflow-y: auto;
}
.badge-severe  { background:#da3633; color:#fff; padding:2px 8px; border-radius:4px; }
.badge-critical{ background:#bd561d; color:#fff; padding:2px 8px; border-radius:4px; }
.badge-high    { background:#d29922; color:#000; padding:2px 8px; border-radius:4px; }
.badge-medium  { background:#388bfd; color:#fff; padding:2px 8px; border-radius:4px; }
.badge-low     { background:#2ea043; color:#fff; padding:2px 8px; border-radius:4px; }
.stTabs [data-baseweb="tab"] { color: #79c0ff; }
.stTabs [aria-selected="true"] { border-bottom: 2px solid #58a6ff; }
div[data-testid="metric-container"] {
    background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar — controls
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ SOC Platform")
    st.markdown("**Threat Intelligence Correlation**  \nAlert Prioritisation Assistant")
    st.markdown("---")

    sample_size = st.selectbox(
        "Dataset sample size",
        options=[5_000, 20_000, 50_000, 100_000, 244_471],
        index=2,
        format_func=lambda x: f"{x:,} events" if x < 244_471 else "Full dataset (244k)",
    )
    run_ml = st.checkbox("Enable ML classifier", value=True)
    st.markdown("---")
    force_refresh_ioc = st.button("🔄 Refresh URLhaus Feed")
    st.markdown("---")
    st.markdown("**Data Sources**")
    st.markdown("- `master_events.csv` (Zeek + IDS)")
    st.markdown("- Abuse.ch URLhaus IOC feed")
    st.markdown("- MITRE ATT&CK STIX 2.1")


# ─────────────────────────────────────────────────────────────────────────────
# Cached loaders
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner="Loading SIEM events…", ttl=600)
def _load_df(n: int) -> pd.DataFrame:
    df = load_events(sample_size=n if n < 244_471 else None)
    df = deduplicate(df)
    return df


@st.cache_resource(show_spinner="Loading threat intelligence feeds…")
def _load_intel(refresh: bool):
    feed = get_feed(force_refresh=refresh)
    mitre = get_mitre()
    return feed, mitre


@st.cache_resource(show_spinner="Training ML classifier…")
def _load_clf(n: int, enabled: bool):
    if not enabled:
        return None
    df = _load_df(n)
    return get_classifier(df=df)


@st.cache_data(show_spinner="Correlating incidents…", ttl=300)
def _correlate(n: int, refresh: bool):
    df = _load_df(n)
    feed, mitre = _load_intel(refresh)
    return correlate_incidents(df, feed=feed, mitre=mitre)


# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap
# ─────────────────────────────────────────────────────────────────────────────
with st.spinner("Loading platform…"):
    df = _load_df(sample_size)
    feed, mitre = _load_intel(force_refresh_ioc)
    clf = _load_clf(sample_size, run_ml)
    incidents = _correlate(sample_size, force_refresh_ioc)

# Attach ML confidence scores
if clf is not None:
    with st.spinner("Scoring events with ML classifier…"):
        df = clf.score_dataframe(df)
else:
    df["threat_confidence"] = df["label_binary"].astype(float) * 0.8

# Attach confidence to incidents from corresponding cluster data
threat_mean_conf = df[df["label_binary"] == 1]["threat_confidence"].mean() if len(df) else 0.5
for inc in incidents:
    src_rows = df[df["src_ip"] == inc["src_ip"]]
    if len(src_rows):
        inc["ml_confidence"] = float(src_rows["threat_confidence"].mean())
    else:
        inc["ml_confidence"] = threat_mean_conf

stats = summary_stats(df)

# ─────────────────────────────────────────────────────────────────────────────
# Header KPI bar
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ Threat Intelligence Correlation & Alert Prioritisation Platform")
st.markdown(f"*Analysed `{stats['total_events']:,}` events across "
            f"`{len(stats['datasets'])}` data sources · "
            f"`{len(incidents)}` active incidents correlated*")

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Total Events", f"{stats['total_events']:,}")
c2.metric("Threat Events", f"{stats['total_threats']:,}",
          delta=f"{100*stats['total_threats']/max(stats['total_events'],1):.1f}% ratio",
          delta_color="inverse")
c3.metric("Benign / FP Filtered", f"{stats['total_benign']:,}",
          delta=f"{stats['fp_reduction_pct']}% reduced")
c4.metric("High-Severity Alerts", f"{stats['high_severity']:,}", delta_color="inverse")
c5.metric("Correlated Incidents", f"{len(incidents)}")
c6.metric("IOC Feed Records", f"{feed.record_count:,}")

st.markdown("---")

# ─────────────────────────────────────────────────────────────────────────────
# Main Tabs
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📋 Commander's BLUF",
    "🔬 SOC Investigation Workbench",
    "🎯 MITRE ATT&CK Matrix",
    "🌐 Threat Intel & IOC Feed",
])


# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — Commander's Executive BLUF
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown("## 📋 Commander's Executive Intelligence Brief")

    # Executive summary paragraph
    exec_summary = generate_executive_summary(incidents, stats)
    st.info(exec_summary)

    # Threat level gauge
    if incidents:
        top_priority = max(i.get("priority_score", 0) for i in incidents)
        gauge_color = ("#da3633" if top_priority >= 8 else
                       "#bd561d" if top_priority >= 6 else
                       "#d29922" if top_priority >= 4 else "#2ea043")
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=top_priority,
            domain={"x": [0, 1], "y": [0, 1]},
            title={"text": "Peak Incident Priority Score", "font": {"color": "#c9d1d9"}},
            gauge={
                "axis": {"range": [0, 10], "tickcolor": "#c9d1d9"},
                "bar": {"color": gauge_color},
                "steps": [
                    {"range": [0, 3], "color": "#0d1117"},
                    {"range": [3, 6], "color": "#161b22"},
                    {"range": [6, 10], "color": "#1c2128"},
                ],
                "threshold": {
                    "line": {"color": "#da3633", "width": 3},
                    "thickness": 0.8,
                    "value": 7,
                },
            },
            number={"font": {"color": "#c9d1d9"}},
        ))
        fig_gauge.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"}, height=250, margin={"t": 40, "b": 0}
        )

        g_col, tbl_col = st.columns([1, 2])
        with g_col:
            st.plotly_chart(fig_gauge, use_container_width=True)
        with tbl_col:
            # Top-5 incidents table
            inc_rows = []
            for inc in incidents[:10]:
                ml_conf = inc.get("ml_confidence", threat_mean_conf)
                bluf = generate_bluf(inc, ml_conf)
                inc_rows.append({
                    "Incident ID": inc["incident_id"],
                    "Source IP": inc["src_ip"],
                    "Priority": f"{inc.get('priority_score', 0):.1f}/10",
                    "Threat Level": bluf["threat_badge"],
                    "Events": inc["event_count"],
                    "Tactics": ", ".join(inc.get("tactics", [])[:2]),
                    "Techniques": ", ".join(inc.get("techniques", [])[:2]),
                    "IOC Match": "✅ YES" if inc.get("ioc_hits") else "—",
                })
            st.markdown("#### Top Prioritised Incidents")
            st.dataframe(pd.DataFrame(inc_rows), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("#### 🗂️ Incident BLUF Reports")

    if not incidents:
        st.warning("No correlated incidents detected in the current sample. "
                   "Try increasing the dataset size.")
    else:
        selected_id = st.selectbox(
            "Select incident for detailed BLUF",
            options=[i["incident_id"] for i in incidents[:30]],
        )
        selected_inc = next((i for i in incidents if i["incident_id"] == selected_id), None)
        if selected_inc:
            ml_conf = selected_inc.get("ml_confidence", threat_mean_conf)
            bluf = generate_bluf(selected_inc, ml_conf)

            b1, b2, b3 = st.columns(3)
            b1.metric("Priority Score", f"{bluf['priority_score']:.1f}/10")
            b2.metric("Threat Level", bluf["threat_badge"])
            b3.metric("ML Confidence", f"{bluf['ml_confidence']*100:.0f}%")

            for section, body in bluf["sections"].items():
                with st.expander(f"▶ {section}", expanded=(section == "BOTTOM LINE")):
                    st.markdown(body)

            st.markdown("**Full BLUF Report (plain text)**")
            st.markdown(f"<div class='bluf-box'>{bluf['bluf_text']}</div>",
                        unsafe_allow_html=True)
            st.download_button(
                "⬇ Export BLUF Report",
                data=bluf["bluf_text"],
                file_name=f"BLUF_{selected_id}.txt",
                mime="text/plain",
            )


# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — SOC Investigation Workbench
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("## 🔬 SOC Analyst Investigation Workbench")

    # ── Filters ──────────────────────────────────────────────────────────
    f1, f2, f3 = st.columns(3)
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

    st.markdown(f"**{len(filtered):,} events** match current filters")

    # ── Alert timeline ────────────────────────────────────────────────────
    st.markdown("#### Alert Volume Timeline (1-hour bins)")
    timeline_df = alert_timeline(df[df["timestamp"].notna()], freq="1h")
    if not timeline_df.empty:
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Bar(
            x=timeline_df["timestamp"], y=timeline_df["benign"],
            name="Benign", marker_color="#2ea043", opacity=0.7,
        ))
        fig_tl.add_trace(go.Bar(
            x=timeline_df["timestamp"], y=timeline_df["threats"],
            name="Threats", marker_color="#da3633", opacity=0.9,
        ))
        fig_tl.update_layout(
            barmode="stack", paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"}, legend={"font": {"color": "#c9d1d9"}},
            xaxis={"title": "Time", "color": "#c9d1d9"},
            yaxis={"title": "Events", "color": "#c9d1d9"},
            height=280, margin={"t": 20, "b": 40},
        )
        st.plotly_chart(fig_tl, use_container_width=True)

    # ── Top Source IPs ────────────────────────────────────────────────────
    st.markdown("#### 🔎 Top Threat Source IPs")
    top_ips_df = top_source_ips(df, n=15)
    if not top_ips_df.empty:
        fig_ips = px.bar(
            top_ips_df, x="event_count", y="src_ip", orientation="h",
            color="max_severity", color_continuous_scale="Reds",
            labels={"event_count": "Threat Events", "src_ip": "Source IP"},
            title="Top Source IPs by Threat Volume",
        )
        fig_ips.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"}, height=420,
            yaxis={"autorange": "reversed", "color": "#c9d1d9"},
            xaxis={"color": "#c9d1d9"}, margin={"t": 40, "b": 20},
            coloraxis_colorbar={"tickfont": {"color": "#c9d1d9"}, "title": {"font": {"color": "#c9d1d9"}, "text": "Severity"}},
        )
        st.plotly_chart(fig_ips, use_container_width=True)

    # ── Category breakdown ────────────────────────────────────────────────
    st.markdown("#### Attack Category Distribution")
    cat_col, prot_col = st.columns(2)

    with cat_col:
        cat_counts = (
            df[df["label_binary"] == 1]["label_category"]
            .value_counts()
            .reset_index()
        )
        cat_counts.columns = ["Category", "Count"]
        fig_cat = px.pie(cat_counts, names="Category", values="Count",
                         color_discrete_sequence=px.colors.sequential.Reds_r,
                         title="Threat Categories")
        fig_cat.update_layout(
            paper_bgcolor="#0d1117", font={"color": "#c9d1d9"},
            legend={"font": {"color": "#c9d1d9"}}, height=350,
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    with prot_col:
        prot_counts = df["protocol"].value_counts().reset_index()
        prot_counts.columns = ["Protocol", "Count"]
        fig_prot = px.bar(prot_counts, x="Protocol", y="Count",
                          color="Protocol",
                          color_discrete_sequence=["#58a6ff", "#388bfd", "#79c0ff"],
                          title="Protocol Distribution")
        fig_prot.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"}, showlegend=False, height=350,
            xaxis={"color": "#c9d1d9"}, yaxis={"color": "#c9d1d9"},
        )
        st.plotly_chart(fig_prot, use_container_width=True)

    # ── ML Confidence distribution ────────────────────────────────────────
    if "threat_confidence" in df.columns and run_ml:
        st.markdown("#### ML Threat Confidence Score Distribution")
        fig_conf = px.histogram(
            df, x="threat_confidence", color="label_binary",
            nbins=50, barmode="overlay",
            color_discrete_map={0: "#2ea043", 1: "#da3633"},
            labels={"threat_confidence": "Threat Confidence", "label_binary": "True Label"},
            title="ML Classifier Confidence (0=Benign, 1=Threat)",
        )
        fig_conf.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"},
            legend={"font": {"color": "#c9d1d9"}},
            xaxis={"color": "#c9d1d9"}, yaxis={"color": "#c9d1d9"},
            height=300,
        )
        st.plotly_chart(fig_conf, use_container_width=True)

        # Feature importances
        if clf:
            fi = clf.feature_importances()
            if fi:
                fi_df = pd.DataFrame(fi).head(10)
                fig_fi = px.bar(fi_df, x="importance", y="feature", orientation="h",
                                color="importance",
                                color_continuous_scale="Blues",
                                title="Top ML Feature Importances")
                fig_fi.update_layout(
                    paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
                    font={"color": "#c9d1d9"}, height=320,
                    yaxis={"autorange": "reversed", "color": "#c9d1d9"},
                    xaxis={"color": "#c9d1d9"},
                    coloraxis_showscale=False,
                )
                st.plotly_chart(fig_fi, use_container_width=True)

    # ── Raw alert table ───────────────────────────────────────────────────
    st.markdown("#### 📄 Raw Alert Table (filtered)")
    cols_show = ["event_id", "timestamp", "src_ip", "dst_ip", "dst_port",
                 "protocol", "label_category", "mitre_tactic", "mitre_technique",
                 "severity", "threat_confidence", "source_dataset"]
    cols_present = [c for c in cols_show if c in filtered.columns]
    st.dataframe(
        filtered[cols_present].sort_values("severity", ascending=False).head(200),
        use_container_width=True, hide_index=True,
    )


# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — MITRE ATT&CK Matrix Navigator
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("## 🎯 MITRE ATT&CK Tactical Matrix Navigator")

    mitre_stats = mitre.stats()
    m1, m2, m3 = st.columns(3)
    m1.metric("Techniques in DB", mitre_stats["technique_count"])
    m2.metric("Tactics", mitre_stats["tactic_count"])
    m3.metric("Source", mitre_stats["source"])

    # Tactic × Technique heatmap
    pivot = tactic_technique_matrix(df)
    if not pivot.empty:
        st.markdown("#### Observed Technique Heatmap (event count)")
        fig_heat = px.treemap(
            pivot, path=["mitre_tactic", "mitre_technique"], values="count",
            color="count",
            color_continuous_scale="Reds",
            title="Attack Technique Coverage Across Tactical Kill-Chain",
        )
        fig_heat.update_layout(
            paper_bgcolor="#0d1117", font={"color": "#c9d1d9"},
            margin={"t": 40, "b": 0}, height=420,
        )
        st.plotly_chart(fig_heat, use_container_width=True)

        # Bar chart by tactic
        tac_counts = pivot.groupby("mitre_tactic")["count"].sum().reset_index()
        tac_counts = tac_counts.sort_values("count", ascending=False)
        fig_tac = px.bar(
            tac_counts, x="mitre_tactic", y="count",
            color="count", color_continuous_scale="Reds",
            title="Threat Events by MITRE ATT&CK Tactic",
            labels={"mitre_tactic": "Tactic", "count": "Event Count"},
        )
        fig_tac.update_layout(
            paper_bgcolor="#0d1117", plot_bgcolor="#0d1117",
            font={"color": "#c9d1d9"},
            xaxis={"color": "#c9d1d9", "tickangle": -30},
            yaxis={"color": "#c9d1d9"},
            coloraxis_showscale=False, height=350,
        )
        st.plotly_chart(fig_tac, use_container_width=True)

    # ── Technique detail cards ────────────────────────────────────────────
    st.markdown("#### 🔍 Technique Detail Lookup")
    observed_techs = sorted(
        t for t in df["mitre_technique"].dropna().unique()
        if isinstance(t, str) and t.strip() not in ("", "nan")
    )
    if observed_techs:
        sel_tech = st.selectbox("Select observed technique", observed_techs)
        tech = mitre.get_technique(sel_tech)
        if tech:
            tc1, tc2 = st.columns(2)
            with tc1:
                st.markdown(f"**ID:** `{tech['id']}`  \n**Name:** {tech['name']}")
                st.markdown(f"**Tactic(s):** {tech['tactic']}")
                st.markdown(f"**Platforms:** {', '.join(tech.get('platforms', []))}")
                st.markdown(f"**Description:**  \n{tech['description'][:400]}…")
            with tc2:
                st.markdown(f"**Detection:**  \n{tech.get('detection', 'N/A')[:300]}")
                if tech.get("mitigations"):
                    st.markdown("**Recommended Mitigations:**")
                    for m in tech["mitigations"][:5]:
                        st.markdown(f"- {m}")

    # Kill-chain progression radar
    st.markdown("#### ATT&CK Kill-Chain Tactic Progression")
    tac_event_counts = df[df["label_binary"] == 1]["mitre_tactic"].value_counts().to_dict()
    radar_tactics = [t for t in TACTIC_ORDER if t in tac_event_counts]
    radar_values = [tac_event_counts.get(t, 0) for t in radar_tactics]
    if radar_tactics:
        fig_radar = go.Figure(go.Scatterpolar(
            r=radar_values,
            theta=radar_tactics,
            fill="toself",
            line_color="#58a6ff",
            fillcolor="rgba(88,166,255,0.2)",
            name="Observed Events",
        ))
        fig_radar.update_layout(
            polar=dict(
                bgcolor="#0d1117",
                radialaxis=dict(visible=True, color="#c9d1d9"),
                angularaxis=dict(color="#c9d1d9"),
            ),
            paper_bgcolor="#0d1117", font={"color": "#c9d1d9"},
            height=400, margin={"t": 40, "b": 20},
            title="MITRE ATT&CK Kill-Chain Radar",
        )
        st.plotly_chart(fig_radar, use_container_width=True)


# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — Threat Intel & IOC Feed Explorer
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("## 🌐 Threat Intelligence & IOC Feed Explorer")

    feed_stats = feed.stats()
    i1, i2, i3, i4 = st.columns(4)
    i1.metric("URLhaus IOC Records", f"{feed_stats['total_records']:,}")
    i2.metric("Unique Malicious IPs", f"{feed_stats['unique_ips']:,}")
    i3.metric("Unique Malicious Hosts", f"{feed_stats['unique_hosts']:,}")
    i4.metric("Feed Updated", feed_stats["loaded_at"] or "Offline seed")

    # ── IP / Domain reputation lookup ─────────────────────────────────────
    st.markdown("#### 🔎 Reputation Lookup")
    lookup_col, result_col = st.columns([1, 2])
    with lookup_col:
        query_ip = st.text_input("Enter IP address", placeholder="e.g. 198.50.128.218")
        if query_ip:
            hits = feed.lookup_ip(query_ip.strip())
            if hits:
                st.error(f"⚠️ **MALICIOUS** — {len(hits)} IOC record(s) found")
                for h in hits[:5]:
                    st.markdown(f"- URL: `{h.get('url', 'N/A')}`  \n"
                                f"  Tags: `{h.get('tags', 'N/A')}`  |  "
                                f"Status: `{h.get('url_status', 'N/A')}`  |  "
                                f"Threat: `{h.get('threat', 'N/A')}`")
            else:
                st.success("✅ **CLEAN** — No URLhaus IOC records found")

    with result_col:
        # Cross-correlation: which observed IPs are in URLhaus?
        st.markdown("##### IOC Hits in Current Dataset")
        threat_ips = df[df["label_binary"] == 1]["src_ip"].dropna().unique()
        ioc_matches = []
        for ip in threat_ips[:500]:
            hits = feed.lookup_ip(ip)
            if hits:
                tags = ", ".join(
                    t.strip() for h in hits for t in (h.get("tags") or "").split(",") if t.strip()
                )
                ioc_matches.append({
                    "IP": ip,
                    "IOC Records": len(hits),
                    "Tags": tags[:60],
                    "Threat": hits[0].get("threat", ""),
                })
        if ioc_matches:
            st.dataframe(pd.DataFrame(ioc_matches), use_container_width=True, hide_index=True)
        else:
            st.info("No direct URLhaus IOC matches found in current sample IPs. "
                    "(URLhaus tracks specific malware hosting IPs — most C2/DDoS source "
                    "IPs differ by campaign. Try the full 244k dataset.)")

    # ── URLhaus feed sample ───────────────────────────────────────────────
    st.markdown("#### 📜 URLhaus Live Feed Sample (top 50 records)")
    if feed._records:
        feed_df = pd.DataFrame(feed._records[:50])
        display_cols = [c for c in ["url", "host", "ip", "tags", "url_status", "threat"]
                        if c in feed_df.columns]
        st.dataframe(feed_df[display_cols], use_container_width=True, hide_index=True)

    # ── MITRE ATT&CK data source status ───────────────────────────────────
    st.markdown("---")
    st.markdown("#### 📚 Intelligence Source Status")
    sources = {
        "master_events.csv": f"✅ Loaded — {stats['total_events']:,} events",
        "Abuse.ch URLhaus Feed": (
            f"✅ {feed_stats['total_records']:,} IOC records · "
            f"{feed_stats['unique_ips']:,} unique IPs · "
            f"Updated: {feed_stats['loaded_at'] or 'offline seed'}"
        ),
        "MITRE ATT&CK STIX 2.1": (
            f"✅ {mitre_stats['technique_count']} techniques · "
            f"{mitre_stats['tactic_count']} tactics · "
            f"Source: {mitre_stats['source']}"
        ),
        "ML Classifier": (
            f"✅ RandomForest trained on {sample_size:,} samples"
            if (clf and run_ml)
            else "⬜ Disabled (enable in sidebar)"
        ),
    }
    for src, status in sources.items():
        st.markdown(f"**{src}**: {status}")
