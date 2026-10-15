"""Dashboard over the pipeline's outputs (results/dashboard, exported from Hive). Run: uv run streamlit run ui/app.py"""
import json
import pathlib

import altair as alt
import pandas as pd
import streamlit as st

ROOT = pathlib.Path(__file__).resolve().parent.parent / "results"
DASH = ROOT / "dashboard"
st.set_page_config(page_title="Network Traffic Analyser", page_icon="🛰️", layout="wide")


@st.cache_data
def table(name):
    df = pd.read_parquet(DASH / name)
    return df.sort_values(df.columns[0]).reset_index(drop=True)


@st.cache_data
def metrics():
    return json.loads((ROOT / "metrics.json").read_text()), json.loads((ROOT / "feature_importance.json").read_text())


if not (DASH / "overview").exists():
    st.error("No pipeline output yet. Run `./run_pipeline.sh` first.")
    st.stop()

overview = table("overview")
SCEN = {r.scenario: f"{r.scenario} · {r.malware}" for r in overview.itertuples()}


def pick_capture(key):
    return st.selectbox("Capture", list(SCEN), format_func=SCEN.get, key=key)


def human(n):
    for unit in ("", "K", "M", "B"):
        if abs(n) < 1000:
            return f"{n:,.1f}{unit}" if unit else f"{n:,.0f}"
        n /= 1000
    return f"{n:,.1f}T"


def page_overview():
    st.title("Network Traffic Analyser")
    st.caption("Wireshark-style packet logs from four real CTU-13 captures (CTU Prague university network, "
               "with botnet-infected lab hosts) → HDFS → Pig → Hive → Spark MLlib.")
    o = overview
    c = st.columns(6)
    c[0].metric("Captures", len(o))
    c[1].metric("Packets (raw rows)", human(o.raw_rows.sum()))
    c[2].metric("Unique packets", human(o.packets.sum()), f"{human(o.duplicates.sum())} duplicates removed", delta_color="off", delta_arrow="off")
    c[3].metric("Flows", human(o.flows.sum()))
    c[4].metric("Bytes on wire", f"{o.bytes.sum() / 1e9:,.1f} GB")
    c[5].metric("Rejected rows", human(o.rejected.sum()), "ARP / IPv6 / malformed", delta_color="off", delta_arrow="off")

    st.subheader("Pipeline")
    st.graphviz_chart("""
digraph { rankdir=LR; node [shape=box, style="rounded,filled", fillcolor="#eef3fb", color="#4a6fa5", fontname="Helvetica", fontsize=11];
  pcap [label="CTU-13 pcaps\\n(.pcap.bz2)"]; csv [label="Wireshark CSV\\nNo., Time, Source,\\nDestination, Protocol, Length, Info"];
  hdfs [label="HDFS\\n/netlogs/raw", shape=cylinder]; pig [label="Pig on Tez\\nparse Info · reject · dedupe\\npackets → 1-min flows"];
  hive [label="Hive on Tez\\nlabels · reverse-flow join\\nhost-minute features · reports"];
  spark [label="Spark MLlib\\nLogReg · RandomForest\\nleave-one-capture-out"]; ui [label="This dashboard"];
  pcap -> csv -> hdfs -> pig -> hive -> spark -> hive -> ui; }""")

    st.subheader("Captures")
    show = o.assign(duration=(pd.to_datetime(o.last_ts) - pd.to_datetime(o.first_ts)).astype(str).str.replace("0 days ", ""))
    st.dataframe(show[["scenario", "malware", "raw_rows", "rejected", "duplicates", "packets", "flows", "bytes", "hosts",
                       "first_ts", "duration"]], hide_index=True, width="stretch")


def page_traffic():
    st.title("Traffic")
    s = pick_capture("traffic")
    t = table("traffic").query("scenario == @s").copy()
    t["minute"] = pd.to_datetime(t.minute).dt.tz_localize("UTC")
    t["other_pkts"] = t.pkts - t.botnet_pkts - t.normal_pkts
    long = t.melt("minute", ["other_pkts", "normal_pkts", "botnet_pkts"], "sender", "packets")
    long["sender"] = long.sender.map({"other_pkts": "background", "normal_pkts": "known normal hosts",
                                      "botnet_pkts": "infected hosts"})
    st.subheader("Packets per minute by sender")
    st.altair_chart(alt.Chart(long).mark_area().encode(
        x=alt.X("minute:T", title="UTC", scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M")), y=alt.Y("packets:Q", stack=True, title="packets / min"),
        color=alt.Color("sender:N", scale=alt.Scale(domain=["background", "known normal hosts", "infected hosts"],
                                                     range=["#9aa5b1", "#3b82f6", "#e4572e"])),
        tooltip=["minute:T", "sender:N", "packets:Q"]).properties(height=280), width="stretch")
    st.caption("Infected hosts alone, per minute:")
    st.altair_chart(alt.Chart(t).mark_line(color="#e4572e").encode(
        x=alt.X("minute:T", title="UTC", scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M")), y=alt.Y("botnet_pkts:Q", title="packets / min"),
        tooltip=["minute:T", "botnet_pkts:Q"]).properties(height=160), width="stretch")

    a, b = st.columns(2)
    with a:
        st.subheader("Protocol mix")
        p = table("protocols").query("scenario == @s")
        st.altair_chart(alt.Chart(p).mark_bar().encode(
            x=alt.X("pkts:Q", title="packets"), y=alt.Y("proto:N", sort="-x", title=None),
            color=alt.Color("proto:N", legend=None), tooltip=["proto", "pkts", "bytes", "flows"]).properties(height=180),
            width="stretch")
    with b:
        st.subheader("Top destination ports")
        tp = table("top_ports").query("scenario == @s").assign(port=lambda d: d.proto + "/" + d.dport.astype(str))
        st.altair_chart(alt.Chart(tp).mark_bar().encode(
            x=alt.X("flows:Q"), y=alt.Y("port:N", sort="-x", title=None),
            tooltip=["port", "flows", "pkts", "n_src"]).properties(height=380), width="stretch")

    st.subheader("Top talkers (by bytes sent)")
    tt = table("top_talkers").query("scenario == @s").sort_values("bytes", ascending=False)
    st.dataframe(tt[["ip", "label", "bytes", "pkts", "flows", "n_dst_ips"]].fillna({"label": ""}), hide_index=True,
                 width="stretch")


PROTO_COLOURS = {"TCP": "#e7e6ff", "UDP": "#daeeff", "ICMP": "#fce0ff"}


def page_packets():
    st.title("Packet log")
    st.caption("The raw input, exactly as it lands in HDFS: Wireshark's CSV export format. "
               "Sample: the first packets sent by infected host 147.32.84.165 in capture ctu52 (Rbot).")
    f = DASH / "sample_botnet_packets.csv"
    if not f.exists() or f.stat().st_size == 0:
        st.info("No packet sample exported.")
        return
    df = pd.read_csv(f, names=["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
    q = st.text_input("Display filter (substring match on any column)", placeholder="e.g. SYN, 6667, UDP, 53")
    if q:
        df = df[df.astype(str).apply(lambda r: r.str.contains(q, case=False, regex=False)).any(axis=1)]
    st.dataframe(df.style.apply(lambda r: [f"background-color: {PROTO_COLOURS.get(r.Protocol, '')}; color: #111"] * len(r),
                                axis=1), hide_index=True, width="stretch", height=640)


PROTOCOLS = {"temporal_70_30": "Known infection, later time — train on first 70% of each capture, test on last 30%",
             "leave_one_capture_out": "Unseen capture — train on 3 captures, test on the 4th (Rbot & NSIS are unseen families)"}


def page_detection():
    st.title("Botnet detection")
    m, imp = metrics()
    st.caption(f"A sample is one university host's behaviour in one minute (≥{m['min_pkts']} packets): flows, fan-out, "
               "unanswered SYNs, ports … Positives: known infected hosts. Negatives: known normal hosts plus unlabelled "
               "background hosts, so precision is a lower bound; *normal FPR* is measured on the verified normal hosts only.")
    proto = st.radio("Evaluation protocol", list(PROTOCOLS), format_func=PROTOCOLS.get)
    res = pd.DataFrame(m["results"]).query("protocol == @proto")
    pooled = res[res.test == "ALL (pooled)"].set_index("model")
    c = st.columns(3)
    for col, (name, r) in zip(c, pooled.iterrows()):
        col.metric(name.replace("_", " "), f"F1 {r.f1:.3f}",
                   f"P {r.precision:.3f} · R {r.recall:.3f} · normal FPR {r.normal_fpr:.3f}", delta_color="off", delta_arrow="off")

    per = res[res.test != "ALL (pooled)"]
    st.subheader("Per capture")
    metric = st.radio("Metric", ["f1", "auc_pr", "recall", "precision"], horizontal=True)
    st.altair_chart(alt.Chart(per.dropna(subset=[metric])).mark_bar().encode(
        x=alt.X("model:N", title=None, axis=alt.Axis(labels=False)), y=alt.Y(f"{metric}:Q", scale=alt.Scale(domain=[0, 1])),
        color=alt.Color("model:N"), column=alt.Column("test:N", title=None),
        tooltip=["test", "model", "precision", "recall", "f1", "auc_pr", "normal_fpr", "tp", "fp", "fn", "tn"])
        .properties(width=150, height=240))
    st.dataframe(res[["test", "model", "precision", "recall", "f1", "auc_pr", "normal_fpr", "tp", "fp", "fn", "tn"]],
                 hide_index=True, width="stretch")

    a, b = st.columns(2)
    with a:
        st.subheader("What the random forest looks at")
        st.altair_chart(alt.Chart(pd.DataFrame(imp[:12])).mark_bar(color="#4a6fa5").encode(
            x="importance:Q", y=alt.Y("feature:N", sort="-x", title=None)).properties(height=340), width="stretch")
    with b:
        st.subheader("Infected vs normal host, per minute (avg)")
        prof = table("label_profile").set_index("label").drop(columns="windows").T
        st.dataframe(prof.style.format("{:,.2f}"), width="stretch", height=420)

    st.subheader("Host-level verdicts (% of a labelled host's test minutes flagged)")
    v = table("host_verdicts").query("protocol == @proto")
    st.dataframe(v.pivot_table(index=["scenario", "ip", "label"], columns="model", values="flagged_pct").reset_index(),
                 hide_index=True, width="stretch")


def page_hunt():
    st.title("Threat hunt")
    st.caption("Every unlabelled university host (147.32.0.0/16) is scored by the leave-one-capture-out random forest that "
               "never saw its capture. These hosts have no ground truth — they are leads for an analyst, not verdicts.")
    s = pick_capture("hunt")
    h = table("suspicious_hosts").query("scenario == @s").sort_values(["flagged_windows", "max_p"], ascending=False)
    flagged = int((h.flagged_windows > 0).sum())
    st.metric("Hosts with at least one flagged minute", flagged)
    st.caption("Top 15 by flagged minutes, then by highest botnet probability in any minute.")
    st.dataframe(h.drop(columns="scenario"), hide_index=True, width="stretch",
                 column_config={"max_p": st.column_config.ProgressColumn("max p(botnet)", min_value=0, max_value=1),
                                "mean_p": st.column_config.ProgressColumn("mean p(botnet)", min_value=0, max_value=1)})


st.navigation([st.Page(page_overview, title="Overview", icon="🏠", url_path="overview", default=True),
               st.Page(page_traffic, title="Traffic", icon="📈", url_path="traffic"),
               st.Page(page_packets, title="Packet log", icon="📜", url_path="packets"),
               st.Page(page_detection, title="Detection", icon="🧪", url_path="detection"),
               st.Page(page_hunt, title="Threat hunt", icon="🔎", url_path="hunt")]).run()
