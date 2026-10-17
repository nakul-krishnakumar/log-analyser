"""Dashboard: analyse an uploaded capture step by step, and browse the CTU-13 study (results/dashboard, exported from Hive).

    uv run streamlit run ui/app.py
"""
import datetime as dt
import json
import os
import pathlib
import re
import socket
import subprocess
import time

import altair as alt
import pandas as pd
import streamlit as st

PROJECT = pathlib.Path(__file__).resolve().parent.parent
ROOT = PROJECT / "results"
DASH = ROOT / "dashboard"
UPLOADS = ROOT / "uploads"
st.set_page_config(page_title="Network Traffic Analyser", page_icon="🛰️", layout="wide")


@st.cache_data
def table(name, base=DASH):
    df = pd.read_parquet(base / name)
    return df.sort_values(df.columns[0]).reset_index(drop=True)


@st.cache_data
def metrics():
    return json.loads((ROOT / "metrics.json").read_text()), json.loads((ROOT / "feature_importance.json").read_text())


HAS_STUDY = (DASH / "overview").exists()
overview = table("overview") if HAS_STUDY else None
SCEN = {r.scenario: f"{r.scenario} · {r.malware}" for r in overview.itertuples()} if HAS_STUDY else {}


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
    traffic_charts(DASH, pick_capture("traffic"))


def traffic_charts(base, s):
    t = table("traffic", base).query("scenario == @s").copy()
    t["minute"] = pd.to_datetime(t.minute).dt.tz_localize("UTC")
    t["other_pkts"] = t.pkts - t.botnet_pkts - t.normal_pkts
    long = t.melt("minute", ["other_pkts", "normal_pkts", "botnet_pkts"], "sender", "packets")
    long["sender"] = long.sender.map({"other_pkts": "unlabelled hosts", "normal_pkts": "known normal hosts",
                                      "botnet_pkts": "infected hosts"})
    st.subheader("Packets per minute by sender")
    st.altair_chart(alt.Chart(long).mark_area().encode(
        x=alt.X("minute:T", title="UTC", scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M")), y=alt.Y("packets:Q", stack=True, title="packets / min"),
        color=alt.Color("sender:N", scale=alt.Scale(domain=["unlabelled hosts", "known normal hosts", "infected hosts"],
                                                     range=["#9aa5b1", "#3b82f6", "#e4572e"])),
        tooltip=["minute:T", "sender:N", "packets:Q"]).properties(height=280), width="stretch")
    if t.botnet_pkts.sum() > 0:
        st.caption("Infected hosts alone, per minute:")
        st.altair_chart(alt.Chart(t).mark_line(color="#e4572e").encode(
            x=alt.X("minute:T", title="UTC", scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M")), y=alt.Y("botnet_pkts:Q", title="packets / min"),
            tooltip=["minute:T", "botnet_pkts:Q"]).properties(height=160), width="stretch")

    a, b = st.columns(2)
    with a:
        st.subheader("Protocol mix")
        p = table("protocols", base).query("scenario == @s")
        st.altair_chart(alt.Chart(p).mark_bar().encode(
            x=alt.X("pkts:Q", title="packets"), y=alt.Y("proto:N", sort="-x", title=None),
            color=alt.Color("proto:N", legend=None), tooltip=["proto", "pkts", "bytes", "flows"]).properties(height=180),
            width="stretch")
    with b:
        st.subheader("Top destination ports")
        tp = table("top_ports", base).query("scenario == @s").assign(port=lambda d: d.proto + "/" + d.dport.astype(str))
        st.altair_chart(alt.Chart(tp).mark_bar().encode(
            x=alt.X("flows:Q"), y=alt.Y("port:N", sort="-x", title=None),
            tooltip=["port", "flows", "pkts", "n_src"]).properties(height=380), width="stretch")

    st.subheader("Top talkers (by bytes sent)")
    tt = table("top_talkers", base).query("scenario == @s").sort_values("bytes", ascending=False)
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


SAMPLE = PROJECT / "data/net/ctu46.truncated.pcap.bz2"
CAPTURE_TYPES = ["pcap", "pcapng", "cap", "gz", "bz2"]
STEPS = [
    ("ingest", "Read the capture", "Every packet becomes one Wireshark-style log line "
     "(No., Time, Source, Destination, Protocol, Length, Info), streamed into HDFS.", r"Found \d+ items"),
    ("pig", "Clean it and build flows · Apache Pig", "Pig reads the Info column (ports, TCP flags, payload size), drops "
     "anything that is not IPv4 TCP/UDP/ICMP, removes duplicate packets and groups packets into one-minute flows.",
     r"records in _0_(flows|rejects)=\d+"),
    ("hive", "Describe each host's behaviour · Apache Hive", "Hive matches every flow with its reply, then summarises each "
     "host minute by minute: how many machines it contacted, how many connections went unanswered, which ports it used.",
     None),
    ("score", "Look for botnet behaviour · Spark MLlib", "A random forest trained on real botnet traffic (CTU-13) scores "
     "every host-minute and flags the ones that behave like infected machines.", r"scored \d+ active hosts.*"),
    ("export", "Prepare the report", "Results are copied from HDFS for this page.", None),
]


def services_up():
    """HDFS, YARN and HiveServer2 accept connections."""
    for port in (9000, 8032, 10000):
        try:
            socket.create_connection(("localhost", port), timeout=0.5).close()
        except OSError:
            return False
    return True


def shell(cmd):
    return subprocess.run(["bash", "-c", f"source ~/hive-lab/bin/hive-env-lab.sh && {cmd}"], capture_output=True, text=True)


def capture_name(filename):
    """A safe name for HDFS paths, the Hive database and Pig: lowercase letters, digits and _ only, made unique."""
    stem = re.sub(r"[^a-z0-9]+", "_", filename.split(".")[0].lower()).strip("_")[:30] or "capture"
    return f"{stem}_{dt.datetime.now():%m%d_%H%M%S}"


def run_steps(path, name):
    env = {"INPUT": str(path), "SCENARIOS": name, "ROOT": f"/netlogs/uploads/{name}", "DB": f"up_{name}",
           "OUT": f"results/uploads/{name}"}
    for i, (stage, title, what, fact) in enumerate(STEPS, 1):
        with st.status(f"Step {i} of {len(STEPS)} · {title}", expanded=True) as box:
            st.caption(what)
            log, lines, t0 = st.empty(), [], time.time()
            proc = subprocess.Popen(["./run_pipeline.sh", stage], cwd=PROJECT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, env={**os.environ, **env})
            for line in proc.stdout:
                lines.append(line.rstrip())
                log.code("\n".join(lines[-8:]) or "starting…", language=None)
            ok = proc.wait() == 0
            secs = round(time.time() - t0)
            if not ok:
                box.update(label=f"Step {i} of {len(STEPS)} · {title} — failed after {secs}s", state="error", expanded=True)
                log.code("\n".join(lines[-30:]), language=None)
                st.error("This step failed. The last lines of its log are above. A file that is not a packet capture, "
                         "or a capture with no IPv4 traffic, is the usual cause.")
                return False
            found = [m.group(0) for line in lines if fact for m in [re.search(fact, line)] if m]
            log.empty()
            if found:
                st.write(" · ".join(found))
            box.update(label=f"Step {i} of {len(STEPS)} · {title} — done in {secs}s", state="complete", expanded=False)
    return True


def show_results(name):
    base = UPLOADS / name / "dashboard"
    o = table("overview", base).iloc[0]
    hosts = table("suspicious_hosts", base).sort_values(["flagged_windows", "max_p"], ascending=False)
    flagged = hosts[hosts.flagged_windows > 0]
    duration = pd.to_datetime(o.last_ts) - pd.to_datetime(o.first_ts)

    st.header(f"Results · {name}")
    c = st.columns(5)
    c[0].metric("Packets", human(o.packets))
    c[1].metric("Flows", human(o.flows))
    c[2].metric("Hosts seen", human(o.hosts))
    c[3].metric("Capture length", str(duration).split(".")[0].replace("0 days ", ""))
    c[4].metric("Skipped (not IPv4)", human(o.rejected), help="ARP, IPv6 and malformed frames are not analysed.")
    if len(flagged):
        st.error(f"**{len(flagged)} host(s) behaved like botnet-infected machines** in at least one minute. "
                 "They are listed first below — treat them as leads to check, not proof.")
    else:
        st.success("**No host behaved like the botnets the model was trained on.** "
                   "Malware that behaves differently can still be missed.")

    st.subheader("Hosts, most suspicious first")
    st.dataframe(hosts.drop(columns="scenario").head(25), hide_index=True, width="stretch", column_config={
        "ip": "Host", "windows": st.column_config.NumberColumn("Active minutes", help="Minutes with at least 5 packets"),
        "flagged_windows": st.column_config.NumberColumn("Flagged minutes"),
        "max_p": st.column_config.ProgressColumn("Highest botnet score", min_value=0, max_value=1),
        "mean_p": st.column_config.ProgressColumn("Average botnet score", min_value=0, max_value=1),
        "flows": "Flows sent", "n_dst_ips": st.column_config.NumberColumn("Most hosts contacted in a minute"),
        "unanswered_syn": "Unanswered connection attempts", "smtp_flows": "Mail (SMTP) flows", "irc_flows": "IRC flows"})

    traffic_charts(base, o.scenario)

    sample = base / "sample_packets.csv"
    if sample.exists() and sample.stat().st_size:
        st.subheader("First packets, as Wireshark would list them")
        st.dataframe(pd.read_csv(sample, names=["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]),
                     hide_index=True, width="stretch", height=320)


def page_analyse():
    st.title("Analyse a capture")
    st.write("Upload a network capture from Wireshark. It goes through the same big-data pipeline as the CTU-13 study — "
             "HDFS, Pig, Hive and Spark — one step at a time, and you get a list of hosts that behave like infected machines.")
    with st.expander("Which file do I upload?"):
        st.markdown("""
**The capture file itself** — in Wireshark: *File → Save As…* and keep the **.pcapng** (or .pcap) format.
`tcpdump -w capture.pcap` works too. Compressed files (`.gz`, `.bz2`) are fine.

Why not Wireshark's CSV export? It names packets by application (DNS, TLS, HTTP …) and leaves out the port numbers,
which this analysis needs. The pipeline makes its own Wireshark-style log from the capture in step 1.

Works best with a few minutes or more of traffic. Only IPv4 is analysed; IPv6 and ARP are counted and skipped.""")

    if not services_up():
        st.warning("The Hadoop cluster (HDFS, YARN, Hive) is not running, so nothing can be analysed yet.")
        if st.button("Start the cluster", type="primary"):
            with st.spinner("Starting HDFS, YARN and HiveServer2 — about a minute…"):
                subprocess.run(["bash", str(pathlib.Path.home() / "hive-lab/bin/hive-lab-start")], capture_output=True)
            st.rerun()
        return
    if shell("hdfs dfs -test -e /netlogs/spark/model").returncode != 0:
        st.warning("The botnet model has not been trained yet. Run `./run_pipeline.sh spark` once, then come back.")
        return

    up = st.file_uploader("Capture file", type=CAPTURE_TYPES, help="pcapng, pcap or cap — optionally .gz / .bz2")
    left, right = st.columns([1, 3])
    go = left.button("Analyse", type="primary", disabled=up is None, width="stretch")
    sample = right.button("Or try a sample: 30 min of a university network with one Virut-infected PC (77 MB)",
                          disabled=not SAMPLE.exists())
    if sample:
        st.caption("The model was trained on this capture, so this is a demo of the workflow, not a test of the model.")
    if go or sample:
        name = capture_name(up.name if go else "sample_ctu46")
        if go:
            path = PROJECT / "data/uploads" / f"{name}.{up.name.split('.', 1)[-1].lower()}"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(up.getbuffer())
        else:
            path = SAMPLE
        if run_steps(path, name):
            st.session_state.current = name

    done = sorted((p.name for p in UPLOADS.glob("*") if (p / "dashboard/overview").exists()), reverse=True) if UPLOADS.exists() else []
    if done:
        st.divider()
        current = st.session_state.get("current", done[0])
        pick = st.selectbox("Analysed captures", done, index=done.index(current) if current in done else 0)
        show_results(pick)


pages = {"Your capture": [st.Page(page_analyse, title="Analyse a capture", icon="📤", url_path="analyse", default=True)]}
if HAS_STUDY:
    pages["CTU-13 study"] = [st.Page(page_overview, title="Overview", icon="🏠", url_path="overview"),
                             st.Page(page_traffic, title="Traffic", icon="📈", url_path="traffic"),
                             st.Page(page_packets, title="Packet log", icon="📜", url_path="packets"),
                             st.Page(page_detection, title="Detection", icon="🧪", url_path="detection"),
                             st.Page(page_hunt, title="Threat hunt", icon="🔎", url_path="hunt")]
st.navigation(pages).run()
