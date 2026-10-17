#!/usr/bin/env bash
# End-to-end network traffic analyser:  pcap -> Wireshark CSV -> HDFS -> Pig -> Hive -> Spark MLlib -> Hive -> dashboard
#
#   ./run_pipeline.sh                     run every stage
#   ./run_pipeline.sh pig hive            run only the named stages (fetch ingest pig hive spark predictions export)
#   SCENARIOS="ctu52" ./run_pipeline.sh   restrict to some captures (default: all four)
#
# One uploaded capture (what the dashboard's "Analyse a capture" page runs), isolated in its own HDFS root + Hive DB:
#   INPUT=x.pcapng SCENARIOS=name ROOT=/netlogs/uploads/name DB=up_name OUT=results/uploads/name \
#     ./run_pipeline.sh ingest pig hive score export
set -euo pipefail
source "$HOME/hive-lab/bin/hive-env-lab.sh"
export PATH="$HOME/hadoop/pig-0.18.0/bin:$HOME/hive-lab/bin:$PATH"
cd "$(dirname "$0")"

NET=data/net
ROOT=${ROOT:-/netlogs}
DB=${DB:-netlogs}
OUT=${OUT:-results}
SCENARIOS=${SCENARIOS:-"ctu46 ctu52 ctu53 ctu54"}
mkdir -p "$NET" "$OUT/dashboard"

# CTU-13 captures (Stratosphere Lab, CTU Prague): capture id -> file name on the mirror
declare -A CAPTURE=([ctu46]=capture20110815-2 [ctu52]=capture20110818-2 [ctu53]=capture20110819 [ctu54]=capture20110815-3)

banner() { printf '\n\033[1;36m==== %s ====\033[0m\n' "$*"; }
timed()  { local t0=$SECONDS; "$@"; printf '\033[2m(%ss)\033[0m\n' $((SECONDS - t0)); }
hql()    { hive-sql --silent=true --outputformat=table --hivevar db="$DB" --hivevar root="$ROOT" -f "$1" </dev/null 2>/dev/null; }  # </dev/null: Beeline's jline crashes on a TTY

fetch() {
  banner "1/7 fetch: CTU-13 header-truncated pcaps (all traffic of a university router)"
  for s in $SCENARIOS; do
    n=${s#ctu}
    [ -s "$NET/$s.truncated.pcap.bz2" ] || curl -fL --retry 3 -o "$NET/$s.truncated.pcap.bz2" \
      "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-$n/${CAPTURE[$s]}.truncated.pcap.bz2"
  done
  ls -lh "$NET"
}

ingest() {
  banner "2/7 ingest: pcap -> Wireshark-style CSV, streamed straight into HDFS"
  hdfs dfs -rm -r -f -skipTrash "$ROOT/raw" >/dev/null
  hdfs dfs -mkdir -p "$ROOT/raw/packets" "$ROOT/raw/labels"
  pids=()
  for s in $SCENARIOS; do
    uv run python ingest/pcap_to_csv.py "${INPUT:-$NET/$s.truncated.pcap.bz2}" | hdfs dfs -put -f - "$ROOT/raw/packets/$s.csv" &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p"; done  # a bare `wait` would hide a failed conversion
  hdfs dfs -put -f labels/ctu13_hosts.csv "$ROOT/raw/labels/"
  hdfs dfs -ls -h "$ROOT/raw/packets"
  hdfs dfs -cat "$ROOT/raw/packets/${SCENARIOS%% *}.csv" 2>/dev/null | head -4 || true
}

pig_stage() {
  banner "3/7 pig: parse Info column, reject non-IP, de-duplicate, packets -> 1-minute flows (Tez on YARN)"
  hdfs dfs -rm -r -f -skipTrash "$ROOT/pig" >/dev/null
  PIG_CLASSPATH="$TEZ_CONF_DIR:$TEZ_HOME/*:$TEZ_HOME/lib/*" \
    pig -x tez -l /dev/null -param IN="$ROOT/raw/packets" -param OUT="$ROOT/pig" pig/packets_to_flows.pig 2>&1 \
    | grep -E 'Success|Failed|ERROR|Input\(s\)|Output\(s\)|Successfully|records in' || true
  hdfs dfs -test -e "$ROOT/pig/flows/_SUCCESS" || { echo "pig stage failed"; exit 1; }
  hdfs dfs -du -s -h "$ROOT/pig/*"
}

hive_stage() {
  banner "4/7 hive: warehouse, label join, reverse-flow join, per-host-minute features (Tez)"
  hql hive/01_warehouse.sql >/dev/null
  banner "4/7 hive: validation + dashboard tables"
  hql hive/02_dashboard.sql | tee "$OUT/hive_reports.txt"
}

spark_stage() {
  banner "5/7 spark mllib: botnet detection (temporal + leave-one-capture-out)"
  uv run python spark/detect_botnets.py 2>&1 | grep -vE 'WARN|^\s*$|NativeCodeLoader|Setting default log level|To adjust logging|log4j2-defaults' \
    | tee results/spark_output.txt
}

score() {
  banner "spark mllib: score every host in the capture with the trained botnet model"
  uv run python spark/score_capture.py "$ROOT" 2>&1 | grep -vE 'WARN|^\s*$|NativeCodeLoader|Setting default log level|To adjust logging|log4j2-defaults'
}

predictions() {
  banner "6/7 hive: query Spark's predictions"
  hql hive/03_predictions.sql | tee results/hive_predictions.txt
}

export_stage() {
  banner "7/7 export: dashboard tables HDFS -> $OUT/dashboard"
  rm -rf "$OUT/dashboard" && mkdir -p "$OUT/dashboard"
  hdfs dfs -get "$ROOT/dashboard/*" "$OUT/dashboard/"
  # A Wireshark-view sample for the UI: an upload's first packets, or the first packets sent by an infected CTU host.
  if [ -n "${INPUT:-}" ]; then
    hdfs dfs -cat "$ROOT/raw/packets/$SCENARIOS.csv" 2>/dev/null | sed -n '2,301p;301q' > "$OUT/dashboard/sample_packets.csv" || true
  else
    hdfs dfs -cat "$ROOT/raw/packets/ctu52.csv" 2>/dev/null | grep -m 300 -E '^"[0-9]+","[^"]+","147\.32\.84\.165"' \
      > "$OUT/dashboard/sample_botnet_packets.csv" || true
  fi
  ls "$OUT/dashboard"
}

stages=("${@:-fetch ingest pig hive spark predictions export}")
for s in ${stages[*]}; do
  case "$s" in
    fetch) timed fetch ;; ingest) timed ingest ;; pig) timed pig_stage ;; hive) timed hive_stage ;;
    spark) timed spark_stage ;; score) timed score ;; predictions) timed predictions ;; export) timed export_stage ;;
    *) echo "unknown stage: $s"; exit 2 ;;
  esac
done
banner "done — dashboard: uv run streamlit run ui/app.py"
