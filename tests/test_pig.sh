#!/usr/bin/env bash
# Runs pig/packets_to_flows.pig in Pig local mode on tests/fixture/ and checks the flow records.
set -euo pipefail
cd "$(dirname "$0")/.."
source "$HOME/hive-lab/bin/hive-env-lab.sh"
out=$(mktemp -d)
"$HOME/hadoop/pig-0.18.0/bin/pig" -x local -l /dev/null -param IN=tests/fixture -param OUT="$out" pig/packets_to_flows.pig >/dev/null 2>&1
flows=$(cat "$out"/flows/part*)
flow() { echo "$flows" | awk -F'\t' -v k="$1" '($2" "$3">"$4":"$7" "$5)==k'; }

check() { [ "$2" = "$3" ] && echo "ok   $1" || { echo "FAIL $1: got '$2', want '$3'"; exit 1; }; }
check "ARP row rejected, header skipped"   "$(cat "$out"/rejects/part* | wc -l)" 1
check "scenario from file name"            "$(echo "$flows" | cut -f1 | sort -u)" ctu99
check "duplicate SYN dropped (3 pkts)"     "$(flow '2011-08-18 13:39 10.0.0.1>10.0.0.2:80 TCP' | cut -f8)" 3
check "flow bytes 60+590+60"               "$(flow '2011-08-18 13:39 10.0.0.1>10.0.0.2:80 TCP' | cut -f9)" 710
check "payload from Len="                  "$(flow '2011-08-18 13:39 10.0.0.1>10.0.0.2:80 TCP' | cut -f10)" 536
check "syn_only,synack,rst,fin"            "$(flow '2011-08-18 13:39 10.0.0.1>10.0.0.2:80 TCP' | cut -f13-16 | tr '\t' ,)" 1,0,0,1
check "SYN-ACK counted on reply flow"      "$(flow '2011-08-18 13:39 10.0.0.2>10.0.0.1:1078 TCP' | cut -f14)" 1
check "next minute = new flow (RST)"       "$(flow '2011-08-18 13:40 10.0.0.1>10.0.0.2:80 TCP' | cut -f15)" 1
check "UDP dport parsed"                   "$(flow '2011-08-18 13:39 10.0.0.1>8.8.8.8:53 UDP' | cut -f8)" 1
check "UDP flag counts are 0, not null"   "$(flow '2011-08-18 13:39 10.0.0.1>8.8.8.8:53 UDP' | cut -f13-16 | tr '\t' ,)" 0,0,0,0
check "ICMP has port 0"                    "$(flow '2011-08-18 13:39 10.0.0.1>8.8.8.8:0 ICMP' | cut -f8)" 1
check "total flows"                        "$(echo "$flows" | wc -l)" 5
rm -rf "$out"
