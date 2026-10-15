-- Stage 4 (Hive): warehouse over Pig's flows + host labels, and the per-host-minute features Spark trains on.
CREATE DATABASE IF NOT EXISTS netlogs;
USE netlogs;

DROP TABLE IF EXISTS raw_packets;
CREATE EXTERNAL TABLE raw_packets (line STRING) LOCATION '/netlogs/raw/packets';

DROP TABLE IF EXISTS rejects;
CREATE EXTERNAL TABLE rejects (scenario STRING, line STRING)
ROW FORMAT DELIMITED FIELDS TERMINATED BY '\t' LOCATION '/netlogs/pig/rejects';

DROP TABLE IF EXISTS flows;
CREATE EXTERNAL TABLE flows (
  scenario STRING, minute STRING, src STRING, dst STRING, proto STRING, sport INT, dport INT,
  pkts BIGINT, bytes BIGINT, payload BIGINT, first_ts STRING, last_ts STRING,
  syn_only BIGINT, synack BIGINT, rst BIGINT, fin BIGINT)
ROW FORMAT DELIMITED FIELDS TERMINATED BY '\t' LOCATION '/netlogs/pig/flows';

DROP TABLE IF EXISTS hosts;
CREATE EXTERNAL TABLE hosts (scenario STRING, ip STRING, label STRING, malware STRING)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' LOCATION '/netlogs/raw/labels'
TBLPROPERTIES ('skip.header.line.count'='1');

-- One row per (capture, source host, minute): what that host did on the network in that minute.
-- Each flow is joined to its reverse flow to see whether the other side ever answered.
DROP TABLE IF EXISTS host_windows;
CREATE EXTERNAL TABLE host_windows (
  scenario STRING, ip STRING, minute STRING,
  n_flows BIGINT, pkts BIGINT, bytes BIGINT, payload BIGINT, bytes_back BIGINT,
  n_dst_ips BIGINT, n_dst_ports BIGINT, n_src_ports BIGINT,
  tcp_flows BIGINT, udp_flows BIGINT, icmp_flows BIGINT,
  syn_flows BIGINT, unanswered_syn BIGINT, rst_pkts BIGINT, fin_pkts BIGINT, one_pkt_flows BIGINT, no_reply_flows BIGINT,
  dns_flows BIGINT, smtp_flows BIGINT, http_flows BIGINT, https_flows BIGINT, irc_flows BIGINT, high_port_flows BIGINT,
  label STRING, malware STRING)
STORED AS PARQUET LOCATION '/netlogs/hive/host_windows';

INSERT OVERWRITE TABLE host_windows
SELECT f.scenario, f.src, f.minute,
       COUNT(*), SUM(f.pkts), SUM(f.bytes), SUM(f.payload), SUM(COALESCE(r.bytes, 0)),
       COUNT(DISTINCT f.dst), COUNT(DISTINCT f.dport), COUNT(DISTINCT f.sport),
       SUM(IF(f.proto = 'TCP', 1, 0)), SUM(IF(f.proto = 'UDP', 1, 0)), SUM(IF(f.proto = 'ICMP', 1, 0)),
       SUM(IF(f.syn_only > 0, 1, 0)), SUM(IF(f.syn_only > 0 AND COALESCE(r.synack, 0) = 0, 1, 0)),
       SUM(f.rst), SUM(f.fin), SUM(IF(f.pkts = 1, 1, 0)), SUM(IF(r.src IS NULL, 1, 0)),
       SUM(IF(f.dport = 53, 1, 0)), SUM(IF(f.dport IN (25, 587), 1, 0)), SUM(IF(f.dport = 80, 1, 0)),
       SUM(IF(f.dport = 443, 1, 0)), SUM(IF(f.dport BETWEEN 6660 AND 6669, 1, 0)), SUM(IF(f.dport > 1024, 1, 0)),
       h.label, h.malware
FROM flows f
LEFT JOIN flows r
  ON r.scenario = f.scenario AND r.minute = f.minute AND r.src = f.dst AND r.dst = f.src
 AND r.proto = f.proto AND r.sport = f.dport AND r.dport = f.sport
LEFT JOIN hosts h ON h.scenario = f.scenario AND h.ip = f.src
GROUP BY f.scenario, f.src, f.minute, h.label, h.malware;
