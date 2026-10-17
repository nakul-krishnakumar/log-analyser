-- Stage 4b (Hive): validation + the traffic tables the dashboard reads (Parquet under <root>/dashboard).
USE ${hivevar:db};
SET hive.resultset.use.unique.column.names=false;

-- Per capture: raw rows -> rejected -> unique packets -> flows. Validates Pig's cleaning end to end.
DROP TABLE IF EXISTS d_overview;
CREATE EXTERNAL TABLE d_overview (
  scenario STRING, malware STRING, raw_rows BIGINT, rejected BIGINT, packets BIGINT, duplicates BIGINT,
  flows BIGINT, bytes BIGINT, hosts BIGINT, first_ts STRING, last_ts STRING)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/overview';

INSERT OVERWRITE TABLE d_overview
SELECT r.scenario, m.malware, r.n, COALESCE(j.n, 0), f.pkts, r.n - COALESCE(j.n, 0) - f.pkts,
       f.flows, f.bytes, f.hosts, f.first_ts, f.last_ts
FROM (SELECT regexp_extract(INPUT__FILE__NAME, '([^/]+)\\.csv$', 1) AS scenario, COUNT(*) - 1 AS n   -- minus CSV header
      FROM raw_packets GROUP BY regexp_extract(INPUT__FILE__NAME, '([^/]+)\\.csv$', 1)) r
JOIN (SELECT scenario, SUM(pkts) AS pkts, COUNT(*) AS flows, SUM(bytes) AS bytes, COUNT(DISTINCT src) AS hosts,
             MIN(first_ts) AS first_ts, MAX(last_ts) AS last_ts FROM flows GROUP BY scenario) f ON f.scenario = r.scenario
LEFT JOIN (SELECT scenario, COUNT(*) AS n FROM rejects GROUP BY scenario) j ON j.scenario = r.scenario
LEFT JOIN (SELECT scenario, MAX(malware) AS malware FROM hosts WHERE label = 'Botnet' GROUP BY scenario) m ON m.scenario = r.scenario;

-- Traffic per minute, split by who sent it.
DROP TABLE IF EXISTS d_traffic;
CREATE EXTERNAL TABLE d_traffic (scenario STRING, minute STRING, pkts BIGINT, bytes BIGINT, flows BIGINT,
  botnet_pkts BIGINT, normal_pkts BIGINT)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/traffic';

INSERT OVERWRITE TABLE d_traffic
SELECT f.scenario, f.minute, SUM(f.pkts), SUM(f.bytes), COUNT(*),
       SUM(IF(h.label = 'Botnet', f.pkts, 0)), SUM(IF(h.label = 'Normal', f.pkts, 0))
FROM flows f LEFT JOIN hosts h ON h.scenario = f.scenario AND h.ip = f.src
GROUP BY f.scenario, f.minute;

DROP TABLE IF EXISTS d_protocols;
CREATE EXTERNAL TABLE d_protocols (scenario STRING, proto STRING, pkts BIGINT, bytes BIGINT, flows BIGINT)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/protocols';

INSERT OVERWRITE TABLE d_protocols
SELECT scenario, proto, SUM(pkts), SUM(bytes), COUNT(*) FROM flows GROUP BY scenario, proto;

-- Top 15 destination ports and top 20 talkers per capture.
DROP TABLE IF EXISTS d_top_ports;
CREATE EXTERNAL TABLE d_top_ports (scenario STRING, proto STRING, dport INT, flows BIGINT, pkts BIGINT, n_src BIGINT)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/top_ports';

INSERT OVERWRITE TABLE d_top_ports
SELECT scenario, proto, dport, flows, pkts, n_src FROM (
  SELECT scenario, proto, dport, COUNT(*) AS flows, SUM(pkts) AS pkts, COUNT(DISTINCT src) AS n_src,
         ROW_NUMBER() OVER (PARTITION BY scenario ORDER BY COUNT(*) DESC) AS rk
  FROM flows WHERE proto <> 'ICMP' GROUP BY scenario, proto, dport) t
WHERE rk <= 15;

DROP TABLE IF EXISTS d_top_talkers;
CREATE EXTERNAL TABLE d_top_talkers (scenario STRING, ip STRING, label STRING, pkts BIGINT, bytes BIGINT,
  flows BIGINT, n_dst_ips BIGINT)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/top_talkers';

INSERT OVERWRITE TABLE d_top_talkers
SELECT t.scenario, t.src, h.label, t.pkts, t.bytes, t.flows, t.n_dst FROM (
  SELECT scenario, src, SUM(pkts) AS pkts, SUM(bytes) AS bytes, COUNT(*) AS flows, COUNT(DISTINCT dst) AS n_dst,
         ROW_NUMBER() OVER (PARTITION BY scenario ORDER BY SUM(bytes) DESC) AS rk
  FROM flows GROUP BY scenario, src) t
LEFT JOIN hosts h ON h.scenario = t.scenario AND h.ip = t.src
WHERE t.rk <= 20;

-- How botnet and normal hosts behave per minute, on average.
DROP TABLE IF EXISTS d_label_profile;
CREATE EXTERNAL TABLE d_label_profile (label STRING, windows BIGINT, n_flows DOUBLE, n_dst_ips DOUBLE,
  n_dst_ports DOUBLE, unanswered_syn DOUBLE, no_reply_flows DOUBLE, dns_flows DOUBLE, smtp_flows DOUBLE,
  http_flows DOUBLE, irc_flows DOUBLE, bytes DOUBLE)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/label_profile';

INSERT OVERWRITE TABLE d_label_profile
SELECT label, COUNT(*), AVG(n_flows), AVG(n_dst_ips), AVG(n_dst_ports), AVG(unanswered_syn), AVG(no_reply_flows),
       AVG(dns_flows), AVG(smtp_flows), AVG(http_flows), AVG(irc_flows), AVG(bytes)
FROM host_windows WHERE label IS NOT NULL GROUP BY label;

-- Printed to results/hive_reports.txt
SELECT * FROM d_overview ORDER BY scenario;
SELECT * FROM d_protocols ORDER BY scenario, pkts DESC;
SELECT * FROM d_label_profile;
SELECT scenario, ip, label, pkts, bytes, flows, n_dst_ips FROM d_top_talkers WHERE label IS NOT NULL ORDER BY scenario, bytes DESC;
