-- Stage 6 (Hive): Spark's predictions come back into the warehouse and feed the dashboard.
USE ${hivevar:db};
SET hive.resultset.use.unique.column.names=false;

DROP TABLE IF EXISTS window_predictions;
CREATE EXTERNAL TABLE window_predictions (
  scenario STRING, ip STRING, minute STRING, label STRING, protocol STRING, model STRING, prediction INT, p_botnet DOUBLE)
STORED AS PARQUET LOCATION '${hivevar:root}/spark/window_predictions';

DROP TABLE IF EXISTS host_scores;
CREATE EXTERNAL TABLE host_scores (
  scenario STRING, ip STRING, windows BIGINT, flagged_windows BIGINT, max_p DOUBLE, mean_p DOUBLE)
STORED AS PARQUET LOCATION '${hivevar:root}/spark/host_scores';

-- Per labelled host and protocol: how much of its (test) time the model flagged it - a host-level verdict.
DROP TABLE IF EXISTS d_host_verdicts;
CREATE EXTERNAL TABLE d_host_verdicts (scenario STRING, ip STRING, label STRING, protocol STRING, model STRING,
  windows BIGINT, flagged BIGINT, flagged_pct DOUBLE)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/host_verdicts';

INSERT OVERWRITE TABLE d_host_verdicts
SELECT scenario, ip, label, protocol, model, COUNT(*), SUM(prediction), ROUND(100 * AVG(prediction), 1)
FROM window_predictions WHERE label IS NOT NULL GROUP BY scenario, ip, label, protocol, model;

-- The 15 unlabelled university hosts per capture that most resemble the bots, with what they did on the wire.
DROP TABLE IF EXISTS d_suspicious_hosts;
CREATE EXTERNAL TABLE d_suspicious_hosts (scenario STRING, ip STRING, windows BIGINT, flagged_windows BIGINT,
  max_p DOUBLE, mean_p DOUBLE, flows BIGINT, n_dst_ips BIGINT, unanswered_syn BIGINT, smtp_flows BIGINT, top_dport INT)
STORED AS PARQUET LOCATION '${hivevar:root}/dashboard/suspicious_hosts';

INSERT OVERWRITE TABLE d_suspicious_hosts
SELECT s.scenario, s.ip, s.windows, s.flagged_windows, s.max_p, s.mean_p,
       w.flows, w.n_dst_ips, w.unanswered_syn, w.smtp_flows, p.dport
FROM (SELECT *, ROW_NUMBER() OVER (PARTITION BY scenario ORDER BY flagged_windows DESC, max_p DESC) AS rk
      FROM host_scores) s
JOIN (SELECT scenario, ip, SUM(n_flows) AS flows, MAX(n_dst_ips) AS n_dst_ips,
             SUM(unanswered_syn) AS unanswered_syn, SUM(smtp_flows) AS smtp_flows
      FROM host_windows GROUP BY scenario, ip) w ON w.scenario = s.scenario AND w.ip = s.ip
LEFT JOIN (SELECT scenario, src, dport, ROW_NUMBER() OVER (PARTITION BY scenario, src ORDER BY COUNT(*) DESC) AS rk
           FROM flows WHERE src LIKE '147.32.%' GROUP BY scenario, src, dport) p
  ON p.scenario = s.scenario AND p.src = s.ip AND p.rk = 1
WHERE s.rk <= 15;

SELECT scenario, ip, label, protocol, model, windows, flagged, flagged_pct FROM d_host_verdicts ORDER BY protocol, scenario, label, ip, model;
SELECT * FROM d_suspicious_hosts ORDER BY scenario, flagged_windows DESC, max_p DESC;
