"""Scores every host in one processed capture with the trained botnet model (saved by detect_botnets.py).

    uv run python spark/score_capture.py /netlogs/uploads/<name>
Reads  <root>/hive/host_windows ; writes <root>/dashboard/suspicious_hosts (one row per host, most suspicious first).
"""
import json
import pathlib
import sys

from pyspark.ml import PipelineModel
from pyspark.ml.functions import vector_to_array
from pyspark.sql import SparkSession, functions as F

HDFS = "hdfs://localhost:9000"
root = HDFS + sys.argv[1]
min_pkts = json.loads((pathlib.Path(__file__).resolve().parent.parent / "results/metrics.json").read_text())["min_pkts"]

spark = (SparkSession.builder.appName("score-capture").master("local[*]")
         .config("spark.driver.memory", "2g").config("spark.ui.showConsoleProgress", "false").getOrCreate())
spark.sparkContext.setLogLevel("WARN")

model = PipelineModel.load(f"{HDFS}/netlogs/spark/model")
features = model.stages[0].getInputCols()
windows = spark.read.parquet(f"{root}/hive/host_windows")
# Same preprocessing as training: minutes with too few packets are skipped, counts are log1p-scaled.
active = windows.filter(F.col("pkts") >= min_pkts)
scored = (model.transform(active.select("scenario", "ip", "minute", *[F.log1p(F.col(c).cast("double")).alias(c) for c in features]))
          .withColumn("p_botnet", vector_to_array("probability")[1]))
behaviour = windows.groupBy("scenario", "ip").agg(
    F.sum("n_flows").alias("flows"), F.max("n_dst_ips").alias("n_dst_ips"),
    F.sum("unanswered_syn").alias("unanswered_syn"), F.sum("smtp_flows").alias("smtp_flows"), F.sum("irc_flows").alias("irc_flows"))
hosts = (scored.groupBy("scenario", "ip")
         .agg(F.count("*").alias("windows"), F.sum("prediction").cast("long").alias("flagged_windows"),
              F.round(F.max("p_botnet"), 4).alias("max_p"), F.round(F.avg("p_botnet"), 4).alias("mean_p"))
         .join(behaviour, ["scenario", "ip"])
         .orderBy(F.desc("flagged_windows"), F.desc("max_p")))
hosts.write.mode("overwrite").parquet(f"{root}/dashboard/suspicious_hosts")

n, flagged = hosts.count(), hosts.filter("flagged_windows > 0").count()
print(f"scored {n} active hosts ({active.count()} host-minutes); {flagged} flagged as botnet-like in at least one minute")
hosts.show(10, truncate=False)
spark.stop()
