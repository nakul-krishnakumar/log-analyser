"""Stage 5 (Spark MLlib): detect botnet-infected hosts from their per-minute network behaviour.

Reads  hdfs:///netlogs/hive/host_windows                       (written by Hive)
Writes hdfs:///netlogs/spark/{window_predictions,host_scores}  (queried back from Hive)
       results/metrics.json, results/feature_importance.json

Samples: one university host (147.32.0.0/16) x one minute with >= MIN_PKTS packets.
Labels:  1 = known infected host; 0 = known normal host OR unlabelled background host (weak label - the background is
         overwhelmingly benign but not verified, so precision measured against it is a lower bound).
Two evaluation protocols: temporal (train on the first 70% of each capture, test on the last 30% - a known infection,
caught later) and leave-one-capture-out (an unseen capture, and for Rbot/NSIS an unseen malware family). The threat-hunt
scores for a capture's background hosts come from the leave-one-out model that never saw that capture.
"""
import json
import pathlib


from pyspark.ml import Pipeline
from pyspark.ml.classification import LogisticRegression, RandomForestClassifier
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.feature import StandardScaler, VectorAssembler
from pyspark.ml.functions import vector_to_array
from pyspark.sql import SparkSession, functions as F

HDFS = "hdfs://localhost:9000/netlogs"
RESULTS = pathlib.Path(__file__).resolve().parent.parent / "results"
ID_COLS = ["scenario", "ip", "minute", "label", "malware"]
MIN_PKTS = 5  # a host-minute with fewer packets carries no evidence either way (idle keep-alives look like idle bots)

spark = (SparkSession.builder.appName("botnet-detection").master("local[*]")
         .config("spark.driver.memory", "4g")
         .config("spark.sql.shuffle.partitions", "48")
         .config("spark.ui.showConsoleProgress", "false")
         .getOrCreate())
spark.sparkContext.setLogLevel("WARN")

raw = spark.read.parquet(f"{HDFS}/hive/host_windows").filter("ip LIKE '147.32.%'")
features = [c for c in raw.columns if c not in ID_COLS]
print("internal host-minutes by label, before/after the activity filter:")
(raw.withColumn("kind", F.coalesce("label", F.lit("background")))
    .groupBy("kind").agg(F.count("*").alias("all"), F.sum((F.col("pkts") >= MIN_PKTS).cast("int")).alias(f"pkts>={MIN_PKTS}"))
    .orderBy("kind").show())

# Counts are heavy-tailed (1 flow vs 50k flows a minute); log1p keeps the linear model sane.
data = (raw.filter(F.col("pkts") >= MIN_PKTS)
        .select(*ID_COLS, *[F.log1p(F.col(c).cast("double")).alias(c) for c in features])
        .withColumn("y", (F.col("label") == "Botnet").cast("double")).fillna({"y": 0.0}).cache())
scenarios = sorted(r.scenario for r in data.select("scenario").distinct().collect())
print(f"samples: {data.count()}  infected: {int(data.agg(F.sum('y')).first()[0])}  features: {len(features)}")


def model(kind):
    est = (LogisticRegression(featuresCol="features", labelCol="y", weightCol="w", maxIter=200) if kind == "logistic_regression"
           else RandomForestClassifier(featuresCol="features", labelCol="y", weightCol="w", numTrees=100, maxDepth=10, seed=42))
    return Pipeline(stages=[VectorAssembler(inputCols=features, outputCol="raw"),
                            StandardScaler(inputCol="raw", outputCol="features"), est])


def evaluate(pred):
    c = {k: int(v or 0) for k, v in pred.groupBy().agg(*[F.sum(F.expr(f"CASE WHEN {e} THEN 1 ELSE 0 END")).alias(n) for n, e in [
        ("tp", "prediction = 1 AND y = 1"), ("fp", "prediction = 1 AND y = 0"),
        ("fn", "prediction = 0 AND y = 1"), ("tn", "prediction = 0 AND y = 0"),
        ("normal_fp", "prediction = 1 AND label = 'Normal'"), ("normal", "label = 'Normal'")]]).first().asDict().items()}
    return c


def scores(c):
    p = c["tp"] / (c["tp"] + c["fp"]) if c["tp"] + c["fp"] else 0.0
    r = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0.0
    return {**c, "precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "normal_fpr": round(c["normal_fp"] / c["normal"], 4) if c["normal"] else None}


def weighted(df):
    pos = df.agg(F.sum("y")).first()[0]
    return df.withColumn("w", F.when(F.col("y") == 1, (df.count() - pos) / pos).otherwise(1.0))  # balance classes


def run(protocol, folds):
    """Fits both models per (train, test) fold; scores every capture in each test set, plus a pooled row per model."""
    rows, preds = [], []
    for train, test in folds:
        caps = sorted(r.scenario for r in test.select("scenario").distinct().collect())
        # Rule baseline: a host talking to 20+ distinct IPs in one minute looks like a scanner/spammer.
        base = test.withColumn("prediction", (F.col("n_dst_ips") >= F.log1p(F.lit(20.0))).cast("double"))
        rows += [{"protocol": protocol, "test": c, "model": "rule_20_dst_ips_per_min",
                  **scores(evaluate(base.filter(F.col("scenario") == c))), "auc_pr": None} for c in caps]
        for kind in ("logistic_regression", "random_forest"):
            fitted = model(kind).fit(weighted(train))
            pred = fitted.transform(test).withColumn("p_botnet", vector_to_array("probability")[1]).cache()
            for c in caps:
                sub = pred.filter(F.col("scenario") == c)
                has_pos = sub.filter("y = 1").limit(1).count() > 0
                auc = BinaryClassificationEvaluator(rawPredictionCol="p_botnet", labelCol="y",
                                                    metricName="areaUnderPR").evaluate(sub) if has_pos else None
                rows.append({"protocol": protocol, "test": c, "model": kind, **scores(evaluate(sub)),
                             "auc_pr": round(auc, 4) if auc is not None else None})
            preds.append(pred.select("scenario", "ip", "minute", "label", F.lit(protocol).alias("protocol"),
                                     F.lit(kind).alias("model"), F.col("prediction").cast("int").alias("prediction"), "p_botnet"))
            if kind == "random_forest":
                importances.append(fitted.stages[-1].featureImportances.toArray())
    for kind in ("rule_20_dst_ips_per_min", "logistic_regression", "random_forest"):
        tot = {k: sum(r[k] for r in rows if r["model"] == kind) for k in ("tp", "fp", "fn", "tn", "normal_fp", "normal")}
        rows.append({"protocol": protocol, "test": "ALL (pooled)", "model": kind, **scores(tot), "auc_pr": None})
    return rows, preds


importances = []
# Protocol 1 - known threat, later time: train on the first 70% of every capture's timeline, test on the last 30%.
t = data.withColumn("t", F.unix_timestamp("minute", "yyyy-MM-dd HH:mm"))
bounds = t.groupBy("scenario").agg(F.min("t").alias("t0"), F.max("t").alias("t1"))
t = t.join(bounds, "scenario").withColumn("late", F.col("t") >= F.col("t0") + 0.7 * (F.col("t1") - F.col("t0")))
temporal_rows, temporal_preds = run("temporal_70_30", [(t.filter(~F.col("late")), t.filter(F.col("late")))])
# Protocol 2 - unseen capture: train on three captures, test on the fourth (two of which are malware families
# that appear nowhere in training).
loo_rows, loo_preds = run("leave_one_capture_out", [(data.filter(F.col("scenario") != c), data.filter(F.col("scenario") == c))
                                                    for c in scenarios])
rows = temporal_rows + loo_rows

print(f"\n{'protocol':<23}{'test':<14}{'model':<26}{'precision':>10}{'recall':>8}{'f1':>8}{'auc_pr':>8}{'normal_fpr':>11}"
      f"{'tp':>7}{'fp':>7}{'fn':>7}{'tn':>8}")
for m in rows:
    print(f"{m['protocol']:<23}{m['test']:<14}{m['model']:<26}{m['precision']:>10}{m['recall']:>8}{m['f1']:>8}"
          f"{m['auc_pr'] if m['auc_pr'] is not None else '-':>8}{m['normal_fpr'] if m['normal_fpr'] is not None else '-':>11}"
          f"{m['tp']:>7}{m['fp']:>7}{m['fn']:>7}{m['tn']:>8}")

out = temporal_preds[0]
for p in temporal_preds[1:] + loo_preds:
    out = out.unionByName(p)
out.write.mode("overwrite").parquet(f"{HDFS}/spark/window_predictions")

# Threat hunt: unlabelled hosts, scored by the random forest that never saw their capture.
(spark.read.parquet(f"{HDFS}/spark/window_predictions")
 .filter("label IS NULL AND model = 'random_forest' AND protocol = 'leave_one_capture_out'")
 .groupBy("scenario", "ip")
 .agg(F.count("*").alias("windows"), F.sum("prediction").alias("flagged_windows"),
      F.round(F.max("p_botnet"), 4).alias("max_p"), F.round(F.avg("p_botnet"), 4).alias("mean_p"))
 .write.mode("overwrite").parquet(f"{HDFS}/spark/host_scores"))

avg_imp = sorted(zip(features, sum(importances) / len(importances)), key=lambda x: -x[1])
RESULTS.mkdir(exist_ok=True)
(RESULTS / "metrics.json").write_text(json.dumps({"features": features, "min_pkts": MIN_PKTS, "results": rows}, indent=2))
(RESULTS / "feature_importance.json").write_text(json.dumps(
    [{"feature": f, "importance": round(float(v), 4)} for f, v in avg_imp], indent=2))
print("\ntop features (RF, mean over folds):", ", ".join(f"{f}={v:.3f}" for f, v in avg_imp[:8]))
print(f"predictions -> {HDFS}/spark/{{window_predictions,host_scores}} ; metrics -> {RESULTS}/metrics.json")
spark.stop()
