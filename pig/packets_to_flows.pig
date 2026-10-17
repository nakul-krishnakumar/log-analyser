-- Stage 3 (Pig): Wireshark CSV packet logs -> clean, de-duplicated packets -> 1-minute flow records.
--   in : $IN   one Wireshark-style CSV per capture (<capture name>.csv):  "No.","Time","Source","Destination","Protocol","Length","Info"
--   out: $OUT/flows    tsv  scenario, minute, src, dst, proto, sport, dport, pkts, bytes, payload, first_ts, last_ts,
--                           syn_only, synack, rst, fin   (per-flow packet counts by TCP flag)
--        $OUT/rejects  rows that are not IPv4 TCP/UDP/ICMP (ARP, IPv6, malformed) - Hive counts them

raw = LOAD '$IN' USING PigStorage('\u0001', '-tagFile') AS (file:chararray, line:chararray);

rows = FOREACH raw GENERATE REGEX_EXTRACT(file, '^(.+)\\.csv$', 1) AS scenario, line,
    REGEX_EXTRACT_ALL(line, '^"\\d+","(\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d\\.\\d+)","(\\d+\\.\\d+\\.\\d+\\.\\d+)","(\\d+\\.\\d+\\.\\d+\\.\\d+)","(TCP|UDP|ICMP)","(\\d+)","(.*)"$') AS f;

SPLIT rows INTO good IF f IS NOT NULL, bad IF f IS NULL AND NOT (line MATCHES '^"No\\.".*');
STORE (FOREACH bad GENERATE scenario, line) INTO '$OUT/rejects' USING PigStorage('\t');

-- Parse Wireshark's Info column: "sport → dport [FLAGS] ... Len=N" (TCP), "sport → dport Len=N" (UDP), text (ICMP).
pkts = FOREACH good GENERATE scenario,
    (chararray) f.$0 AS ts, (chararray) f.$1 AS src, (chararray) f.$2 AS dst, (chararray) f.$3 AS proto, (long) f.$4 AS len,
    (int) REGEX_EXTRACT(f.$5, '^(\\d+) \\u2192 ', 1) AS sport,
    (int) REGEX_EXTRACT(f.$5, ' \\u2192 (\\d+)', 1) AS dport,
    REGEX_EXTRACT(f.$5, '\\[([A-Z, ]+)\\]', 1) AS flags,
    (long) REGEX_EXTRACT(f.$5, 'Len=(\\d+)', 1) AS payload;

-- The capture router sees some frames twice; identical (time, endpoints, size, flags) packets are dropped.
uniq = DISTINCT pkts;

marked = FOREACH uniq GENERATE scenario, SUBSTRING(ts, 0, 16) AS minute, src, dst, proto,
    (sport IS NULL ? 0 : sport) AS sport, (dport IS NULL ? 0 : dport) AS dport, len,
    (payload IS NULL ? 0L : payload) AS payload, ts,
    -- flags is null for UDP/ICMP; the IS NOT NULL guard keeps these 0 rather than null
    (flags IS NOT NULL AND flags == 'SYN' ? 1 : 0) AS syn_only, (flags IS NOT NULL AND flags == 'SYN, ACK' ? 1 : 0) AS synack,
    (flags IS NOT NULL AND flags MATCHES '.*RST.*' ? 1 : 0) AS rst, (flags IS NOT NULL AND flags MATCHES '.*FIN.*' ? 1 : 0) AS fin;

-- NetFlow-style unidirectional flow records with a 60 s active timeout (one record per 5-tuple per minute).
grp = GROUP marked BY (scenario, minute, src, dst, proto, sport, dport);
flows = FOREACH grp GENERATE FLATTEN(group), COUNT(marked) AS pkts, SUM(marked.len) AS bytes,
    SUM(marked.payload) AS payload, MIN(marked.ts) AS first_ts, MAX(marked.ts) AS last_ts,
    SUM(marked.syn_only) AS syn_only, SUM(marked.synack) AS synack, SUM(marked.rst) AS rst, SUM(marked.fin) AS fin;
STORE flows INTO '$OUT/flows' USING PigStorage('\t');
