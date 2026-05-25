"""
SNS Network Traffic Dataset Builder
=====================================
Project: Developing a Synthetic Nervous System — Network Layer Extension
Companion to: sns_bert_db.py (conversational manipulation detection)

Integration:  session_id is the shared foreign key linking this dataset
              to the RAW_CONVERSATIONS table in sns_bert.db. When both
              datasets are present for a session, the combined signal
              (suspicious language + suspicious traffic) is much stronger
              than either alone.

Traffic Pattern Taxonomy (mirrors the 6-vector NLP taxonomy):
  NORMAL (label = 0):
    normal_browsing        - Typical human browsing cadence
    normal_api_usage       - Steady, well-spaced API calls
    normal_session         - Standard session open/close behavior

  SUSPICIOUS (label = 1):
    port_scanning          - Rapid sequential port probing (reconnaissance)
    ddos_pattern           - High-frequency flood from single or distributed source
    c2_beaconing           - Periodic, clock-like callbacks (botnet C2 behavior)
    data_exfiltration      - Unusually large outbound payloads, off-hours timing
    adversarial_probing    - Systematic endpoint enumeration (maps to adversarial_prompting)
    session_hijack         - Sudden IP/user-agent change mid-session (maps to trust_violation)
"""

import sqlite3
import random
import math
import re
from datetime import datetime, timedelta

DB_PATH        = "sns_bert.db"    # append to existing BERT DB
TRAFFIC_DB     = "sns_network.db" # standalone traffic DB (also importable)
random.seed(42)

# ──────────────────────────────────────────────────────────────────────────────
# SCHEMA  (new tables — safe to run against existing sns_bert.db)
# ──────────────────────────────────────────────────────────────────────────────

NETWORK_SCHEMA = """
-- ============================================================
-- TABLE: network_sessions
-- One row per session. session_id links to conversations.session_id
-- ============================================================
CREATE TABLE IF NOT EXISTS network_sessions (
    net_session_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT    NOT NULL UNIQUE,   -- FK → conversations.session_id
    src_ip              TEXT    NOT NULL,
    dst_ip              TEXT    NOT NULL,
    user_agent          TEXT,
    protocol            TEXT    NOT NULL DEFAULT 'HTTPS',
    session_start       TEXT    NOT NULL,
    session_end         TEXT,
    total_packets       INTEGER NOT NULL DEFAULT 0,
    total_bytes_in      INTEGER NOT NULL DEFAULT 0,
    total_bytes_out     INTEGER NOT NULL DEFAULT 0,
    label               INTEGER NOT NULL CHECK (label IN (0,1)),
    -- 0 = NORMAL, 1 = SUSPICIOUS
    traffic_pattern     TEXT    NOT NULL,
    severity            INTEGER DEFAULT 0 CHECK (severity IN (0,1,2,3)),
    notes               TEXT
);

-- ============================================================
-- TABLE: packet_events
-- Individual packet-level events within a session
-- ============================================================
CREATE TABLE IF NOT EXISTS packet_events (
    event_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    net_session_id      INTEGER NOT NULL REFERENCES network_sessions(net_session_id),
    session_id          TEXT    NOT NULL,
    timestamp           TEXT    NOT NULL,
    src_ip              TEXT    NOT NULL,
    dst_ip              TEXT    NOT NULL,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            TEXT,
    packet_size_bytes   INTEGER,
    direction           TEXT    CHECK (direction IN ('inbound','outbound')),
    flag                TEXT,   -- SYN, ACK, FIN, RST, PSH
    inter_arrival_ms    REAL,   -- ms since last packet in this session
    payload_entropy     REAL,   -- Shannon entropy of payload (0.0–8.0)
    label               INTEGER NOT NULL CHECK (label IN (0,1)),
    anomaly_score       REAL    DEFAULT 0.0  -- 0.0 = clean, 1.0 = highly anomalous
);

-- ============================================================
-- TABLE: traffic_features
-- Pre-computed ML features per session (ready for sklearn/BERT fusion)
-- ============================================================
CREATE TABLE IF NOT EXISTS traffic_features (
    feature_id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT    NOT NULL UNIQUE,
    -- Timing features
    avg_inter_arrival_ms    REAL,
    std_inter_arrival_ms    REAL,
    min_inter_arrival_ms    REAL,
    max_inter_arrival_ms    REAL,
    burstiness_score        REAL,   -- ratio of std to mean inter-arrival
    -- Volume features
    packets_per_minute      REAL,
    bytes_per_packet_avg    REAL,
    outbound_inbound_ratio  REAL,
    -- Port / protocol features
    unique_dst_ports        INTEGER,
    sequential_port_flag    INTEGER DEFAULT 0,  -- 1 = ports accessed in sequence
    privileged_port_access  INTEGER DEFAULT 0,  -- 1 = ports < 1024 touched
    -- Behavioral features
    session_duration_sec    REAL,
    user_agent_changed      INTEGER DEFAULT 0,  -- 1 = UA changed mid-session
    ip_changed              INTEGER DEFAULT 0,  -- 1 = src IP changed mid-session
    off_hours_activity      INTEGER DEFAULT 0,  -- 1 = traffic after midnight local
    beacon_regularity       REAL    DEFAULT 0.0,-- 0.0 = irregular, 1.0 = clock-like
    -- Payload features
    avg_payload_entropy     REAL,
    large_outbound_flag     INTEGER DEFAULT 0,  -- 1 = single packet > 1MB out
    -- Ground truth
    label                   INTEGER NOT NULL,
    traffic_pattern         TEXT    NOT NULL
);

-- ============================================================
-- TABLE: traffic_taxonomy  (reference)
-- ============================================================
CREATE TABLE IF NOT EXISTS traffic_taxonomy (
    pattern_type        TEXT PRIMARY KEY,
    label               INTEGER NOT NULL,
    nlp_analog          TEXT,   -- matching pattern in conversational dataset
    description         TEXT,
    example_signals     TEXT,
    severity_range      TEXT
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_net_session    ON network_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_pkt_session    ON packet_events(net_session_id);
CREATE INDEX IF NOT EXISTS idx_feat_session   ON traffic_features(session_id);
CREATE INDEX IF NOT EXISTS idx_feat_label     ON traffic_features(label);
"""

# ──────────────────────────────────────────────────────────────────────────────
# TAXONOMY  (mirrors the NLP 6-vector taxonomy)
# ──────────────────────────────────────────────────────────────────────────────

TRAFFIC_TAXONOMY = [
    # (pattern_type, label, nlp_analog, description, example_signals, severity)
    ("normal_browsing", 0,
     "safe_interaction",
     "Human-paced HTTP/S browsing with natural timing variance and modest payloads.",
     "inter-arrival > 500ms, small payloads, 2-5 ports, standard user agent",
     "0 (N/A)"),
    ("normal_api_usage", 0,
     "safe_interaction",
     "Programmatic but well-behaved API calls: consistent cadence, small bursts.",
     "regular intervals, authenticated, low unique port count, small payloads",
     "0 (N/A)"),
    ("normal_session", 0,
     "safe_interaction",
     "Standard application session: login, activity, graceful logout.",
     "SYN→ACK→FIN lifecycle, stable IP/UA, session under 30 min",
     "0 (N/A)"),
    ("port_scanning", 1,
     "adversarial_prompting",
     "Rapid sequential probing across port range — classic reconnaissance before attack.",
     "sequential dst_ports, inter-arrival < 10ms, high RST rate, privileged port access",
     "2–3"),
    ("ddos_pattern", 1,
     "goalpost_moving",
     "Flood of requests designed to exhaust resources; targets shift as defenses respond.",
     "packets_per_minute > 500, tiny payloads, many SYN without ACK, single source",
     "3"),
    ("c2_beaconing", 1,
     "gaslighting",
     "Bot checking in with command-and-control server on a near-perfect timer — hard to "
     "spot because individual packets look innocent.",
     "beacon_regularity > 0.9, off_hours_activity, encrypted small payloads, fixed interval",
     "2–3"),
    ("data_exfiltration", 1,
     "trust_violation",
     "Large outbound transfers, often off-hours, often to unusual IPs. "
     "The network equivalent of leaking confidences.",
     "outbound_inbound_ratio > 10, large_outbound_flag, off_hours, high payload entropy",
     "3"),
    ("adversarial_probing", 1,
     "adversarial_prompting",
     "Systematic enumeration of API endpoints or model inputs — probing guardrails "
     "the same way jailbreak attempts probe token filters.",
     "many unique paths, crafted payloads, elevated entropy, rapid sequential requests",
     "2–3"),
    ("session_hijack", 1,
     "trust_violation",
     "Attacker takes over a legitimate session mid-stream: IP or user-agent suddenly "
     "changes, then behavior shifts. Maps to trust_violation / gaslighting combo.",
     "user_agent_changed=1 OR ip_changed=1, abrupt behavioral shift, re-auth attempts",
     "3"),
]

# ──────────────────────────────────────────────────────────────────────────────
# HELPER UTILITIES
# ──────────────────────────────────────────────────────────────────────────────

COMMON_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile Safari/604.1",
]
BOT_USER_AGENTS = [
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "Wget/1.21.4",
    "custom-scanner/0.1",
    "",   # blank UA — common in scanners
]
COMMON_PORTS   = [80, 443, 8080, 8443, 3000, 5000]
SENSITIVE_PORTS = [22, 23, 21, 25, 3306, 5432, 6379, 27017]
ALL_PORTS       = COMMON_PORTS + SENSITIVE_PORTS + list(range(8000, 8020))

def rand_ip(internal=False):
    if internal:
        return f"192.168.{random.randint(0,5)}.{random.randint(1,254)}"
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_ts(base_dt, offset_ms):
    """Return ISO timestamp string offset_ms milliseconds from base_dt."""
    return (base_dt + timedelta(milliseconds=offset_ms)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

def shannon_entropy(byte_distribution):
    """Shannon entropy given a list of byte-frequency floats."""
    total = sum(byte_distribution)
    if total == 0:
        return 0.0
    probs = [b / total for b in byte_distribution if b > 0]
    return -sum(p * math.log2(p) for p in probs)

def normal_entropy():
    """Entropy for normal HTTPS traffic: ~5.5–7.5 bits (encrypted but structured)."""
    return round(random.uniform(5.5, 7.5), 3)

def high_entropy():
    """Entropy for compressed/encrypted data exfiltration: ~7.5–8.0 bits."""
    return round(random.uniform(7.5, 8.0), 3)

def low_entropy():
    """Entropy for simple payloads (scan probes): ~1.0–3.5 bits."""
    return round(random.uniform(1.0, 3.5), 3)

# ──────────────────────────────────────────────────────────────────────────────
# SESSION GENERATORS
# Each returns (session_dict, [packet_dicts], feature_dict)
# ──────────────────────────────────────────────────────────────────────────────

def _base_session(session_id, label, pattern, severity, src_ip=None, dst_ip=None,
                  ua=None, protocol="HTTPS"):
    hour = random.randint(8, 22) if label == 0 else random.randint(0, 23)
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28), hour,
                       random.randint(0,59), random.randint(0,59))
    return {
        "session_id":    session_id,
        "src_ip":        src_ip or rand_ip(),
        "dst_ip":        dst_ip or rand_ip(),
        "user_agent":    ua or random.choice(COMMON_USER_AGENTS),
        "protocol":      protocol,
        "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label":         label,
        "traffic_pattern": pattern,
        "severity":      severity,
        "_base_dt":      base_dt,   # internal, not inserted
    }

# ── NORMAL BROWSING ──────────────────────────────────────────────────────────

def gen_normal_browsing(session_id):
    s = _base_session(session_id, 0, "normal_browsing", 0)
    base_dt = s["_base_dt"]
    src, dst = s["src_ip"], s["dst_ip"]
    ua = s["user_agent"]

    packets = []
    t_ms = 0
    n_requests = random.randint(8, 25)
    inter_arrivals = []

    for i in range(n_requests):
        # Natural browsing: 500ms – 8s between requests
        gap = random.uniform(500, 8000)
        inter_arrivals.append(gap)
        t_ms += gap
        port = random.choice([443, 443, 443, 80])
        size = random.randint(200, 4096)
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": port,
            "protocol": "HTTPS" if port == 443 else "HTTP",
            "packet_size_bytes": size, "direction": "outbound",
            "flag": "PSH", "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 0, "anomaly_score": 0.0,
        })
        # Response packet
        t_ms += random.uniform(10, 150)
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": dst, "dst_ip": src,
            "src_port": port, "dst_port": packets[-1]["src_port"],
            "protocol": packets[-1]["protocol"],
            "packet_size_bytes": random.randint(500, 50000),
            "direction": "inbound", "flag": "ACK",
            "inter_arrival_ms": round(random.uniform(10, 150), 2),
            "payload_entropy": normal_entropy(), "label": 0, "anomaly_score": 0.0,
        })

    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound")
    avg_ia    = sum(inter_arrivals) / len(inter_arrivals)
    std_ia    = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in
    s["notes"] = "Synthetic normal browsing session"

    features = {
        "session_id": session_id, "label": 0, "traffic_pattern": "normal_browsing",
        "avg_inter_arrival_ms":  round(avg_ia, 2),
        "std_inter_arrival_ms":  round(std_ia, 2),
        "min_inter_arrival_ms":  round(min(inter_arrivals), 2),
        "max_inter_arrival_ms":  round(max(inter_arrivals), 2),
        "burstiness_score":      round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":    round(len(packets) / (duration / 60), 2),
        "bytes_per_packet_avg":  round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in if total_in > 0 else 1, 4),
        "unique_dst_ports":      len(set(p["dst_port"] for p in packets if p["direction"]=="outbound")),
        "sequential_port_flag":  0, "privileged_port_access": 0,
        "session_duration_sec":  round(duration, 2),
        "user_agent_changed":    0, "ip_changed": 0,
        "off_hours_activity":    1 if s["_base_dt"].hour < 6 or s["_base_dt"].hour > 22 else 0,
        "beacon_regularity":     round(random.uniform(0.0, 0.2), 4),
        "avg_payload_entropy":   round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag":   0,
    }
    return s, packets, features

# ── NORMAL API USAGE ─────────────────────────────────────────────────────────

def gen_normal_api(session_id):
    s = _base_session(session_id, 0, "normal_api_usage", 0,
                      ua=random.choice(COMMON_USER_AGENTS + BOT_USER_AGENTS[:3]))
    base_dt = s["_base_dt"]
    src, dst = s["src_ip"], s["dst_ip"]

    packets = []
    t_ms = 0
    inter_arrivals = []
    n_calls = random.randint(10, 40)

    for _ in range(n_calls):
        gap = random.uniform(200, 2000)   # programmatic but not hyper-fast
        inter_arrivals.append(gap)
        t_ms += gap
        size = random.randint(100, 2048)
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": size,
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 0, "anomaly_score": 0.0,
        })
        t_ms += random.uniform(5, 50)
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": dst, "dst_ip": src,
            "src_port": 443, "dst_port": packets[-1]["src_port"],
            "protocol": "HTTPS", "packet_size_bytes": random.randint(200, 4096),
            "direction": "inbound", "flag": "ACK",
            "inter_arrival_ms": round(random.uniform(5, 50), 2),
            "payload_entropy": normal_entropy(), "label": 0, "anomaly_score": 0.0,
        })

    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound")
    avg_ia    = sum(inter_arrivals) / len(inter_arrivals)
    std_ia    = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in
    s["notes"] = "Synthetic normal API usage"

    features = {
        "session_id": session_id, "label": 0, "traffic_pattern": "normal_api_usage",
        "avg_inter_arrival_ms":  round(avg_ia, 2),
        "std_inter_arrival_ms":  round(std_ia, 2),
        "min_inter_arrival_ms":  round(min(inter_arrivals), 2),
        "max_inter_arrival_ms":  round(max(inter_arrivals), 2),
        "burstiness_score":      round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":    round(len(packets) / (duration / 60), 2),
        "bytes_per_packet_avg":  round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in if total_in > 0 else 1, 4),
        "unique_dst_ports": 1,
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1 if s["_base_dt"].hour < 6 or s["_base_dt"].hour > 22 else 0,
        "beacon_regularity": round(random.uniform(0.1, 0.35), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── NORMAL SESSION ────────────────────────────────────────────────────────────

def gen_normal_session(session_id):
    s = _base_session(session_id, 0, "normal_session", 0)
    base_dt = s["_base_dt"]
    src, dst = s["src_ip"], s["dst_ip"]

    packets = []
    t_ms = 0

    # SYN handshake
    for flag in ["SYN", "SYN-ACK", "ACK"]:
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src if flag != "SYN-ACK" else dst,
            "dst_ip": dst if flag != "SYN-ACK" else src,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "TCP", "packet_size_bytes": 60,
            "direction": "outbound" if flag != "SYN-ACK" else "inbound",
            "flag": flag, "inter_arrival_ms": round(random.uniform(1, 5), 2),
            "payload_entropy": 0.5, "label": 0, "anomaly_score": 0.0,
        })
        t_ms += random.uniform(1, 5)

    inter_arrivals = []
    for _ in range(random.randint(5, 20)):
        gap = random.uniform(800, 5000)
        inter_arrivals.append(gap)
        t_ms += gap
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": random.randint(300, 8192),
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 0, "anomaly_score": 0.0,
        })

    # Graceful FIN
    t_ms += random.uniform(100, 500)
    packets.append({
        "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
        "src_ip": src, "dst_ip": dst,
        "src_port": random.randint(49152, 65535), "dst_port": 443,
        "protocol": "TCP", "packet_size_bytes": 60,
        "direction": "outbound", "flag": "FIN",
        "inter_arrival_ms": round(random.uniform(100, 500), 2),
        "payload_entropy": 0.0, "label": 0, "anomaly_score": 0.0,
    })

    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound")
    avg_ia    = sum(inter_arrivals) / len(inter_arrivals) if inter_arrivals else 1000

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in
    s["notes"] = "Synthetic normal session (SYN→activity→FIN)"

    features = {
        "session_id": session_id, "label": 0, "traffic_pattern": "normal_session",
        "avg_inter_arrival_ms": round(avg_ia, 2),
        "std_inter_arrival_ms": round(random.uniform(200, 1500), 2),
        "min_inter_arrival_ms": 1.0,
        "max_inter_arrival_ms": round(max(inter_arrivals) if inter_arrivals else 5000, 2),
        "burstiness_score":     round(random.uniform(0.2, 0.6), 4),
        "packets_per_minute":   round(len(packets) / (duration / 60), 2),
        "bytes_per_packet_avg": round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in if total_in > 0 else 1, 4),
        "unique_dst_ports": 1,
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1 if s["_base_dt"].hour < 6 or s["_base_dt"].hour > 22 else 0,
        "beacon_regularity": round(random.uniform(0.0, 0.15), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── PORT SCANNING ─────────────────────────────────────────────────────────────

def gen_port_scan(session_id):
    # Mirrors: adversarial_prompting — systematic probing to find vulnerabilities
    base_hour = random.choice([1, 2, 3, 4, 22, 23])  # off-hours
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       base_hour, random.randint(0,59), 0)
    src = rand_ip()
    dst = rand_ip()
    s = {
        "session_id": session_id, "src_ip": src, "dst_ip": dst,
        "user_agent": random.choice(BOT_USER_AGENTS),
        "protocol": "TCP", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "port_scanning", "severity": 3,
        "notes": "Synthetic port scan — sequential probe across port range",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    # Sequential port scan: SYN to ports 1–1024 in order
    start_port = random.randint(1, 100)
    n_ports = random.randint(200, 1024)
    ports_hit = list(range(start_port, start_port + n_ports))
    inter_arrivals = []

    for p_num in ports_hit:
        gap = random.uniform(0.5, 8)   # very fast — milliseconds between probes
        inter_arrivals.append(gap)
        t_ms += gap
        flag = random.choice(["SYN", "SYN", "SYN", "RST"])
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": p_num % 65535 or 1,
            "protocol": "TCP", "packet_size_bytes": 60,
            "direction": "outbound", "flag": flag,
            "inter_arrival_ms": round(gap, 3),
            "payload_entropy": low_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.75, 0.99), 3),
        })

    avg_ia  = sum(inter_arrivals) / len(inter_arrivals)
    std_ia  = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    duration = t_ms / 1000

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = sum(p["packet_size_bytes"] for p in packets)
    s["total_bytes_in"]  = 0

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "port_scanning",
        "avg_inter_arrival_ms":  round(avg_ia, 3),
        "std_inter_arrival_ms":  round(std_ia, 3),
        "min_inter_arrival_ms":  round(min(inter_arrivals), 3),
        "max_inter_arrival_ms":  round(max(inter_arrivals), 3),
        "burstiness_score":      round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":    round(len(packets) / (duration / 60), 2),
        "bytes_per_packet_avg":  60.0,
        "outbound_inbound_ratio": 999.0,  # all outbound, no responses
        "unique_dst_ports":      n_ports,
        "sequential_port_flag":  1,
        "privileged_port_access": 1,
        "session_duration_sec":  round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1,
        "beacon_regularity": round(random.uniform(0.7, 0.95), 4),
        "avg_payload_entropy":   round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── DDoS PATTERN ──────────────────────────────────────────────────────────────

def gen_ddos(session_id):
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       random.randint(0,23), random.randint(0,59), 0)
    src = rand_ip()
    dst = rand_ip()
    s = {
        "session_id": session_id, "src_ip": src, "dst_ip": dst,
        "user_agent": "",  # blank in floods
        "protocol": "TCP/UDP", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "ddos_pattern", "severity": 3,
        "notes": "Synthetic DDoS flood — high packet rate, tiny payloads",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    n_pkts = random.randint(800, 2000)
    inter_arrivals = []

    for _ in range(n_pkts):
        gap = random.uniform(0.05, 2.5)   # sub-millisecond to ~2ms
        inter_arrivals.append(gap)
        t_ms += gap
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53]),
            "protocol": random.choice(["TCP", "UDP", "TCP"]),
            "packet_size_bytes": random.randint(40, 200),
            "direction": "outbound",
            "flag": random.choice(["SYN", "SYN", "PSH", "ACK"]),
            "inter_arrival_ms": round(gap, 3),
            "payload_entropy": low_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.85, 0.99), 3),
        })

    avg_ia   = sum(inter_arrivals) / len(inter_arrivals)
    std_ia   = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    duration = t_ms / 1000

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = sum(p["packet_size_bytes"] for p in packets)
    s["total_bytes_in"]  = 0

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "ddos_pattern",
        "avg_inter_arrival_ms": round(avg_ia, 3),
        "std_inter_arrival_ms": round(std_ia, 3),
        "min_inter_arrival_ms": round(min(inter_arrivals), 3),
        "max_inter_arrival_ms": round(max(inter_arrivals), 3),
        "burstiness_score":     round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":   round(len(packets) / max(duration / 60, 0.001), 2),
        "bytes_per_packet_avg": round(s["total_bytes_out"] / len(packets), 1),
        "outbound_inbound_ratio": 999.0,
        "unique_dst_ports":     len(set(p["dst_port"] for p in packets)),
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1 if base_dt.hour < 6 or base_dt.hour > 22 else 0,
        "beacon_regularity": round(random.uniform(0.3, 0.65), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── C2 BEACONING ──────────────────────────────────────────────────────────────

def gen_c2_beacon(session_id):
    # Mirrors: gaslighting — regular, subtle, hard to spot if you don't know the baseline
    base_hour = random.choice([0, 1, 2, 3, 4])   # always off-hours
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       base_hour, 0, 0)
    src = rand_ip(internal=True)   # C2 beacons come FROM internal infected host
    dst = rand_ip()
    beacon_interval = random.choice([30000, 60000, 300000, 600000])  # 30s, 1m, 5m, 10m
    jitter = beacon_interval * random.uniform(0.01, 0.05)  # tiny jitter to evade detection

    s = {
        "session_id": session_id, "src_ip": src, "dst_ip": dst,
        "user_agent": random.choice(BOT_USER_AGENTS),
        "protocol": "HTTPS", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "c2_beaconing", "severity": 2,
        "notes": f"Synthetic C2 beacon — {beacon_interval/1000:.0f}s interval with {jitter/1000:.1f}s jitter",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    n_beacons = random.randint(8, 20)
    inter_arrivals = []

    for _ in range(n_beacons):
        gap = beacon_interval + random.uniform(-jitter, jitter)
        inter_arrivals.append(gap)
        t_ms += gap
        size = random.randint(60, 512)   # small encrypted checkin
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": size,
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.55, 0.80), 3),
        })
        # C2 response (small command)
        t_ms += random.uniform(50, 200)
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": dst, "dst_ip": src,
            "src_port": 443, "dst_port": packets[-1]["src_port"],
            "protocol": "HTTPS", "packet_size_bytes": random.randint(60, 256),
            "direction": "inbound", "flag": "ACK",
            "inter_arrival_ms": round(random.uniform(50, 200), 2),
            "payload_entropy": normal_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.55, 0.80), 3),
        })

    avg_ia  = sum(inter_arrivals) / len(inter_arrivals)
    std_ia  = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    # Key signal: beacon regularity = 1 - (std/mean). Close to 1.0 = clock-like
    regularity = round(max(0, 1.0 - (std_ia / avg_ia)), 4)
    duration = t_ms / 1000

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = sum(p["packet_size_bytes"] for p in packets if p["direction"]=="outbound")
    s["total_bytes_in"]  = sum(p["packet_size_bytes"] for p in packets if p["direction"]=="inbound")

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "c2_beaconing",
        "avg_inter_arrival_ms": round(avg_ia, 2),
        "std_inter_arrival_ms": round(std_ia, 2),
        "min_inter_arrival_ms": round(min(inter_arrivals), 2),
        "max_inter_arrival_ms": round(max(inter_arrivals), 2),
        "burstiness_score":     round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":   round(len(packets) / (duration / 60), 2),
        "bytes_per_packet_avg": round((s["total_bytes_out"] + s["total_bytes_in"]) / len(packets), 1),
        "outbound_inbound_ratio": round(s["total_bytes_out"] / s["total_bytes_in"] if s["total_bytes_in"] > 0 else 1, 4),
        "unique_dst_ports": 1,
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1,
        "beacon_regularity": regularity,   # ← The key feature. Normal < 0.3. C2 > 0.85
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── DATA EXFILTRATION ─────────────────────────────────────────────────────────

def gen_exfiltration(session_id):
    # Mirrors: trust_violation — betrayal of established relationship
    base_hour = random.choice([1, 2, 3, 4])
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       base_hour, 0, 0)
    src = rand_ip(internal=True)
    dst = rand_ip()

    s = {
        "session_id": session_id, "src_ip": src, "dst_ip": dst,
        "user_agent": random.choice(BOT_USER_AGENTS + COMMON_USER_AGENTS[:2]),
        "protocol": "HTTPS", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "data_exfiltration", "severity": 3,
        "notes": "Synthetic data exfiltration — large outbound payload, off-hours",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    inter_arrivals = []

    # Initial recon / auth: small packets
    for _ in range(random.randint(3, 8)):
        gap = random.uniform(200, 2000)
        inter_arrivals.append(gap)
        t_ms += gap
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": random.randint(100, 512),
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.3, 0.5), 3),
        })

    # The exfiltration burst: large outbound payloads
    n_large = random.randint(3, 10)
    for _ in range(n_large):
        gap = random.uniform(50, 500)
        inter_arrivals.append(gap)
        t_ms += gap
        size = random.randint(500_000, 5_000_000)   # 500KB–5MB chunks
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": size,
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": high_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.80, 0.99), 3),
        })

    avg_ia   = sum(inter_arrivals) / len(inter_arrivals)
    std_ia   = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound") or 1

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "data_exfiltration",
        "avg_inter_arrival_ms": round(avg_ia, 2),
        "std_inter_arrival_ms": round(std_ia, 2),
        "min_inter_arrival_ms": round(min(inter_arrivals), 2),
        "max_inter_arrival_ms": round(max(inter_arrivals), 2),
        "burstiness_score":     round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":   round(len(packets) / max(duration / 60, 0.001), 2),
        "bytes_per_packet_avg": round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in, 4),   # ← Very high
        "unique_dst_ports": 1,
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 0, "ip_changed": 0,
        "off_hours_activity": 1,   # always off-hours
        "beacon_regularity": round(random.uniform(0.0, 0.2), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 1,   # ← Key flag
    }
    return s, packets, features

# ── ADVERSARIAL PROBING ───────────────────────────────────────────────────────

def gen_adversarial_probe(session_id):
    # Mirrors: adversarial_prompting — testing model guardrails systematically
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       random.randint(0,23), random.randint(0,59), 0)
    src = rand_ip()
    dst = rand_ip()

    s = {
        "session_id": session_id, "src_ip": src, "dst_ip": dst,
        "user_agent": random.choice(BOT_USER_AGENTS),
        "protocol": "HTTPS", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "adversarial_probing", "severity": 2,
        "notes": "Synthetic adversarial probing — rapid endpoint enumeration, crafted payloads",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    inter_arrivals = []
    n_probes = random.randint(40, 150)

    for i in range(n_probes):
        gap = random.uniform(10, 200)   # fast but not instant
        inter_arrivals.append(gap)
        t_ms += gap
        # Entropy of crafted payloads varies — probing different encodings
        entropy = random.choice([low_entropy(), normal_entropy(), high_entropy()])
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([80, 443, 8080, 8443]),
            "protocol": "HTTPS",
            "packet_size_bytes": random.randint(256, 8192),
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": entropy, "label": 1,
            "anomaly_score": round(random.uniform(0.6, 0.92), 3),
        })
        # Mostly 403/404 responses — server is refusing
        if random.random() < 0.7:
            t_ms += random.uniform(5, 30)
            packets.append({
                "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
                "src_ip": dst, "dst_ip": src,
                "src_port": packets[-1]["dst_port"], "dst_port": packets[-1]["src_port"],
                "protocol": "HTTPS", "packet_size_bytes": random.randint(100, 400),
                "direction": "inbound", "flag": "ACK",
                "inter_arrival_ms": round(random.uniform(5, 30), 2),
                "payload_entropy": low_entropy(), "label": 1,
                "anomaly_score": round(random.uniform(0.4, 0.7), 3),
            })

    avg_ia   = sum(inter_arrivals) / len(inter_arrivals)
    std_ia   = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound") or 1

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "adversarial_probing",
        "avg_inter_arrival_ms": round(avg_ia, 2),
        "std_inter_arrival_ms": round(std_ia, 2),
        "min_inter_arrival_ms": round(min(inter_arrivals), 2),
        "max_inter_arrival_ms": round(max(inter_arrivals), 2),
        "burstiness_score":     round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":   round(len(packets) / max(duration / 60, 0.001), 2),
        "bytes_per_packet_avg": round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in, 4),
        "unique_dst_ports":     len(set(p["dst_port"] for p in packets)),
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": random.randint(0, 1),
        "ip_changed": 0,
        "off_hours_activity": 1 if base_dt.hour < 6 or base_dt.hour > 22 else 0,
        "beacon_regularity": round(random.uniform(0.2, 0.5), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 0,
    }
    return s, packets, features

# ── SESSION HIJACK ────────────────────────────────────────────────────────────

def gen_session_hijack(session_id):
    # Mirrors: trust_violation + gaslighting — uses established context to do damage
    base_dt = datetime(2024, random.randint(1,12), random.randint(1,28),
                       random.randint(9, 18), random.randint(0,59), 0)
    legitimate_src = rand_ip()
    hijacker_src   = rand_ip()
    dst = rand_ip()
    legitimate_ua  = random.choice(COMMON_USER_AGENTS)
    hijacker_ua    = random.choice(BOT_USER_AGENTS + COMMON_USER_AGENTS)
    while hijacker_ua == legitimate_ua:
        hijacker_ua = random.choice(BOT_USER_AGENTS + COMMON_USER_AGENTS)

    s = {
        "session_id": session_id, "src_ip": legitimate_src, "dst_ip": dst,
        "user_agent": legitimate_ua,
        "protocol": "HTTPS", "session_start": base_dt.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": 1, "traffic_pattern": "session_hijack", "severity": 3,
        "notes": f"Synthetic session hijack — IP changes from {legitimate_src} to {hijacker_src} mid-session; UA changes",
        "_base_dt": base_dt,
    }

    packets = []
    t_ms = 0
    inter_arrivals = []

    # Phase 1: Legitimate session (looks totally normal)
    for _ in range(random.randint(5, 12)):
        gap = random.uniform(500, 5000)
        inter_arrivals.append(gap)
        t_ms += gap
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": legitimate_src, "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": random.randint(200, 4096),
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": normal_entropy(), "label": 0,
            "anomaly_score": 0.05,
        })

    # Sudden IP + UA change — the hijack moment
    t_ms += random.uniform(100, 800)
    for _ in range(random.randint(5, 15)):
        gap = random.uniform(50, 300)   # attacker moves faster
        inter_arrivals.append(gap)
        t_ms += gap
        packets.append({
            "session_id": session_id, "timestamp": rand_ts(base_dt, t_ms),
            "src_ip": hijacker_src,  # ← IP changed!
            "dst_ip": dst,
            "src_port": random.randint(49152, 65535), "dst_port": 443,
            "protocol": "HTTPS", "packet_size_bytes": random.randint(1024, 10000),
            "direction": "outbound", "flag": "PSH",
            "inter_arrival_ms": round(gap, 2),
            "payload_entropy": high_entropy(), "label": 1,
            "anomaly_score": round(random.uniform(0.80, 0.99), 3),
        })

    avg_ia   = sum(inter_arrivals) / len(inter_arrivals)
    std_ia   = math.sqrt(sum((x - avg_ia)**2 for x in inter_arrivals) / len(inter_arrivals))
    duration = t_ms / 1000
    total_out = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "outbound")
    total_in  = sum(p["packet_size_bytes"] for p in packets if p["direction"] == "inbound") or 1

    s["session_end"]     = rand_ts(base_dt, t_ms)
    s["total_packets"]   = len(packets)
    s["total_bytes_out"] = total_out
    s["total_bytes_in"]  = total_in

    features = {
        "session_id": session_id, "label": 1, "traffic_pattern": "session_hijack",
        "avg_inter_arrival_ms": round(avg_ia, 2),
        "std_inter_arrival_ms": round(std_ia, 2),
        "min_inter_arrival_ms": round(min(inter_arrivals), 2),
        "max_inter_arrival_ms": round(max(inter_arrivals), 2),
        "burstiness_score":     round(std_ia / avg_ia if avg_ia > 0 else 0, 4),
        "packets_per_minute":   round(len(packets) / max(duration / 60, 0.001), 2),
        "bytes_per_packet_avg": round((total_out + total_in) / len(packets), 1),
        "outbound_inbound_ratio": round(total_out / total_in, 4),
        "unique_dst_ports": 1,
        "sequential_port_flag": 0, "privileged_port_access": 0,
        "session_duration_sec": round(duration, 2),
        "user_agent_changed": 1,   # ← Key flag
        "ip_changed": 1,           # ← Key flag
        "off_hours_activity": 1 if base_dt.hour < 6 or base_dt.hour > 22 else 0,
        "beacon_regularity": round(random.uniform(0.0, 0.3), 4),
        "avg_payload_entropy": round(sum(p["payload_entropy"] for p in packets)/len(packets), 3),
        "large_outbound_flag": 1 if total_out > 1_000_000 else 0,
    }
    return s, packets, features

# ──────────────────────────────────────────────────────────────────────────────
# DATASET COMPOSITION
# 200 sessions: 100 normal (3 types), 100 suspicious (6 types)
# Session IDs are shared with sns_bert.db conversations (session_001 – session_200)
# ──────────────────────────────────────────────────────────────────────────────

NORMAL_GENERATORS = [gen_normal_browsing, gen_normal_api, gen_normal_session]

SUSPICIOUS_GENERATORS = [
    gen_port_scan,
    gen_ddos,
    gen_c2_beacon,
    gen_exfiltration,
    gen_adversarial_probe,
    gen_session_hijack,
]

def compose_dataset():
    """Return list of (session, packets, features) tuples for 200 sessions."""
    dataset = []

    # 100 normal sessions — rotate through the 3 normal types
    for i in range(1, 101):
        sid = f"session_{i:03d}"
        gen = NORMAL_GENERATORS[i % len(NORMAL_GENERATORS)]
        dataset.append(gen(sid))

    # 100 suspicious sessions — roughly even split across 6 attack types
    for i in range(101, 201):
        sid = f"session_{i:03d}"
        gen = SUSPICIOUS_GENERATORS[(i - 101) % len(SUSPICIOUS_GENERATORS)]
        dataset.append(gen(sid))

    random.shuffle(dataset)
    return dataset

# ──────────────────────────────────────────────────────────────────────────────
# DATABASE BUILD
# ──────────────────────────────────────────────────────────────────────────────

def build_network_db(db_path=TRAFFIC_DB):
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    statements = re.split(r';\s*\n', NETWORK_SCHEMA)
    for stmt in statements:
        lines = [l for l in stmt.splitlines() if not l.strip().startswith("--")]
        clean = "\n".join(lines).strip()
        if clean:
            try:
                cur.execute(clean)
            except sqlite3.OperationalError as e:
                print(f"WARN schema: {e}")
    conn.commit()

    # Insert taxonomy
    for row in TRAFFIC_TAXONOMY:
        pattern, label, analog, desc, signals, sev = row
        try:
            cur.execute("""
                INSERT OR IGNORE INTO traffic_taxonomy
                (pattern_type, label, nlp_analog, description, example_signals, severity_range)
                VALUES (?,?,?,?,?,?)
            """, (pattern, label, analog, desc, signals, sev))
        except Exception as e:
            print(f"WARN taxonomy: {e}")
    conn.commit()

    dataset = compose_dataset()
    pkt_count = 0

    for session, packets, features in dataset:
        sid = session["session_id"]
        # Remove internal key before insert
        s_clean = {k: v for k, v in session.items() if k != "_base_dt"}

        cur.execute("""
            INSERT OR IGNORE INTO network_sessions
            (session_id, src_ip, dst_ip, user_agent, protocol,
             session_start, session_end, total_packets,
             total_bytes_in, total_bytes_out, label, traffic_pattern, severity, notes)
            VALUES (:session_id,:src_ip,:dst_ip,:user_agent,:protocol,
                    :session_start,:session_end,:total_packets,
                    :total_bytes_in,:total_bytes_out,:label,:traffic_pattern,:severity,:notes)
        """, s_clean)
        net_id = cur.lastrowid

        for pkt in packets:
            cur.execute("""
                INSERT INTO packet_events
                (net_session_id, session_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, packet_size_bytes, direction, flag, inter_arrival_ms,
                 payload_entropy, label, anomaly_score)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (net_id, pkt["session_id"], pkt["timestamp"],
                  pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"],
                  pkt["protocol"], pkt["packet_size_bytes"], pkt["direction"],
                  pkt["flag"], pkt["inter_arrival_ms"],
                  pkt["payload_entropy"], pkt["label"], pkt["anomaly_score"]))
        pkt_count += len(packets)

        cur.execute("""
            INSERT OR IGNORE INTO traffic_features
            (session_id, avg_inter_arrival_ms, std_inter_arrival_ms,
             min_inter_arrival_ms, max_inter_arrival_ms, burstiness_score,
             packets_per_minute, bytes_per_packet_avg, outbound_inbound_ratio,
             unique_dst_ports, sequential_port_flag, privileged_port_access,
             session_duration_sec, user_agent_changed, ip_changed,
             off_hours_activity, beacon_regularity, avg_payload_entropy,
             large_outbound_flag, label, traffic_pattern)
            VALUES (:session_id,:avg_inter_arrival_ms,:std_inter_arrival_ms,
                    :min_inter_arrival_ms,:max_inter_arrival_ms,:burstiness_score,
                    :packets_per_minute,:bytes_per_packet_avg,:outbound_inbound_ratio,
                    :unique_dst_ports,:sequential_port_flag,:privileged_port_access,
                    :session_duration_sec,:user_agent_changed,:ip_changed,
                    :off_hours_activity,:beacon_regularity,:avg_payload_entropy,
                    :large_outbound_flag,:label,:traffic_pattern)
        """, features)

    conn.commit()

    # ── Report ──
    cur.execute("SELECT COUNT(*) FROM network_sessions")
    total_s = cur.fetchone()[0]
    cur.execute("SELECT label, COUNT(*) FROM network_sessions GROUP BY label")
    label_counts = dict(cur.fetchall())
    cur.execute("SELECT traffic_pattern, COUNT(*) FROM network_sessions GROUP BY traffic_pattern ORDER BY COUNT(*) DESC")
    patterns = cur.fetchall()
    cur.execute("SELECT COUNT(*) FROM packet_events")
    total_pkts = cur.fetchone()[0]
    cur.execute("SELECT AVG(session_duration_sec), AVG(packets_per_minute), AVG(beacon_regularity) FROM traffic_features")
    avgs = cur.fetchone()
    cur.execute("SELECT AVG(beacon_regularity) FROM traffic_features WHERE label=1 AND traffic_pattern='c2_beaconing'")
    c2_beacon_avg = cur.fetchone()[0]

    conn.close()

    print("\n" + "="*65)
    print("  SNS Network Traffic Database — Build Complete")
    print(f"  {db_path}")
    print("="*65)
    print(f"\n  Sessions         : {total_s}")
    print(f"  Normal  (0)      : {label_counts.get(0,0)}")
    print(f"  Suspicious (1)   : {label_counts.get(1,0)}")
    print(f"  Total packets    : {total_pkts:,}")
    print(f"\n  Pattern breakdown:")
    for p, c in patterns:
        bar = "█" * c
        print(f"    {p:<28} {c:>3}  {bar}")
    print(f"\n  Avg session duration  : {avgs[0]:.1f}s")
    print(f"  Avg packets/min       : {avgs[1]:.1f}")
    print(f"  Avg beacon regularity : {avgs[2]:.3f}")
    print(f"  C2 beacon regularity  : {c2_beacon_avg:.3f}  ← should be > 0.85")
    print("="*65)
    print("\n  Join key: network_sessions.session_id ↔ conversations.session_id")
    print("  Multimodal query example:")
    print("    SELECT c.raw_text, ld.pattern_type AS nlp_pattern,")
    print("           ns.traffic_pattern, tf.beacon_regularity, tf.large_outbound_flag")
    print("    FROM conversations c")
    print("    JOIN labeled_data ld ON c.conversation_id = ld.conversation_id")
    print("    JOIN network_sessions ns ON c.session_id = ns.session_id")
    print("    JOIN traffic_features tf ON tf.session_id = ns.session_id")
    print("    WHERE ld.label = 1 AND ns.label = 1")
    print("    -- Sessions flagged by BOTH the NLP model AND the network layer")
    print("="*65 + "\n")


if __name__ == "__main__":
    build_network_db()
    print("Done! To merge into sns_bert.db, run:")
    print("  python sns_network_traffic.py  (creates sns_network.db)")
    print("  sqlite3 sns_bert.db 'ATTACH \"sns_network.db\" AS net;'")
    print("  -- then use net.network_sessions, net.traffic_features, etc.")
