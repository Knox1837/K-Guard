"""
ml/config.py 
 Tunables for the K-Guard ML anomaly detector.
"""
# Tuning for further accuracy

# arbitrary keywords considered sensitive
SENSITIVE_KEYWORDS = ["shadow", "passwd", "secret", "root", ".ssh", "credential"]

# Ports considered "well known"
# expected for outbound traffic
WELL_KNOWN_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995}

# Max seconds between a READ and a CONNECT to consider them part of the same window (~5 seconds)
READ_THEN_CONNECT_WINDOW_NS = 5 * 1_000_000_000

# IsolationForest params
CONTAMINATION = 0.05
RANDOM_STATE = 42

# Log-scale large byte counts before feeding them to the model so a single huge exfil transfer doesn't totally dominate every other feature scale
LOG_SCALE_BYTES = True
