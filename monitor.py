import argparse, csv, hashlib, ipaddress, json, re
from datetime import datetime, timezone
from pathlib import Path

CRED = [re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*([^\s,;]{3,})"),
        re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|secret)\s*[:=]\s*([^\s,;]{6,})")]
URL = re.compile(r"""https?://[A-Za-z0-9.-]+(?::\d{1,5})?(?:/[^\s"'<>]*)?""")
DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu|invalid|test|example)\b")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HIGH = ("ransomware", "breach", "exploit", "dump", "exposed", "leak")

def redact(text):
    found = False
    for pat in CRED:
        def sub(m):
            nonlocal found
            found = True
            return f"{m.group(1)}=[REDACTED]"
        text = pat.sub(sub, text)
    return text, found

def load_config(path):
    c = json.loads(path.read_text(encoding="utf-8"))
    keys = ("organizations", "domains", "products", "keywords")
    for k in keys:
        if not isinstance(c.get(k, []), list): raise ValueError(f"{k} must be a list")
    return {k: [str(x).strip().lower() for x in c.get(k, []) if str(x).strip()] for k in keys}

def load_records(path):
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict): data = data.get("records", [])
        if not isinstance(data, list): raise ValueError("JSON must be a list or contain a records list")
        return [x for x in data if isinstance(x, dict)]
    if path.suffix.lower() == ".jsonl":
        return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f: return list(csv.DictReader(f))
    raise ValueError("Input must be .json, .jsonl, or .csv")

def analyze(record, config):
    title = str(record.get("title", "Untitled"))
    body = str(record.get("text", record.get("content", "")))
    safe, has_cred = redact(title + "\n" + body)
    low = safe.lower()
    matches = [{"category": k, "term": t} for k, terms in config.items() for t in terms if t in low]
    urls = sorted(set(URL.findall(safe)))
    domains = sorted(set(x.lower() for x in DOMAIN.findall(safe)))
    ips = []
    for candidate in IP.findall(safe):
        try: ipaddress.ip_address(candidate); ips.append(candidate)
        except ValueError: pass
    score = (3 if any(x["category"] in ("organizations","domains","products") for x in matches) else 0)
    score += 2 if urls or domains or ips else 0
    score += 2 if has_cred else 0
    score += 1 if any(w in low for w in HIGH) else 0
    score = min(score, 8)
    fingerprint = hashlib.sha256("|".join([str(record.get("source","unknown")), title, safe, str(record.get("date","")), str(record.get("id",""))]).encode()).hexdigest()
    return {"record_id": str(record.get("id") or fingerprint[:12]), "source": str(record.get("source","unspecified")),
            "date": str(record.get("date","")), "title": title, "safe_text": safe,
            "source_reference": str(record.get("url","")), "watchlist_matches": matches,
            "indicators": {"urls": urls, "domains": domains, "ip_addresses": sorted(set(ips))},
            "credential_like_pattern_detected": has_cred, "priority_score": score,
            "priority": "high" if score >= 6 else "medium" if score >= 3 else "low",
            "fingerprint_sha256": fingerprint, "analyzed_at_utc": datetime.now(timezone.utc).isoformat()}

def main():
    p = argparse.ArgumentParser(description="Analyze authorized threat-intelligence exports.")
    p.add_argument("--input", required=True, type=Path); p.add_argument("--config", required=True, type=Path); p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    try:
        cfg, records = load_config(a.config), load_records(a.input)
        unique = {}
        for record in records:
            result = analyze(record, cfg); unique.setdefault(result["fingerprint_sha256"], result)
        out = a.out; out.mkdir(parents=True, exist_ok=True); results = list(unique.values())
        (out/"report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        fields = ["record_id","source","date","title","priority_score","priority","credential_like_pattern_detected","source_reference","fingerprint_sha256"]
        with (out/"report.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
            for x in results: w.writerow({k:x.get(k,"") for k in fields})
    except (OSError, ValueError, json.JSONDecodeError, csv.Error) as e: p.error(str(e))
    print(f"Analyzed {len(records)} record(s); wrote {len(results)} unique finding(s) to {a.out}")

if __name__ == "__main__": main()
