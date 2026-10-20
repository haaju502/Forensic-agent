#!/usr/bin/env python3
"""Offline forensics JSONL -> OpenSearch, stdlib only. Dev lab HTTP/localhost."""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

COMMON = {
    "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"},
    "host": {"properties": {"name": {"type": "keyword"}, "hostname": {"type": "keyword"}, "os": {"properties": {"type": {"type": "keyword"}, "platform": {"type": "keyword"}, "version": {"type": "keyword"}, "kernel": {"type": "keyword"}}}}},
    "event": {"properties": {"module": {"type": "keyword"}, "dataset": {"type": "keyword"}, "kind": {"type": "keyword"}, "category": {"type": "keyword"}, "action": {"type": "keyword"}}},
    "logsource": {"properties": {"product": {"type": "keyword"}, "service": {"type": "keyword"}, "category": {"type": "keyword"}, "artifact": {"type": "keyword"}}},
    "forensic": {"properties": {"scan_id": {"type": "keyword"}, "source_artifact": {"type": "keyword"}, "collected_at": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}, "raw_record": {"type": "object", "enabled": False}}},
    "file": {"properties": {"path": {"type": "keyword", "ignore_above": 4096}, "size": {"type": "long"}, "hash": {"properties": {"md5": {"type": "keyword"}, "sha1": {"type": "keyword"}, "sha256": {"type": "keyword"}}}}},
    "process": {"properties": {"pid": {"type": "long", "ignore_malformed": True}, "name": {"type": "keyword"}, "hash": {"properties": {"md5": {"type": "keyword"}, "sha1": {"type": "keyword"}, "sha256": {"type": "keyword"}}}}},
    "source": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "port": {"type": "integer", "ignore_malformed": True}}},
    "destination": {"properties": {"ip": {"type": "ip", "ignore_malformed": True}, "port": {"type": "integer", "ignore_malformed": True}}},
}


def request(base, method, path, data=None, content_type="application/json"):
    payload = None if data is None else (data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode())
    req = urllib.request.Request(base.rstrip('/') + path, data=payload, method=method, headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {exc.code} {path}: {detail[:1600]}") from exc


def make_index(base, name, mappings):
    status, info = request(base, "GET", f"/_cat/indices/{name}?format=json") if index_exists(base, name) else (None, None)
    if status:
        print(f"[index] exists: {name}")
        return
    body = {"settings": {"number_of_shards": 1, "number_of_replicas": 0, "mapping.total_fields.limit": 2500}, "mappings": mappings}
    request(base, "PUT", f"/{name}", body)
    print(f"[index] created: {name}")


def index_exists(base, name):
    req = urllib.request.Request(base.rstrip('/') + '/' + name, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=15):
            return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        raise


def each_jsonl(path):
    with path.open(encoding="utf-8") as stream:
        for lineno, line in enumerate(stream, 1):
            if line.strip():
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{path}:{lineno}: invalid JSON: {e}") from e
                if not isinstance(obj, dict):
                    raise ValueError(f"{path}:{lineno}: expected JSON object")
                yield obj


def doc_key(obj, file_name, lineno):
    # Stable for repeated imports; changed documents get a distinct hash within the same scan.
    # Do not rely on timestamp as the uniqueness key: multiple observations can share timestamp.
    serialized = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    seed = f"{obj.get('forensic', {}).get('scan_id', '')}|{file_name}|{lineno}|{serialized}"
    return hashlib.sha256(seed.encode()).hexdigest()


def bulk(base, actions):
    if not actions:
        return 0
    ndjson = "\n".join(json.dumps(a, ensure_ascii=False, separators=(",", ":")) for a in actions) + "\n"
    _, res = request(base, "POST", "/_bulk?refresh=wait_for", ndjson.encode(), "application/x-ndjson")
    errors = [x for x in res.get("items", []) if not (200 <= next(iter(x.values())).get("status", 0) < 300)]
    if errors:
        for item in errors[:3]:
            print("[bulk error]", json.dumps(item, ensure_ascii=False)[:1200], file=sys.stderr)
        raise RuntimeError(f"Bulk import failed: {len(errors)} of {len(res.get('items', []))} documents")
    return len(res.get("items", []))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scan-dir", type=Path, help="Agent output/scan-... directory containing final/ and manifest.json")
    ap.add_argument("--detections", type=Path, help="JSONL file (for testing without scan folder)")
    ap.add_argument("--events", type=Path, help="JSONL file (for testing without scan folder)")
    ap.add_argument("--manifest", type=Path, help="Optional manifest.json")
    ap.add_argument("--url", default="http://127.0.0.1:9200")
    args = ap.parse_args()
    if args.scan_dir:
        args.detections = args.scan_dir / 'final' / 'detections.jsonl'
        args.events = args.scan_dir / 'final' / 'forensic-events.jsonl'
        if (args.scan_dir / 'manifest.json').exists():
            args.manifest = args.scan_dir / 'manifest.json'
    if not args.detections or not args.events:
        ap.error("Provide --scan-dir or both --detections and --events")
    for file in [args.detections, args.events]:
        if not file.is_file():
            ap.error(f"File not found: {file}")
    # Pre-validate before touching OpenSearch
    sources = [("forensic-detections-v1", args.detections), ("forensic-host-events-v1", args.events)]
    payloads = [(index, path, list(each_jsonl(path))) for index, path in sources]
    manifest = None
    if args.manifest:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            ap.error("manifest.json must be an object")
    request(args.url, "GET", "/")
    for index, _, _ in payloads:
        make_index(args.url, index, {"dynamic": True, "properties": COMMON})
    if manifest is not None:
        make_index(args.url, "forensic-scans-v1", {"dynamic": True, "properties": {"scan_id": {"type": "keyword"}, "@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}}})
    for index, path, objs in payloads:
        total = 0
        for start in range(0, len(objs), 250):
            part = objs[start:start+250]
            actions = []
            for j, obj in enumerate(part, start=start + 1):
                actions.append({"index": {"_index": index, "_id": doc_key(obj, path.name, j)}})
                actions.append(obj)
            total += bulk(args.url, actions)
        print(f"[import] {index}: {total} records")
    if manifest is not None:
        scan_id = manifest.get("scan_id") or next((o.get("forensic", {}).get("scan_id") for _, _, rows in payloads for o in rows), None)
        if not scan_id:
            raise ValueError("No scan_id in manifest or records")
        manifest["scan_id"] = scan_id
        # Keep scan as summary, not full raw ZIP/logs.
        request(args.url, "PUT", "/forensic-scans-v1/_doc/" + urllib.parse.quote(scan_id, safe="") + "?refresh=wait_for", manifest)
        print("[import] forensic-scans-v1: 1 manifest")
    print("[done] Import complete. Repeating the same import replaces existing IDs instead of duplicating rows.")

if __name__ == "__main__":
    import urllib.parse
    main()
