#!/usr/bin/env python3
"""Linux forensic PoC agent. Python >= 3.9, stdlib only.
Run two independent engines: Loki-RS and a Velociraptor offline collector.
Normalize their output as portable JSONL without losing source records.
"""
import argparse
import datetime as dt
import hashlib
import json
import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

UTC = dt.timezone.utc

def now():
    return dt.datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")

def append_event(out, event):
    out.write(json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")

def tool_run(argv, cwd, log_path, timeout, env=None):
    started = now()
    with log_path.open("w", encoding="utf-8", errors="replace") as logfile:
        logfile.write("COMMAND: " + json.dumps([str(x) for x in argv]) + "\n")
        logfile.flush()
        try:
            with subprocess.Popen([str(x) for x in argv], cwd=str(cwd), env=env,
                                  stdout=logfile, stderr=subprocess.STDOUT, start_new_session=True) as proc:
                try:
                    code = proc.wait(timeout=timeout)
                    return {"status": "success" if code == 0 else "failed", "exit_code": code,
                            "started_at": started, "finished_at": now(), "log": str(log_path)}
                except subprocess.TimeoutExpired:
                    import signal
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait()
                    return {"status": "timeout", "exit_code": None,
                            "started_at": started, "finished_at": now(), "log": str(log_path)}
        except Exception as ex:
            logfile.write(f"\nEXECUTION ERROR: {type(ex).__name__}: {ex}\n")
            return {"status": "failed", "exit_code": None, "error": str(ex),
                    "started_at": started, "finished_at": now(), "log": str(log_path)}

def normalize_hashes(value):
    """Velociraptor Hash uses upper-case keys; Loki-RS uses lower-case."""
    if not isinstance(value, dict):
        return {}
    result = {}
    for key, digest_value in value.items():
        key = str(key).lower().replace("-", "")
        if key in ("md5", "sha1", "sha256") and isinstance(digest_value, str) and digest_value:
            result[key] = digest_value.lower()
    return result


def valid_time(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value


def logsource_record(product, category, service, artifact):
    # Flat strings make filtering and aggregations reliable in OpenSearch.
    return {"product": product, "category": category, "service": service, "artifact": artifact}


def common(scan_id, host, source, artifact, collected_at, category, scan_mode=None):
    product = "linux"
    return {
        "host": {"name": host, "os": {"type": product}},
        "event": {"module": source, "dataset": artifact, "kind": "event",
                  "category": [category], "action": "observed"},
        "logsource": logsource_record(product, category, source, artifact),
        "forensic": {"scan_id": scan_id, "source_artifact": artifact,
                     "collected_at": collected_at, **({"scan_mode": scan_mode} if scan_mode else {})},
    }


def loki_normalize(input_path, output_path, scan_id, host, collected_at, scan_mode):
    count = 0
    invalid = 0
    with input_path.open("r", encoding="utf-8", errors="replace") as source, output_path.open("w", encoding="utf-8") as target:
        for n, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError("JSONL row is not object")
            except ValueError:
                invalid += 1
                continue
            event_type = str(row.get("event_type") or "").lower()
            # Loki-RS process event field names may evolve; keep raw_record in all cases.
            # Only *_match events are detections (INFO/status events are not alerts).
            if event_type not in ("file_match", "process_match"):
                continue
            is_process = event_type == "process_match"
            category = "process" if is_process else "file"
            artifact = "Loki-RS/" + event_type
            item = common(scan_id, row.get("hostname") or host, "loki-rs", artifact,
                          collected_at, category, scan_mode)
            item["@timestamp"] = valid_time(row.get("timestamp")) or collected_at
            item["event"].update({"kind": "alert", "action": event_type})
            if is_process:
                # Use only field names actually present; unrecognized fields remain in raw_record.
                item["process"] = {
                    "pid": safe_int(row.get("pid") or row.get("process_id")),
                    "name": row.get("process_name") or row.get("name"),
                    "executable": row.get("process_path") or row.get("exe"),
                    "command_line": row.get("command_line") or row.get("cmdline"),
                }
            else:
                item["file"] = {
                    "path": row.get("file_path"), "size": row.get("file_size"),
                    "hash": normalize_hashes({"md5": row.get("md5"), "sha1": row.get("sha1"),
                                               "sha256": row.get("sha256")}),
                    "mtime": valid_time(row.get("file_modified")),
                }
            item["loki"] = {"severity": row.get("level"), "score": row.get("score"),
                            "reasons": row.get("reasons"), "event_type": row.get("event_type")}
            item["forensic"]["raw_record"] = row
            append_event(target, item)
            count += 1
    return {"rows": count, "invalid_json_lines": invalid}


# Classify by actual artifact name (slashes are URL-encoded in ZIP paths).
def category_of(artifact):
    a = artifact.lower()
    if "pslist" in a:
        return "process"
    if "netstat" in a:
        return "network"
    if "sshkeyfilecmd" in a:
        return "intrusion_detection"
    if "crontab" in a or "services" in a:
        return "persistence"
    if "filefinder" in a:
        return "file"
    if "lastuserlogin" in a:
        return "authentication"
    if ".users" in a:
        return "user"
    if "proc.modules" in a:
        return "kernel"
    if "client.info" in a:
        return "host"
    return "other"


def network_ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_artifact(artifact, row, scan_id, hostname, observed_at, scan_mode):
    from urllib.parse import unquote
    artifact = unquote(artifact)
    category = category_of(artifact)
    item = common(scan_id, hostname, "velociraptor", artifact, observed_at, category, scan_mode)
    # Snapshots use collection time; historical facts use their native event time.
    event_time = observed_at
    if category == "process":
        started = valid_time(row.get("CreateTime"))
        event_time = started or observed_at
        item["process"] = {
            "pid": safe_int(row.get("Pid")), "parent": {"pid": safe_int(row.get("Ppid"))},
            "name": row.get("Name"), "executable": row.get("Exe"),
            "command_line": row.get("CommandLine"), "start": started,
            "hash": normalize_hashes(row.get("Hash")),
            "memory": {"rss": {"bytes": row.get("RSS")}},
        }
        item["user"] = {"name": row.get("Username")}
    elif category == "file":
        item["file"] = {
            "path": row.get("OSPath"), "size": row.get("Size"),
            "mtime": valid_time(row.get("MTime")),
            "ctime": valid_time(row.get("CTime")),
            "atime": valid_time(row.get("ATime")),
            "mode": row.get("Mode"), "hash": normalize_hashes(row.get("Hash")),
        }
    elif category == "network":
        # Netstat is a socket snapshot: "source" = local endpoint, "destination" = remote endpoint.
        item["source"] = {"ip": network_ip(row.get("LocalAddr")), "port": safe_int(row.get("LocalPort"))}
        item["destination"] = {"ip": network_ip(row.get("RemoteAddr")), "port": safe_int(row.get("RemotePort"))}
        item["network"] = {"transport": "tcp" if "tcp" in artifact.lower() else None,
                           "state": row.get("State")}
        info = row.get("ProcessInfo")
        if isinstance(info, dict):
            item["process"] = {"pid": safe_int(info.get("Pid")),
                               "name": (info.get("Command") or "").strip() or None,
                               "command_line": (info.get("CommandLine") or "").replace("\x00", " ").strip() or None}
    elif category == "authentication":
        event_time = valid_time(row.get("login_time")) or observed_at
        item["user"] = {"name": row.get("login_User")}
        item["source"] = {"ip": network_ip(row.get("login_IpAddr"))}
        item["authentication"] = {"login_time": valid_time(row.get("login_time")),
                                  "logout_time": valid_time(row.get("logout_time")),
                                  "terminal": row.get("login_Terminal"),
                                  "type": row.get("login_Type")}
    elif category == "persistence":
        # Distinguish cron table entries, cron scripts, and systemd services.
        item["persistence"] = {"command": row.get("Command"), "path": row.get("Path") or row.get("OSPath"),
                               "unit": row.get("Unit"), "active": row.get("Active"),
                               "sub_state": row.get("Sub")}
        if "CronScripts" in artifact:
            item["file"] = {"path": row.get("OSPath"), "mtime": valid_time(row.get("Mtime"))}
    elif category == "user":
        item["user"] = {"name": row.get("User"), "id": row.get("Uid"), "group_id": row.get("Gid"),
                        "home": row.get("Homedir"), "shell": row.get("Shell")}
    elif category == "kernel":
        item["kernel"] = {"module": {"name": row.get("Name"), "address": row.get("Address"),
                                     "size": row.get("Size"), "status": row.get("Status"),
                                     "use_count": row.get("UseCount")}}
    elif category == "host":
        if row.get("Hostname"):
            item["host"].update({"name": row["Hostname"], "architecture": row.get("Architecture"),
                                 "hostname": row.get("Hostname"),
                                 "os": {"type": "linux", "platform": row.get("Platform"),
                                        "version": row.get("PlatformVersion"),
                                        "kernel": row.get("KernelVersion")}})
    elif category == "intrusion_detection":
        item["event"]["kind"] = "alert"
        item["event"]["action"] = "ssh_authorized_key_command"

        item["detection"] = {
            "type": "ssh_key_forced_command",
            "description": "SSH key contains a forced command option",
            "source": "velociraptor"
        }
    item["@timestamp"] = event_time
    item["forensic"]["raw_record"] = row
    return item

def safe_int(x):
    try:
        return int(x) if x is not None else None
    except (ValueError, TypeError):
        return None

def forensic_normalize(zip_path, output_path, scan_id, hostname, observed_at, scan_mode):
    result = {"rows": 0, "by_artifact": {}, "invalid_json_lines": 0}
    with zipfile.ZipFile(zip_path) as archive, output_path.open("w", encoding="utf-8") as output:
        for member in archive.infolist():
            name = member.filename
            if not (name.startswith("results/") and name.endswith(".json") and not name.endswith(".json.index")):
                continue
            artifact = name[len("results/"):-len(".json")]
            with archive.open(member) as src:
                for line in src:
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                        if not isinstance(row, dict):
                            raise ValueError("Not an object")
                    except (ValueError, json.JSONDecodeError):
                        result["invalid_json_lines"] += 1
                        continue
                    append_event(output, normalize_artifact(artifact, row, scan_id, hostname, observed_at, scan_mode))
                    result["rows"] += 1
                    result["by_artifact"][artifact] = result["by_artifact"].get(artifact, 0) + 1
    return result

def main():
    parser = argparse.ArgumentParser(description="Linux forensic PoC: Loki-RS + Velociraptor")
    parser.add_argument("scan", nargs="?", choices=["scan"], default="scan")
    parser.add_argument("--mode", choices=["file", "process", "both"], default="file",
                        help="Loki-RS scan mode; Velociraptor collector is unchanged (default: file)")
    parser.add_argument("--path", help="Absolute directory for Loki filesystem scan (file/both); default / for both")
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout per engine in seconds")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    collector = root / "bin" / "Collector_velociraptor-v0.77.3-linux-amd64-musl"
    loki = root / "bin" / "loki"
    signatures = root / "signatures"
    if args.mode == "file" and not args.path:
        parser.error("--path is required in file mode")
    if args.mode == "process" and args.path:
        parser.error("--path is not used in process mode; omit --path")
    scan_path = None
    if args.mode in ("file", "both"):
        selected = args.path if args.path else "/"
        if not Path(selected).expanduser().is_absolute():
            parser.error("--path must be an absolute path")
        try:
            scan_path = Path(selected).expanduser().resolve(strict=True)
        except OSError as exc:
            parser.error(f"Invalid --path: {exc}")
        if not scan_path.is_dir():
            parser.error("--path must be an existing directory")
    for path in (collector, loki):
        if not path.is_file():
            parser.error(f"Missing executable: {path}")
    for directory in (signatures / "yara", signatures / "iocs"):
        if not directory.is_dir():
            parser.error(f"Missing signature directory: {directory}")
    if not any((signatures / "yara").rglob("*.yar")) and not any((signatures / "yara").rglob("*.yara")):
        parser.error("No YARA rules found")
    scan_id = "scan-" + dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    session = root / "output" / scan_id
    raw = session / "raw"
    final = session / "final"
    work = session / "work"
    for d in (raw, final, work):
        d.mkdir(parents=True, exist_ok=False)
    host = os.uname().nodename
    # Create a private runtime: binary and signatures remain side by side.
    # Copying gives a stable snapshot of the rules for this scan.
    loki_work = work / "loki-runtime"
    loki_work.mkdir()
    shutil.copy2(loki, loki_work / "loki")
    (loki_work / "loki").chmod((loki_work / "loki").stat().st_mode | 0o100)
    shutil.copytree(signatures, loki_work / "signatures")
    (loki_work / "config").mkdir()
    loki_jsonl = raw / "loki.jsonl"
    print(f"[agent] scan_id={scan_id}")
    print(f"[agent] scan_mode={args.mode}")
    print(f"[agent] scan_path={scan_path if scan_path is not None else '(process-only)'}")
    print("[agent] Running Loki-RS...")
    loki_args = [loki_work / "loki", "--no-tui", "--threads", "1", "--no-html",
                 "--jsonl", loki_jsonl]
    if args.mode == "file":
        loki_args += ["--folder", scan_path, "--no-procs", "--scan-all-files"]
    elif args.mode == "process":
        loki_args += ["--no-fs"]
    else:
        loki_args += ["--folder", scan_path, "--scan-all-files"]
    loki_status = tool_run(loki_args, loki_work, session / "loki.log", args.timeout)
    loki_status["scan_mode"] = args.mode
    # Do not let old or unrelated collection ZIPs be mixed into this scan.
    collector_work = work / "collector"
    collector_work.mkdir()
    print("[agent] Running Velociraptor Offline Collector (autoexec)...")
    collector_status = tool_run([collector], collector_work, session / "velociraptor.log", args.timeout)
    candidates = sorted(collector_work.glob("Collection-*.zip"), key=lambda p: p.stat().st_mtime)
    zip_path = raw / "velociraptor-collection.zip"
    if candidates:
        shutil.move(str(candidates[-1]), str(zip_path))
        collector_status["collection_zip_found"] = True
    else:
        collector_status["collection_zip_found"] = False
        collector_status["status"] = "failed"
        collector_status["error"] = "No Collection-*.zip found in collector working directory"
    observed_at = now()
    normalized = {}
    if loki_jsonl.is_file():
        normalized["loki"] = loki_normalize(loki_jsonl, final / "detections.jsonl", scan_id, host, observed_at, args.mode)
    else:
        normalized["loki"] = {"rows": 0, "error": "Loki JSONL not created"}
        loki_status["status"] = "failed"
    if zip_path.is_file():
        try:
            normalized["velociraptor"] = forensic_normalize(zip_path, final / "forensic-events.jsonl", scan_id, host, observed_at, args.mode)
            if normalized["velociraptor"]["rows"] == 0:
                collector_status["status"] = "failed"
                collector_status["error"] = "Collection ZIP contains no forensic result records"
        except (zipfile.BadZipFile, OSError, ValueError) as ex:
            normalized["velociraptor"] = {"rows": 0, "error": str(ex)}
            collector_status["status"] = "failed"
    manifest = {"scan_id": scan_id, "host": {"name": host, "os": "linux"},
                "scan_path": str(scan_path) if scan_path is not None else None,
                "scan_mode": args.mode, "collected_at": observed_at,
                "engines": {"loki": loki_status, "velociraptor": collector_status},
                "normalized": normalized,
                "evidence": {"loki_jsonl": str(loki_jsonl) if loki_jsonl.exists() else None,
                             "velociraptor_zip": str(zip_path) if zip_path.exists() else None,
                             "zip_sha256": digest(zip_path) if zip_path.exists() else None},
                "rules": {"directory": str(signatures),
                          "files": {str(p.relative_to(signatures)): digest(p)
                                    for p in sorted(signatures.rglob("*")) if p.is_file()}}}
    write_json(session / "manifest.json", manifest)
    print(f"[agent] output={session}")
    print(f"[agent] loki={loki_status['status']}, findings={normalized['loki']['rows']}")
    print(f"[agent] velociraptor={collector_status['status']}, forensic_events={normalized.get('velociraptor', {}).get('rows', 0)}")
    return 0 if loki_status["status"] == collector_status["status"] == "success" else 1

if __name__ == "__main__":
    sys.exit(main())
