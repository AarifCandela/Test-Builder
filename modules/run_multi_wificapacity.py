#!/usr/bin/env python3
# run_multi_wifi_capacity.py
#
# Launch multiple lf_wifi_capacity_test.py runs in parallel:
#  UDP/TCP × Upload/Download × IPv4/IPv6
# Creates stations per-radio via create_station.py, then passes
# non-overlapping --stations lists to each capacity instance.

import argparse, subprocess, shlex, time, requests, math, os
from collections import defaultdict

SCENARIOS = [
  # label,  protocol,   direction, ip_ver,  ul_rate,  dl_rate
  ("u4_up", "UDP-IPv4", "upload",  4,       "100Mbps","0bps"),
  ("u4_dn", "UDP-IPv4", "download",4,       "0bps",   "100Mbps"),
  ("t4_up", "TCP-IPv4", "upload",  4,       "100Mbps","0bps"),
  ("t4_dn", "TCP-IPv4", "download",4,       "0bps",   "100Mbps"),
  ("u6_up", "UDP-IPv6", "upload",  6,       "100Mbps","0bps"),
  ("u6_dn", "UDP-IPv6", "download",6,       "0bps",   "100Mbps"),
  ("t6_up", "TCP-IPv6", "upload",  6,       "100Mbps","0bps"),
  ("t6_dn", "TCP-IPv6", "download",6,       "0bps",   "100Mbps"),
]

def get_json(host, port, path):
  r = requests.get(f"http://{host}:{port}{path}", timeout=10)
  r.raise_for_status()
  return r.json()

def radiostatus_free(host, port, radios):
  free = {}
  for r in radios:
    shelf, res, port_id = r.split(".")
    j = get_json(host, port, f"/radiostatus/{shelf}/{res}/{port_id}")
    rs = j.get(r, {})
    max_sta = int(rs.get("max_sta", 0))
    up = int(rs.get("stations_up", 0))
    down = int(rs.get("stations_down", 0))
    used = up + down
    free[r] = max(0, max_sta - used)
    print(f"[radio] {r}: max_sta={max_sta} used={used} free={free[r]}")
  return free

def split_counts_across_radios(total, radios, free):
  # fair split, respecting each radio’s free capacity
  n = len(radios)
  per = [total // n] * n
  for i in range(total % n): per[i]+=1
  alloc = {}
  short = 0
  for i,r in enumerate(radios):
    can = min(per[i], free.get(r,0))
    alloc[r]=can
    short += per[i]-can
  if short>0:
    for r in radios:
      spare = free.get(r,0)-alloc[r]
      if spare>0:
        take=min(spare, short)
        alloc[r]+=take
        short-=take
        if not short: break
  return alloc

def call(cmdlist):
  print("[RUN]", " ".join(shlex.quote(x) for x in cmdlist))
  return subprocess.Popen(cmdlist, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def build_sta_series(prefix, start_id, count, radio):
  # Matches create_station.py naming (fully-qualified EIDs).
  # We’ll let create_station.py actually create these.
  names=[]
  for i in range(count):
    eid = radio.split(".")
    shelf, res = eid[0], eid[1]
    sta = f"{prefix}{start_id+i:04d}"
    names.append(f"{shelf}.{res}.{sta}")
  return names

def main():
  ap = argparse.ArgumentParser(description="Parallel Wi-Fi Capacity Orchestrator")
  ap.add_argument("--mgr", default="localhost")
  ap.add_argument("--port", type=int, default=8080)
  ap.add_argument("--radios", required=True, help="comma list: 1.1.wiphy0,1.1.wiphy1")
  ap.add_argument("--ssid", required=True)
  ap.add_argument("--password", default="")
  ap.add_argument("--security", default="wpa2")
  ap.add_argument("--upstream", default="1.1.eth1")
  ap.add_argument("--per_scenario", type=int, default=6, help="stations per scenario (total, split across radios)")
  ap.add_argument("--duration_ms", type=int, default=60000)
  ap.add_argument("--start_block", type=int, default=1000, help="ID block size per scenario")
  ap.add_argument("--base_prefix", default="sta")
  ap.add_argument("--lf_user", default="lanforge")
  ap.add_argument("--lf_password", default="lanforge")
  ap.add_argument("--report_root", default="./CapacityRuns")
  ap.add_argument("--python", default="python3")
  ap.add_argument("--create_station_script", default="/home/lanforge/scripts/py-scripts/create_station.py")
  ap.add_argument("--capacity_script", default="/home/lanforge/scripts/py-scripts/lf_wifi_capacity_test.py")
  ap.add_argument("--no_create", action="store_true", help="skip station creation (use existing)")
  args, passthru = ap.parse_known_args()

  radios = [r.strip() for r in args.radios.split(",") if r.strip()]

  # 1) Plan capacity per radio
  free = radiostatus_free(args.mgr, args.port, radios)

  scenario_plans = {}
  for idx, sc in enumerate(SCENARIOS):
    label, *_ = sc
    alloc = split_counts_across_radios(args.per_scenario, radios, free)
    scenario_plans[label] = {"alloc":alloc, "blocks":{}}
    # reserve from free so later scenarios won’t overbook
    for r,c in alloc.items():
      free[r] = max(0, free[r]-c)

  # 2) Create stations (per radio, per scenario), gather EIDs
  all_station_sets = {}  # label -> list of station EIDs
  procs = []

  for idx, sc in enumerate(SCENARIOS):
    label, *_ = sc
    base_id = idx * args.start_block
    cursor = base_id
    stations_for_label=[]
    for r in radios:
      count = scenario_plans[label]["alloc"].get(r,0)
      if count<=0: continue
      sta_names = build_sta_series(args.base_prefix, cursor, count, r)  # "sta" only
      stations_for_label.extend(sta_names)

      if not args.no_create and count>0:
        # Call create_station.py for this block
        # NOTE: create_station.py takes --num_stations and --start_id + --prefix + --radio
        cs_cmd = [
          args.python, args.create_station_script,
          "--mgr", args.mgr,
          "--mgr_port", str(args.port),
          "--radio", r,
          "--ssid", args.ssid,
          "--passwd", args.password,
          "--security", args.security,
          "--num_stations", str(count),
          "--start_id", str(cursor),
          "--prefix", args.base_prefix,
          "--no_pre_cleanup"  # avoid wiping earlier blocks
        ]
        procs.append(call(cs_cmd))
        time.sleep(0.1)

      cursor += count

    all_station_sets[label] = stations_for_label

  # Wait for all create_station.py processes to finish
  for p in procs:
    for line in iter(p.stdout.readline, ''):
      print(line, end="")
    p.wait()

  # 3) Launch parallel lf_wifi_capacity_test.py per scenario
  os.makedirs(args.report_root, exist_ok=True)
  runners=[]
  for label, proto, direction, ipver, ul_rate, dl_rate in SCENARIOS:
    stations_csv = ",".join(all_station_sets[label]) if all_station_sets[label] else ""
    inst = f"inst_{label}"
    cfg  = f"cfg_{label}"
    rep  = os.path.join(args.report_root, label)

    cmd = [
      args.python, args.capacity_script,
      "--mgr", args.mgr, "--port", str(args.port),
      "--lf_user", args.lf_user, "--lf_password", args.lf_password,
      "--instance_name", inst, "--config_name", cfg,
      "--upstream", args.upstream,
      "--batch_size", "1", "--loop_iter", "1",
      "--protocol", proto,
      "--duration", str(args.duration_ms),
      "--download_rate", dl_rate,
      "--upload_rate", ul_rate,
      "--pull_report",
      "--stations", stations_csv,
      "--report_dir", rep,
      "--local_lf_report_dir", rep,
      "--set", "Leave Ports UP", "1",
    ]
    # We are NOT passing --create_stations here; we already created them.
    # If you need SSID/security for GUI metadata, uncomment:
    # cmd += ["--ssid", args.ssid, "--security", args.security, "--paswd", args.password]

    runners.append(call(cmd))
    time.sleep(0.15)  # small stagger to reduce contention

  # 4) Stream outputs and wait
  for p in runners:
    for line in iter(p.stdout.readline, ''):
      print(line, end="")
    p.wait()

  print("\n[+] All parallel Wi-Fi capacity runs completed.")

if __name__ == "__main__":
  main()
