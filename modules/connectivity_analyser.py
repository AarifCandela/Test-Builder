#!/usr/bin/env python3
"""
connectivity_analyser.py (v4)

What it does (no phantom flags!):
  1) For each radio (EID), create N stations with create_station.py --create_admin_down,
     using a smart per-radio start_id so names never collide (sta0000.. on radio#1,
     then sta0003.. on radio#2, etc). Optional --start_id lets you jump ahead.
  2) Stage addressing per your mode:
       --dual      : IPv4 DHCP + IPv6 AUTO + DHCPv6 (default)
       --ipv4_only : IPv4 DHCP only, IPv6 DELETED
       --ipv6_only : IPv6 AUTO + DHCPv6 only
  3) Start sniffer, wait for pcap to start growing (silent)
  4) Bring stations UP with set_port (cmd_flags.from_dhcp, current_flags toggled, interest.ifdown set)
  5) Poll /ports only for the created station aliases until theyre up (or retry with longer capture)
  6) Run connectiontime_auto.py with --dhcpv6 (unchanged logic)
  7) Save .pcap and .csv in a time-named folder under /home/lanforge/Desktop/ConnectivityRuns

Defaults:
  channel=36, channel_bw=20, duration=60s
  sniffer runs on the first radio by default (override with --sniff_radio)

Requires:
  /home/lanforge/scripts/py-scripts/create_station.py
  /home/lanforge/scripts/py-scripts/lf_sniff_radio.py
  /home/lanforge/scripts/py-scripts/connectiontime_auto.py
"""

import argparse, os, sys, time, signal, subprocess, json
from datetime import datetime
import requests

SCRIPTS_DIR    = "/home/lanforge/scripts/py-scripts"
CREATE_STATION = os.path.join(SCRIPTS_DIR, "create_station.py")     # real script (admin-down capable)
LF_SNIFF       = os.path.join(SCRIPTS_DIR, "lf_sniff_radio.py")
CONN_ANALYZE   = os.path.join(SCRIPTS_DIR, "connectiontime_auto.py")

PYTHON   = "python3"
SUDO_PW  = "lanforge"

# ---------- helpers ----------
def run_cmd(cmd, wait=True):
    if not wait:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def chmod_777(path):
    if not os.path.exists(path): return
    subprocess.run(["sudo", "-S", "chmod", "777", path], input=f"{SUDO_PW}\n", text=True, capture_output=True)

def wait_for_pcap_growth(path, timeout=20):
    start = time.time(); last = -1
    while time.time() - start < timeout:
        if os.path.exists(path):
            sz = os.path.getsize(path)
            if sz > 0:
                if last == -1:
                    last = sz; time.sleep(1); continue
                if sz > last:
                    return True
        time.sleep(1)
    return False

# ---------- REST ----------
class LF:
    def __init__(self, host="localhost", port=8080, timeout=10):
        self.base = f"http://{host}:{port}"
        self.s = requests.Session()
        self.s.headers.update({"Accept":"application/json"})
        self.timeout = timeout

    def post(self, path, payload):
        r = self.s.post(self.base+path, json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r

    def get(self, path, params=None):
        r = self.s.get(self.base+path, params=params or {}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def set_port(self, shelf, resource, port, **kwargs):
        payload = {"shelf":shelf, "resource":resource, "port":port}
        payload.update(kwargs)
        return self.post("/cli-json/set_port", payload)

    def ports_snapshot(self):
        return self.get("/ports", params={"fields":"ip,ipv6 address,alias,port,_links,down,phantom,parent dev,hardware"})

# ---------- set_port bits (confirmed via set_port.html) ----------
# constants
CMD_FROM_DHCP = 512

CF_IF_DOWN       = 1
CF_USE_DHCP      = 2147483648
CF_USE_DHCPV6    = 2199023255552
CF_IGNORE_DHCP   = 562949953421312

I_DHCP        = 16384
I_DHCPV6      = 16777216
I_IFDOWN      = 8388608
I_IPV6_ADDRS  = 131072

def build_interest(*bits): return int(sum(bits))

# ---------- Stage (admin-down) ----------
def stage_ipv6_only_down(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_IF_DOWN | CF_USE_DHCPV6 | CF_IGNORE_DHCP,
        interest=build_interest(I_DHCP, I_DHCPV6, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="AUTO", ipv6_addr_link="AUTO", ipv6_dflt_gw="AUTO")

def stage_ipv4_only_down(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_IF_DOWN | CF_USE_DHCP,
        interest=build_interest(I_DHCP, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="DELETED", ipv6_addr_link="DELETED", ipv6_dflt_gw="DELETED")

def stage_dual_down(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_IF_DOWN | CF_USE_DHCP | CF_USE_DHCPV6,
        interest=build_interest(I_DHCP, I_DHCPV6, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="AUTO", ipv6_addr_link="AUTO", ipv6_dflt_gw="AUTO")

# ---------- Bring UP ----------
def bring_up_ipv6(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_USE_DHCPV6 | CF_IGNORE_DHCP,
        interest=build_interest(I_DHCP, I_DHCPV6, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="AUTO", ipv6_addr_link="AUTO", ipv6_dflt_gw="AUTO")

def bring_up_ipv4(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_USE_DHCP,
        interest=build_interest(I_DHCP, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="DELETED", ipv6_addr_link="DELETED", ipv6_dflt_gw="DELETED")

def bring_up_dual(lf, shelf, resource, sta):
    lf.set_port(shelf, resource, sta,
        cmd_flags=CMD_FROM_DHCP,
        current_flags=CF_USE_DHCP | CF_USE_DHCPV6,
        interest=build_interest(I_DHCP, I_DHCPV6, I_IFDOWN, I_IPV6_ADDRS),
        ipv6_addr_global="AUTO", ipv6_addr_link="AUTO", ipv6_dflt_gw="AUTO")

def bring_all_down(lf: LF, shelf, resource, stations):
    for sta in stations:
        lf.set_port(shelf, resource, sta,
            cmd_flags=CMD_FROM_DHCP,
            current_flags=CF_IF_DOWN,  # down only
            interest=build_interest(I_RPT_TIMER, I_IFDOWN)
        )

# ---------- /ports helpers ----------
def ports_ok(snapshot_json, sta_aliases):
    ok = 0
    details = []
    wanted = set(sta_aliases)
    for iface in snapshot_json.get("interfaces", []):
        key = list(iface.keys())[0]
        obj = iface[key]
        alias = obj.get("alias","")
        if alias in wanted:
            line = {
                "alias": alias,
                "down": obj.get("down", True),
                "phantom": obj.get("phantom", False),
                "ip": obj.get("ip",""),
                "ipv6": obj.get("ipv6 address",""),
                "eid": obj.get("port","")
            }
            details.append(line)
            if (not line["phantom"]) and (not line["down"]):
                ok += 1
    return ok, details

def print_port_summary(details):
    for d in sorted(details, key=lambda x:x["alias"]):
        print(f"   {d['alias']:>10} | down={str(d['down']):<5} phantom={str(d['phantom']):<5} | ip={d['ip']:<15} | v6={d['ipv6']}")

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Connectivity Analyser (create_station + set_port + sniffer + analysis)")
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--password", default="")
    ap.add_argument("--security", default="wpa2", choices=["open","wep","wpa","wpa2","wpa3"])

    ap.add_argument("--radio", default="1.1.wiphy0", help="Comma-separated radio EIDs, e.g. 1.1.wiphy0,1.1.wiphy1")
    ap.add_argument("--sniff_radio", "-sr", default=None, help="Sniffer radio (EID or name); default=first in --radio")
    ap.add_argument("--mgr", default="localhost")
    ap.add_argument("--mgr_port", type=int, default=8080)
    ap.add_argument("--shelf", type=int, default=1)
    ap.add_argument("--resource", type=int, default=1)

    ap.add_argument("--channel","-c", default="36")
    ap.add_argument("--channel_bw","-b", default="20")
    ap.add_argument("--monitor_name", default="sniffer0")
    ap.add_argument("--duration","-t", type=int, default=60)

    ap.add_argument("--num_stations", type=int, default=2)
    ap.add_argument("--start_id", type=int, default=None, help="Optional base start-id; if omitted, starts at 0 and auto-increments by --num_stations per radio.")
    ap.add_argument("--prefix", default="sta")

    ap.add_argument("--ipv4_only", action="store_true")
    ap.add_argument("--ipv6_only", action="store_true")
    ap.add_argument("--dual", action="store_true", help="Force dual-stack (default if neither ipv4_only nor ipv6_only is set)")

    ap.add_argument("--outfile_root","-d", default="/home/lanforge/Desktop/ConnectivityRuns", help="Root folder; a timestamped subfolder will be created here.")
    ap.add_argument("--outfile_name", help="Optional basename for files; default sniff_<timestamp>")

    ap.add_argument("--client_mac_list","-mac", nargs="+", help="Optional manual MAC list for analyzer")
    ap.add_argument("--no_cleanup", action="store_true")
    args = ap.parse_args()

    # Mode selection (default dual)
    mode = "dual"
    if args.ipv4_only: mode = "ipv4"
    if args.ipv6_only: mode = "ipv6"

    radios = [r.strip() for r in args.radio.split(",") if r.strip()]
    sniff_radio = args.sniff_radio or radios[0]

    # Create timestamped folder
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(args.outfile_root, ts)
    os.makedirs(outdir, exist_ok=True)
    base = os.path.splitext(args.outfile_name)[0] if args.outfile_name else f"sniff_{ts}"
    pcap = os.path.join(outdir, f"{base}.pcap")
    csv  = os.path.join(outdir, f"{base}.csv")

    decrypt = f"{args.password}:{args.ssid}" if args.password else None

    print(f"\n=== START ===")
    print(f"SSID : {args.ssid}")
    print(f"Mode : {mode}")
    print(f"Radios: {', '.join(radios)}")
    print(f"Out  : {outdir}")
    print(f"PCAP : {pcap}")
    print(f"CSV  : {csv}")
    print(f"Ch/BW: {args.channel}/{args.channel_bw}")
    print(f"Dur  : {args.duration}s")
    print("================")

    lf = LF(args.mgr, args.mgr_port)

    # 1) CREATE admin-down with non-overlapping ranges per radio
    all_stas = []
    base_start = args.start_id if args.start_id is not None else 0
    for idx, r in enumerate(radios):
        this_start = base_start + idx * args.num_stations
        cs_cmd = [
            PYTHON, CREATE_STATION,
            "--mgr", args.mgr, "--mgr_port", str(args.mgr_port),
            "--radio", r,
            "--security", args.security,
            "--ssid", args.ssid,
            "--num_stations", str(args.num_stations),
            "--start_id", str(this_start),
            "--prefix", args.prefix,
            "--create_admin_down"
        ]
        if args.password and args.security != "open":
            cs_cmd += ["--passwd", args.password]

        print(f"[1] Creating stations (down) on {r} start_id={this_start} count={args.num_stations} ...")
        rc, out, err = run_cmd(cs_cmd)
        if out: print(out)
        if err: print(err, file=sys.stderr)

        # Track expected aliases exactly
        for i in range(this_start, this_start + args.num_stations):
            all_stas.append(f"{args.prefix}{i:04d}")

    # 2) Stage addressing per-mode (while down)
    print("[2] Staging addressing (while down)...")
    if mode == "ipv4":
        for sta in all_stas: stage_ipv4_only_down(lf, args.shelf, args.resource, sta)
    elif mode == "ipv6":
        for sta in all_stas: stage_ipv6_only_down(lf, args.shelf, args.resource, sta)
    else:
        for sta in all_stas: stage_dual_down(lf, args.shelf, args.resource, sta)

    # Prepare retry windows (stop early if all up)
    retry_durations = []
    base_d = args.duration
    for extra in (0, 30, 60, 120):
        dur = base_d + extra
        if dur <= 300:
            retry_durations.append(dur)
    if 300 not in retry_durations:
        retry_durations.append(300)

    analyzed = False
    for attempt_idx, dur in enumerate(retry_durations, start=1):
        print(f"[3.{attempt_idx}] Starting sniffer (duration={dur}s) on {sniff_radio} ...")
        sniff_cmd = [
            PYTHON, LF_SNIFF,
            "--mgr", args.mgr, "--mgr_port", str(args.mgr_port),
            "--radio", sniff_radio,
            "--outfile", pcap,
            "--duration", str(dur),
            "--channel", str(args.channel),
            "--channel_bw", str(args.channel_bw),
            "--monitor_name", "sniffer0"
        ]
        sniff_proc = run_cmd(sniff_cmd, wait=False)
        signal.signal(signal.SIGINT, lambda s,f:(sniff_proc.terminate(), sys.exit(1)))
        wait_for_pcap_growth(pcap)

        # Bring them up using the exact working pattern (toggle IF_DOWN off, include interest.ifdown)
        print(f"[3.{attempt_idx}] Bringing stations UP ...")
        if mode == "ipv4":
            for sta in all_stas: bring_up_ipv4(lf, args.shelf, args.resource, sta)
        elif mode == "ipv6":
            for sta in all_stas: bring_up_ipv6(lf, args.shelf, args.resource, sta)
        else:
            for sta in all_stas: bring_up_dual(lf, args.shelf, args.resource, sta)

        # Poll only our stations
        deadline = time.time() + max(20, min(60, dur // 2))
        all_up = False
        while time.time() < deadline:
            snap = lf.ports_snapshot()
            ok, details = ports_ok(snap, all_stas)
            if ok == len(all_stas):
                all_up = True
                break
            time.sleep(2)

        # Wait for sniffer end
        try:
            sniff_proc.communicate(timeout=dur + 20)
        except subprocess.TimeoutExpired:
            sniff_proc.kill(); sniff_proc.communicate()
        chmod_777(pcap)

        # If everyone up or this was last attempt -> analyze
        if all_up or attempt_idx == len(retry_durations):
            snap = lf.ports_snapshot()
            ok, details = ports_ok(snap, all_stas)
            print("[ports] final status:")
            print_port_summary(details)

            print("[4] Running analysis...")
            analyze = [
                PYTHON, CONN_ANALYZE,
                "--pcap_file", pcap,
                "--output_csv", csv,
                "--dhcpv6"
            ]
            if decrypt:
                analyze += ["--decrypt_phrase", decrypt]
            if args.client_mac_list:
                analyze += ["--client_mac_list"] + args.client_mac_list
            else:
                analyze += ["--auto-detect-clients"]

            rc, out, err = run_cmd(analyze)
            if out: print(out)
            if err: print(err, file=sys.stderr)
            chmod_777(csv)

            analyzed = True
            break
        else:
            print("[i] Not all stations UP; preparing another attempt with longer capture ...")
            bring_all_down(lf, args.shelf, args.resource, all_stas)
            time.sleep(2)

    if not analyzed:
        print("[!] Analysis was not executed due to repeated failures to bring up all stations.")

    print(f"[+] Done.\nFolder: {outdir}\nPCAP  : {pcap}\nCSV   : {csv if analyzed else '(analysis skipped)'}\n=== END ===")


if __name__ == "__main__":
    main()
