#!/usr/bin/env python3
"""
vap_stage10.py

Stage10 builds on stage9 with these upgrades:

1. Human-friendly pulse rates (--pulse_dl / --pulse_ul) like "10m", "500k", etc.
2. More realistic control loop:
   - Faster to add load when CU is low
   - Slower / patient when CU is high (CU falls slower than it rises)
   - Micro-adjustments when in tolerance to avoid flapping
   - Keeps CU hovering around target and *holding* there
3. Stabilization trigger:
   - After CU sits inside target +/- tolerance for --trigger_after minutes straight,
     we will (once) run the commands in --do_cmd <file>, line by line.
     This lets you kick off downstream tests at steady-state load.
4. dl_bias clarified and enforced:
   - dl_bias = fraction of "extra CU load" we try to source from AP->STA
     (downlink endpoint on vAP). Remaining fraction goes to STA->AP uplink.
5. Monitor handling stays safe:
   - We *never* delete a monitor or touch someone else's interface
   - We try to iw set 'monichan' monitor mode + channel but if kernel says busy, we shrug
6. We don't touch eth1, attenuators, or anything that's not in our lane.
   We leave the CX RUNNING when we exit.

Pipeline summary:
(1) create vAP (no upstream)
(2) create STA against vAP
(3) build UDP DL+UL endpoints, make CX RUNNING (start at 0 load)
(4) ensure/prepare monitor 'monichan' on station PHY
(5) calibration:
    - measure idle CU for target_ssid
    - apply pulse_dl/pulse_ul
    - measure CU again
    - estimate gain_dl / gain_ul (CU% per Mbps)
    - predict starting DL/UL rates aimed at target CU
(6) long-run HOLD loop:
    - read CU repeatedly
    - proportional adjust of DL/UL (with damping & patience)
    - track stability window; optionally fire --do_cmd once
    - keep interference running as long as script lives

CX remains RUNNING after script exits.
"""

import argparse, os, sys, time, json, subprocess, signal, re, math
from datetime import datetime
import requests

PYTHON = "python3"
SCRIPTS_DIR = "/home/lanforge/scripts/py-scripts"
CREATE_VAP = os.path.join(SCRIPTS_DIR, "lf_create_vap_cv.py")
CREATE_STA = os.path.join(SCRIPTS_DIR, "create_station.py")

SUDO_PASS = "lanforge"
MON_NAME  = "monichan"

###############################################################################
# LANforge REST helper
###############################################################################
class LFAPI:
    def __init__(self, mgr="localhost", port=8080):
        self.base = f"http://{mgr}:{port}"
        self.s = requests.Session()
        self.s.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def _post_json(self, path, payload):
        r = self.s.post(self.base + path, data=json.dumps(payload))
        if not r.ok:
            print(f"ERROR {r.status_code}: {r.text}")
        r.raise_for_status()
        txt = r.text.strip()
        return json.loads(txt) if txt else {}

    def _get_json(self, path, params=None):
        r = self.s.get(self.base + path, params=params or {})
        r.raise_for_status()
        return r.json()

    def ports_snapshot(self):
        fields = "alias,port,down,phantom,ip,ipv6 address,parent dev"
        return self._get_json("/ports", params={"fields": fields})

    def add_endp(self, alias, shelf, resource, port, endp_type,
                 min_rate, max_rate):
        payload = {
            "alias": alias,
            "shelf": shelf,
            "resource": resource,
            "port": port,
            "type": endp_type,
            "ip_port": "AUTO",
            "is_rate_bursty": "false",
            "min_rate": int(min_rate),
            "max_rate": int(max_rate),
            "min_pkt": "AUTO",
            "max_pkt": "MTU"
        }
        return self._post_json("/cli-json/add_endp", payload)

    def add_cx(self, alias, tx_endp, rx_endp):
        payload = {
            "alias": alias,
            "tx_endp": tx_endp,
            "rx_endp": rx_endp,
            "test_mgr": "default_tm"
        }
        return self._post_json("/cli-json/add_cx", payload)

    def set_cx_state(self, alias, state):
        payload = {
            "test_mgr": "default_tm",
            "cx_name": alias,
            "cx_state": state
        }
        return self._post_json("/cli-json/set_cx_state", payload)

    def rm_cx(self, alias):
        payload = { "test_mgr":"default_tm", "cx_name":alias }
        return self._post_json("/cli-json/rm_cx", payload)

    def rm_endp(self, endp_name):
        payload = { "endp_name": endp_name }
        return self._post_json("/cli-json/rm_endp", payload)

    def set_endp_tx_bounds(self, endp_name, min_tx_bps, max_tx_bps, bursty=False):
        payload = {
            "name": endp_name,
            "min_tx_rate": int(min_tx_bps),
            "max_tx_rate": int(max_tx_bps),
            "is_bursty": "true" if bursty else "false"
        }
        return self._post_json("/cli-json/set_endp_tx_bounds", payload)

    def add_monitor(self, shelf, resource, radio, ap_name=MON_NAME):
        payload = {
            "shelf": shelf,
            "resource": resource,
            "radio": radio,     # "wiphy1"
            "ap_name": ap_name, # "monichan"
            "flags": 0,
            "flags_mask": 0,
            "aid": 0,
            "bssid": "00:00:00:00:00:00"
        }
        return self._post_json("/cli-json/add_monitor", payload)

###############################################################################
# Core helpers
###############################################################################
def run_cmd(cmd_list, sudo=False, check=False, input_txt=None):
    """
    Run command list (no shell). If sudo=True, prepend sudo -S with SUDO_PASS.
    We keep tshark stderr quiet unless check=True.
    """
    full_cmd = cmd_list
    stdin_data = input_txt
    if sudo:
        full_cmd = ["sudo", "-S"] + cmd_list
        stdin_data = (stdin_data or "") + SUDO_PASS + "\n"

    print(">", " ".join(full_cmd))
    p = subprocess.run(
        full_cmd,
        text=True,
        capture_output=True,
        input=stdin_data
    )
    if p.stdout:
        print(p.stdout, end="")
    if p.stderr and (check or "tshark" not in cmd_list[0].lower()):
        print(p.stderr, end="", file=sys.stderr)

    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed rc={p.returncode}")
    return p

def parse_eid(eid):
    parts = eid.split(".")
    if len(parts) < 3:
        raise ValueError(f"Bad EID: {eid}")
    return int(parts[0]), int(parts[1]), parts[2]

def extract_prefix_and_start_id(alias):
    # "sta_cochan0000" -> ("sta_cochan", 0)
    m = re.search(r"(.*?)(\d+)$", alias)
    if m:
        return m.group(1), int(m.group(2))
    return alias, 0

def find_alias_info(snapshot, alias):
    for iface in snapshot.get("interfaces", []):
        info = list(iface.values())[0]
        if info.get("alias") == alias:
            return info
    return None

def find_first_vap(snapshot):
    for iface in snapshot.get("interfaces", []):
        info = list(iface.values())[0]
        al = info.get("alias", "")
        if al.startswith("vap") and not info.get("phantom", False):
            return info
    return None

def ensure_monitor(lf, station_radio_eid, channel):
    """
    Make sure MON_NAME exists on same resource/radio as station_radio_eid.
    We NEVER delete. We just create if missing.
    Then we *try* iw to enforce monitor mode + channel. If kernel says busy
    because STA is active on that PHY, that's OK. PHY is already on same channel.
    """
    sh, rs, radio_name = parse_eid(station_radio_eid)

    snap = lf.ports_snapshot()
    mon_info = find_alias_info(snap, MON_NAME)
    if not mon_info:
        lf.add_monitor(sh, rs, radio_name, ap_name=MON_NAME)
        time.sleep(2)
        snap = lf.ports_snapshot()
        mon_info = find_alias_info(snap, MON_NAME)

    if not mon_info:
        print("[!] monitor iface did not appear after add_monitor")
        return None

    # Best-effort "iw" prep. We do NOT care if 'busy' is printed.
    run_cmd(["iw", f"{MON_NAME}", "set", "monitor", "otherbss"],
            sudo=True, check=False)
    run_cmd(["iw", "dev", f"{MON_NAME}", "set", "type", "monitor"],
            sudo=True, check=False)
    run_cmd(["iw", f"{MON_NAME}", "set", "channel", str(channel)],
            sudo=True, check=False)

    return MON_NAME

def tshark_qbss_samples(mon_iface, target_ssid, capture_secs=2, bursts=3, gap=0.5):
    """
    Collect wlan.qbss.cu from target_ssid beacons.
    Convert each raw CU byte (0..255) ? % = raw/255 * 100.
    """
    if not mon_iface:
        return []

    fexp = f'(wlan.fc.type_subtype==8 && wlan.ssid=="{target_ssid}" && wlan.qbss.cu)'

    all_vals = []
    for _ in range(bursts):
        cmd = [
            "tshark",
            "-i", mon_iface,
            "-a", f"duration:{capture_secs}",
            "-Y", fexp,
            "-T", "fields",
            "-e", "wlan.qbss.cu"
        ]
        p = run_cmd(cmd, sudo=True, check=False)

        for line in p.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = int(line)
            except ValueError:
                continue

            pct = (raw / 255.0) * 100.0
            if pct < 0:
                pct = 0.0
            if pct > 100:
                pct = 100.0
            all_vals.append(pct)

        time.sleep(gap)

    return all_vals

def read_cu(mon_iface, target_ssid, capture_secs, bursts, smooth_prev=None, alpha=0.6):
    """
    Return (CU_smooth, CU_raw_avg).
    CU_smooth is exponential-smoothed using alpha.
    """
    vals = tshark_qbss_samples(mon_iface, target_ssid,
                               capture_secs=capture_secs,
                               bursts=bursts)
    if not vals:
        return (smooth_prev, None)

    cu_now = sum(vals) / float(len(vals))
    if smooth_prev is None:
        cu_smooth = cu_now
    else:
        cu_smooth = alpha * cu_now + (1.0 - alpha) * smooth_prev
    return (cu_smooth, cu_now)

def safe_gain(delta_cu, delta_rate_mbps, floor_min=0.5):
    """
    %CU per Mbps for DL or UL.
    If math is bad or tiny, clamp to floor_min so we still respond.
    """
    if delta_rate_mbps <= 0:
        return floor_min
    gain = delta_cu / delta_rate_mbps
    if gain <= 0 or math.isnan(gain) or math.isinf(gain):
        gain = floor_min
    return gain

def clamp(v, lo, hi):
    return hi if v > hi else lo if v < lo else v

def parse_rate(strval):
    """
    Parse human-friendly rate strings:
      "10m"  => 10 megabits/sec
      "500k" => 500 kilobits/sec
      "2g"   => 2 gigabits/sec
      "7500000" => raw bps
    Suffixes (case-insensitive):
      b = bits
      k = kilobits (=1000)
      m = megabits (=1e6)
      g = gigabits (=1e9)
    Returns integer bps.
    """
    if strval is None:
        return None
    s = str(strval).strip().lower()
    m = re.match(r"^\s*([0-9]+)\s*([bkmg]?)\s*$", s)
    if not m:
        # fallback: try int
        try:
            return int(s)
        except ValueError:
            raise ValueError(f"Bad rate '{strval}'")
    num = int(m.group(1))
    suf = m.group(2)
    mult = 1
    if suf == "k":
        mult = 1000
    elif suf == "m":
        mult = 1_000_000
    elif suf == "g":
        mult = 1_000_000_000
    # 'b' or '' just means raw bits
    return num * mult

def run_trigger_file(cmd_file):
    """
    Read file with lines of shell commands. For each non-empty line,
    run it via subprocess (no sudo, user's env). We print stdout/stderr.
    We do *not* stop on failure.
    """
    if not cmd_file:
        return
    if not os.path.exists(cmd_file):
        print(f"[TRIGGER] file {cmd_file} not found, skipping trigger.")
        return
    print(f"[TRIGGER] executing commands from {cmd_file}")
    with open(cmd_file, "r") as f:
        for rawline in f:
            line = rawline.strip()
            if not line:
                continue
            print(f"[TRIGGER] -> {line}")
            try:
                p = subprocess.run(line, shell=True, text=True,
                                   capture_output=True)
                if p.stdout:
                    print(f"[TRIGGER stdout] {p.stdout.strip()}")
                if p.stderr:
                    print(f"[TRIGGER stderr] {p.stderr.strip()}", file=sys.stderr)
            except Exception as e:
                print(f"[TRIGGER] command failed: {e}", file=sys.stderr)

###############################################################################
def main():
    ap = argparse.ArgumentParser(
        description="Hold DUT QBSS CU near target as interference, then optionally trigger external actions once stable."
    )

    # LANforge mgr defaults
    ap.add_argument("--mgr", default="localhost")
    ap.add_argument("--port", type=int, default=8080)

    # vAP config (this is our self-made AP that feeds/receives traffic)
    ap.add_argument("--vap_radio",    default="wiphy0", help="LANforge radio for vAP (ex: wiphy0)")
    ap.add_argument("--vap_channel",  default="6",      help="Channel number for vAP/STA/monitor (ex: 6)")
    ap.add_argument("--vap_bw",       default="20")
    ap.add_argument("--vap_ssid",     default="interferer-ssid")
    ap.add_argument("--vap_passwd",   default="interferer-pass")
    ap.add_argument("--vap_security", default="wpa2")

    # STA config (client station on vAP)
    ap.add_argument("--station_radio", default="1.1.wiphy1",
                    help="EID-style radio name for station (ex: 1.1.wiphy1)")
    ap.add_argument("--station",       default="sta_cochan0000",
                    help="station alias (ex: sta_cochan0000)")

    # DUT CU target (this is the REAL AP you're trying to load)
    ap.add_argument("--target_ssid",  required=True,
                    help="The REAL AP SSID whose CU we measure off beacons")
    ap.add_argument("--target_cu",    type=float, default=40.0,
                    help="Desired QBSS CU percentage")
    ap.add_argument("--tolerance", type=float, default=3.0,
                    help="%% window for 'in range'")

    # Control loop timing / capture
    ap.add_argument("--loops",            type=int, default=999999,
                    help="Max control iterations before we exit (jammer lifetime)")
    ap.add_argument("--dwell_sec",        type=int, default=30,
                    help="Seconds between control iterations (settle time)")
    ap.add_argument("--capture_secs",     type=int, default=2,
                    help="Seconds per tshark burst")
    ap.add_argument("--bursts_per_loop",  type=int, default=3,
                    help="How many bursts per CU measurement")

    # Patience on downward moves:
    ap.add_argument("--down_hold_cycles", type=int, default=1,
                    help="If CU too high, wait this many extra loops (to let CU fall on its own) before we actually cut rates. "
                         "0 = cut immediately like up direction.")

    # Calibration pulse
    # These can be given human-style (10m, 500k, etc.)
    ap.add_argument("--pulse_dl", default="10m",
                    help="Initial calibration downlink pulse rate (bps or k/m/g suffix). Default ~10m = ~10Mbps vAP->STA")
    ap.add_argument("--pulse_ul", default="2m",
                    help="Initial calibration uplink pulse rate (bps or k/m/g suffix). Default ~2m = ~2Mbps STA->vAP")
    ap.add_argument("--pulse_dwell", type=int, default=20,
                    help="Seconds to hold pulse load before sampling cu_pulse")

    # Bias between DL and UL after calibration
    ap.add_argument("--dl_bias", type=float, default=0.8,
                    help="Fraction of incremental CU we try to source from downlink (vAP->STA). "
                         "Remaining (1-dl_bias) is sourced from uplink (STA->vAP). "
                         "Example dl_bias=0.8 => DL carries 80% of airtime load.")

    # Bounds and controller gains
    ap.add_argument("--max_rate_bps", type=int, default=200_000_000,
                    help="Hard clamp per-direction rate (bps)")
    ap.add_argument("--min_rate_bps", type=int, default=0,
                    help="Floor per-direction rate (bps)")
    ap.add_argument("--kp_scale", type=float, default=0.5,
                    help="Global proportional aggressiveness. Higher = stronger changes per CU error.")

    # Stabilization trigger
    ap.add_argument("--trigger_after", type=float, default=5.0,
                    help="Minutes of continuous in-range CU before we fire --do_cmd once.")
    ap.add_argument("--do_cmd", default=None,
                    help="Path to a file of shell commands to run once we're stable for trigger_after minutes.")

    args = ap.parse_args()
    lf = LFAPI(args.mgr, args.port)

    # parse pulse_dl / pulse_ul to integer bps
    pulse_dl_bps = parse_rate(args.pulse_dl)
    pulse_ul_bps = parse_rate(args.pulse_ul)
    if pulse_dl_bps is None:
        pulse_dl_bps = 10_000_000
    if pulse_ul_bps is None:
        pulse_ul_bps = 2_000_000

    ###########################################################################
    # build names for cx+endpoints
    ###########################################################################
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    cx_name   = f"CX_{args.station}"
    endp_dl   = f"DL_{args.station}_{ts}"  # vAP -> STA
    endp_ul   = f"UL_{args.station}_{ts}"  # STA -> vAP

    print("========== STAGE10 PLAN ==========")
    print(f"mgr              : {args.mgr}:{args.port}")
    print(f"vAP radio        : {args.vap_radio}")
    print(f"vAP chan/bw      : {args.vap_channel}/{args.vap_bw}")
    print(f"vAP ssid/sec/psk : {args.vap_ssid}/{args.vap_security}/{args.vap_passwd}")
    print(f"STA radio        : {args.station_radio}")
    print(f"STA alias        : {args.station}")
    print(f"monitor alias    : {MON_NAME}")
    print(f"target ssid      : {args.target_ssid}")
    print(f"target CU        : {args.target_cu} +/- {args.tolerance}")
    print(f"dl_bias          : {args.dl_bias}")
    print(f"pulse rates      : DL={pulse_dl_bps}bps UL={pulse_ul_bps}bps")
    print(f"dwell_sec        : {args.dwell_sec}")
    print(f"pulse_dwell      : {args.pulse_dwell}")
    print(f"kp_scale         : {args.kp_scale}")
    print(f"down_hold_cycles : {args.down_hold_cycles}")
    print(f"trigger_after    : {args.trigger_after} min, do_cmd={args.do_cmd}")
    print("=================================")

    ###########################################################################
    # 1. Create / apply vAP (no upstream)
    ###########################################################################
    vap_cmd = [
        PYTHON, CREATE_VAP,
        "--mgr", args.mgr,
        "--port", str(args.port),
        "--delete_old_scenario",
        "--scenario_name", "cochan_scn",
        "--vap_radio", args.vap_radio,
        "--vap_channel", str(args.vap_channel),
        "--vap_ssid", args.vap_ssid,
        "--vap_passwd", args.vap_passwd,
        "--vap_security", args.vap_security,
        "--vap_bw", str(args.vap_bw),
        "--vap_mode", "AUTO",
        "--set_upstream", "False",
        "--set", "BSS-Load", "True"
    ]
    
    run_cmd(vap_cmd, check=False)

    vap_info = None
    for _ in range(30):
        snap = lf.ports_snapshot()
        vap_info = find_first_vap(snap)
        if vap_info:
            break
        time.sleep(1)
    if not vap_info:
        print("FATAL: no vAP interface detected.")
        sys.exit(1)

    vap_alias = vap_info["alias"]     # "vap0000"
    vap_eid   = vap_info["port"]      # like "1.1.9"
    shelf_v, res_v, _tmpvap = parse_eid(vap_eid)

    print(f"[+] vAP up: {vap_alias} eid={vap_eid}")

    ###########################################################################
    # 2. Create / ensure station
    ###########################################################################
    sta_prefix, sta_start_id = extract_prefix_and_start_id(args.station)
    sta_cmd = [
        PYTHON, CREATE_STA,
        "--mgr", args.mgr,
        "--port", str(args.port),
        "--radio", args.station_radio,
        "--ssid", args.vap_ssid,
        "--passwd", args.vap_passwd,
        "--security", args.vap_security,
        "--num_stations", "1",
        "--start_id", str(sta_start_id),
        "--prefix", sta_prefix
    ]
    run_cmd(sta_cmd, check=False)

    sta_info = None
    for _ in range(60):
        snap = lf.ports_snapshot()
        st = find_alias_info(snap, args.station)
        if st and (not st.get("down", True)) and (not st.get("phantom", False)):
            ip4 = st.get("ip", "0.0.0.0")
            if ip4 not in ("0.0.0.0", ""):
                sta_info = st
                break
        time.sleep(1)

    if sta_info:
        print(f"[+] STA {args.station} up ip={sta_info.get('ip')} eid={sta_info.get('port')}")
        sta_eid = sta_info["port"]
    else:
        print(f"[!] STA {args.station} has no IP yet, continuing anyway")
        sh_fb, rs_fb, _tmp = parse_eid(args.station_radio)
        sta_eid = f"{sh_fb}.{rs_fb}.{args.station}"

    shelf_s, res_s, _tmpsta = parse_eid(sta_eid)

    ###########################################################################
    # 3. Kill existing CX of same base name (best effort)
    ###########################################################################
    print("[*] clearing old CX if any")
    try:
        lf.set_cx_state(cx_name, "STOPPED")
    except Exception:
        pass
    try:
        lf.rm_cx(cx_name)
    except Exception:
        pass
    # can't wildcard older DL_/UL_ endpoints, safe to ignore

    ###########################################################################
    # 4. Create endpoints & CX. start at ZERO load.
    ###########################################################################
    cur_dl = 0
    cur_ul = 0
    lf.add_endp(endp_dl, shelf_v, res_v, vap_alias,
                "lf_udp", cur_dl, cur_dl)  # vAP -> STA
    lf.add_endp(endp_ul, shelf_s, res_s, args.station,
                "lf_udp", cur_ul, cur_ul)  # STA -> vAP
    lf.add_cx(cx_name, endp_dl, endp_ul)
    time.sleep(2)
    lf.set_cx_state(cx_name, "RUNNING")
    print(f"[+] CX {cx_name} RUNNING (DL={cur_dl}, UL={cur_ul})")

    ###########################################################################
    # 5. Ensure persistent monitor on same PHY as station radio
    ###########################################################################
    print(f"[*] ensuring monitor {MON_NAME} on {args.station_radio} ch {args.vap_channel}")
    mon_iface = ensure_monitor(lf, args.station_radio, args.vap_channel)
    if mon_iface:
        print(f"[+] monitor iface ready: {mon_iface}")
    else:
        print("[!] monitor iface missing. CU reads may be None. We'll still try.")

    ###########################################################################
    # 6. CALIBRATION
    ###########################################################################
    # A. idle CU
    print("[CAL] Measuring baseline CU (idle, 0 load)...")
    smooth_cu = None
    time.sleep(args.dwell_sec)  # let things settle quiet
    smooth_cu, cu_idle_now = read_cu(mon_iface,
                                     args.target_ssid,
                                     args.capture_secs,
                                     args.bursts_per_loop,
                                     smooth_prev=None)
    cu_idle = smooth_cu if smooth_cu is not None else 0.0
    print(f"[CAL] cu_idle ~ {cu_idle:.2f}% (raw={cu_idle_now})")

    # B. pulse CU
    cur_dl = clamp(pulse_dl_bps, args.min_rate_bps, args.max_rate_bps)
    cur_ul = clamp(pulse_ul_bps, args.min_rate_bps, args.max_rate_bps)
    print(f"[CAL] Applying pulse DL={cur_dl}bps UL={cur_ul}bps ...")
    lf.set_endp_tx_bounds(endp_dl, cur_dl, cur_dl, bursty=False)
    lf.set_endp_tx_bounds(endp_ul, cur_ul, cur_ul, bursty=False)

    time.sleep(args.pulse_dwell)

    smooth_cu, cu_pulse_now = read_cu(mon_iface,
                                      args.target_ssid,
                                      args.capture_secs,
                                      args.bursts_per_loop,
                                      smooth_prev=smooth_cu)
    cu_pulse = smooth_cu if smooth_cu is not None else cu_idle
    print(f"[CAL] cu_pulse ~ {cu_pulse:.2f}% (raw={cu_pulse_now})")

    delta_cu = max(0.0, cu_pulse - cu_idle)

    dl_mbps = cur_dl / 1e6 if cur_dl > 0 else 0.0
    ul_mbps = cur_ul / 1e6 if cur_ul > 0 else 0.0

    # Gains: %CU per Mbps from DL, UL, weighted by dl_bias split logic
    gain_dl = safe_gain(delta_cu * args.dl_bias,
                        dl_mbps if dl_mbps > 0 else 1.0)
    gain_ul = safe_gain(delta_cu * (1.0 - args.dl_bias),
                        ul_mbps if ul_mbps > 0 else 1.0)

    print(f"[CAL] gain_dl ~ {gain_dl:.3f} %CU/Mbps, gain_ul ~ {gain_ul:.3f} %CU/Mbps")

    cu_deficit = args.target_cu - cu_idle
    if cu_deficit < 0:
        # Channel already too hot with zero traffic. We'll start tiny.
        want_dl_mbps = 0.1
        want_ul_mbps = 0.05
    else:
        need_dl_part = cu_deficit * args.dl_bias
        need_ul_part = cu_deficit * (1.0 - args.dl_bias)

        want_dl_mbps = need_dl_part / gain_dl if gain_dl > 0 else 0.1
        want_ul_mbps = need_ul_part / gain_ul if gain_ul > 0 else 0.05

        if want_dl_mbps < 0: want_dl_mbps = 0
        if want_ul_mbps < 0: want_ul_mbps = 0

    pred_dl_bps = int(want_dl_mbps * 1e6)
    pred_ul_bps = int(want_ul_mbps * 1e6)
    pred_dl_bps = clamp(pred_dl_bps, args.min_rate_bps, args.max_rate_bps)
    pred_ul_bps = clamp(pred_ul_bps, args.min_rate_bps, args.max_rate_bps)

    print(f"[CAL] predicted start DL={pred_dl_bps}bps (~{want_dl_mbps:.2f} Mbps) "
          f"UL={pred_ul_bps}bps (~{want_ul_mbps:.2f} Mbps)")

    # Apply predicted starting load
    cur_dl = pred_dl_bps
    cur_ul = pred_ul_bps
    lf.set_endp_tx_bounds(endp_dl, cur_dl, cur_dl, bursty=False)
    lf.set_endp_tx_bounds(endp_ul, cur_ul, cur_ul, bursty=False)

    time.sleep(args.dwell_sec)

    ###########################################################################
    # 7. HOLD LOOP
    #
    # We'll continue adjusting traffic to sit on target CU and keep it there.
    # We'll also watch stability time and eventually trigger --do_cmd (once).
    ###########################################################################
    prev_err_sign = None

    # proportional gains derived from calibration and scaled by kp_scale
    kp_dl_base = args.kp_scale / gain_dl if gain_dl > 0 else args.kp_scale
    kp_ul_base = args.kp_scale / gain_ul if gain_ul > 0 else args.kp_scale

    print(f"[CTRL] kp_dl_base={kp_dl_base:.4f}, kp_ul_base={kp_ul_base:.4f}")
    print("========== HOLD LOOP (active jammer) ==========")

    smooth_cu_loop = smooth_cu  # carry from calibration
    stable_sec_accum = 0.0      # how long (sec) we've been in tolerance
    trigger_fired = False
    down_wait_left = 0          # patience counter for downward moves

    for loop_idx in range(1, args.loops + 1):
        # Measure CU
        smooth_cu_loop, cu_raw_now = read_cu(
            mon_iface,
            args.target_ssid,
            args.capture_secs,
            args.bursts_per_loop,
            smooth_prev=smooth_cu_loop
        )

        if smooth_cu_loop is None:
            print(f"[loop {loop_idx}] CU=None (no beacon?). Keep DL={cur_dl}, UL={cur_ul}")
            # can't make smart decisions with no CU, just sleep
            time.sleep(args.dwell_sec)
            continue

        cu_now = smooth_cu_loop
        err = args.target_cu - cu_now
        err_sign = 0
        if err > 0:
            err_sign = 1
        elif err < 0:
            err_sign = -1

        low  = args.target_cu - args.tolerance
        high = args.target_cu + args.tolerance
        in_band = (low <= cu_now <= high)

        print(f"[loop {loop_idx}] CU~{cu_now:.2f}% (raw={cu_raw_now}) "
              f"target={args.target_cu}% +/-{args.tolerance}% "
              f"err={err:.2f} "
              f"rates DL={cur_dl} UL={cur_ul}")

        # stability accounting for trigger
        if in_band:
            stable_sec_accum += args.dwell_sec
            print(f"    in tolerance for ~{stable_sec_accum:.1f}s "
                  f"(need {args.trigger_after*60:.1f}s to trigger)")
        else:
            stable_sec_accum = 0.0
            print("    out of tolerance, stability timer reset")

        # trigger external command if we've been stable long enough
        if (not trigger_fired and args.do_cmd and
            stable_sec_accum >= args.trigger_after * 60.0):
            run_trigger_file(args.do_cmd)
            trigger_fired = True
            print("    [TRIGGER] fired external commands.")

        # If we�re basically in range, we still might micro-adjust,
        # but take smaller steps and clamp max jump to 10%.
        kp_dl = kp_dl_base
        kp_ul = kp_ul_base

        # overshoot damping: reversed direction? soften gains
        if prev_err_sign is not None and err_sign != 0 and err_sign != prev_err_sign:
            kp_dl *= 0.5
            kp_ul *= 0.5
            print("    [dampen] reversed direction, halving kp_dl/kp_ul")

        # compute raw proportional deltas (Mbps)
        delta_dl_mbps = kp_dl * err
        delta_ul_mbps = kp_ul * err

        # if we're in-band already, throttle our twitchiness
        if in_band:
            delta_dl_mbps *= 0.25
            delta_ul_mbps *= 0.25

        # "down" patience logic:
        # if CU is high (err<0 means need LESS load), we don't instantly drop every loop.
        # we let down_wait_left count down first.
        want_cut = (err < 0 and not in_band)
        if want_cut and down_wait_left > 0:
            # pretend we have no negative delta this loop (let CU settle on its own)
            print(f"    [linger] CU high but waiting {down_wait_left} more cycle(s) before cutting rates")
            delta_dl_mbps = max(0.0, delta_dl_mbps)  # don't reduce
            delta_ul_mbps = max(0.0, delta_ul_mbps)  # don't reduce
            down_wait_left -= 1
        elif want_cut and down_wait_left == 0:
            # next time we detect high CU, reset waiting window
            down_wait_left = args.down_hold_cycles

        # New target bps
        new_dl_bps = int(cur_dl + (delta_dl_mbps * 1e6))
        new_ul_bps = int(cur_ul + (delta_ul_mbps * 1e6))

        # clamp hard limits
        new_dl_bps = clamp(new_dl_bps, args.min_rate_bps, args.max_rate_bps)
        new_ul_bps = clamp(new_ul_bps, args.min_rate_bps, args.max_rate_bps)

        # inside tolerance? also clamp max per-loop jump to 10% (but at least 100kbps)
        if in_band:
            max_jump_dl = max(100_000, int(cur_dl * 0.10))
            max_jump_ul = max(100_000, int(cur_ul * 0.10))
            diff_dl = new_dl_bps - cur_dl
            diff_ul = new_ul_bps - cur_ul
            if abs(diff_dl) > max_jump_dl:
                new_dl_bps = cur_dl + (max_jump_dl if diff_dl > 0 else -max_jump_dl)
            if abs(diff_ul) > max_jump_ul:
                new_ul_bps = cur_ul + (max_jump_ul if diff_ul > 0 else -max_jump_ul)

        # push only if changed
        if new_dl_bps != cur_dl or new_ul_bps != cur_ul:
            print(f"    apply DL={new_dl_bps} UL={new_ul_bps}")
            cur_dl = new_dl_bps
            cur_ul = new_ul_bps
            try:
                lf.set_endp_tx_bounds(endp_dl, cur_dl, cur_dl, bursty=False)
            except Exception as e:
                print(f"    warn DL set_endp_tx_bounds failed: {e}")
            try:
                lf.set_endp_tx_bounds(endp_ul, cur_ul, cur_ul, bursty=False)
            except Exception as e:
                print(f"    warn UL set_endp_tx_bounds failed: {e}")
        else:
            print("    (no rate change this loop)")

        prev_err_sign = err_sign

        # chill before next measurement
        time.sleep(args.dwell_sec)

    ###########################################################################
    # done looping. we DO NOT tear anything down.
    ###########################################################################
    print("========== DONE (leaving CX RUNNING) ==========")
    print(f"Final CU est : {smooth_cu_loop}")
    print(f"Final rates  : DL={cur_dl} UL={cur_ul}")
    print("To stop CX manually later:")
    print(f"curl -s -H 'Content-Type: application/json' "
          f"-d '{{\"test_mgr\":\"default_tm\",\"cx_name\":\"{cx_name}\",\"cx_state\":\"STOPPED\"}}' "
          f"http://{args.mgr}:{args.port}/cli-json/set_cx_state")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))
    main()
