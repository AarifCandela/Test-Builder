#!/usr/bin/env python3
"""
capacity_tester.py (v1.4)

- Creates or reuses stations, sets port mode (IPv4/IPv6/dual)
- Leaves ports UP by default; only toggles if --reset_ports is given
- Runs lf_wifi_capacity_test.py with passthrough of all user args
"""

import argparse, os, sys, time, subprocess, requests
from datetime import datetime

SCRIPTS_DIR    = "/home/lanforge/scripts/py-scripts"
CREATE_STATION = os.path.join(SCRIPTS_DIR, "create_station.py")
WIFI_CAPACITY  = os.path.join(SCRIPTS_DIR, "lf_wifi_capacity_test.py")

PYTHON, SUDO_PW = "python3", "lanforge"

# ---------------- helpers ----------------
def run_cmd(cmd, wait=True):
    if not wait:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def chmod_777(path):
    if os.path.exists(path):
        subprocess.run(["sudo","-S","chmod","777",path], input=f"{SUDO_PW}\n", text=True, capture_output=True)

class LF:
    def __init__(self, host="localhost", port=8080, timeout=10):
        self.base = f"http://{host}:{port}"
        self.s = requests.Session()
        self.s.headers.update({"Accept":"application/json"})
        self.timeout = timeout
    def post(self, path, payload):
        r=self.s.post(self.base+path,json=payload,timeout=self.timeout);r.raise_for_status();return r
    def get(self, path, params=None):
        r=self.s.get(self.base+path,params=params or {},timeout=self.timeout);r.raise_for_status();return r.json()
    def set_port(self,shelf,resource,port,**kw):
        body={"shelf":shelf,"resource":resource,"port":port};body.update(kw)
        return self.post("/cli-json/set_port",body)
    def ports_snapshot(self):
        return self.get("/ports",params={"fields":"ip,ipv6 address,alias,port,down,phantom"})

# bit flags
CMD_FROM_DHCP=512
CF_IF_DOWN=1; CF_USE_DHCP=2147483648; CF_USE_DHCPV6=2199023255552; CF_IGNORE_DHCP=562949953421312
I_DHCP=16384; I_DHCPV6=16777216; I_IFDOWN=8388608; I_IPV6_ADDRS=131072
def I(*b): return int(sum(b))

# staging funcs
def stage(lf,shelf,res,sta,mode,bring_up=False):
    """stage (and optionally bring up) according to mode"""
    if mode=="ipv4":
        cur = CF_USE_DHCP if bring_up else (CF_IF_DOWN|CF_USE_DHCP)
        lf.set_port(shelf,res,sta,cmd_flags=CMD_FROM_DHCP,current_flags=cur,
                    interest=I(I_DHCP,I_IFDOWN,I_IPV6_ADDRS),
                    ipv6_addr_global="DELETED",ipv6_addr_link="DELETED",ipv6_dflt_gw="DELETED")
    elif mode=="ipv6":
        cur = (CF_USE_DHCPV6|CF_IGNORE_DHCP) if bring_up else (CF_IF_DOWN|CF_USE_DHCPV6|CF_IGNORE_DHCP)
        lf.set_port(shelf,res,sta,cmd_flags=CMD_FROM_DHCP,current_flags=cur,
                    interest=I(I_DHCP,I_DHCPV6,I_IFDOWN,I_IPV6_ADDRS),
                    ipv6_addr_global="AUTO",ipv6_addr_link="AUTO",ipv6_dflt_gw="AUTO")
    else:
        cur = (CF_USE_DHCP|CF_USE_DHCPV6) if bring_up else (CF_IF_DOWN|CF_USE_DHCP|CF_USE_DHCPV6)
        lf.set_port(shelf,res,sta,cmd_flags=CMD_FROM_DHCP,current_flags=cur,
                    interest=I(I_DHCP,I_DHCPV6,I_IFDOWN,I_IPV6_ADDRS),
                    ipv6_addr_global="AUTO",ipv6_addr_link="AUTO",ipv6_dflt_gw="AUTO")

def ports_ready(snapshot, names, mode="dual"):
    ok=0; want=set(names)
    for iface in snapshot.get("interfaces",[]):
        k=list(iface.keys())[0]; j=iface[k]; al=j.get("alias","")
        if al in want and not j.get("phantom",False) and not j.get("down",True):
            if mode=="ipv6":
                if j.get("ipv6 address")!="DELETED": ok+=1
            else:
                if j.get("ip") not in ("0.0.0.0",""): ok+=1
    return ok

def find_existing(snapshot,prefix="sta",limit=None):
    out=[]
    for iface in snapshot.get("interfaces",[]):
        k=list(iface.keys())[0]; j=iface[k]
        al=j.get("alias","")
        if al.startswith(prefix) and not j.get("phantom",False):
            out.append(al)
    out.sort()
    return out[:limit] if limit else out

def flag_present(extra, names): return any(f in extra for f in names)

# ---------------- main ----------------
def main():
    ap=argparse.ArgumentParser(description="Capacity tester v1.4 (leave ports up by default, optional --reset_ports)")
    ap.add_argument("--ssid"); ap.add_argument("--password",default="")
    ap.add_argument("--security",default="wpa2",choices=["open","wep","wpa","wpa2","wpa3"])
    ap.add_argument("--radio",default="1.1.wiphy0"); ap.add_argument("--num_stations",type=int,default=2)
    ap.add_argument("--start_id",type=int,default=None); ap.add_argument("--prefix",default="sta")
    ap.add_argument("--ipv4_only",action="store_true"); ap.add_argument("--ipv6_only",action="store_true"); ap.add_argument("--dual",action="store_true")
    ap.add_argument("--use_existing_stas",action="store_true"); ap.add_argument("--sta_prefix",default="sta"); ap.add_argument("--max_stas",type=int,default=None)
    ap.add_argument("--reset_ports",action="store_true",help="Force ports down/up before test")
    ap.add_argument("--protocol",default="UDP-IPv4"); ap.add_argument("--download_rate",default="1Gbps"); ap.add_argument("--upload_rate",default="0bps")
    ap.add_argument("--duration",type=int,default=6000); ap.add_argument("--upstream",default="1.1.eth1")
    ap.add_argument("-o","--outdir",default="/home/lanforge/Desktop/CapacityRuns")
    ap.add_argument("--mgr",default="localhost"); ap.add_argument("--mgr_port",type=int,default=8080)
    ap.add_argument("--shelf",type=int,default=1); ap.add_argument("--resource",type=int,default=1)

    known, extra = ap.parse_known_args(); args=known
    lf=LF(args.mgr,args.mgr_port)
    mode="dual"
    if args.ipv4_only: mode="ipv4"
    if args.ipv6_only: mode="ipv6"

    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir=os.path.join(args.outdir,ts); os.makedirs(outdir,exist_ok=True)
    aliases=[]

    # ---- Station Handling ----
    if args.use_existing_stas:
        snap=lf.ports_snapshot(); aliases=find_existing(snap,args.sta_prefix,args.max_stas)
        if not aliases: sys.exit("[!] No existing stations found.")
        print(f"[reuse] {len(aliases)} stations reused.")
        if args.reset_ports:
            print("[reset] cycling ports ...")
            for a in aliases: stage(lf,args.shelf,args.resource,a,mode,bring_up=False)
            for a in aliases: stage(lf,args.shelf,args.resource,a,mode,bring_up=True)
    else:
        if not args.ssid: sys.exit("Error: --ssid required for creation")
        radios=[r.strip() for r in args.radio.split(",") if r.strip()]
        base=args.start_id or 0
        for i,r in enumerate(radios):
            sid=base+i*args.num_stations
            cmd=[PYTHON,CREATE_STATION,"--mgr",args.mgr,"--mgr_port",str(args.mgr_port),
                 "--radio",r,"--security",args.security,"--ssid",args.ssid,
                 "--num_stations",str(args.num_stations),"--start_id",str(sid),
                 "--prefix",args.prefix,"--create_admin_down"]
            if args.password and args.security!="open": cmd+=["--passwd",args.password]
            print(f"[create] {r} start_id={sid}")
            rc,out,err=run_cmd(cmd); 
            if out: print(out); 
            if err: print(err,file=sys.stderr)
            for j in range(sid,sid+args.num_stations): aliases.append(f"{args.prefix}{j:04d}")
        # bring up once after creation
        for a in aliases: stage(lf,args.shelf,args.resource,a,mode,bring_up=False)
        for a in aliases: stage(lf,args.shelf,args.resource,a,mode,bring_up=True)

    # wait for IPs
    print("[ipcheck] waiting for IPs ...")
    t0=time.time()
    while time.time()-t0<180:
        snap=lf.ports_snapshot(); ok=ports_ready(snap,aliases,mode)
        if ok==len(aliases): print(f"All {ok} have IPs."); break
        time.sleep(5)
    else: print("[!] Some missing IPs, continuing.")

    eids=[f"{args.shelf}.{args.resource}.{a}" for a in aliases]

    # ---- Run WiFi Capacity ----
    cmd=[PYTHON,WIFI_CAPACITY,
         "--mgr",args.mgr,"--port",str(args.mgr_port),
         "--upstream",args.upstream,
         "--protocol",args.protocol,
         "--duration",str(args.duration),
         "--stations",",".join(eids),
         "--upload_rate",args.upload_rate,
         "--download_rate",args.download_rate,
         "--pull_report","--local_lf_report_dir",outdir]

    # default adds if not user-supplied
    if not flag_present(extra,{"--lf_user"}): cmd+=["--lf_user","lanforge"]
    if not flag_present(extra,{"--lf_password"}): cmd+=["--lf_password","lanforge"]
    if not flag_present(extra,{"--batch_size"}): cmd+=["--batch_size",str(len(eids))]
    if not flag_present(extra,{"--loop_iter"}): cmd+=["--loop_iter","1"]
    if not flag_present(extra,{"--verbosity"}): cmd+=["--verbosity","11"]

    cmd+=extra

    print(f"[run] executing WiFi Capacity for {len(eids)} stations...")
    rc,out,err=run_cmd(cmd)
    if out: print(out)
    if err: print(err,file=sys.stderr)
    chmod_777(outdir)
    print(f"[+] Done.\nFolder: {outdir}\nStations: {len(eids)}\nProtocol: {args.protocol}\n=== END ===")

if __name__=="__main__":
    main()
