#!/usr/bin/env python3
import json
import subprocess
import sys

CONFIG_FILE = "rvr_scenarios.json"

def run_scenario(name):
    with open(CONFIG_FILE) as f:
        scenarios = json.load(f)
    if name not in scenarios:
        print(f"Scenario '{name}' not found in {CONFIG_FILE}")
        sys.exit(1)

    s = scenarios[name]

    cmd = [
    "python3", "/home/lanforge/scripts/lf_rvr_test.py",
    "--mgr", "localhost",
    "--upstream", s["upstream"],
    "--station", s["station"],
    "--dut", s["dut"],
    "--download_speed", "85%",
    "--upload_speed", "0",
    "--duration", s["duration"],
    "--raw_line", f"sel_port-0: {s['station']}",
    "--raw_line", f"pkts: {s['packet_size']}",
    "--raw_line", f"traffic_types: {s['traffic_type']}",
    "--raw_line", f"directions: {s['direction']}",
    "--raw_line", f"attenuator: {s['attenuator']}",
    "--raw_line", f"attenuations: {s['attenuations']}",
    "--raw_line", f"channels: {s['channel']}",
    "--pull_report",
    "--local_lf_report_dir", "/home/lanforge/Desktop/rvr_reports",
    "--log_level", "info"
    ]
    
    print("Running:", " ".join(cmd))
    subprocess.run(cmd)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 run_rvr_wrapper.py <scenario_name>")
        sys.exit(1)

    run_scenario(sys.argv[1])
